import queue
import threading
import logging
import re
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

from . import db
from . import fixtures
from . import utils
from . import credentials
from . import ssh_compat  # 구형 장비 SSH 레거시 알고리즘 호환(import 시 적용)
from config import get_config

logger = logging.getLogger(__name__)


def _sanitize_error_msg(error_str: str) -> str:
    """Redact sensitive info (passwords, credentials) from error messages.

    Security fix: Error logs may expose SSH credentials, file paths, or network topology.
    Remove known patterns and limit length to prevent log injection attacks.
    """
    if not error_str:
        return ""
    sanitized = re.sub(r'(password|credential|secret|key|auth)\s*[:=]\s*["\']?[^\s"\']+"?', '[REDACTED]', error_str, flags=re.I)
    sanitized = re.sub(r'/[a-zA-Z0-9/_\-\.]+\.pem', '[REDACTED]', sanitized)
    return sanitized[:200] if len(sanitized) > 200 else sanitized

_worker_queue = None
_worker_threads = []
_collecting_switches = set()
_collector_lock = threading.Lock()

# UI/단축 vendor 값 → netmiko device_type & config/parser 키 정규화.
# 연결 테스트(connectivity)는 매핑했으나 수집 경로는 raw vendor를 써서
# "unsupported device_type" 오류가 났다 → 동일 정규화 적용.
_NETMIKO_VENDOR = {
    "cisco": "cisco_ios",
    "nexus": "cisco_nxos",
    "cisco_nexus": "cisco_nxos",
    "arista": "arista_eos",
    "extreme": "extreme_exos",
    "extremexos": "extreme_exos",
    "extreme_xos": "extreme_exos",
    "extreme-xos": "extreme_exos",
    "exos": "extreme_exos",
    "extremenetworks": "extreme_exos",
    "juniper": "juniper_junos",
    "paloalto": "paloalto_panos",
    "alteon": "alteon",
    "radware": "alteon",
    "radware_alteon": "alteon",
    "nortel_alteon": "alteon",
}


def _norm_vendor(vendor):
    """벤더 값을 netmiko device_type/내부 키로 정규화(이미 정확하면 그대로).

    벤더 미지정('unknown'/빈값)은 가장 흔한 Cisco IOS로 시도(fallback).
    """
    v = (vendor or "").strip().lower()
    if v in ("", "unknown"):
        return "cisco_ios"
    return _NETMIKO_VENDOR.get(v, v)


def _is_unknown_vendor(vendor):
    return (vendor or "").strip().lower() in ("", "unknown")


def _detect_vendor_from_version(text):
    """show version 출력에서 실제 벤더(device_type) 학습. 못 찾으면 None.

    순서 중요: NX-OS는 'Cisco Nexus...NX-OS'라 Cisco보다 먼저 판별한다.
    """
    t = (text or "").lower()
    if not t:
        return None
    if "nx-os" in t or "nexus" in t:
        return "cisco_nxos"
    if "arista" in t:
        return "arista_eos"
    if "extremexos" in t or "exos" in t or "extreme networks" in t:
        return "extreme_exos"
    if "junos" in t or "juniper" in t:
        return "juniper_junos"
    if "ios-xe" in t or "ios xe" in t or "cisco ios" in t or "ios software" in t or "cisco" in t:
        return "cisco_ios"
    return None


def _commands_for(vendor):
    """벤더의 수집 명령 집합. config에 없으면 파서 모듈 COMMANDS로 폴백."""
    cmds = get_config().get_commands(vendor)
    if cmds:
        return cmds
    try:
        from . import parsers
        parser = parsers.get_parser(vendor)
        return dict(getattr(parser, "COMMANDS", {}) or {})
    except Exception:
        return {}


# 벤더별 페이징 비활성화 명령(긴 출력 잘림 방지). EXOS는 'terminal length 0'이 아니라
# 'disable clpaging'. 미정의 벤더는 페이징 명령을 생략한다.
_PAGING_CMD = {
    "cisco_ios": "terminal length 0",
    "arista_eos": "terminal length 0",
    "extreme_exos": "disable clpaging",
    "juniper_junos": "set cli screen-length 0",
}

# 포트채널 멤버 해석용 추가 명령(config 무관 항상 시도). 설비/TPS 직결이
# MAC 테이블에 Po로 보일 때 실제 물리 멤버포트를 알아내기 위함.
_PORT_CHANNEL_CMD = {
    "cisco_nxos": "show port-channel summary",
}


def init_collector():
    global _worker_queue, _worker_threads
    config = get_config()
    max_workers = config.get_max_concurrent()

    # Replace queue and start fresh workers (old workers are daemon threads, auto-cleanup)
    _worker_queue = queue.Queue(maxsize=100)
    _worker_threads = []

    for i in range(max_workers):
        t = threading.Thread(target=_worker_loop, daemon=True, name=f"collector-worker-{i}")
        t.start()
        _worker_threads.append(t)

    utils.log_event("info", "collector_init", workers=max_workers)


def collect_switch(db_path, switch_id, username=None, password=None):
    """Enqueue an async collection for a switch.

    M5 (async_credential): Credentials are NEVER placed in the queue payload.
    If username/password are passed directly (backward-compat), they are moved
    into the in-memory session store and the local references are dropped
    immediately. The worker loads them from the session store and clears them
    after collection completes (success or failure).

    Returns:
        dict with status 'queued' or 'error'
    """
    global _worker_queue, _collecting_switches

    utils.log_event("info", "collect_switch_requested", switch_id=switch_id)

    if _worker_queue is None:
        init_collector()

    with _collector_lock:
        if switch_id in _collecting_switches:
            utils.log_event("warning", "collect_already_in_progress", switch_id=switch_id)
            return {
                "status": "error",
                "message": f"Switch {switch_id} is already being collected"
            }

        _collecting_switches.add(switch_id)

    try:
        # M5 (CWE-522): Move directly-passed credentials into the session store so
        # the queue payload stays free of plaintext. Kept INSIDE the try so any
        # failure here also releases the in-progress mark via _abort_enqueue.
        if username is not None or password is not None:
            credentials.save_credential(switch_id, username, password)
            username = None
            password = None
        # M5: payload carries no credentials, only the work identifiers.
        _worker_queue.put((db_path, switch_id), block=False)
        position = _worker_queue.qsize()
        utils.log_event("info", "collect_queued", switch_id=switch_id, position=position)
        return {
            "status": "queued",
            "switch_id": switch_id,
            "queue_position": position
        }
    except queue.Full:
        # M5: queue failed before the worker can run; clear session creds now.
        _abort_enqueue(switch_id)
        utils.log_event("error", "collect_queue_full", switch_id=switch_id)
        return {
            "status": "error",
            "message": "Queue is full"
        }
    except Exception as e:
        # M5 (W1): Any other enqueue-time failure must also release the
        # in-progress mark and dispose the session credential to avoid leaks.
        _abort_enqueue(switch_id)
        sanitized = _sanitize_error_msg(str(e))
        utils.log_event("error", "collect_enqueue_error", switch_id=switch_id, error=sanitized)
        return {
            "status": "error",
            "message": "Failed to enqueue collection"
        }


def _abort_enqueue(switch_id):
    """Release in-progress mark and dispose session credential after a failed enqueue."""
    with _collector_lock:
        _collecting_switches.discard(switch_id)
    credentials.clear_session_switch(switch_id)


def _worker_loop():
    global _worker_queue, _collecting_switches

    while True:
        # MEDIUM FIX (CPU optimization): Remove timeout to prevent unnecessary wakeups (busy-wait)
        # Worker will block indefinitely until task arrives, reducing CPU usage
        # Note: No timeout means queue.Empty will never be raised (unreachable code removed)
        # M5 (async_credential): payload carries no credentials, only identifiers.
        db_path, switch_id = _worker_queue.get()

        username = None
        password = None
        cred = None
        try:
            utils.log_event("info", "collect_start", switch_id=switch_id)
            db.set_switch_status(db_path, switch_id, "collecting")

            switch = db.get_switch(db_path, switch_id)
            if not switch:
                raise ValueError(f"Switch {switch_id} not found")

            # 벤더 정규화(cisco→cisco_ios 등): device_type/commands/parser 일관 사용
            raw_vendor = switch["vendor"]
            is_unknown = _is_unknown_vendor(raw_vendor)
            vendor = _norm_vendor(raw_vendor)
            config = get_config()

            if config.app.get("demo_mode"):
                outputs = fixtures.get_demo_outputs_for_vendor(vendor)
                utils.log_event("info", "demo_mode_outputs", switch_id=switch_id, vendor=vendor)
            else:
                # M5 (CWE-522): Load credentials from the session store at the
                # moment of use; fail explicitly if none were supplied.
                cred = credentials.load_credential(switch_id)
                if not cred:
                    raise ValueError(f"No credentials available for switch {switch_id}")
                username = cred.get("username")
                password = cred.get("password")
                # M12: 설정된 출발지 IP로 바인딩(장비 ACL 통과). 미설정이면 OS 기본 라우팅.
                source_ip = db.get_setting(db_path, "source_ip") or None
                if vendor == "alteon":
                    # Alteon은 메뉴형 CLI(netmiko 미지원) → 전용 paramiko 수집
                    outputs = _alteon_collect(switch, username, password, source_ip=source_ip)
                    eff_vendor = "alteon"
                else:
                    # 벤더 미지정이면 접속 후 show version으로 실제 벤더 학습
                    outputs, eff_vendor = _ssh_collect(
                        switch, username, password, vendor,
                        source_ip=source_ip, detect_vendor=is_unknown)
                # 학습 성공 시 DB 벤더 갱신 + 이번 파싱도 학습된 벤더로
                if is_unknown and eff_vendor and eff_vendor != raw_vendor:
                    try:
                        db.update_switch(db_path, switch_id, vendor=eff_vendor)
                        utils.log_event("info", "vendor_learned",
                                        switch_id=switch_id, vendor=eff_vendor)
                    except Exception as _e:
                        utils.log_event("warning", "vendor_update_failed",
                                        switch_id=switch_id, error=_sanitize_error_msg(str(_e)))
                    vendor = eff_vendor

            raw_outputs_path = _save_raw_outputs(db_path, switch_id, switch["name"], outputs)
            utils.log_event("info", "raw_outputs_saved", path=str(raw_outputs_path))

            parsed_data = _parse_outputs(vendor, outputs, switch_id)

            # M3: Detect disconnected MAC entries before saving new snapshot
            prev_snapshot_id = db.latest_snapshot_id(db_path, switch_id)
            if prev_snapshot_id is not None:
                # Build (vlan, mac, port) tuples from current parsed data
                curr_macs = [(m.get("vlan"), m.get("mac"), m.get("port"))
                            for m in parsed_data.get("macs", [])]
                db._detect_disconnected(db_path, switch_id, prev_snapshot_id, curr_macs)

            snapshot_id = db.save_snapshot(db_path, switch_id)
            db.save_ports(db_path, snapshot_id, switch_id, parsed_data.get("ports", []))
            db.save_mac_entries(db_path, snapshot_id, switch_id, parsed_data.get("macs", []))
            db.save_arp_entries(db_path, snapshot_id, switch_id, parsed_data.get("arps", []))
            # NX-OS 포트채널 멤버(Po → 물리 멤버포트) 저장 — 설비 대조 해석용
            db.save_port_channels(db_path, snapshot_id, switch_id, parsed_data.get("port_channels", []))
            # VLAN 이름(show vlan brief)은 스냅샷 무관 최신값으로 교체 저장
            if parsed_data.get("vlans"):
                db.save_vlan_names(db_path, switch_id, parsed_data.get("vlans", []))

            # show logging/show log 분석: 최근 15줄 + flapping/looping/err 탐지
            log_out = outputs.get("logging", "")
            if log_out:
                try:
                    import json as _json
                    from . import log_analyzer
                    la = log_analyzer.analyze(log_out, tail=15)
                    db.save_switch_logs(
                        db_path, switch_id, "\n".join(la["recent"]),
                        _json.dumps(la["events"], ensure_ascii=False), la["alert"])
                    if la["alert"] in ("warning", "critical"):
                        utils.log_event("warning", "log_anomaly_detected",
                                        switch_id=switch_id, alert=la["alert"],
                                        events=len(la["events"]))
                except Exception as e:
                    utils.log_event("warning", "log_analyze_skipped",
                                    error=_sanitize_error_msg(str(e)))

            db.set_switch_status(db_path, switch_id, "done")
            utils.log_event("info", "collect_done", switch_id=switch_id, snapshot_id=snapshot_id)

        except Exception as e:
            # Sanitize error messages to prevent credential/path exposure in logs (security fix: CVE-style issue)
            sanitized_error = _sanitize_error_msg(str(e))
            utils.log_event("error", "collect_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
            db.set_switch_status(db_path, switch_id, "failed", error=sanitized_error)
        finally:
            # CWE-522 fix: Explicitly clear credentials from memory to prevent plaintext exposure
            # M5 (W2): cred is a defensive copy from load_credential; emptying the
            # dict drops the plaintext references it holds.
            if isinstance(cred, dict):
                cred.clear()
            cred = None
            username = None
            password = None
            # M5 (async_credential): Worker owns credential disposal. Clear the
            # session store entry regardless of success/failure/exception.
            credentials.clear_session_switch(switch_id)
            with _collector_lock:
                _collecting_switches.discard(switch_id)
            # CRITICAL: Safely call task_done() even if queue was replaced during test teardown
            try:
                _worker_queue.task_done()
            except ValueError:
                # Queue was replaced during reinit; ignore this error (happens in tests)
                pass


def _ssh_collect(switch, username, password, vendor, max_retries=3, source_ip=None,
                 detect_vendor=False):
    """Collect outputs from network device via SSH with exponential backoff retry logic.

    Args:
        switch: Switch dict with 'name' and 'ip'
        username: SSH username
        password: SSH password
        vendor: Device vendor/type (연결/명령 기본값)
        max_retries: Max retry attempts (default: 3) - handles transient network failures
        source_ip: M12 — bind outbound SSH to this local IP (pass device ACL). None = OS default.
        detect_vendor: True면 접속 후 show version으로 실제 벤더를 학습해 명령/파서를 그에 맞춘다.

    Returns:
        (outputs: dict, effective_vendor: str)  # 학습된 실제 벤더(미학습 시 입력 vendor)

    Raises:
        ImportError: If netmiko not installed
        Exception: After max_retries exhausted
    """
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise ImportError("netmiko not installed")

    config = get_config()
    commands = config.get_commands(vendor)
    eff_vendor = vendor
    ssh_timeout = config.collector.get("ssh_timeout", 30)
    read_timeout = config.collector.get("read_timeout", 60)

    # FIX: read_timeout은 netmiko send_command()의 인자이지 ConnectHandler 생성자 인자가
    # 아니다. 생성자에 넣으면 "unexpected keyword argument 'read_timeout'" 오류.
    device = {
        "device_type": vendor,
        "ip": switch["ip"],
        "username": username,
        "password": password,
        # enable secret: 1차로 로그인 비밀번호를 사용(많은 환경에서 동일).
        "secret": password,
        "conn_timeout": ssh_timeout,
        "fast_cli": False
    }

    # Exponential backoff retry loop for transient network failures (robustness improvement)
    import time
    for attempt in range(max_retries):
        utils.log_event("info", "ssh_connect", switch=switch["name"], vendor=vendor, attempt=attempt+1, max_retries=max_retries)

        try:
            outputs = {}
            conn_device = dict(device)
            if source_ip:
                # M12: 출발지 IP 바인딩한 소켓을 netmiko에 전달(재연결마다 새 소켓)
                from . import netbind
                conn_device["sock"] = netbind.bind_socket(switch["ip"], 22, source_ip, ssh_timeout)
            with ConnectHandler(**conn_device) as conn:
                # user 모드(>)면 enable 진입. IOS-XE는 user 모드에서 show 명령이
                # "% Invalid input"으로 거부되므로 특권 모드로 올라간다.
                try:
                    if hasattr(conn, "check_enable_mode") and not conn.check_enable_mode():
                        conn.enable()
                except Exception as _e:
                    utils.log_event("warning", "enable_failed",
                                    switch=switch["name"], error=_sanitize_error_msg(str(_e)))
                # 벤더별 페이징 비활성화(미정의 벤더는 생략). 실패해도 수집은 계속.
                paging = _PAGING_CMD.get(eff_vendor)
                if paging:
                    try:
                        conn.send_command(paging, read_timeout=read_timeout)
                    except Exception:
                        pass
                # 벤더 미지정이면 show version으로 실제 벤더 학습 → 명령/파서 그에 맞춤
                if detect_vendor:
                    try:
                        ver = conn.send_command("show version", read_timeout=read_timeout)
                        outputs["version"] = ver
                        detected = _detect_vendor_from_version(ver)
                        if detected and detected != eff_vendor:
                            eff_vendor = detected
                            commands = _commands_for(eff_vendor) or commands
                            utils.log_event("info", "vendor_detected",
                                            switch=switch["name"], vendor=eff_vendor)
                            # 학습된 벤더의 페이징도 한 번 더 적용(EXOS 등)
                            p2 = _PAGING_CMD.get(eff_vendor)
                            if p2 and p2 != paging:
                                try:
                                    conn.send_command(p2, read_timeout=read_timeout)
                                except Exception:
                                    pass
                    except Exception as _e:
                        utils.log_event("warning", "vendor_detect_failed",
                                        switch=switch["name"], error=_sanitize_error_msg(str(_e)))
                # 명령별 개별 예외 처리: 한 명령이 실패(미지원/타임아웃)해도 나머지는 수집.
                # (예: EXOS의 특정 show 명령이 없어도 전체 수집이 실패하지 않도록)
                cmd_errors = 0
                for key, command in commands.items():
                    try:
                        outputs[key] = conn.send_command(command, read_timeout=read_timeout)
                        utils.log_event("debug", "command_executed", command=command)
                    except Exception as _ce:
                        outputs[key] = ""
                        cmd_errors += 1
                        utils.log_event("warning", "command_failed", switch=switch["name"],
                                        command=command, error=_sanitize_error_msg(str(_ce)))
                # 모든 명령이 실패(응답 전무)면 장비 무응답/명령셋 불일치 → 수집 실패 처리
                if commands and cmd_errors == len(commands):
                    raise RuntimeError("all collection commands failed")
                # 포트채널 멤버 해석 명령(config에 없어도 벤더별로 항상 시도)
                pc_cmd = _PORT_CHANNEL_CMD.get(eff_vendor)
                if pc_cmd and "port_channel" not in outputs:
                    try:
                        outputs["port_channel"] = conn.send_command(pc_cmd, read_timeout=read_timeout)
                    except Exception:
                        pass
            return outputs, eff_vendor
        except Exception as e:
            # Sanitize SSH error messages to prevent credential/host info exposure (security fix)
            sanitized_error = _sanitize_error_msg(str(e))

            if attempt < max_retries - 1:
                # Exponential backoff: 1s, 2s, 4s (retry on transient failures)
                wait_time = 2 ** attempt
                utils.log_event("warning", "ssh_retry", switch=switch["name"], attempt=attempt+1, max_retries=max_retries, wait_seconds=wait_time, error_type=type(e).__name__)
                time.sleep(wait_time)
            else:
                # Final attempt failed, log and raise
                utils.log_event("error", "ssh_error", switch=switch["name"], error_type=type(e).__name__, error=sanitized_error)
                raise
        finally:
            # FIX: 매 시도마다 복사본(conn_device)만 정리한다. 이전엔 원본 device를
            # clear()해서 retry 2회차에 device/conn_device가 빈 dict가 되고 source
            # 바인딩 소켓도 사라져 재시도가 깨졌다. 원본 device는 retry 위해 유지하고,
            # 함수 종료(return/raise) 시 GC로 정리된다.
            if 'conn_device' in locals():
                conn_device.clear()
            username = None
            password = None


def _alteon_read(shell, timeout=25, idle=0.6):
    """Alteon 대화형 셸에서 프롬프트/유휴까지 읽기. 'more' 페이징은 스페이스로 넘긴다."""
    import time as _t
    buf = ""
    deadline = _t.monotonic() + timeout
    last_data = _t.monotonic()
    while _t.monotonic() < deadline:
        if shell.recv_ready():
            buf += shell.recv(65535).decode("utf-8", "replace")
            last_data = _t.monotonic()
            tail = buf[-120:].lower()
            if "more" in tail or "continue" in tail or "q to quit" in tail:
                try:
                    shell.send(" ")
                except Exception:
                    pass
        else:
            if _t.monotonic() - last_data > idle:
                s = buf.rstrip()
                if (not s) or s.endswith("#") or s.endswith(">") or s.endswith("$"):
                    break
                if _t.monotonic() - last_data > idle * 4:
                    break
            _t.sleep(0.15)
    return buf


def _alteon_collect(switch, username, password, source_ip=None):
    """Alteon 메뉴형 CLI 수집(netmiko 미지원 → paramiko 대화형 셸).

    각 명령은 루트('/')에서 전체 경로(/info/...)로 실행. 페이징은 스페이스로 넘김.
    한 명령이 실패해도 나머지는 계속(원본 저장으로 진단 가능). 반환: outputs dict.
    """
    import paramiko
    import time as _t
    from . import ssh_compat
    ssh_compat.enable_legacy_algorithms()  # 구형 장비 SSH 호환
    from .parsers import alteon as _alt

    host = switch["ip"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sock = None
    if source_ip:
        from . import netbind
        sock = netbind.bind_socket(host, 22, source_ip, 30)
    outputs = {}
    try:
        client.connect(host, port=22, username=username, password=password,
                       timeout=30, allow_agent=False, look_for_keys=False, sock=sock)
        shell = client.invoke_shell(width=250, height=1000)
        _t.sleep(1.0)
        _alteon_read(shell, timeout=5)        # 로그인 배너/프롬프트 비우기
        for key, cmd in _alt.COMMANDS.items():
            try:
                shell.send("/\n")             # 루트 메뉴로 이동
                _alteon_read(shell, timeout=4)
                shell.send(cmd + "\n")
                outputs[key] = _alteon_read(shell, timeout=30)
            except Exception as _ce:
                outputs[key] = ""
                utils.log_event("warning", "alteon_command_failed",
                                switch=switch["name"], command=cmd,
                                error=_sanitize_error_msg(str(_ce)))
    finally:
        try:
            client.close()
        except Exception:
            pass
    return outputs


def _save_raw_outputs(db_path, switch_id, switch_name, outputs):
    config = get_config()
    raw_outputs_root = Path(config.get_raw_outputs_path())

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = raw_outputs_root / switch_name / now
    output_dir.mkdir(parents=True, exist_ok=True)

    for key, content in outputs.items():
        file_path = output_dir / f"{key}.txt"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    return output_dir


def _parse_outputs(vendor, outputs, switch_id):
    utils.log_event("info", "parse_outputs", vendor=vendor, switch_id=switch_id)

    try:
        from . import parsers
        parser = parsers.get_parser(vendor)
        return parser.parse(outputs, switch_id)
    except ValueError:
        utils.log_event("warning", "parser_not_found", vendor=vendor)
        return {"ports": [], "macs": [], "arps": []}


def _ip_allowed(ip, allowed_ranges):
    """SSRF 재검증: 예약/위험 대역 거부 + allowed_ip_ranges 화이트리스트.

    자동 수집은 수동 엔드포인트를 거치지 않으므로 여기서 동일 검증을 수행한다.
    """
    import ipaddress
    if not ip:
        return False
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_reserved:
        return False
    if allowed_ranges:
        for cidr in allowed_ranges:
            try:
                if addr in ipaddress.IPv4Network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    return True


def collect_all_registered(db_path):
    """자동 수집: 저장된 자격증명이 있는 모든 스위치/방화벽을 일괄 수집.

    스위치는 워커 큐로(비동기), 방화벽은 즉시 수집. 자격증명 없는 장비는 건너뜀.
    SSRF: 수동 경로와 동일하게 대상 IP를 collect 직전 재검증.
    Returns: {"switches": n, "firewalls": n}
    """
    import json as _json
    result = {"switches": 0, "firewalls": 0}
    _allowed_ranges = get_config().collector.get("allowed_ip_ranges")

    # 스위치: 저장된 계정 복호화 → 큐잉(기존 워커가 수집)
    try:
        for sw in db.get_switches(db_path):
            if not _ip_allowed(sw.get("ip"), _allowed_ranges):
                utils.log_event("warning", "auto_collect_skip_invalid_ip",
                                switch_id=sw.get("id"))
                continue
            blob = db.get_switch_credential(db_path, sw["id"])
            if not blob:
                continue
            # 스위치 자격증명은 "username|password" 형식(credentials.encrypt_credential)
            dec = credentials.decrypt_credential(blob)
            if not dec or "|" not in dec:
                continue
            username, password = dec.split("|", 1)
            collect_switch(db_path, sw["id"], username, password)
            result["switches"] += 1
    except Exception as e:
        utils.log_event("error", "auto_collect_switches_error", error=_sanitize_error_msg(str(e)))

    # 방화벽: 저장된 토큰/계정으로 즉시 수집
    try:
        from . import firewall as firewall_mod
        src = db.get_setting(db_path, "source_ip") or None
        for fw in db.list_firewalls(db_path):
            if not _ip_allowed(fw.get("host"), _allowed_ranges):
                utils.log_event("warning", "auto_collect_skip_invalid_fw_ip",
                                firewall_id=fw.get("id"))
                continue
            blob = db.get_firewall_credential(db_path, fw["id"])
            if not blob:
                continue
            dec = credentials.decrypt_text(blob)
            if not dec:
                continue
            try:
                saved = _json.loads(dec)
            except (ValueError, TypeError):
                continue
            try:
                db.set_firewall_status(db_path, fw["id"], "collecting")
                r = firewall_mod.collect_firewall(
                    fw["vendor"], fw["host"], fw.get("port"),
                    token=saved.get("token", ""), username=saved.get("username", ""),
                    password=saved.get("password", ""), source_ip=src)
                db.save_firewall_interfaces(db_path, fw["id"], r["interfaces"])
                db.save_firewall_arp(db_path, fw["id"], r["arp"])
                db.set_firewall_status(db_path, fw["id"], "done")
                result["firewalls"] += 1
            except Exception as e:
                db.set_firewall_status(db_path, fw["id"], "failed")
                utils.log_event("error", "auto_collect_fw_error", firewall_id=fw["id"],
                                error=_sanitize_error_msg(str(e)))
    except Exception as e:
        utils.log_event("error", "auto_collect_firewalls_error", error=_sanitize_error_msg(str(e)))

    utils.log_event("info", "auto_collect_done", switches=result["switches"], firewalls=result["firewalls"])
    return result
