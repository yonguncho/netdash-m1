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
    "juniper": "juniper_junos",
    "paloalto": "paloalto_panos",
}


def _norm_vendor(vendor):
    """벤더 값을 netmiko device_type/내부 키로 정규화(이미 정확하면 그대로)."""
    v = (vendor or "").strip().lower()
    return _NETMIKO_VENDOR.get(v, v)


# 벤더별 페이징 비활성화 명령(긴 출력 잘림 방지). EXOS는 'terminal length 0'이 아니라
# 'disable clpaging'. 미정의 벤더는 페이징 명령을 생략한다.
_PAGING_CMD = {
    "cisco_ios": "terminal length 0",
    "arista_eos": "terminal length 0",
    "extreme_exos": "disable clpaging",
    "juniper_junos": "set cli screen-length 0",
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
            vendor = _norm_vendor(switch["vendor"])
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
                outputs = _ssh_collect(switch, username, password, vendor, source_ip=source_ip)

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


def _ssh_collect(switch, username, password, vendor, max_retries=3, source_ip=None):
    """Collect outputs from network device via SSH with exponential backoff retry logic.

    Args:
        switch: Switch dict with 'name' and 'ip'
        username: SSH username
        password: SSH password
        vendor: Device vendor/type
        max_retries: Max retry attempts (default: 3) - handles transient network failures
        source_ip: M12 — bind outbound SSH to this local IP (pass device ACL). None = OS default.

    Returns:
        dict: Command outputs keyed by command name

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
    ssh_timeout = config.collector.get("ssh_timeout", 30)
    read_timeout = config.collector.get("read_timeout", 60)

    # FIX: read_timeout은 netmiko send_command()의 인자이지 ConnectHandler 생성자 인자가
    # 아니다. 생성자에 넣으면 "unexpected keyword argument 'read_timeout'" 오류.
    device = {
        "device_type": vendor,
        "ip": switch["ip"],
        "username": username,
        "password": password,
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
                # 벤더별 페이징 비활성화(미정의 벤더는 생략). 실패해도 수집은 계속.
                paging = _PAGING_CMD.get(vendor)
                if paging:
                    try:
                        conn.send_command(paging, read_timeout=read_timeout)
                    except Exception:
                        pass
                for key, command in commands.items():
                    output = conn.send_command(command, read_timeout=read_timeout)
                    outputs[key] = output
                    utils.log_event("debug", "command_executed", command=command)
            return outputs
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
