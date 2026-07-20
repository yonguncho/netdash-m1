# -*- coding: utf-8 -*-
"""서버(리눅스/윈도우) 현황 수집.

수집 2단계:
① 무자격(항상): TCP 포트 스캔 + 역방향 DNS(hostname) +
   기존 스위치 수집 데이터(ARP/MAC 테이블) 대조로 MAC·연결 스위치/포트 파악.
② SSH 상세(자격증명 있을 때): 리눅스 = hostname/OS/인터페이스 MAC/리스닝 포트,
   윈도우 = OpenSSH 서버가 있으면 hostname/OS. (WinRM은 미지원 — 폐쇄망 의존성 최소화)

VM 판정: MAC OUI(가상화 벤더 대역)로 자동 추정. 수동 지정이 항상 우선.
"""
import re
import socket
import threading

from . import db, utils, credentials

# 스캔 대상 공통 포트(서버 용도 파악용 — 과도한 스캔 금지)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 1433, 1521,
                2049, 3128, 3306, 3389, 5432, 5900, 8080, 8443, 9090]
_SCAN_TIMEOUT = 1.0
_SCAN_CONCURRENCY = 12

# 가상머신 MAC OUI(제조사 고정 대역) — 앞 3바이트
_VM_OUI = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "00:1C:14": "VMware",
    "00:15:5D": "Hyper-V",
    "08:00:27": "VirtualBox",
    "52:54:00": "KVM/QEMU",
    "00:16:3E": "Xen",
}


def _norm_mac(mac):
    """MAC을 AA:BB:CC:DD:EE:FF 로 정규화(콜론/하이픈/점 표기 수용)."""
    if not mac:
        return ""
    hexs = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
    if len(hexs) != 12:
        return str(mac).upper()
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)).upper()


def guess_vm_from_mac(mac):
    """MAC OUI로 VM 여부 추정. 반환: (is_vm: bool|None, vendor: str)."""
    m = _norm_mac(mac)
    if len(m) < 8:
        return None, ""
    vendor = _VM_OUI.get(m[:8])
    if vendor:
        return True, vendor
    return False, ""


def scan_ports(ip, ports=None, timeout=_SCAN_TIMEOUT):
    """TCP connect 스캔(동시 제한). 열린 포트 오름차순 리스트 반환."""
    ports = ports or COMMON_PORTS
    open_ports = []
    lock = threading.Lock()
    sem = threading.Semaphore(_SCAN_CONCURRENCY)

    def _one(p):
        with sem:
            try:
                with socket.create_connection((ip, p), timeout=timeout):
                    with lock:
                        open_ports.append(p)
            except OSError:
                pass

    threads = [threading.Thread(target=_one, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 3)
    return sorted(open_ports)


def reverse_dns(ip):
    """역방향 DNS로 hostname 조회(실패 시 빈 문자열 — 폐쇄망 DNS 없음 무해)."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name
    except OSError:
        return ""


def netbios_name(ip, timeout=2):
    """NetBIOS 이름 질의(UDP 137)로 hostname 조회 — 계정 없이 윈도우 서버 이름 획득.

    폐쇄망은 DNS PTR이 없는 경우가 많아 역DNS로는 hostname을 못 얻는다. 윈도우는
    NBNS Node Status Request(NBSTAT)에 응답하므로 계정 없이 컴퓨터 이름을 알 수 있다.
    리눅스는 보통 무응답(Samba 미구동 시) → 빈 문자열. 실패해도 무해.
    """
    # NBSTAT node status request: trailer '*'(0x2A)+null 15개, name type 0x00
    query = (b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x20\x43\x4b" + b"\x41" * 30 + b"\x00\x00\x21\x00\x01")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(2048)
        # 응답 헤더(12) + 질의반향(34) 뒤: [답변수(1B)] 이어서 이름 16B 레코드들
        if len(data) < 57:
            return ""
        num = data[56]
        off = 57
        for _ in range(num):
            if off + 18 > len(data):
                break
            name = data[off:off + 15].decode("ascii", "ignore").strip()
            ntype = data[off + 15]
            flags = data[off + 16] << 8 | data[off + 17]
            is_group = bool(flags & 0x8000)
            # 유니크 + 워크스테이션 서비스(0x00) = 컴퓨터 이름
            if ntype == 0x00 and not is_group and name:
                return name[:100]
            off += 18
        return ""
    except (OSError, socket.timeout, IndexError):
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _ssh_exec(ip, username, password, commands, timeout=15):
    """paramiko로 명령 목록 실행 → {cmd: output}. 연결 실패 시 예외."""
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    out = {}
    try:
        cli.connect(ip, port=22, username=username, password=password,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                    look_for_keys=False, allow_agent=False)
        for cmd in commands:
            try:
                _, stdout, _ = cli.exec_command(cmd, timeout=timeout)
                out[cmd] = stdout.read().decode("utf-8", "replace")[:20000]
            except Exception:
                out[cmd] = ""
    finally:
        cli.close()
    return out


def _ssh_detail_linux(ip, username, password):
    """리눅스 SSH 상세: hostname, OS, 첫 물리 인터페이스 MAC, 리스닝 포트."""
    o = _ssh_exec(ip, username, password,
                  ["hostname", "uname -sr", "ip -o link", "ss -tln"])
    detail = {}
    if o.get("hostname", "").strip():
        detail["hostname"] = o["hostname"].strip().splitlines()[0][:100]
    if o.get("uname -sr", "").strip():
        detail["os_info"] = o["uname -sr"].strip().splitlines()[0][:120]
    # ip -o link: "2: ens192: <...> link/ether 00:50:56:aa:bb:cc ..."
    for ln in (o.get("ip -o link") or "").splitlines():
        if "link/ether" in ln and "lo:" not in ln:
            m = re.search(r"link/ether\s+([0-9a-f:]{17})", ln, re.I)
            if m:
                detail["mac"] = _norm_mac(m.group(1))
                break
    # ss -tln: "LISTEN 0 128 0.0.0.0:22 ..." → 리스닝 포트
    lports = set()
    for ln in (o.get("ss -tln") or "").splitlines():
        m = re.search(r"[\d.\[\]:*]+:(\d+)\s", ln)
        if m and "LISTEN" in ln.upper():
            lports.add(int(m.group(1)))
    if lports:
        detail["open_ports"] = ",".join(str(p) for p in sorted(lports)[:40])
    return detail


def _ssh_detail_windows(ip, username, password):
    """윈도우 SSH 상세(OpenSSH 서버 설치 시): hostname, OS 버전."""
    o = _ssh_exec(ip, username, password, ["hostname", "ver"])
    detail = {}
    if o.get("hostname", "").strip():
        detail["hostname"] = o["hostname"].strip().splitlines()[0][:100]
    ver = (o.get("ver") or "").strip()
    if ver:
        detail["os_info"] = ver.splitlines()[-1][:120]
    return detail


def detect_os(ip, username, password, timeout=15):
    """SSH 접속 후 OS 자동 인식: 'linux' | 'windows' | None(접속 실패).

    ① SSH 배너(transport.remote_version)에 'windows'가 있으면 윈도우 OpenSSH.
    ② 아니면 'uname -s' 실행 — 성공하고 Linux/BSD/Darwin이면 리눅스 계열.
    ③ 배너 판별이 되면 명령 없이 즉시 반환(비용 절감).
    """
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(ip, port=22, username=username, password=password,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                    look_for_keys=False, allow_agent=False)
        banner = ""
        try:
            banner = (cli.get_transport().remote_version or "").lower()
        except Exception:
            banner = ""
        if "windows" in banner:
            return "windows"
        try:
            _, stdout, _ = cli.exec_command("uname -s", timeout=timeout)
            uname = stdout.read().decode("utf-8", "replace").strip().lower()
            if any(k in uname for k in ("linux", "bsd", "darwin", "sunos", "aix")):
                return "linux"
        except Exception:
            pass
        # uname이 안 먹고(윈도우 cmd) 배너에 단서 없으면 윈도우로 간주
        return "windows"
    except Exception as e:
        utils.log_event("warning", "server_os_detect_failed", ip=ip,
                        error=str(e)[:120])
        return None
    finally:
        try:
            cli.close()
        except Exception:
            pass


def collect_server(db_path, server_id, username=None, password=None):
    """서버 1대 수집(동기). 무자격 단계는 항상, SSH 상세는 자격증명 있을 때.

    반환: {"status": "done"|"failed", ...수집 필드}
    """
    sv = db.get_server(db_path, server_id)
    if not sv:
        return {"status": "failed", "error": "not found"}
    ip = sv["ip"]
    utils.log_event("info", "server_collect_start", server_id=server_id, ip=ip)
    db.update_server(db_path, server_id, status="collecting")

    fields = {}
    errors = []

    # ① 무자격: 포트 스캔 + hostname(역DNS/NetBIOS) + 스위치 데이터 대조(MAC·연결 위치)
    open_ports = []
    try:
        open_ports = scan_ports(ip)
        fields["open_ports"] = ",".join(str(p) for p in open_ports)
    except Exception as e:
        errors.append("스캔: %s" % e)
    # hostname: 역방향 DNS → (없으면) NetBIOS 이름질의(UDP137, 윈도우 무자격 조회)
    rdns = reverse_dns(ip) or netbios_name(ip)
    if rdns:
        fields["hostname"] = rdns
    # 연결 위치: ARP→MAC→스위치포트. 물리 포트 우선, Po면 물리 멤버로 해석.
    loc = db.find_mac_location(db_path, ip)
    if loc.get("mac"):
        fields["mac"] = _norm_mac(loc["mac"])
    if loc.get("switch_name"):
        fields["switch_name"] = loc["switch_name"]
        port = loc.get("port") or ""
        pl = port.lower()
        if pl.startswith(("po", "port-channel")) and loc.get("switch_id"):
            # 물리 서버의 실제 케이블 포트: 포트채널 집합(Po10) → 물리 멤버포트로 치환
            try:
                pc = db.get_port_channel_members(db_path)
                members = pc.get((loc["switch_id"], pl))
                if members:
                    port = "%s (%s)" % (", ".join(members), port)
            except Exception:
                pass
        fields["switch_port"] = port

    # ② SSH 상세(자격증명 시) — 실패해도 무자격 결과는 유지
    if username and password:
        os_type = (sv.get("os_type") or "auto").lower()
        # OS 자동 인식: 'auto'이거나 미설정이면 접속해서 판별 후 os_type 확정
        if os_type not in ("linux", "windows"):
            detected = detect_os(ip, username, password)
            if detected:
                os_type = detected
                fields["os_type"] = detected
                utils.log_event("info", "server_os_detected",
                                server_id=server_id, os_type=detected)
            else:
                os_type = "linux"   # 접속 실패 시 기본값(상세는 아래서 다시 시도)
        try:
            if os_type == "windows":
                fields.update(_ssh_detail_windows(ip, username, password))
            else:
                fields.update(_ssh_detail_linux(ip, username, password))
        except Exception as e:
            errors.append("SSH: %s" % str(e)[:120])

    # VM 자동 추정(MAC 확보 시) — 사용자가 이미 VM으로 지정했으면 유지
    mac = fields.get("mac") or sv.get("mac")
    if mac and not sv.get("is_vm"):
        is_vm, vendor = guess_vm_from_mac(mac)
        if is_vm:
            fields["is_vm"] = 1
            utils.log_event("info", "server_vm_detected", server_id=server_id,
                            vendor=vendor)

    # 상태 판정: '열린 포트 존재 = 도달(up)'이 1순위.
    # 서버는 툴 PC에서 22번(SSH)이 막힌 경우가 많으므로 22 유무로 판단하지 않고,
    # 스캔에서 확인된 '열린 포트가 하나라도 있으면' 도달로 본다.
    reachable = bool(open_ports)
    if reachable:
        fields["status"] = "done"
        fields["last_error"] = "; ".join(errors) if errors else ""
    elif fields.get("hostname") or fields.get("mac"):
        # 포트는 안 열렸지만 hostname/MAC이 확인됨(방화벽이 스캔 차단 등) → 정보는 있음
        fields["status"] = "done"
        fields["last_error"] = "열린 포트 미확인(스캔 차단 가능) — hostname/MAC로 식별"
    else:
        fields["status"] = "failed"
        fields["last_error"] = "; ".join(errors) if errors else "도달 불가(열린 포트·정보 없음)"
    db.update_server(db_path, server_id, collected=True, **fields)
    utils.log_event("info", "server_collect_done", server_id=server_id,
                    status=fields["status"], ports=fields.get("open_ports", ""))
    return {"status": fields["status"], **fields}


def collect_all_servers(db_path, max_workers=8, common_user=None,
                        common_pass=None, persist=False):
    """등록된 전 서버 일괄 (재)수집(스레드풀).

    계정 우선순위: 공통 계정(common_user/pass) > 서버별 저장 계정 > 무자격.
    공통 계정 + persist=True면 각 서버에 그 계정을 저장한다.
    """
    import concurrent.futures as _cf
    servers = db.list_servers(db_path)
    done = failed = 0
    common = bool(common_user and common_pass)
    if common and persist:
        blob = credentials.encrypt_credential(common_user, common_pass)
        if blob:
            for sv in servers:
                try:
                    db.update_server_cred(db_path, sv["id"], blob)
                except Exception:
                    pass

    def _one(sv):
        if common:
            username, password = common_user, common_pass
        else:
            username = password = None
            blob = db.get_server_credential(db_path, sv["id"])
            if blob:
                dec = credentials.decrypt_credential(blob)
                if dec and "|" in dec:
                    username, password = dec.split("|", 1)
        return collect_server(db_path, sv["id"], username, password)

    with _cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(_one, servers):
            if res.get("status") == "done":
                done += 1
            else:
                failed += 1
    utils.log_event("info", "server_collect_all_done", done=done, failed=failed)
    return {"done": done, "failed": failed, "total": len(servers)}
