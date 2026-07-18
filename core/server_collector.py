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

    # ① 무자격: 포트 스캔 + 역DNS + 스위치 데이터 대조(MAC·연결 위치)
    try:
        ports = scan_ports(ip)
        fields["open_ports"] = ",".join(str(p) for p in ports)
    except Exception as e:
        errors.append("스캔: %s" % e)
    rdns = reverse_dns(ip)
    if rdns:
        fields["hostname"] = rdns
    loc = db.find_mac_location(db_path, ip)
    if loc.get("mac"):
        fields["mac"] = _norm_mac(loc["mac"])
    if loc.get("switch_name"):
        fields["switch_name"] = loc["switch_name"]
        fields["switch_port"] = loc.get("port") or ""

    # ② SSH 상세(자격증명 시) — 실패해도 무자격 결과는 유지
    if username and password:
        try:
            if (sv.get("os_type") or "linux") == "windows":
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

    ok = bool(fields.get("open_ports") or fields.get("hostname")
              or fields.get("mac")) and not (errors and username)
    fields["status"] = "done" if ok else "failed"
    fields["last_error"] = "; ".join(errors) if errors else ""
    db.update_server(db_path, server_id, collected=True, **fields)
    utils.log_event("info", "server_collect_done", server_id=server_id,
                    status=fields["status"], ports=fields.get("open_ports", ""))
    return {"status": fields["status"], **fields}


def collect_all_servers(db_path, max_workers=8):
    """등록된 전 서버 일괄 수집(스레드풀). 저장 계정 있으면 SSH 상세 포함."""
    import concurrent.futures as _cf
    servers = db.list_servers(db_path)
    done = failed = 0

    def _one(sv):
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
