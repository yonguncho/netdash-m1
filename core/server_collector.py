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
                2049, 2222, 3128, 3306, 3389, 5432, 5900, 5985, 5986,
                8080, 8443, 9090]
# SSH가 열려 있을 수 있는 포트 후보(22 우선, 대체 포트 폴백)
SSH_PORT_CANDIDATES = [22, 2222]


def pick_ssh_port(open_ports):
    """열린 포트 중 SSH로 쓸 포트 선택(22 우선, 없으면 2222 등). 없으면 None."""
    op = set(open_ports or [])
    for p in SSH_PORT_CANDIDATES:
        if p in op:
            return p
    return None
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
    """MAC을 AA:BB:CC:DD:EE:FF 로 정규화(콜론/하이픈/점 표기 수용).

    AIX/Solaris는 앞 0을 생략해 출력한다(예: '0:9:6b:8f:ab:cd', '0.9.6b...') →
    구분자로 나눠 옥텟 단위로 0을 채워 표준 표기로 맞춘다.
    """
    if not mac:
        return ""
    s = str(mac).strip()
    parts = re.split(r"[:\-.]", s)
    if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p or "") for p in parts):
        return ":".join(p.rjust(2, "0") for p in parts).upper()
    hexs = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(hexs) != 12:
        return s.upper()
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


def _ssh_exec(ip, username, password, commands, timeout=15, port=22):
    """paramiko로 명령 목록 실행 → {cmd: output}. 연결 실패 시 예외."""
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    out = {}
    try:
        cli.connect(ip, port=port, username=username, password=password,
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


def _first_mac_from_text(text):
    """임의 OS의 인터페이스 출력에서 첫 물리 MAC 추출(루프백·전부0 제외).

    지원 표기: 'link/ether aa:bb:..'(iproute2), 'ether aa:bb:..'(BSD/macOS/ESXi),
    'HWaddr aa:bb:..'(구형 ifconfig), 'aa.bb.cc.dd.ee.ff'(Solaris/AIX netstat -in),
    'aa-bb-cc-dd-ee-ff'(일부 유닉스).
    """
    for ln in (text or "").splitlines():
        low = ln.lower()
        if " lo" in low and ("loopback" in low or low.strip().startswith("lo")):
            continue
        # AIX/Solaris는 앞 0을 생략(0:9:6b:..., 0.9.6b...) → 1~2자리 옥텟 허용
        # ESXi `esxcli network nic list`는 구분자 있는 MAC이 표 중간에 위치 → 콜론형 우선 검색
        m = (re.search(r"(?:link/ether|ether|hwaddr|address:)\s+"
                       r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", ln)
             or re.search(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", ln)
             or re.search(r"\b([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b", ln)
             or re.search(r"\b([0-9a-fA-F]{1,2}(?:\.[0-9a-fA-F]{1,2}){5})\b", ln)
             # HP-UX lanscan: '0x00306EF4A1B2'
             or re.search(r"\b0x([0-9a-fA-F]{12})\b", ln))
        if not m:
            continue
        mac = _norm_mac(m.group(1).replace("-", ":").replace(".", ":"))
        if mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return mac
    return ""


def _listening_ports_from_text(text):
    """netstat/ss 출력에서 LISTEN 포트 집합 추출(플랫폼 표기 차이 흡수)."""
    ports = set()
    for ln in (text or "").splitlines():
        if "LISTEN" not in ln.upper():
            continue
        # 0.0.0.0:22 / *.22 / *:22 / [::]:443 등
        m = (re.search(r"[\d.\[\]:*]+:(\d{1,5})\s", ln)
             or re.search(r"\*\.(\d{1,5})\s", ln)
             or re.search(r"\.(\d{1,5})\s+\S+\s+LISTEN", ln))
        if m:
            try:
                p = int(m.group(1))
                if 0 < p < 65536:
                    ports.add(p)
            except ValueError:
                pass
    return ports


# 플랫폼 무관 폴백 명령 — 되는 것만 결과로 취한다(없는 명령은 빈 출력).
_UNIX_CMDS = [
    "hostname", "uname -n",                       # hostname
    "uname -a", "uname -sr",                      # OS 정보
    "ip -o link", "ifconfig -a", "netstat -in",   # MAC (Linux / BSD·AIX·HP-UX / Solaris·AIX)
    "lanscan",                                    # HP-UX MAC(0x00306EF4A1B2)
    "ss -tln", "netstat -an",                     # 리스닝 포트
    "esxcli system version get",                  # VMware ESXi
    "esxcli network nic list",
]


def _ssh_detail_unix(ip, username, password, port=22):
    """범용 UNIX 계열 SSH 상세 — Linux/AIX/Solaris/HP-UX/BSD/macOS/ESXi 공용.

    OS를 특정하지 못해도(unknown) 동작하도록 여러 명령을 시도해 성공한 것만 취합한다.
    반환: {hostname?, os_info?, mac?, open_ports?}
    """
    o = _ssh_exec(ip, username, password, _UNIX_CMDS, port=port)
    detail = {}
    # hostname: hostname → uname -n 폴백
    for c in ("hostname", "uname -n"):
        v = (o.get(c) or "").strip()
        if v and "not found" not in v.lower():
            detail["hostname"] = v.splitlines()[0][:100]
            break
    # OS 정보: esxcli(ESXi) → uname -a → uname -sr
    esx = (o.get("esxcli system version get") or "").strip()
    if esx:
        _ver = re.search(r"Version:\s*(\S+)", esx)
        _prod = re.search(r"Product:\s*(.+)", esx)
        detail["os_info"] = ((_prod.group(1).strip() + " " if _prod else "VMware ESXi ") +
                             (_ver.group(1) if _ver else ""))[:120].strip()
    else:
        for c in ("uname -a", "uname -sr"):
            v = (o.get(c) or "").strip()
            if v and "not found" not in v.lower():
                detail["os_info"] = v.splitlines()[0][:120]
                break
    # MAC: iproute2 → ifconfig → netstat -in → esxcli nic
    for c in ("ip -o link", "ifconfig -a", "netstat -in", "esxcli network nic list"):
        mac = _first_mac_from_text(o.get(c))
        if mac:
            detail["mac"] = mac
            break
    # 리스닝 포트: ss → netstat
    lports = set()
    for c in ("ss -tln", "netstat -an"):
        lports = _listening_ports_from_text(o.get(c))
        if lports:
            break
    if lports:
        detail["open_ports"] = ",".join(str(p) for p in sorted(lports)[:40])
    return detail


# 하위 호환 별칭 — 기존 호출부/테스트가 쓰던 이름(내부는 범용 폴백으로 통일)
def _ssh_detail_linux(ip, username, password, port=22):
    """리눅스 SSH 상세(= 범용 UNIX 폴백). AIX/Solaris/ESXi 등에서도 최대한 수집."""
    return _ssh_detail_unix(ip, username, password, port=port)


def _ssh_detail_windows(ip, username, password, port=22):
    """윈도우 SSH 상세(OpenSSH 서버 설치 시): hostname, OS 버전."""
    o = _ssh_exec(ip, username, password, ["hostname", "ver"], port=port)
    detail = {}
    if o.get("hostname", "").strip():
        detail["hostname"] = o["hostname"].strip().splitlines()[0][:100]
    ver = (o.get("ver") or "").strip()
    if ver:
        detail["os_info"] = ver.splitlines()[-1][:120]
    return detail


def infer_os_from_scan(open_ports, netbios_hit=False):
    """무자격 신호(열린 포트·NetBIOS)로 OS 추정: 'windows' | 'linux' | None.

    SSH(22)가 툴 PC에서 막힌 서버도 OS를 표시하기 위한 폴백. SSH 상세(detect_os)가
    성공하면 그 결과가 우선한다.
      - Windows 신호: 3389(RDP)/445(SMB)/135(RPC)/139(NetBIOS) 또는 NetBIOS 응답.
      - Linux 신호: 22(SSH) 열림 + Windows 신호 없음.
    """
    ports = set(open_ports or [])
    win_signals = ports & {135, 139, 445, 3389}
    if netbios_hit or win_signals:
        return "windows"
    if 22 in ports:
        return "linux"
    return None


def os_family_from_uname(uname):
    """`uname -s`/`uname -a` 출력 → OS 계열. 미상이면 'unknown'.

    linux/windows 외의 OS(AIX·Solaris·HP-UX·ESXi·BSD·macOS)도 그대로 식별해,
    수집을 '지원 안 함'으로 떨구지 않고 범용 UNIX 경로로 처리하게 한다.
    """
    u = (uname or "").strip().lower()
    if not u:
        return "unknown"
    if "linux" in u:
        return "linux"
    if "vmkernel" in u or "esxi" in u:
        return "esxi"
    if "aix" in u:
        return "aix"
    if "sunos" in u or "solaris" in u:
        return "solaris"
    if "hp-ux" in u or "hpux" in u:
        return "hpux"
    if "darwin" in u:
        return "macos"
    if "bsd" in u:
        return "bsd"
    if "cygwin" in u or "msys" in u or "mingw" in u or "windows" in u:
        return "windows"
    return "unknown"


# UNIX 계열로 취급(= 범용 폴백 명령으로 상세 수집) — windows만 별도 경로
UNIX_LIKE = ("linux", "aix", "solaris", "hpux", "bsd", "macos", "esxi", "unix")


def detect_os(ip, username, password, timeout=15, port=22):
    """SSH 접속 후 OS 자동 인식. 반환: 'windows'|'linux'|'aix'|'solaris'|'hpux'|
    'bsd'|'macos'|'esxi'|'unknown', 접속 실패 시 None.

    ① SSH 배너(transport.remote_version)에 'windows'면 윈도우 OpenSSH.
    ② 아니면 'uname -s'(실패 시 'uname -a') → os_family_from_uname으로 계열 판정.
    ③ 판정 불가여도 'unknown'을 반환 — 호출부가 범용 UNIX 경로로 수집을 시도한다
       (이전엔 windows로 단정해 유닉스 서버 상세가 비었음).
    """
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cli.connect(ip, port=port, username=username, password=password,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                    look_for_keys=False, allow_agent=False)
        banner = ""
        try:
            banner = (cli.get_transport().remote_version or "").lower()
        except Exception:
            banner = ""
        if "windows" in banner:
            return "windows"
        for cmd in ("uname -s", "uname -a"):
            try:
                _, stdout, _ = cli.exec_command(cmd, timeout=timeout)
                out = stdout.read().decode("utf-8", "replace")
                fam = os_family_from_uname(out)
                if fam != "unknown":
                    return fam
            except Exception:
                continue
        return "unknown"   # 미상 — 범용 UNIX + 윈도우 양쪽 시도
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
    rdns = reverse_dns(ip)
    nb_hit = False
    if not rdns:
        nb = netbios_name(ip)
        if nb:
            rdns = nb
            nb_hit = True
    if rdns:
        fields["hostname"] = rdns
    # OS 자동 추정(무자격): SSH가 막힌 서버도 열린 포트·NetBIOS로 OS를 표시.
    # 사용자가 이미 linux/windows로 지정했으면 유지. SSH 상세(detect_os) 성공 시 덮어씀.
    if (sv.get("os_type") or "auto").lower() not in ("linux", "windows"):
        inferred = infer_os_from_scan(open_ports, nb_hit)
        if inferred:
            fields["os_type"] = inferred
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

    # ② SSH 상세(자격증명 시) — 22 고정이 아니라 스캔에서 열린 SSH 포트(22/2222)로 접속.
    #    SSH 포트가 안 열렸으면 상세는 생략하되 무자격 결과(포트·hostname·MAC·OS추정)는 유지.
    if username and password:
        ssh_port = pick_ssh_port(open_ports)
        if ssh_port is None:
            errors.append("SSH 포트(22/2222) 미개방 — 상세 수집 생략(포트/hostname/MAC로 식별)")
        else:
            os_type = (sv.get("os_type") or "auto").lower()
            # OS 자동 인식: 사용자가 windows/UNIX계열로 확정하지 않았으면 접속해 판별.
            # (AIX·Solaris·HP-UX·ESXi·BSD·macOS도 그대로 확정 — 'unknown'이면 양쪽 시도)
            if os_type not in ("windows",) + UNIX_LIKE:
                detected = detect_os(ip, username, password, port=ssh_port)
                if detected:
                    os_type = detected
                    fields["os_type"] = detected
                    utils.log_event("info", "server_os_detected",
                                    server_id=server_id, os_type=detected, port=ssh_port)
                else:
                    os_type = "unknown"   # 접속 실패 — 아래에서 범용 경로로 재시도
            try:
                if os_type == "windows":
                    fields.update(_ssh_detail_windows(ip, username, password, port=ssh_port))
                else:
                    # linux 및 그 외 모든 OS(aix/solaris/hpux/bsd/macos/esxi/unknown)
                    d = _ssh_detail_unix(ip, username, password, port=ssh_port)
                    if not d and os_type == "unknown":
                        # UNIX 명령이 전부 안 먹음 → 윈도우 계열일 수 있어 한 번 더 시도
                        d = _ssh_detail_windows(ip, username, password, port=ssh_port)
                        if d:
                            fields["os_type"] = "windows"
                    fields.update(d)
                    # 수집된 OS 원문으로 계열을 확정(os_type이 unknown으로 남지 않게)
                    if fields.get("os_info") and (fields.get("os_type") or os_type) in ("unknown", "auto"):
                        fam = os_family_from_uname(fields["os_info"])
                        if fam != "unknown":
                            fields["os_type"] = fam
            except Exception as e:
                errors.append("SSH(:%d): %s" % (ssh_port, str(e)[:110]))

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


_progress = {"running": False, "done": 0, "total": 0, "message": ""}
_prog_lock = threading.Lock()
_stop = False   # 전체 수집 중지 요청


def get_progress():
    """서버 전체 수집 진행 상태 스냅샷 {running, done, total, message}."""
    with _prog_lock:
        return dict(_progress)


def _set_progress(**kw):
    with _prog_lock:
        _progress.update(kw)


def request_stop():
    """진행 중인 서버 전체 수집에 중지 요청(남은 서버는 건너뜀)."""
    global _stop
    with _prog_lock:
        if not _progress.get("running"):
            return False
        _stop = True
        _progress["message"] = "중지 요청됨 — 마무리 중…"
    return True


def _is_stop():
    with _prog_lock:
        return _stop


def collect_all_servers(db_path, max_workers=8, common_user=None,
                        common_pass=None, persist=False, ids=None):
    """등록된 서버 일괄 (재)수집(스레드풀). ids 주면 그 서버들만.

    계정 우선순위: 공통 계정(common_user/pass) > 서버별 저장 계정 > 무자격.
    공통 계정 + persist=True면 각 서버에 그 계정을 저장한다.
    """
    import concurrent.futures as _cf
    global _stop
    servers = db.list_servers(db_path)
    if ids:
        _idset = set(int(x) for x in ids)
        servers = [s for s in servers if s.get("id") in _idset]
    done = failed = 0
    with _prog_lock:
        _stop = False   # 새 수집 시작 — 중지 플래그 초기화
    _set_progress(running=True, done=0, total=len(servers), message="서버 수집 중")
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
        if _is_stop():
            return {"status": "skipped"}   # 중지 요청 후 남은 서버는 건너뜀
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

    skipped = 0   # 중지 요청 후 시도조차 하지 않은 서버(실패로 집계하지 않음)
    try:
        with _cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for res in ex.map(_one, servers):
                st = (res or {}).get("status")
                if st == "done":
                    done += 1
                elif st == "skipped":
                    skipped += 1
                else:
                    failed += 1
                _set_progress(done=done + failed + skipped,
                              message="서버 수집 중 (%d/%d)" % (done + failed + skipped, len(servers)))
    finally:
        if _is_stop():
            _msg = "중지됨(성공 %d · 실패 %d · 건너뜀 %d)" % (done, failed, skipped)
        else:
            _msg = "완료(성공 %d · 실패 %d)" % (done, failed)
        _set_progress(running=False, message=_msg)
    utils.log_event("info", "server_collect_all_done", done=done, failed=failed, skipped=skipped)
    return {"done": done, "failed": failed, "skipped": skipped, "total": len(servers)}
