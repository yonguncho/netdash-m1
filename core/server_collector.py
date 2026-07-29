# -*- coding: utf-8 -*-
"""서버(리눅스/윈도우) 현황 수집.

수집 2단계:
① 무자격(항상): TCP 포트 스캔 + 역방향 DNS(hostname) +
   기존 스위치 수집 데이터(ARP/MAC 테이블) 대조로 MAC·연결 스위치/포트 파악.
② SSH 상세(자격증명 있을 때): 리눅스 = hostname/OS/인터페이스 MAC/리스닝 포트,
   윈도우 = OpenSSH 서버가 있으면 hostname/OS. (WinRM은 미지원 — 폐쇄망 의존성 최소화)

VM 판정: MAC OUI(가상화 벤더 대역)로 자동 추정. 수동 지정이 항상 우선.
"""
import base64
import json
import os
import re
import socket
import subprocess
import threading

from . import db, utils, credentials

# 스캔 대상 공통 포트(서버 용도 파악용 — 과도한 스캔 금지)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 830, 1433, 1521,
                2049, 2200, 2222, 3128, 3306, 3389, 5432, 5900, 5985, 5986,
                8022, 8080, 8443, 9090, 22222]
# SSH가 열려 있을 만한 관용 포트(먼저 확인할 우선순위).
# 이 목록에 없어도 **열린 포트의 배너를 직접 확인**해 SSH를 찾는다(find_ssh_port).
SSH_PORT_CANDIDATES = [22, 2222, 2200, 22222, 8022, 830]

_BANNER_TIMEOUT = 1.5
# SSH일 가능성이 없어 배너 확인을 건너뛰는 포트(웹·DB·RDP 등)
_NON_SSH_PORTS = {80, 135, 139, 443, 445, 1433, 1521, 3306, 3389, 5432,
                  5900, 5985, 5986, 8080, 8443}


def looks_like_ssh(ip, port, timeout=_BANNER_TIMEOUT):
    """그 포트가 실제 SSH인지 배너로 확인.

    SSH 서버는 연결 직후 'SSH-2.0-...' 를 먼저 보낸다(RFC 4253). 포트 번호로
    추측하지 않고 이 배너로 판정한다.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            head = s.recv(64) or b""
        return head[:4] == b"SSH-"
    except OSError:
        return False


def find_ssh_port(ip, open_ports, probe=True):
    """SSH 접속에 쓸 포트를 **실측으로** 찾는다. 없으면 None.

    ① 관용 포트(22·2222·2200·22222·8022·830)가 열려 있으면 그것부터 배너 확인
    ② 못 찾으면 **열린 포트 전체**를 배너로 확인 — 보안 정책으로 22를 막고
       SSH를 비표준 포트로 옮겨 둔 서버가 흔하다. 예전에는 22/2222가 아니면
       "SSH 포트 미개방 — 상세 수집 생략"으로 끝나 사양을 아예 못 가져왔다.
    probe=False면 배너 확인 없이 관용 포트만 고른다(단위 테스트·오프라인용).
    """
    op = list(open_ports or [])
    if not op:
        return None
    ordered = [p for p in SSH_PORT_CANDIDATES if p in op]
    if not probe:
        return ordered[0] if ordered else None
    for p in ordered:
        if looks_like_ssh(ip, p):
            return p
    for p in sorted(set(op) - set(ordered) - _NON_SSH_PORTS):
        if looks_like_ssh(ip, p):
            utils.log_event("info", "ssh_port_discovered", ip=ip, port=p)
            return p
    # 배너를 못 받았어도 관용 포트가 열려 있으면 그대로 시도한다.
    # 배너가 느린 서버·중간 장비가 배너를 지우는 환경에서 **기존에 되던 수집을
    # 잃지 않도록** 하는 안전망이다(탐색은 어디까지나 추가 기능).
    if ordered:
        return ordered[0]
    return None


def pick_ssh_port(open_ports):
    """관용 포트만 보는 선택(배너 확인 없음) — 하위 호환용."""
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


def local_arp_mac(ip):
    """이 PC의 ARP 캐시에서 IP의 MAC을 읽는다. 없으면 빈 문자열.

    같은 서브넷의 서버라면, 포트 스캔(TCP SYN)만으로도 ARP 캐시가 채워진다
    (ARP는 TCP보다 먼저 일어나므로 **접속이 거부돼도** 항목이 남는다).
    계정도, 스위치 ARP 테이블도 필요 없는 **공짜 경로**인데 예전에는 쓰지 않아,
    바로 옆 대역 서버조차 MAC이 비어 있었다.

    다른 서브넷 IP는 캐시에 없다(게이트웨이만 ARP한다) → 빈 문자열. 즉
    게이트웨이 MAC을 서버 MAC으로 잘못 넣을 위험이 없다.
    """
    try:
        if os.name == "nt":
            p = subprocess.run(["arp", "-a", str(ip)], capture_output=True,
                               timeout=5,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            p = subprocess.run(["ip", "neigh", "show", str(ip)],
                               capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    text = (p.stdout or b"").decode("utf-8", "replace")
    for line in text.splitlines():
        # 조회한 IP가 있는 줄에서만 MAC을 뽑는다 — arp -a가 인자를 무시하고
        # 전체 테이블을 뱉는 환경이 있어, 남의 MAC을 가져오면 안 된다.
        if str(ip) not in line:
            continue
        m = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
        if not m:
            continue
        mac = _norm_mac(m.group(0))
        # 미완성(incomplete) 항목은 00:00:… 이나 FF:FF:… 로 나온다
        if mac and mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return mac
    return ""


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


def _cred_candidates(db_path, server_id, username, password):
    """시도할 계정 후보 [(user, pw, 라벨)] — 입력 계정 → 이 서버에 저장된 계정.

    수집 팝업에 공통 계정을 넣으면 **서버별 저장 계정을 덮어써서**, OS가 섞인
    환경(Windows·RHEL·SUSE·Debian)에서는 대부분 인증 실패가 났다.
    입력 계정이 거부되면 그 서버에 저장된 계정으로 한 번 더 시도한다.

    시도 횟수는 최대 2회로 제한한다 — 계정 잠금 정책이 있는 환경에서 후보를
    무한정 돌리면 계정이 잠긴다.
    """
    out = []
    if username and password:
        out.append((username, password, "입력 계정"))
    try:
        blob = db.get_server_credential(db_path, server_id)
        if blob:
            dec = credentials.decrypt_credential(blob)
            if dec and "|" in dec:
                u, pw = dec.split("|", 1)
                if u and pw and (u, pw) not in [(c[0], c[1]) for c in out]:
                    out.append((u, pw, "저장 계정"))
    except Exception:
        pass
    return out[:2]


def _is_auth_error(e):
    t = str(e).lower()
    return "authentication" in t or "auth failed" in t or "인증" in t


# SNMP 기본값 — 폐쇄망 운영 서버는 감시용 snmpd가 이미 떠 있는 경우가 많다.
# 읽기 전용 GET만 쓰므로 기본 켬으로 두되, 커뮤니티는 설정에서 바꿀 수 있다.
SNMP_DEFAULT_COMMUNITY = "public"


def snmp_enabled(db_path):
    try:
        return db.get_setting(db_path, "snmp_enabled", "1") != "0"
    except Exception:
        return True


def snmp_community(db_path):
    """설정에 저장된 SNMP 커뮤니티(암호화 저장). 없으면 기본값."""
    try:
        blob = db.get_setting(db_path, "snmp_community_blob", "") or ""
        if blob:
            v = credentials.decrypt_text(blob)
            if v:
                return v
    except Exception:
        pass
    return SNMP_DEFAULT_COMMUNITY


def _ssh_connect(cli, ip, port, username, password, timeout):
    """SSH 접속 — password 인증이 거부되면 keyboard-interactive로 재시도.

    paramiko의 SSHClient.connect()는 비밀번호를 주면 `auth_password` 만 시도하고
    실패 시 그대로 예외를 낸다(로그: "Authentication (password) failed").
    그런데 PAM을 쓰는 리눅스(RHEL·SUSE·Debian 등)는 `PasswordAuthentication no` +
    `KbdInteractiveAuthentication yes` 로 **password 방식을 막아 둔 경우가 흔하다**.
    이때 비밀번호가 맞아도 인증이 실패해 사양 수집이 통째로 건너뛰어졌다.
    같은 비밀번호로 keyboard-interactive를 한 번 더 시도한다.
    """
    import paramiko
    try:
        cli.connect(ip, port=port, username=username, password=password,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                    look_for_keys=False, allow_agent=False)
        return "password"
    except paramiko.AuthenticationException as first:
        tr = None
        try:
            tr = paramiko.Transport((ip, port))
            tr.banner_timeout = timeout
            tr.start_client(timeout=timeout)

            def _answer(title, instructions, prompt_list):
                # 프롬프트가 몇 개든 같은 비밀번호로 응답(Password: 하나가 대부분)
                return [password for _ in prompt_list]

            tr.auth_interactive(username, _answer)
            if not tr.is_authenticated():
                raise first
            cli._transport = tr          # 이후 exec_command가 이 세션을 쓴다
            utils.log_event("info", "ssh_auth_keyboard_interactive", ip=ip, port=port)
            return "keyboard-interactive"
        except Exception:
            if tr is not None:
                try:
                    tr.close()
                except Exception:
                    pass
            raise first                  # 원래 인증 실패를 그대로 알린다


_BATCH_MARK = "__NETDASH_CMD_%d__"
_MAX_CMD_OUT = 20000


def _ssh_exec(ip, username, password, commands, timeout=15, port=22, batch=False):
    """paramiko로 명령 목록 실행 → {cmd: output}. 연결 실패 시 예외.

    batch=True면 **모든 명령을 한 세션에서 한 번에** 실행한다(POSIX 셸 전용).

    왜 배치가 필요한가: paramiko의 exec_command()는 명령마다 새 SSH 세션 채널을
    연다. OpenSSH의 `MaxSessions` 기본값은 **10**이라, 명령이 10개를 넘으면
    11번째부터 서버가 채널 개설을 거부하고 여기서 조용히 빈 문자열이 된다.
    UNIX 상세는 명령이 26개이고 사양(CPU/메모리/디스크) 명령이 전부 13번째
    이후라, **hostname·OS·MAC·포트는 들어오는데 사양만 통째로 비는** 증상이
    났다(Windows는 명령이 9개라 한도에 걸리지 않아 정상이었다).
    """
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    out = {}
    try:
        _ssh_connect(cli, ip, port, username, password, timeout)
        if batch and commands:
            try:
                return _ssh_exec_batched(cli, commands, timeout)
            except Exception as e:
                # 셸이 특이한 장비 등 — 개별 실행으로 폴백(한도 문제는 남지만
                # 아무것도 못 얻는 것보다 낫다)
                utils.log_event("warning", "ssh_batch_failed_fallback", ip=ip,
                                error=str(e)[:120])
        for cmd in commands:
            try:
                _, stdout, _ = cli.exec_command(cmd, timeout=timeout)
                out[cmd] = stdout.read().decode("utf-8", "replace")[:_MAX_CMD_OUT]
            except Exception:
                out[cmd] = ""
    finally:
        cli.close()
    return out


def _ssh_exec_batched(cli, commands, timeout):
    """명령 전체를 한 셸 세션에서 실행하고 구분자로 잘라 {cmd: output} 복원.

    각 명령 앞에 고유 마커를 출력하고, 명령의 stderr는 버린다(없는 명령의
    'not found'가 출력에 섞이지 않게). 마커는 줄 단위가 아니라 **문자열**로
    쪼개므로 개행 없이 끝나는 출력도 안전하다.
    """
    parts = []
    for i, cmd in enumerate(commands):
        parts.append("echo '%s'" % (_BATCH_MARK % i))
        parts.append("{ %s ; } 2>/dev/null" % cmd)
    parts.append("echo '%s'" % (_BATCH_MARK % len(commands)))
    # 줄바꿈으로 구분한다. '; '로 이으면 명령 자체에 포함된 세미콜론
    # (예: cpuinfo 명령)과 구분되지 않아 읽기·디버깅이 어렵다.
    script = "\n".join(parts)

    # 한 세션에 26개 명령이 들어가므로 개별 타임아웃보다 넉넉히 준다.
    _, stdout, _ = cli.exec_command(script, timeout=max(timeout * 3, 45))
    text = stdout.read().decode("utf-8", "replace")

    out = {}
    for i, cmd in enumerate(commands):
        start = text.find(_BATCH_MARK % i)
        if start < 0:
            out[cmd] = ""
            continue
        start += len(_BATCH_MARK % i)
        end = text.find(_BATCH_MARK % (i + 1), start)
        seg = text[start:] if end < 0 else text[start:end]
        out[cmd] = seg.lstrip("\r\n")[:_MAX_CMD_OUT]
    if not any(out.values()):
        raise RuntimeError("배치 실행 결과가 전부 비었음")
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


# ── 하드웨어 사양(CPU·메모리·디스크) 파싱 ─────────────────────────
# df 집계에서 제외할 의사(pseudo) 파일시스템 — 실제 저장 용량이 아님
_DF_SKIP_FS = {
    "tmpfs", "devtmpfs", "devfs", "none", "udev", "overlay", "shm", "ramfs",
    "proc", "procfs", "sysfs", "cgroup", "cgroup2", "squashfs", "efivarfs",
    "swap", "mnttab", "objfs", "ctfs", "fd", "sharefs",
}
# 마운트 지점이 이것(또는 그 하위)이면 제외 — 런타임/커널용 임시 영역
_DF_SKIP_MOUNT = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/run",
                  "/system/volatile", "/etc/svc/volatile")


def _clean_cpu_model(s):
    """CPU 모델 문자열 정리(공백 압축·길이 제한). 빈 값이면 빈 문자열."""
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s[:100]


# 사양 값 상한 — 명령 출력이 깨져 터무니없는 수가 들어오면 sqlite 바인딩이
# OverflowError를 던져 그 서버가 'collecting'으로 고착되고 일괄 수집 루프까지 끊긴다.
_MAX_CORES = 4096
_MAX_MEM_MB = 64 * 1024 * 1024        # 64 TB
_MAX_DISK_GB = 1024 * 1024            # 1 PB


def _int(s, limit=None):
    """숫자 문자열 → int. 변환 불가/범위 초과면 0.

    `str.isdigit()`는 '²'·'㊂' 같은 유니코드 숫자에 True를 주지만 int()는 던진다.
    사양 파싱은 SSH stdout(로그인 배너·바이너리 잔여물 혼입 가능)을 다루므로
    검사와 변환을 한 곳에서 같은 규칙으로 처리한다.
    """
    try:
        n = int(str(s).strip())
    except (TypeError, ValueError):
        return 0
    if n < 0 or (limit is not None and n > limit):
        return 0
    return n


def _skip_df_mount(mount):
    for p in _DF_SKIP_MOUNT:
        if mount == p or mount.startswith(p + "/"):
            return True
    return False


def _df_group_key(fs, mount):
    """같은 저장 풀에 속하는 df 행을 하나로 묶는 키.

    df는 '한 줄 = 한 디스크'가 아니다. 그대로 더하면 크게 틀린다:
      - ZFS: `tank/data`·`tank/logs` 데이터셋이 각각 풀 전체를 보고 → 배수 과다
      - APFS: `/dev/disk1s1`·`/dev/disk1s5`가 같은 컨테이너 용량을 보고 → 배수 과다
      - ESXi: Filesystem 칸이 장치명이 아니라 타입명(`VMFS-6`) → 장치명으로 묶으면
        데이터스토어 여러 개가 하나로 뭉개져 대폭 누락
    """
    if fs.startswith("/"):
        m = re.match(r"(/dev/disk\d+)s\d+", fs)      # APFS 컨테이너(macOS)
        return m.group(1) if m else fs               # 그 외는 장치 단위(bind 중복 제거)
    if "/" in fs:
        return fs.split("/")[0]                      # ZFS 데이터셋 → 풀 단위
    return (fs, mount)                               # 타입명(VMFS-6 등) → 마운트로 구분


def parse_df_kb(text):
    """`df -Pk`(POSIX 형식) 출력 → (전체 KB, 사용 KB). 로컬 디스크만 합산.

    의사 FS(tmpfs·proc…)·원격 공유(NFS `host:/path`, CIFS `//host/share`)는 제외한다.
    같은 풀을 공유하는 행들(ZFS 데이터셋·APFS 볼륨)은 한 덩어리로 묶어
    `전체 = 그중 최대 크기`, `사용 = 최대 크기 - 최대 여유`로 계산한다
    (풀 여유 공간은 구성원이 공유하므로 이 값이 풀 실제 사용량이다).
    수치가 완전히 같은 행은 같은 파일시스템의 중복 마운트(bind·subvolume)로 보고
    한 번만 세며, 이때는 df가 보고한 Used를 그대로 쓴다(ext4 예약 블록까지 정확).
    """
    groups = {}
    for ln in (text or "").splitlines():
        parts = ln.split()
        if len(parts) < 6:
            continue
        fs, blocks, ub, avail = parts[0], parts[1], parts[2], parts[3]
        if not (re.fullmatch(r"\d+", blocks) and re.fullmatch(r"\d+", ub)):
            continue                       # 헤더/줄바꿈된 행
        if fs.lower() in _DF_SKIP_FS or ":" in fs or fs.startswith("//"):
            continue
        mount = " ".join(parts[5:])
        if _skip_df_mount(mount):
            continue
        g = groups.setdefault(_df_group_key(fs, mount), set())
        # 같은 수치의 행이 반복되면(bind 마운트·subvolume) 같은 파일시스템이다 → 1회만
        g.add((_int(blocks), _int(ub), _int(avail)))

    total = used = 0
    for rows in groups.values():
        rows = list(rows)
        if len(rows) == 1:
            total += rows[0][0]
            used += rows[0][1]      # df가 보고한 Used(ext4 예약 블록까지 정확)
            continue
        pool = max(r[0] for r in rows)            # 풀 전체 크기
        free = max(r[2] for r in rows)            # 공유 여유 공간
        total += pool
        used += max(pool - free, 0)
    return total, used


def _kb_to_gb(kb):
    return round(kb / 1048576.0, 1)


def _parse_meminfo_mb(text):
    """`/proc/meminfo`의 MemTotal(kB) → MB. 없으면 0."""
    m = re.search(r"^MemTotal:\s+(\d+)\s*kB", text or "", re.M)
    return int(int(m.group(1)) / 1024) if m else 0


def _parse_lscpu(text):
    """`lscpu` → (모델명, 논리 코어 수)."""
    model, cores = "", 0
    for ln in (text or "").splitlines():
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if k == "model name" and not model:
            model = v
        elif k == "cpu(s)" and not cores:
            cores = _int(v, _MAX_CORES)
    return _clean_cpu_model(model), cores


def _parse_cpuinfo(text):
    """`grep model name` + `grep -c ^processor` 합친 출력 → (모델명, 코어 수)."""
    model, cores = "", 0
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if ":" in s and "model name" in s.lower():
            model = model or s.split(":", 1)[1].strip()
        elif not cores:
            cores = _int(s, _MAX_CORES)
    return _clean_cpu_model(model), cores


def _parse_prtconf(text):
    """AIX/Solaris `prtconf` → (모델명, 프로세서 수, 메모리 MB)."""
    t = text or ""
    m = re.search(r"Processor Type:\s*(.+)", t, re.I)
    model = _clean_cpu_model(m.group(1)) if m else ""
    m = re.search(r"Number Of Processors:\s*(\d+)", t, re.I)
    cores = int(m.group(1)) if m else 0
    mem_mb = 0
    m = re.search(r"Memory\s+size:\s*(\d+)\s*(Megabytes|Gigabytes|MB|GB)?", t, re.I)
    if m:
        v = int(m.group(1))
        mem_mb = v * 1024 if (m.group(2) or "MB").lower().startswith("g") else v
    return model, cores, mem_mb


def _parse_psrinfo(text):
    """Solaris `psrinfo -pv` → (모델명, 가상 프로세서 수)."""
    virt = 0
    cands = []
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("the physical processor"):
            m = re.search(r"and (\d+) virtual processors?", s, re.I)
            if m:
                virt += int(m.group(1))
            continue
        if s.lower().startswith("the "):
            continue
        cands.append(s)
    for s in cands:                       # x86: 'Intel(r) Xeon(r) ... @ 2.50GHz'
        if "@" in s:
            return _clean_cpu_model(s), virt
    if cands:                             # SPARC: 'SPARC-T5 (chipid 0, clock ...)'
        return _clean_cpu_model(re.sub(r"\s*\(.*", "", cands[-1])), virt
    return "", virt


def _parse_machinfo(text):
    """HP-UX `machinfo` → (모델명, CPU 수, 메모리 MB)."""
    t = text or ""
    model, cores, mem_mb = "", 0, 0
    m = re.search(r"^\s*(\d+)\s+(.+?)\s+processors?\b", t, re.I | re.M)
    if m:
        cores = int(m.group(1))
        model = _clean_cpu_model(m.group(2))
    m = re.search(r"Memory:\s*([\d.]+)\s*(MB|GB)", t, re.I)
    if m:
        v = float(m.group(1))
        mem_mb = int(v * 1024) if m.group(2).upper() == "GB" else int(v)
    return model, cores, mem_mb


def _parse_sysctl(text):
    """BSD/macOS `sysctl hw.*` → (모델명, CPU 수, 메모리 MB)."""
    kv = {}
    for ln in (text or "").splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            kv[k.strip()] = v.strip()
    model = _clean_cpu_model(kv.get("hw.model", ""))
    cores = _int(kv.get("hw.ncpu"), _MAX_CORES)
    mem_mb = 0
    for k in ("hw.memsize", "hw.physmem"):
        b = _int(kv.get(k))
        if b:
            mem_mb = int(b / 1048576)
            break
    return model, cores, mem_mb


def _parse_esxcli_hw(text):
    """ESXi `esxcli hardware cpu global get` + `memory get` → (스레드 수, 메모리 MB)."""
    t = text or ""
    m = re.search(r"CPU Threads:\s*(\d+)", t, re.I) or re.search(r"CPU Cores:\s*(\d+)", t, re.I)
    cores = int(m.group(1)) if m else 0
    m = re.search(r"Physical Memory:\s*(\d+)\s*Bytes", t, re.I)
    mem_mb = int(int(m.group(1)) / 1048576) if m else 0
    return cores, mem_mb


# ── 장착 구성(메모리 모듈 · 물리 디스크) ──────────────────────────
_MAX_MODULES = 64        # DIMM 슬롯/디스크 개수 상한(출력 폭주 방어)


def _size_token_to_mb(tok):
    """'16384 MB' / '16 GB' / '894.3G' / '1.8T' / '512M' → MB(정수). 못 읽으면 0."""
    m = re.match(r"\s*([\d.]+)\s*([KMGTP])", str(tok or "").strip(), re.I)
    if not m:
        return 0
    try:
        v = float(m.group(1))
    except ValueError:
        return 0
    unit = m.group(2).upper()
    mult = {"K": 1 / 1024.0, "M": 1, "G": 1024, "T": 1024 * 1024, "P": 1024 * 1024 * 1024}
    return int(v * mult[unit])


def parse_dmidecode_memory(text):
    """`dmidecode -t 17` → (모듈 목록, 전체 슬롯 수).

    슬롯이 비어 있으면 'Size: No Module Installed'이라 슬롯 수에만 반영한다.
    dmidecode는 root 권한이 필요하다 — 권한이 없으면 출력이 비어 (빈 목록, 0)이 된다.
    """
    modules, slots = [], 0
    for block in re.split(r"\n(?=Handle |Memory Device)", text or ""):
        if "Memory Device" not in block:
            continue
        kv = {}
        for ln in block.splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1)
                kv[k.strip().lower()] = v.strip()
        if "size" not in kv:
            continue
        slots += 1
        size_mb = _size_token_to_mb(kv["size"])
        if not size_mb:                       # 'No Module Installed' 등 빈 슬롯
            continue
        modules.append({
            "size_mb": size_mb,
            "locator": kv.get("locator", "")[:40],
            "type": kv.get("type", "")[:20],
            "speed": kv.get("speed", "")[:24],
            "maker": _unknown_to_blank(kv.get("manufacturer", ""))[:40],
            "part": _unknown_to_blank(kv.get("part number", ""))[:40],
        })
        if len(modules) >= _MAX_MODULES:
            break
    return modules, min(slots, _MAX_MODULES)


def _unknown_to_blank(s):
    """'Unknown'·'Not Specified'·'To Be Filled By O.E.M.' 같은 무의미 값은 빈 문자열로."""
    v = str(s or "").strip()
    if v.lower() in ("unknown", "not specified", "none", "no module installed",
                     "to be filled by o.e.m.", "n/a", "[empty]", "other"):
        return ""
    return v


def parse_lsblk_disks(text):
    """`lsblk -dn -P -o NAME,MODEL,SIZE,ROTA,TYPE` → 물리 디스크 목록.

    -P(key="value") 형식을 쓰는 이유: 모델명에 공백이 있어 컬럼 분해가 깨진다.
    """
    disks = []
    for ln in (text or "").splitlines():
        kv = dict(re.findall(r'(\w+)="([^"]*)"', ln))
        if not kv or kv.get("TYPE") != "disk":
            continue
        name = kv.get("NAME", "")
        size_mb = _size_token_to_mb(kv.get("SIZE", ""))
        if not size_mb:
            continue
        if name.startswith("nvme"):
            kind = "NVMe"
        elif kv.get("ROTA") == "0":
            kind = "SSD"
        elif kv.get("ROTA") == "1":
            kind = "HDD"
        else:
            kind = ""
        disks.append({"name": name[:32], "model": _unknown_to_blank(kv.get("MODEL"))[:60],
                      "size_gb": round(size_mb / 1024.0, 1), "kind": kind})
        if len(disks) >= _MAX_MODULES:
            break
    return disks


def parse_iostat_disks(text):
    """Solaris `iostat -En` → 물리 디스크 목록.

    형식: 'c0t0d0  Soft Errors: ...' / 'Vendor: SEAGATE Product: ST973402 ...' /
          'Size: 73.40GB <73400057856 bytes>'
    """
    disks = []
    cur = None
    for ln in (text or "").splitlines():
        s = ln.rstrip()
        if not s:
            continue
        if not s[0].isspace() and "Soft Errors:" in s:
            if cur and cur.get("size_gb"):
                disks.append(cur)
            cur = {"name": s.split()[0][:32], "model": "", "size_gb": 0, "kind": ""}
            continue
        if cur is None:
            continue
        m = re.search(r"Vendor:\s*(\S+)\s+Product:\s*(.+?)\s+Revision:", s)
        if m:
            cur["model"] = ("%s %s" % (m.group(1), m.group(2).strip()))[:60]
            continue
        m = re.search(r"Size:\s*([\d.]+)\s*([KMGTP])B", s, re.I)
        if m:
            cur["size_gb"] = round(_size_token_to_mb(m.group(1) + m.group(2)) / 1024.0, 1)
    if cur and cur.get("size_gb"):
        disks.append(cur)
    return disks[:_MAX_MODULES]


def summarize_modules(modules, slots_total=0):
    """모듈 목록 → '16GB×4 (DDR4)' 같은 한 줄 요약. 빈 목록이면 빈 문자열."""
    if not modules:
        return ""
    counts = {}
    for m in modules:
        counts[m.get("size_mb", 0)] = counts.get(m.get("size_mb", 0), 0) + 1
    parts = []
    for size_mb in sorted(counts, reverse=True):
        gb = size_mb / 1024.0
        label = ("%gGB" % gb) if size_mb >= 1024 else ("%dMB" % size_mb)
        parts.append("%s×%d" % (label, counts[size_mb]))
    types = [t for t in {_unknown_to_blank(m.get("type")) for m in modules} if t]
    out = " + ".join(parts)
    if types:
        out += " (%s)" % ", ".join(sorted(types))
    if slots_total and slots_total > len(modules):
        out += " · %d/%d 슬롯" % (len(modules), slots_total)
    return out


def summarize_disks(disks):
    """디스크 목록 → 'SSD 2 · HDD 2' 같은 한 줄 요약. 빈 목록이면 빈 문자열."""
    if not disks:
        return ""
    counts = {}
    for d in disks:
        counts[d.get("kind") or "디스크"] = counts.get(d.get("kind") or "디스크", 0) + 1
    return " · ".join("%s %d" % (k, counts[k]) for k in sorted(counts))


# 플랫폼 무관 폴백 명령 — 되는 것만 결과로 취한다(없는 명령은 빈 출력).
# LC_ALL=C: 한글 로케일 서버에서 lscpu가 '모델명:'/'CPU:'로 나와 파싱이 전멸하는 것 방지.
_CMD_LSCPU = "LC_ALL=C lscpu"
_CMD_CPUINFO = "grep -m1 'model name' /proc/cpuinfo; grep -c ^processor /proc/cpuinfo"
_CMD_ESXHW = "esxcli hardware cpu global get; esxcli hardware memory get"
_CMD_DF = "LC_ALL=C df -Pk"
# Solaris 기본 /usr/bin/df 와 HP-UX df 는 -P 를 지원하지 않아 디스크가 항상 비었다.
# 둘 다 POSIX와 같은 컬럼 순서(kbytes used avail %used mount)라 같은 파서를 쓴다.
# (AIX는 df -P를 지원하므로 여기 넣지 않는다 — AIX `df -k`는 3번째가 Used가 아니라 Free)
_CMD_DF_XPG4 = "LC_ALL=C /usr/xpg4/bin/df -Pk"     # Solaris
_CMD_DF_BDF = "LC_ALL=C bdf"                        # HP-UX
# 장착 구성 — dmidecode는 root 권한이 필요하다.
# 일반 계정이면 빈 출력이므로 NOPASSWD sudo가 설정된 환경을 위해 sudo -n 도 시도한다
# (-n: 비밀번호를 묻지 않고 즉시 실패 → 프롬프트로 세션이 멈추지 않는다).
_CMD_DIMM = "LC_ALL=C dmidecode -t 17"
_CMD_DIMM_SUDO = "LC_ALL=C sudo -n dmidecode -t 17"
# -P(key="value") 형식: 모델명 공백 때문에 컬럼 분해가 깨지는 것 방지
_CMD_LSBLK = "LC_ALL=C lsblk -dn -P -o NAME,MODEL,SIZE,ROTA,TYPE"
_CMD_IOSTAT = "LC_ALL=C iostat -En"                 # Solaris 물리 디스크

_UNIX_CMDS = [
    "hostname", "uname -n",                       # hostname
    "uname -a", "uname -sr",                      # OS 정보
    "ip -o link", "ifconfig -a", "netstat -in",   # MAC (Linux / BSD·AIX·HP-UX / Solaris·AIX)
    "lanscan",                                    # HP-UX MAC(0x00306EF4A1B2)
    "ss -tln", "netstat -an",                     # 리스닝 포트
    "esxcli system version get",                  # VMware ESXi
    "esxcli network nic list",
    # 하드웨어 사양 — CPU/메모리
    _CMD_LSCPU, _CMD_CPUINFO, "cat /proc/meminfo",    # Linux
    "prtconf", "psrinfo -pv",                     # AIX / Solaris
    "machinfo",                                   # HP-UX
    "sysctl hw.model hw.ncpu hw.physmem hw.memsize",   # BSD / macOS
    _CMD_ESXHW,                                   # ESXi
    # 디스크 — POSIX 우선, 안 되는 OS만 대체 명령이 값을 채운다
    _CMD_DF, _CMD_DF_XPG4, _CMD_DF_BDF,
    # 장착 구성 — 메모리 모듈 / 물리 디스크
    _CMD_DIMM, _CMD_DIMM_SUDO, _CMD_LSBLK, _CMD_IOSTAT,
]


def _specs_from_unix(o):
    """UNIX 계열 명령 출력 모음 → 사양 필드 dict(확인된 값만 담는다).

    반환 키: cpu_model, cpu_cores, mem_total_mb, disk_total_gb, disk_used_gb
    """
    model, cores = _parse_lscpu(o.get(_CMD_LSCPU) or o.get("lscpu"))
    if not model or not cores:
        m, c = _parse_cpuinfo(o.get(_CMD_CPUINFO))
        model, cores = model or m, cores or c
    mem_mb = _parse_meminfo_mb(o.get("cat /proc/meminfo"))

    if not (model and cores and mem_mb):          # AIX / Solaris
        m, c, mm = _parse_prtconf(o.get("prtconf"))
        model, cores, mem_mb = model or m, cores or c, mem_mb or mm
    if not (model and cores):                     # Solaris CPU 상세
        m, c = _parse_psrinfo(o.get("psrinfo -pv"))
        model, cores = model or m, cores or c
    if not (model and cores and mem_mb):          # HP-UX
        m, c, mm = _parse_machinfo(o.get("machinfo"))
        model, cores, mem_mb = model or m, cores or c, mem_mb or mm
    if not (model and cores and mem_mb):          # BSD / macOS
        m, c, mm = _parse_sysctl(o.get("sysctl hw.model hw.ncpu hw.physmem hw.memsize"))
        model, cores, mem_mb = model or m, cores or c, mem_mb or mm
    if not (cores and mem_mb):                    # ESXi
        c, mm = _parse_esxcli_hw(o.get(_CMD_ESXHW))
        cores, mem_mb = cores or c, mem_mb or mm

    spec = {}
    if model:
        spec["cpu_model"] = model
    # 상한 클램프: 깨진 출력에서 나온 거대 정수가 sqlite 바인딩(OverflowError)을 터뜨려
    # 그 서버가 'collecting'으로 고착되고 일괄 수집 루프까지 끊기는 것을 막는다.
    if 0 < cores <= _MAX_CORES:
        spec["cpu_cores"] = cores
    if 0 < mem_mb <= _MAX_MEM_MB:
        spec["mem_total_mb"] = mem_mb
    for _c in (_CMD_DF, "df -Pk", _CMD_DF_XPG4, _CMD_DF_BDF):
        total_kb, used_kb = parse_df_kb(o.get(_c))
        if total_kb:
            spec["disk_total_gb"] = min(_kb_to_gb(total_kb), _MAX_DISK_GB)
            spec["disk_used_gb"] = min(_kb_to_gb(used_kb), _MAX_DISK_GB)
            break

    # 장착 구성 — 얻지 못하면 키를 넣지 않는다(기존 값 보존)
    mods, slots = parse_dmidecode_memory(o.get(_CMD_DIMM))
    if not mods:                                   # root 아님 → sudo -n 결과 사용
        mods, slots = parse_dmidecode_memory(o.get(_CMD_DIMM_SUDO))
    if mods:
        spec["mem_modules"] = json.dumps(mods, ensure_ascii=False)
    if slots:
        spec["mem_slots_total"] = slots
    disks = parse_lsblk_disks(o.get(_CMD_LSBLK)) or parse_iostat_disks(o.get(_CMD_IOSTAT))
    if disks:
        spec["disk_devices"] = json.dumps(disks, ensure_ascii=False)
    return spec


# ── 윈도우 사양 ───────────────────────────────────────────────────
# wmic(구형 서버) 우선, 없으면 PowerShell(WMI)로 폴백. 둘 다 CMD 한 줄로 실행 가능.
_CMD_WIN_CPU = "wmic cpu get Name,NumberOfLogicalProcessors /format:list"
_CMD_WIN_MEM = "wmic ComputerSystem get TotalPhysicalMemory /format:list"
_CMD_WIN_DISK = "wmic logicaldisk where DriveType=3 get DeviceID,Size,FreeSpace /format:list"
def _ps_command(script):
    """PowerShell 스크립트 → `powershell -EncodedCommand <base64>` 한 줄.

    따옴표로 감싸 넘기면(`powershell -Command "...$_..."`) cmd.exe와 SSH 계층을
    지나며 `$` 변수가 통째로 사라지고, PowerShell이 명령을 실행하지 않은 채
    문자열만 되돌려준다(rc=0이라 성공처럼 보여 더 위험하다). base64(UTF-16LE)로
    넘기면 따옴표·$·파이프가 어느 계층도 건드리지 못한다.
    """
    return ("powershell -NoProfile -NonInteractive -EncodedCommand "
            + base64.b64encode(script.encode("utf-16-le")).decode("ascii"))


# 진행률 표시가 stderr로 CLIXML을 뿜어 로그를 어지럽히므로 끈다.
_PS_PREFIX = "$ProgressPreference='SilentlyContinue';"

_CMD_WIN_PS = _ps_command(
    _PS_PREFIX +
    "$c=Get-WmiObject Win32_Processor|Select-Object -First 1;"
    "$s=Get-WmiObject Win32_ComputerSystem;"
    "$d=Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3';"
    "Write-Output ('CPU=' + $c.Name);"
    "Write-Output ('CORES=' + $s.NumberOfLogicalProcessors);"
    "Write-Output ('MEM=' + $s.TotalPhysicalMemory);"
    "Write-Output ('DTOTAL=' + ($d|Measure-Object Size -Sum).Sum);"
    "Write-Output ('DFREE=' + ($d|Measure-Object FreeSpace -Sum).Sum)"
)
# 장착 구성 — 메모리 슬롯(모듈별) / 물리 디스크
_CMD_WIN_DIMM = ("wmic memorychip get Capacity,DeviceLocator,Manufacturer,PartNumber,"
                 "Speed,SMBIOSMemoryType /format:list")
_CMD_WIN_SLOTS = "wmic memphysical get MemoryDevices /format:list"
_CMD_WIN_PDISK = "wmic diskdrive get Model,Size,InterfaceType /format:list"
# PowerShell 폴백은 wmic이 없거나 MediaType(SSD/HDD)이 필요할 때만 2차로 실행한다.
# 한 줄에 하나씩 '|' 구분으로 뽑아 파싱을 단순화한다.
_CMD_WIN_PS_HW = _ps_command(
    _PS_PREFIX +
    "Get-WmiObject Win32_PhysicalMemory|ForEach-Object{"
    "Write-Output ('DIMM|'+$_.Capacity+'|'+$_.DeviceLocator+'|'+$_.Manufacturer"
    "+'|'+$_.PartNumber+'|'+$_.Speed+'|'+$_.SMBIOSMemoryType)};"
    "Get-WmiObject Win32_PhysicalMemoryArray|ForEach-Object{"
    "Write-Output ('SLOTS|'+$_.MemoryDevices)};"
    "try{Get-PhysicalDisk -ErrorAction Stop|ForEach-Object{"
    "Write-Output ('DISK|'+$_.FriendlyName+'|'+$_.Size+'|'+$_.MediaType)}}"
    "catch{Get-WmiObject Win32_DiskDrive|ForEach-Object{"
    "Write-Output ('DISK|'+$_.Model+'|'+$_.Size+'|')}}"
)
# 1차: hostname/버전 + wmic + 장착구성 PowerShell.
# 장착구성 PS(_CMD_WIN_PS_HW)를 1차에 둔 이유 — wmic의 InterfaceType은 버스 종류라
# SSD/HDD를 알 수 없다. 그 정보는 Get-PhysicalDisk(MediaType)에만 있으므로 어차피
# 매번 필요하다. 같은 연결에서 함께 실행해 SSH 인증이 2회로 늘어나는 것을 막는다.
# 요약 PS(_CMD_WIN_PS)만 wmic이 실패했을 때 2차로 실행한다.
_WIN_CMDS = ["hostname", "ver", _CMD_WIN_CPU, _CMD_WIN_MEM, _CMD_WIN_DISK,
             _CMD_WIN_DIMM, _CMD_WIN_SLOTS, _CMD_WIN_PDISK, _CMD_WIN_PS_HW]
_WIN_CMDS_PS = [_CMD_WIN_PS]

# SMBIOS 메모리 타입 코드 → 표기(자주 쓰이는 것만)
_SMBIOS_MEM_TYPE = {"20": "DDR", "21": "DDR2", "24": "DDR3", "26": "DDR4",
                    "34": "DDR5", "27": "LPDDR", "29": "LPDDR3", "30": "LPDDR4"}

# wmic Win32_PhysicalMemory.Manufacturer는 제조사명이 아니라 JEDEC ID를 16진 문자열로
# 주는 경우가 많다(예: '80CE000080CE' = Samsung). 그대로 두면 화면에 의미 없는 코드가
# 뜨므로, 아는 코드는 이름으로 바꾸고 모르는 16진 코드는 비운다.
_JEDEC_VENDOR = {
    "80CE": "Samsung", "CE00": "Samsung",
    "802C": "Micron", "2C00": "Micron",
    "80AD": "SK Hynix", "AD00": "SK Hynix",
    "859B": "Crucial", "9B85": "Crucial",
    "04CB": "A-DATA", "CB04": "A-DATA",
    "0198": "Kingston", "9801": "Kingston",
    "82FE": "Elpida", "FE02": "Elpida",
    "830B": "Transcend", "014F": "Transcend",
    "80B5": "Kingmax", "8551": "Qimonda",
}


def _clean_maker(s):
    """메모리 제조사 표기 정리 — JEDEC 16진 코드는 이름으로, 모르면 빈 문자열."""
    v = _unknown_to_blank(s)
    if not v:
        return ""
    hexs = re.sub(r"[^0-9A-Fa-f]", "", v)
    # 전체가 16진수이고 4자리 이상이면 JEDEC 코드로 본다(제조사명은 보통 글자를 포함)
    if len(hexs) == len(v.replace(" ", "")) and len(hexs) >= 4:
        return _JEDEC_VENDOR.get(hexs[:4].upper(), "")
    return v


def parse_win_memorychip(text):
    """`wmic memorychip ... /format:list` → 메모리 모듈 목록."""
    modules = []
    cur = {}

    def _flush():
        if not cur:
            return
        size_mb = int(_int(cur.get("Capacity")) / 1048576)
        if size_mb:
            speed = cur.get("Speed", "")
            modules.append({
                "size_mb": size_mb,
                "locator": _unknown_to_blank(cur.get("DeviceLocator"))[:40],
                "type": _SMBIOS_MEM_TYPE.get(cur.get("SMBIOSMemoryType", ""), ""),
                "speed": ("%s MT/s" % speed) if speed.isdigit() else "",
                "maker": _clean_maker(cur.get("Manufacturer"))[:40],
                "part": _unknown_to_blank(cur.get("PartNumber"))[:40],
            })

    for k, v in _parse_kv_lines(text):
        if k in cur:                      # 같은 키가 다시 나오면 다음 모듈 블록
            _flush()
            cur = {}
        cur[k] = v
    _flush()
    return modules[:_MAX_MODULES]


def parse_win_diskdrive(text):
    """`wmic diskdrive ... /format:list` → 물리 디스크 목록.

    wmic의 InterfaceType은 버스 종류(SCSI/IDE/USB)이지 SSD/HDD가 아니다.
    실제로 NVMe SSD가 'SCSI'로 나오므로 이를 '종류'로 쓰면 오해를 부른다 →
    bus에 따로 담고 kind(SSD/HDD)는 비워 둔다(PowerShell MediaType이 채운다).
    """
    disks = []
    cur = {}

    def _flush():
        size = _int(cur.get("Size"))
        if size:
            disks.append({"name": "", "model": _unknown_to_blank(cur.get("Model"))[:60],
                          "size_gb": _bytes_to_gb(size), "kind": "",
                          "bus": _unknown_to_blank(cur.get("InterfaceType"))[:12]})

    for k, v in _parse_kv_lines(text):
        if k in cur:
            _flush()
            cur = {}
        cur[k] = v
    _flush()
    return disks[:_MAX_MODULES]


def parse_win_ps_hw(text):
    """PowerShell 폴백('DIMM|...' / 'SLOTS|n' / 'DISK|...') → (모듈, 슬롯수, 디스크)."""
    modules, disks, slots = [], [], 0
    for ln in (text or "").splitlines():
        f = ln.strip().split("|")
        if f[0] == "DIMM" and len(f) >= 7:
            size_mb = int(_int(f[1]) / 1048576)
            if size_mb:
                modules.append({
                    "size_mb": size_mb, "locator": _unknown_to_blank(f[2])[:40],
                    "type": _SMBIOS_MEM_TYPE.get(f[6].strip(), ""),
                    "speed": ("%s MT/s" % f[5].strip()) if f[5].strip().isdigit() else "",
                    "maker": _clean_maker(f[3])[:40],
                    "part": _unknown_to_blank(f[4])[:40]})
        elif f[0] == "SLOTS" and len(f) >= 2:
            slots += _int(f[1], _MAX_MODULES)
        elif f[0] == "DISK" and len(f) >= 4:
            size = _int(f[2])
            if size:
                disks.append({"name": "", "model": _unknown_to_blank(f[1])[:60],
                              "size_gb": _bytes_to_gb(size),
                              "kind": _unknown_to_blank(f[3])[:12], "bus": ""})
    return modules[:_MAX_MODULES], min(slots, _MAX_MODULES), disks[:_MAX_MODULES]


def _merge_disks(wmic_disks, ps_disks):
    """wmic(버스 종류) + PowerShell(SSD/HDD) 결과 합치기.

    PowerShell 쪽이 MediaType(SSD/HDD)을 아는 유일한 경로라 이를 기준으로 삼고,
    같은 용량의 wmic 항목이 있으면 버스 종류만 옮겨 붙인다.
    """
    if not ps_disks:
        return wmic_disks
    by_size = {}
    for d in wmic_disks or []:
        by_size.setdefault(d.get("size_gb"), d)
    merged = []
    for d in ps_disks:
        w = by_size.get(d.get("size_gb"))
        merged.append(dict(d, bus=(w or {}).get("bus", "")))
    return merged


def _parse_kv_lines(text):
    """`Key=Value` 형식 출력 → [(key, value)] (중복 키 보존 — 다중 CPU/디스크)."""
    out = []
    for ln in (text or "").splitlines():
        s = ln.strip()
        if "=" in s:
            k, v = s.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def _bytes_to_gb(b):
    return round(b / 1073741824.0, 1)


def _specs_from_windows(o):
    """윈도우 명령 출력 모음 → 사양 필드 dict(확인된 값만)."""
    model, cores, mem_mb = "", 0, 0
    dtotal = dfree = 0
    saw_free = False        # FreeSpace를 실제로 하나라도 읽었는지
    # wmic — CPU는 소켓마다 블록이 반복되므로 논리 프로세서 수는 합산
    for k, v in _parse_kv_lines(o.get(_CMD_WIN_CPU)):
        if k == "Name" and not model:
            model = _clean_cpu_model(v)
        elif k == "NumberOfLogicalProcessors":
            cores += _int(v, _MAX_CORES)
    for k, v in _parse_kv_lines(o.get(_CMD_WIN_MEM)):
        if k == "TotalPhysicalMemory":
            mem_mb = int(_int(v) / 1048576)
    for k, v in _parse_kv_lines(o.get(_CMD_WIN_DISK)):
        if k == "Size":
            dtotal += _int(v)
        elif k == "FreeSpace":
            n = _int(v)
            if n:
                dfree += n
                saw_free = True
    # PowerShell 폴백(wmic 미설치 — Windows 11/Server 2025)
    if not (model and cores and mem_mb and dtotal):
        ps = dict(_parse_kv_lines(o.get(_CMD_WIN_PS)))
        model = model or _clean_cpu_model(ps.get("CPU", ""))
        cores = cores or _int(ps.get("CORES"), _MAX_CORES)
        mem_mb = mem_mb or int(_int(ps.get("MEM")) / 1048576)
        if not dtotal:
            dtotal = _int(ps.get("DTOTAL"))
            dfree = _int(ps.get("DFREE"))
            saw_free = saw_free or bool(dfree)

    spec = {}
    if model:
        spec["cpu_model"] = model
    if 0 < cores <= _MAX_CORES:
        spec["cpu_cores"] = cores
    if 0 < mem_mb <= _MAX_MEM_MB:
        spec["mem_total_mb"] = mem_mb
    if dtotal:
        spec["disk_total_gb"] = min(_bytes_to_gb(dtotal), _MAX_DISK_GB)
        # FreeSpace를 못 읽었으면 사용량을 '전체'로 계산해 화면에 빨강 100%가
        # 뜬다(가짜 용량 경보). 총량만 알고 사용량은 모르는 상태로 둔다.
        if saw_free:
            spec["disk_used_gb"] = min(_bytes_to_gb(max(dtotal - dfree, 0)), _MAX_DISK_GB)

    # 장착 구성 — wmic 우선, PowerShell 결과는 항상 겹쳐 본다.
    # (조건부로 두면 wmic이 '다 채웠다'고 판정돼 SSD/HDD가 영영 비는데,
    #  그 정보는 Get-PhysicalDisk에만 있어 wmic으로는 절대 알 수 없다)
    modules = parse_win_memorychip(o.get(_CMD_WIN_DIMM))
    slots = 0
    for k, v in _parse_kv_lines(o.get(_CMD_WIN_SLOTS)):
        if k == "MemoryDevices":
            slots += _int(v, _MAX_MODULES)
    pdisks = parse_win_diskdrive(o.get(_CMD_WIN_PDISK))
    pm, ps_slots, pd = parse_win_ps_hw(o.get(_CMD_WIN_PS_HW))
    modules = modules or pm
    slots = slots or ps_slots
    pdisks = _merge_disks(pdisks, pd)
    if modules:
        spec["mem_modules"] = json.dumps(modules, ensure_ascii=False)
    if slots:
        spec["mem_slots_total"] = slots
    if pdisks:
        spec["disk_devices"] = json.dumps(pdisks, ensure_ascii=False)
    return spec


def _ssh_detail_unix(ip, username, password, port=22):
    """범용 UNIX 계열 SSH 상세 — Linux/AIX/Solaris/HP-UX/BSD/macOS/ESXi 공용.

    OS를 특정하지 못해도(unknown) 동작하도록 여러 명령을 시도해 성공한 것만 취합한다.
    반환: {hostname?, os_info?, mac?, open_ports?, cpu_model?, cpu_cores?,
           mem_total_mb?, disk_total_gb?, disk_used_gb?}
    """
    # batch=True: 26개 명령을 한 세션에서 실행 — OpenSSH MaxSessions(기본 10)에
    # 걸려 사양 명령이 전부 빈값이 되던 것을 막는다(왕복도 26회 → 1회로 줄어든다).
    o = _ssh_exec(ip, username, password, _UNIX_CMDS, port=port, batch=True)
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
    # 하드웨어 사양(CPU/메모리/디스크) — 확인된 값만 채운다.
    # 사양 파싱이 실패해도 위에서 얻은 hostname·OS·MAC·포트는 반드시 살린다
    # (여기서 예외가 새면 그 서버의 SSH 상세가 통째로 유실된다).
    try:
        spec = _specs_from_unix(o)
        detail.update(spec)
        if not spec:
            # 사양이 하나도 안 나온 이유를 남긴다 — 어떤 명령이 응답했는지가 핵심 단서.
            # (권한 부족·명령 부재·셸 제한 등은 서버마다 다르다)
            got = sorted(k.split()[-1] for k, v in o.items() if (v or "").strip())
            utils.log_event("warning", "server_spec_empty", ip=ip,
                            responded=",".join(got[:12]) or "(없음)",
                            total_cmds=len(o))
            detail["_spec_hint"] = ("사양 명령이 응답하지 않음 — 응답한 명령: %s"
                                    % (", ".join(got[:6]) or "없음"))
    except Exception as e:
        utils.log_event("warning", "server_spec_parse_failed", ip=ip, error=str(e)[:120])
        detail["_spec_hint"] = "사양 파싱 실패: %s" % str(e)[:80]
    return detail


# 하위 호환 별칭 — 기존 호출부/테스트가 쓰던 이름(내부는 범용 폴백으로 통일)
def _ssh_detail_linux(ip, username, password, port=22):
    """리눅스 SSH 상세(= 범용 UNIX 폴백). AIX/Solaris/ESXi 등에서도 최대한 수집."""
    return _ssh_detail_unix(ip, username, password, port=port)


def _ssh_detail_windows(ip, username, password, port=22):
    """윈도우 SSH 상세(OpenSSH 서버 설치 시): hostname, OS 버전, CPU/메모리/디스크."""
    o = _ssh_exec(ip, username, password, _WIN_CMDS, port=port)
    detail = {}
    if o.get("hostname", "").strip():
        detail["hostname"] = o["hostname"].strip().splitlines()[0][:100]
    ver = (o.get("ver") or "").strip()
    if ver:
        detail["os_info"] = ver.splitlines()[-1][:120]
    try:
        spec = _specs_from_windows(o)
    except Exception as e:
        utils.log_event("warning", "server_spec_parse_failed", ip=ip, error=str(e)[:120])
        return detail
    if not (spec.get("cpu_model") and spec.get("cpu_cores")
            and spec.get("mem_total_mb") and spec.get("disk_total_gb")
            and spec.get("mem_modules") and spec.get("disk_devices")):
        # wmic 미설치(Windows 11/Server 2025)·정책 차단 → PowerShell로 재시도.
        # 접속을 한 번 더 열지만, wmic이 되는 대부분의 서버에서는 건너뛴다.
        try:
            o.update(_ssh_exec(ip, username, password, _WIN_CMDS_PS, port=port))
            spec = _specs_from_windows(o)
        except Exception as e:
            utils.log_event("warning", "server_win_ps_fallback_failed", ip=ip,
                            error=str(e)[:120])
    detail.update(spec)
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


# 수집 중인 서버 id — 같은 서버를 동시에 수집하면 두 수집본이 서로를 덮어써
# (실패본이 성공본을 지움) 스캔 소켓도 배로 든다. 스위치·방화벽과 같은 방식.
_inflight = set()
_inflight_lock = threading.Lock()


def collect_server(db_path, server_id, username=None, password=None):
    """서버 1대 수집(동기). 무자격 단계는 항상, SSH 상세는 자격증명 있을 때.

    같은 서버가 이미 수집 중이면 건너뛴다(status="skipped").
    반환: {"status": "done"|"failed"|"skipped", ...수집 필드}
    """
    sv = db.get_server(db_path, server_id)
    if not sv:
        return {"status": "failed", "error": "not found"}
    with _inflight_lock:
        if server_id in _inflight:
            utils.log_event("info", "server_collect_already_running", server_id=server_id)
            return {"status": "skipped", "error": "already collecting"}
        _inflight.add(server_id)
    try:
        return _collect_server_locked(db_path, server_id, sv, username, password)
    except Exception as e:
        # 예외가 나가면 status가 'collecting'인 채로 남아 화면에 영구 '수집중'
        # 배지가 붙는다(일괄 수집은 예외를 잡아 '실패'라고 보고하는데 DB는 수집중).
        # 복구는 앱 재시작(reset_stale_collecting)뿐이었다.
        try:
            db.update_server(db_path, server_id, status="failed",
                             last_error=str(e)[:200])
        except Exception:
            pass
        utils.log_event("error", "server_collect_error", server_id=server_id,
                        error=str(e)[:200], error_type=type(e).__name__)
        raise
    finally:
        with _inflight_lock:
            _inflight.discard(server_id)


def _collect_server_locked(db_path, server_id, sv, username, password):
    """collect_server 본체 — 같은 서버 중복 수집이 배제된 상태에서만 호출된다."""
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
    # 이미 확정된 계열이면 유지한다. 예전엔 linux/windows만 지켜서, 드롭다운이나 SSH로
    # 확정한 AIX·Solaris·HP-UX·ESXi가 '22번 열림 → linux'로 덮어써졌다
    # (계정 없는 수집이나 진단을 한 번만 눌러도 파괴됨). SSH 상세 성공 시에는 덮어쓴다.
    _cur_os = (sv.get("os_type") or "auto").lower()
    if _cur_os not in ("windows",) + UNIX_LIKE:
        inferred = infer_os_from_scan(open_ports, nb_hit)
        if inferred:
            fields["os_type"] = inferred
    # 연결 위치: ARP→MAC→스위치포트. 물리 포트 우선, Po면 물리 멤버로 해석.
    def _apply_location(loc):
        """{switch_name, switch_id, port} → fields. 포트채널은 물리 멤버로 풀어 쓴다."""
        if not loc.get("switch_name"):
            return False
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
        return True

    loc = db.find_mac_location(db_path, ip)
    if loc.get("mac"):
        fields["mac"] = _norm_mac(loc["mac"])
    _apply_location(loc)

    # 스위치 ARP에 없으면 이 PC의 ARP 캐시를 본다 — 같은 서브넷이면 포트 스캔만으로
    # 이미 채워져 있다. 계정도 스위치 수집도 필요 없는 공짜 경로.
    if not fields.get("mac") and not sv.get("mac"):
        _lm = local_arp_mac(ip)
        if _lm:
            fields["mac"] = _lm
            utils.log_event("info", "server_mac_from_local_arp",
                            server_id=server_id, ip=ip)

    # ② SSH 상세(자격증명 시) — 포트 번호로 추측하지 않고 **열린 포트의 배너를 확인**해
    #    실제 SSH 포트를 찾는다. 22를 막고 비표준 포트로 옮긴 서버가 많은데, 예전에는
    #    22/2222만 보고 "SSH 포트 미개방"으로 끝나 사양을 아예 못 가져왔다.
    if not (username and password) and open_ports:
        # 계정이 없으면 SSH 상세(=CPU·메모리·디스크 사양)를 아예 시도하지 않는다.
        # 도달 자체가 안 되는 서버(열린 포트 0)에는 붙이지 않는다 —
        # 진짜 사유('도달 불가')를 가리면 안 된다.
        # 예전엔 이때 아무 안내도 남기지 않아, 화면은 '정상'인데 사양만 비어 있고
        # 로그에도 단서가 없었다("왜 사양이 안 잡히지?"의 실제 원인).
        utils.log_event("info", "server_no_credential_skip_detail",
                        server_id=server_id, ip=ip)
        errors.append("계정 없음 — 사양(CPU·메모리·디스크)은 수집하지 못했습니다. "
                      "이 서버의 계정을 저장하거나 수집 시 입력하세요")
    if username and password:
        ssh_port = find_ssh_port(ip, open_ports)
        if ssh_port is None:
            errors.append(
                "SSH 서버를 찾지 못해 상세 수집 생략 — 열린 포트(%s)에서 SSH 응답이 "
                "없습니다(포트/hostname/MAC로 식별)"
                % (",".join(str(p) for p in open_ports) if open_ports else "없음"))
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
            # 계정 후보: 입력 계정 → 이 서버에 저장된 계정.
            # 수집 팝업의 공통 계정이 서버별 저장 계정을 덮어써서, OS가 섞인 환경
            # (Windows·RHEL·SUSE·Debian)에서는 대부분 인증 실패가 났다.
            # 인증이 거부된 경우에만 다음 후보로 넘어간다(최대 2회 — 계정 잠금 방지).
            _cands = _cred_candidates(db_path, server_id, username, password)                 or [(username, password, "입력 계정")]
            _auth_err = None
            for _u, _pw, _label in _cands:
                try:
                    if os_type == "windows":
                        fields.update(_ssh_detail_windows(ip, _u, _pw, port=ssh_port))
                    else:
                        # linux 및 그 외 모든 OS(aix/solaris/hpux/bsd/macos/esxi/unknown)
                        d = _ssh_detail_unix(ip, _u, _pw, port=ssh_port)
                        # 윈도우 폴백 판정에 'd가 비었는가'를 쓰면 안 된다 — hostname·
                        # netstat는 cmd.exe에도 있어 윈도우에서도 d가 채워진다. UNIX 고유
                        # 신호(uname의 os_info / ip link의 MAC)가 없을 때만 윈도우로 본다.
                        if os_type == "unknown" and not (d.get("os_info") or d.get("mac")):
                            w = _ssh_detail_windows(ip, _u, _pw, port=ssh_port)
                            if w.get("os_info") or w.get("cpu_model") or w.get("mem_total_mb"):
                                fields["os_type"] = "windows"
                                d = dict(d, **w)      # 무자격 단계에서 얻은 값은 보존
                        _hint = d.pop("_spec_hint", None)
                        if _hint:
                            errors.append(_hint)
                        fields.update(d)
                        # 수집된 OS 원문으로 계열 확정(os_type이 unknown으로 남지 않게)
                        if fields.get("os_info") and                                 (fields.get("os_type") or os_type) in ("unknown", "auto"):
                            fam = os_family_from_uname(fields["os_info"])
                            if fam != "unknown":
                                fields["os_type"] = fam
                    username, password = _u, _pw      # 성공한 계정을 이후 단계에서 재사용
                    if _label != "입력 계정":
                        utils.log_event("info", "server_cred_fallback_used",
                                        server_id=server_id, ip=ip, used=_label)
                    _auth_err = None
                    break
                except Exception as e:
                    if _is_auth_error(e) and _label != _cands[-1][2]:
                        _auth_err = e            # 다음 후보로
                        utils.log_event("info", "server_cred_rejected",
                                        server_id=server_id, ip=ip, tried=_label)
                        continue
                    _auth_err = e
                    break
            if _auth_err is not None:
                _m = str(_auth_err)
                if _is_auth_error(_auth_err):
                    errors.append(
                        "SSH 인증 실패(:%d) — 시도한 계정: %s. 이 서버의 계정을 "
                        "저장하거나 수집 시 그 서버 계정을 입력하세요"
                        % (ssh_port, ", ".join(c[2] for c in _cands)))
                else:
                    errors.append("SSH(:%d): %s" % (ssh_port, _m[:110]))
            # OS 계열과 무관하게, 사양이 하나도 안 채워졌으면 사유를 남긴다.
            _spec_keys0 = ("cpu_model", "cpu_cores", "mem_total_mb", "disk_total_gb")
            if not any(fields.get(k) for k in _spec_keys0) and not errors:
                errors.append("사양 명령이 응답하지 않았습니다 — 계정 권한·셸 제한을 확인하세요")
                utils.log_event("warning", "server_spec_empty_after_ssh",
                                server_id=server_id, ip=ip, port=ssh_port,
                                os_type=os_type)

    # ②-B WMI(DCOM) 폴백 — SSH로 사양을 못 얻은 Windows 서버.
    #     SSH가 아예 닫혀 있거나(포트 미개방) 인증이 막힌 경우가 대상이다.
    #     Windows는 원래 WMI로 사양을 노출하므로 135(RPC)가 열려 있으면 시도한다.
    _spec_keys = ("cpu_model", "cpu_cores", "mem_total_mb", "disk_total_gb")
    if (username and password and not any(fields.get(k) for k in _spec_keys)):
        try:
            from . import wmi_collect
        except Exception:
            wmi_collect = None
        # RDP(3389)만 보여도 Windows로 본다 — 그런 서버는 대개 WinRM(5985)이
        # 함께 열려 있고, 거기로 사양을 읽을 수 있다.
        _win_like = ((fields.get("os_type") or sv.get("os_type") or "").lower() == "windows"
                     or bool(set(open_ports or []) & {135, 445, 3389, 5985, 5986}))
        if wmi_collect and wmi_collect.available() and _win_like                 and wmi_collect.can_try(open_ports):
            try:
                # SSH와 같은 이유로 WMI도 계정이 서버마다 다를 수 있다 —
                # 인증이 거부되면 이 서버에 저장된 계정으로 한 번 더 시도한다.
                _wc = _cred_candidates(db_path, server_id, username, password)                     or [(username, password, "입력 계정")]
                # 전송은 열린 포트로 정한다: WinRM(단일 포트) 우선, 그다음 DCOM.
                # DCOM은 135가 열려 있어도 동적 포트가 막혀 실패하는 일이 잦다.
                _tr = wmi_collect.transports_for(open_ports)
                w, _we = None, None
                for _u, _pw, _label in _wc:
                    for _t, _tp in _tr:
                        try:
                            w = wmi_collect.collect(ip, _u, _pw, transport=_t, port=_tp)
                            _we = None
                            break
                        except Exception as ex:
                            _we = ex
                            if _is_auth_error(ex):
                                break        # 계정 문제면 다른 전송도 같다
                    if w is not None:
                        if _label != "입력 계정":
                            utils.log_event("info", "server_cred_fallback_used",
                                            server_id=server_id, ip=ip, used=_label)
                        break
                    if _we is not None and not _is_auth_error(_we):
                        break                 # 전송 문제 — 계정을 바꿔도 같다
                if _we is not None:
                    raise _we
                for k in ("hostname", "os_info", "mac", "cpu_model", "cpu_cores",
                          "mem_total_mb", "disk_total_gb", "disk_used_gb"):
                    if w.get(k) and not fields.get(k):
                        fields[k] = w[k]
                if w.get("mem_modules"):
                    # 제조사 코드(80CE…)는 SSH 경로와 같은 규칙으로 정규화
                    for _m in w["mem_modules"]:
                        if _m.get("maker"):
                            _m["maker"] = _clean_maker(_m["maker"])
                        if _m.get("speed"):
                            _m["speed"] = "%s MT/s" % _m["speed"]
                    fields["mem_modules"] = json.dumps(w["mem_modules"], ensure_ascii=False)
                if w.get("mem_slots"):
                    fields["mem_slots_total"] = int(w["mem_slots"])
                if w.get("disk_devices"):
                    fields["disk_devices"] = json.dumps(w["disk_devices"], ensure_ascii=False)
                fields["os_type"] = "windows"
                # SSH 실패 사유는 이제 의미가 없다 — WMI로 사양을 확보했다.
                errors[:] = [e for e in errors if "SSH" not in e and "사양" not in e]
                utils.log_event("info", "server_spec_via_wmi", server_id=server_id, ip=ip)
            except Exception as e:
                errors.append("WMI 폴백 실패 — %s" % str(e)[:110])

    # ②-C SNMP(161/UDP) 폴백 — 여기까지 와서도 사양이 비어 있는 서버.
    #     SSH가 닫혔거나 계정이 아예 없는 리눅스·UNIX 서버가 대상이다(WMI는 Windows 전용).
    #     운영 서버는 감시용 snmpd가 이미 떠 있는 경우가 많고, 읽기 전용 GET만 쓴다.
    #     도달 자체가 안 되는 서버에는 시도하지 않는다 — 진짜 사유('도달 불가')를
    #     SNMP 무응답 메시지로 덮어쓰고, 서버마다 몇 초씩 헛되이 기다리게 된다.
    _reachable = bool(open_ports) or bool(fields.get("hostname") or fields.get("mac"))
    if (_reachable and not any(fields.get(k) for k in _spec_keys)
            and snmp_enabled(db_path)):
        try:
            from . import snmp_collect
        except Exception:
            snmp_collect = None
        if snmp_collect:
            try:
                sn = snmp_collect.collect(ip, snmp_community(db_path))
                got = False
                for k in ("hostname", "os_info", "mac", "cpu_model", "cpu_cores",
                          "mem_total_mb", "disk_total_gb", "disk_used_gb"):
                    if sn.get(k) and not fields.get(k):
                        fields[k] = sn[k]
                        got = got or k in _spec_keys
                if got:
                    # 사양을 확보했으므로 SSH/WMI 실패 사유는 더 이상 사용자에게
                    # 보여줄 이유가 없다(해결된 문제로 화면을 어지럽히지 않는다).
                    errors[:] = [e for e in errors
                                 if "SSH" not in e and "사양" not in e
                                 and "WMI" not in e and "계정 없음" not in e]
                    if fields.get("os_info") and (fields.get("os_type")
                                                  or sv.get("os_type")
                                                  or "auto") in ("auto", "unknown", None):
                        fam = os_family_from_uname(fields["os_info"])
                        if fam != "unknown":
                            fields["os_type"] = fam
                    utils.log_event("info", "server_spec_via_snmp",
                                    server_id=server_id, ip=ip)
                else:
                    errors.append("SNMP 응답에 사양 정보(HOST-RESOURCES-MIB)가 없습니다")
            except snmp_collect.SnmpClosed:
                # 서버는 살아 있는데 161을 아무도 안 듣는다 → 커뮤니티를 백날 바꿔도 안 된다.
                errors.append("SNMP 미동작 — 이 서버에 snmpd가 떠 있지 않습니다"
                              "(설치·기동해야 사양 수집 가능)")
                utils.log_event("info", "server_snmp_closed", server_id=server_id, ip=ip)
            except Exception as e:
                # 타임아웃 등 — 원인이 둘(차단/커뮤니티)이라 둘 다 알린다.
                errors.append(
                    "SNMP 응답 없음 — UDP 161 차단 또는 커뮤니티 불일치"
                    "(설정▸SNMP 커뮤니티 확인) (%s)" % str(e)[:60])
                utils.log_event("info", "server_snmp_no_reply", server_id=server_id, ip=ip)

    # 연결 위치 재조회 — MAC을 뒤늦게 얻는 경로가 많다(SSH·WMI·SNMP·로컬 ARP).
    # 위 ①단계는 IP→MAC(스위치 ARP)이 있을 때만 동작해서, MAC은 채워졌는데
    # 연결스위치·포트만 비는 서버가 많았다. MAC이 있으면 여기서 한 번 더 찾는다.
    if not fields.get("switch_name"):
        _mac = fields.get("mac") or sv.get("mac")
        if _mac:
            _loc2 = db.find_location_by_mac(db_path, _mac)
            if _apply_location(_loc2):
                utils.log_event("info", "server_port_resolved_by_mac",
                                server_id=server_id, ip=ip,
                                switch=_loc2.get("switch_name"))

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
    try:
        db.update_server(db_path, server_id, collected=True, **fields)
    except Exception as e:
        # 저장 실패로 예외가 새면 status가 'collecting'으로 고착되고(위 818행에서 이미 씀)
        # 일괄 수집의 결과 소비 루프까지 끊긴다. 상태만이라도 되돌리고 실패로 보고한다.
        utils.log_event("error", "server_collect_save_failed", server_id=server_id,
                        error=str(e)[:160])
        try:
            db.update_server(db_path, server_id, status="failed",
                             last_error="수집 결과 저장 실패: %s" % str(e)[:100])
        except Exception:
            pass
        return {"status": "failed", "error": "save failed"}
    utils.log_event("info", "server_collect_done", server_id=server_id,
                    status=fields["status"], ports=fields.get("open_ports", ""))
    return {"status": fields["status"], **fields}


_progress = {"running": False, "done": 0, "total": 0, "message": ""}
_prog_lock = threading.Lock()
_stop = False   # 전체 수집 중지 요청


def get_progress():
    """서버 전체 수집 진행 상태 스냅샷 {running, done, total, message, stopping}."""
    with _prog_lock:
        st = dict(_progress)
        st["stopping"] = bool(_stop and _progress.get("running"))
        return st


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
                        common_pass=None, persist=False, ids=None, no_cred=False):
    """등록된 서버 일괄 (재)수집(스레드풀). ids 주면 그 서버들만.

    계정 우선순위: 공통 계정(common_user/pass) > 서버별 저장 계정 > 무자격.
    공통 계정 + persist=True면 각 서버에 그 계정을 저장한다.

    no_cred=True면 어떤 계정도 쓰지 않는다(진단 전용). 저장 계정 조회도 하지 않아
    '계정 없이 확인'이라고 안내한 화면이 실제로도 계정을 쓰지 않게 보장한다.

    이미 일괄 수집이 진행 중이면 시작하지 않는다(status="already_running").
    진행률·중지 플래그가 모듈 전역이라, 두 수집이 겹치면 먼저 끝난 쪽이
    running=False로 덮어써 UI가 '완료'로 보이는데 실제로는 계속 돌고,
    그 뒤 중지 요청이 먹지 않는다. 스위치·방화벽과 같은 단일 실행 규칙.
    """
    import concurrent.futures as _cf
    global _stop
    with _prog_lock:
        if _progress.get("running"):
            utils.log_event("warning", "server_collect_all_already_running")
            return {"status": "already_running", "done": 0, "failed": 0,
                    "skipped": 0, "total": 0}
        _stop = False            # 새 수집 시작 — 중지 플래그 초기화
        _progress.update(running=True, done=0, total=0, message="서버 수집 준비 중")
    if no_cred:                     # 진단 전용 — 계정을 아예 쓰지 않는다
        common_user = common_pass = None
        persist = False
    try:
        return _collect_all_locked(db_path, max_workers, common_user, common_pass,
                                   persist, ids, _cf, no_cred)
    except Exception:
        _set_progress(running=False, message="수집 오류로 중단됨")
        raise


def _collect_all_locked(db_path, max_workers, common_user, common_pass,
                        persist, ids, _cf, no_cred=False):
    """collect_all_servers 본체 — running=True를 이미 선점한 상태에서 호출된다."""
    servers = db.list_servers(db_path)
    if ids:
        _idset = set(int(x) for x in ids)
        servers = [s for s in servers if s.get("id") in _idset]
    done = failed = 0
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
        username = password = None
        if no_cred:
            pass                    # 진단 전용 — 저장 계정도 쓰지 않는다
        elif common:
            username, password = common_user, common_pass
        else:
            blob = db.get_server_credential(db_path, sv["id"])
            if blob:
                dec = credentials.decrypt_credential(blob)
                if dec and "|" in dec:
                    username, password = dec.split("|", 1)
        try:
            return collect_server(db_path, sv["id"], username, password)
        except Exception as e:
            # 한 대의 예외가 ex.map 소비 루프를 끊어 나머지 서버가 통째로 중단되던 것 방지
            utils.log_event("error", "server_collect_worker_error",
                            server_id=sv.get("id"), error=str(e)[:160])
            return {"status": "failed"}

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
