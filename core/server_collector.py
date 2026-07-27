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
    return spec


# ── 윈도우 사양 ───────────────────────────────────────────────────
# wmic(구형 서버) 우선, 없으면 PowerShell(WMI)로 폴백. 둘 다 CMD 한 줄로 실행 가능.
_CMD_WIN_CPU = "wmic cpu get Name,NumberOfLogicalProcessors /format:list"
_CMD_WIN_MEM = "wmic ComputerSystem get TotalPhysicalMemory /format:list"
_CMD_WIN_DISK = "wmic logicaldisk where DriveType=3 get DeviceID,Size,FreeSpace /format:list"
_CMD_WIN_PS = (
    'powershell -NoProfile -Command "'
    "$c=Get-WmiObject Win32_Processor|Select-Object -First 1;"
    "$s=Get-WmiObject Win32_ComputerSystem;"
    "$d=Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3';"
    "Write-Output ('CPU=' + $c.Name);"
    "Write-Output ('CORES=' + $s.NumberOfLogicalProcessors);"
    "Write-Output ('MEM=' + $s.TotalPhysicalMemory);"
    "Write-Output ('DTOTAL=' + ($d|Measure-Object Size -Sum).Sum);"
    "Write-Output ('DFREE=' + ($d|Measure-Object FreeSpace -Sum).Sum)"
    '"'
)
# 1차(항상): hostname/버전 + wmic. PowerShell은 wmic이 없을 때만 2차로 실행한다
# — PowerShell 콜드 스타트가 서버당 0.5~2초라 매번 돌리면 일괄 수집이 크게 느려진다.
_WIN_CMDS = ["hostname", "ver", _CMD_WIN_CPU, _CMD_WIN_MEM, _CMD_WIN_DISK]
_WIN_CMDS_PS = [_CMD_WIN_PS]


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
    return spec


def _ssh_detail_unix(ip, username, password, port=22):
    """범용 UNIX 계열 SSH 상세 — Linux/AIX/Solaris/HP-UX/BSD/macOS/ESXi 공용.

    OS를 특정하지 못해도(unknown) 동작하도록 여러 명령을 시도해 성공한 것만 취합한다.
    반환: {hostname?, os_info?, mac?, open_ports?, cpu_model?, cpu_cores?,
           mem_total_mb?, disk_total_gb?, disk_used_gb?}
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
    # 하드웨어 사양(CPU/메모리/디스크) — 확인된 값만 채운다.
    # 사양 파싱이 실패해도 위에서 얻은 hostname·OS·MAC·포트는 반드시 살린다
    # (여기서 예외가 새면 그 서버의 SSH 상세가 통째로 유실된다).
    try:
        detail.update(_specs_from_unix(o))
    except Exception as e:
        utils.log_event("warning", "server_spec_parse_failed", ip=ip, error=str(e)[:120])
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
            and spec.get("mem_total_mb") and spec.get("disk_total_gb")):
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
                    # 윈도우 폴백 판정에 'd가 비었는가'를 쓰면 안 된다 — hostname·
                    # netstat는 cmd.exe에도 있어 윈도우에서도 d가 채워진다. UNIX 고유
                    # 신호(uname의 os_info / ifconfig·ip link의 MAC)가 없을 때만 윈도우로 본다.
                    # (Bitvise 등 서드파티 SSH 서버는 배너·uname으로 OS를 못 잡아 unknown이 된다)
                    if os_type == "unknown" and not (d.get("os_info") or d.get("mac")):
                        w = _ssh_detail_windows(ip, username, password, port=ssh_port)
                        if w.get("os_info") or w.get("cpu_model") or w.get("mem_total_mb"):
                            fields["os_type"] = "windows"
                            d = dict(d, **w)      # 무자격 단계에서 얻은 값은 보존
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
    try:
        return _collect_all_locked(db_path, max_workers, common_user, common_pass,
                                   persist, ids, _cf)
    except Exception:
        _set_progress(running=False, message="수집 오류로 중단됨")
        raise


def _collect_all_locked(db_path, max_workers, common_user, common_pass,
                        persist, ids, _cf):
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
        if common:
            username, password = common_user, common_pass
        else:
            username = password = None
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
