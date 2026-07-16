"""PC 프로필 — 수집 PC(MAC) 단위로 출발지 IP·계정을 등록/사용.

배경(다중 PC 운영): 출발지 IP(source_ip)가 전역 설정이라 A가 저장하면 B PC에서
수집해도 A의 IP로 바인딩되고, 저장 계정(DPAPI)은 저장한 PC에서만 복호화돼
다른 PC가 주 서버가 되면 수집이 실패했다.

해결: 계정/출발지 IP를 저장할 때 그 PC의 이더넷 MAC·IP·호스트명과 함께
pc_profiles 테이블에 등록하고, 수집을 실행하는 PC가 자기 MAC으로 검색해
"자기 IP·자기 계정"으로 접속을 시도한다.

- 키: 이더넷 어댑터 MAC (감지 실패 시 "HOST:<hostname>" 폴백)
- 계정은 DPAPI 암호화 blob — 어차피 그 PC에서만 복호화되므로 프로필과 궁합이 맞음
- 출발지 IP: 프로필 값 우선 → 전역 설정(app_settings.source_ip) 폴백
"""
import ctypes
import socket
import uuid

from . import db, credentials, utils


def _detect_local_ip():
    """현재 PC의 기본 경로 소스 IPv4 (UDP connect 트릭 — 패킷 전송 없음)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.254", 1))  # 폐쇄망 가정 — 사설 대역으로 라우트 질의
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        return ip if not ip.startswith("127.") else None
    except OSError:
        return None


def _adapters_ipv4():
    """[(ip, mac)] 목록 — Windows GetAdaptersInfo(IPv4). 실패 시 빈 리스트."""
    try:
        MAX_ADAPTER_NAME = 260
        MAX_ADAPTER_DESC = 132
        MAX_ADAPTER_ADDR = 8

        class IP_ADDR_STRING(ctypes.Structure):
            pass

        IP_ADDR_STRING._fields_ = [
            ("Next", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddress", ctypes.c_char * 16),
            ("IpMask", ctypes.c_char * 16),
            ("Context", ctypes.c_ulong),
        ]

        class IP_ADAPTER_INFO(ctypes.Structure):
            pass

        IP_ADAPTER_INFO._fields_ = [
            ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
            ("ComboIndex", ctypes.c_ulong),
            ("AdapterName", ctypes.c_char * MAX_ADAPTER_NAME),
            ("Description", ctypes.c_char * MAX_ADAPTER_DESC),
            ("AddressLength", ctypes.c_uint),
            ("Address", ctypes.c_ubyte * MAX_ADAPTER_ADDR),
            ("Index", ctypes.c_ulong),
            ("Type", ctypes.c_uint),
            ("DhcpEnabled", ctypes.c_uint),
            ("CurrentIpAddress", ctypes.POINTER(IP_ADDR_STRING)),
            ("IpAddressList", IP_ADDR_STRING),
            ("GatewayList", IP_ADDR_STRING),
            ("DhcpServer", IP_ADDR_STRING),
            ("HaveWins", ctypes.c_uint),
            ("PrimaryWinsServer", IP_ADDR_STRING),
            ("SecondaryWinsServer", IP_ADDR_STRING),
            ("LeaseObtained", ctypes.c_ulonglong),
            ("LeaseExpires", ctypes.c_ulonglong),
        ]

        GetAdaptersInfo = ctypes.windll.iphlpapi.GetAdaptersInfo
        size = ctypes.c_ulong(0)
        GetAdaptersInfo(None, ctypes.byref(size))
        if size.value == 0:
            return []
        buf = ctypes.create_string_buffer(size.value)
        if GetAdaptersInfo(buf, ctypes.byref(size)) != 0:
            return []
        result = []
        adapter = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
        while adapter:
            a = adapter.contents
            mac = ":".join("%02X" % b for b in a.Address[:a.AddressLength])
            addr = a.IpAddressList
            while True:
                ip = addr.IpAddress.decode("ascii", "ignore").strip("\x00")
                if ip and ip != "0.0.0.0" and mac:
                    result.append((ip, mac))
                if not addr.Next:
                    break
                addr = addr.Next.contents
            adapter = a.Next
        return result
    except Exception:
        return []


def get_local_identity():
    """현재 PC 식별 정보: {mac, ip, hostname}.

    MAC은 소스 IP가 잡힌 어댑터의 것을 우선, 못 찾으면 uuid.getnode(),
    그것도 랜덤 값(멀티캐스트 비트)이면 "HOST:<hostname>" 폴백 키.
    """
    hostname = socket.gethostname()
    ip = _detect_local_ip()
    mac = None
    if ip:
        for a_ip, a_mac in _adapters_ipv4():
            if a_ip == ip:
                mac = a_mac
                break
    if not mac:
        node = uuid.getnode()
        if not (node >> 40) & 1:  # 멀티캐스트 비트 = getnode 실패(랜덤) 표식
            mac = ":".join("%02X" % ((node >> s) & 0xFF)
                           for s in range(40, -8, -8))
    if not mac:
        mac = "HOST:" + hostname  # 최후 폴백 — 호스트명 키
    return {"mac": mac, "ip": ip, "hostname": hostname}


def save_profile(db_path, username=None, password=None, source_ip=None):
    """현재 PC의 프로필(MAC·IP·계정)을 등록/갱신.

    - username/password 주어지면 DPAPI 암호화해 저장(이 PC에서만 복호화 가능).
      None이면 기존 계정 blob 유지.
    - source_ip 주어지면 그 값, 없으면 자동 감지 IP.
    """
    ident = get_local_identity()
    cred_blob = None
    if username and password:
        cred_blob = credentials.encrypt_credential(username, password)
    src = source_ip if source_ip is not None else ident["ip"]
    db.upsert_pc_profile(db_path, ident["mac"], ident["hostname"],
                         src, cred_blob)
    utils.log_event("info", "pc_profile_saved", mac=ident["mac"],
                    hostname=ident["hostname"], source_ip=src or "(auto)",
                    has_cred=bool(cred_blob))
    return ident


def get_profile(db_path):
    """현재 PC(MAC)의 프로필 조회. 없으면 None."""
    try:
        ident = get_local_identity()
        return db.get_pc_profile(db_path, ident["mac"])
    except Exception:
        return None


def get_source_ip(db_path):
    """수집 출발지 IP: 내 PC 프로필 우선 → 전역 설정 폴백. 없으면 None."""
    prof = get_profile(db_path)
    if prof and prof.get("source_ip"):
        return prof["source_ip"]
    try:
        return db.get_setting(db_path, "source_ip") or None
    except Exception:
        return None


def get_credential(db_path):
    """내 PC 프로필의 계정 (username, password). 없거나 복호화 실패 시 None.

    DPAPI라 다른 PC가 저장한 blob은 여기서 복호화되지 않는다 — 각 PC는
    자기가 등록한 계정만 쓰게 되는 것이 의도된 동작.
    """
    prof = get_profile(db_path)
    if not prof or not prof.get("cred_blob"):
        return None
    dec = credentials.decrypt_credential(prof["cred_blob"])
    if not dec or "|" not in dec:
        return None
    username, password = dec.split("|", 1)
    return (username, password)
