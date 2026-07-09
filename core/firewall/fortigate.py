# -*- coding: utf-8 -*-
"""M10: FortiGate 클라이언트 (ARP 테이블, 인터페이스 수집).

프로덕션본(C:\\AI_WORKPLACE\\NetDash\\core\\fortigate.py) 이식.

지원 인증:
  1. API 토큰: Authorization: Bearer <token>
  2. 관리자 계정: username + password → 세션 쿠키 + CSRF (REST API)
  3. SSH 직접 접근: 'get system arp' CLI
"""
import logging
import re

logger = logging.getLogger(__name__)


def _make_session(host, port, token, username, password, verify_ssl, source_ip=None):
    """인증 완료된 requests.Session 반환. (session, base_url). source_ip로 출발지 바인딩."""
    from .. import netbind
    base = f"https://{host}:{port}"
    s = netbind.requests_session(source_ip, verify=verify_ssl)

    if not verify_ssl:
        # 자체서명 인증서 환경 허용. 단 무검증 수집은 audit를 위해 경고로 남긴다.
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("fortigate TLS verification DISABLED host=%s", host)

    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    elif username and password:
        r = s.post(f"{base}/logincheck",
                   data={"username": username, "secretkey": password}, timeout=10)
        r.raise_for_status()
        csrf = r.cookies.get("ccsrftoken", "").strip('"')
        if csrf:
            s.headers["X-CSRFTOKEN"] = csrf
        if "Authentication Failure" in r.text:
            raise PermissionError("FortiGate 로그인 실패 — 계정/비밀번호 확인")
    else:
        raise ValueError("token 또는 username/password 중 하나 필요")

    return s, base


# FortiOS 버전별 ARP monitor 엔드포인트(상위 우선 시도). 7.x는 network/arp,
# 일부 빌드는 router/arp. 모두 404면 REST에 ARP monitor가 없는 버전이다.
_ARP_PATHS = (
    "/api/v2/monitor/network/arp",
    "/api/v2/monitor/router/arp",
)


def _get_with_retry(session, url, timeout=15, retries=3):
    """GET + 429(Too Many Requests) 시 Retry-After 만큼 대기 후 재시도.

    FortiGate는 REST 로그인/호출 속도 제한이 있어 연속 호출 시 429를 반환한다.
    """
    import time as _t
    r = session.get(url, timeout=timeout)
    for _ in range(retries):
        if r.status_code != 429:
            break
        try:
            wait = min(30, int(r.headers.get("Retry-After", 10) or 10))
        except (TypeError, ValueError):
            wait = 10
        logger.warning("fortigate 429 rate-limited url=%s wait=%ss", url, wait)
        _t.sleep(wait)
        r = session.get(url, timeout=timeout)
    return r


def _fetch_arp(s, base, host):
    """열린 세션으로 ARP 조회(경로 폴백 + 429 재시도)."""
    data = None
    tried = []
    for path in _ARP_PATHS:
        r = _get_with_retry(s, f"{base}{path}")
        tried.append(f"{path}={r.status_code}")
        if r.status_code == 404:
            continue  # 이 버전엔 없는 경로 → 다음 후보
        r.raise_for_status()
        data = r.json()
        break

    if data is None:
        # 어떤 ARP monitor 경로도 없음 → 빈 결과. 계정이 있으면 SSH(get system arp) 권장.
        logger.warning("fortigate ARP REST endpoint not found host=%s tried=%s", host, ",".join(tried))
        return []

    entries = []
    for e in data.get("results", []):
        ip = (e.get("ip") or "").strip()
        mac = (e.get("mac") or "").strip().upper()
        iface = (e.get("interface") or "").strip()
        if ip and mac and mac != "00:00:00:00:00:00":
            entries.append({"ip": ip, "mac": mac, "interface": iface})
    logger.info("fortigate_arp host=%s collected=%d", host, len(entries))
    return entries


def get_arp_table(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """FortiGate 전체 ARP 테이블 수집.

    Returns: [{"ip", "mac", "interface"}, ...]
    """
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    return _fetch_arp(s, base, host)


def _mask_to_prefix(mask):
    """넷마스크/프리픽스 문자열을 프리픽스 숫자 문자열로 정규화.

    '255.255.255.0'→'24', '24'→'24', '/24'→'24'. 변환 불가 시 원문 유지.
    """
    if mask in (None, ""):
        return ""
    m = str(mask).strip().lstrip("/")
    if m.isdigit():
        return m
    if m.count(".") == 3:
        try:
            bits = "".join(bin(int(o))[2:].zfill(8) for o in m.split("."))
            if "01" not in bits:                 # 연속 1 마스크만 유효
                return str(bits.count("1"))
        except (ValueError, TypeError):
            pass
    return m


def _split_ip_mask(val):
    """'10.0.0.1 255.255.255.0' / '10.0.0.1/24' / '10.0.0.1' → (ip, prefix).

    마스크는 항상 프리픽스 숫자('24')로 정규화해 반환.
    """
    if not val:
        return "", ""
    val = str(val).strip()
    if " " in val:
        p = val.split()
        return p[0], _mask_to_prefix(p[1] if len(p) > 1 else "")
    if "/" in val:
        p = val.split("/")
        return p[0], _mask_to_prefix(p[1])
    return val, ""


def _parse_monitor_interfaces(results):
    """monitor/system/interface 결과(dict 또는 list) → 인터페이스 목록(실제 런타임 IP)."""
    items = results.values() if isinstance(results, dict) else (results or [])
    ifaces = []
    for e in items:
        if not isinstance(e, dict):
            continue
        ip, mask = _split_ip_mask(e.get("ip"))
        if not mask and e.get("mask") not in (None, ""):
            mask = _mask_to_prefix(e.get("mask"))
        if ip and ip != "0.0.0.0":
            ifaces.append({
                "name": e.get("name", "") or e.get("interface_name", ""),
                "ip": ip, "mask": mask,
                "vdom_zone": e.get("vdom", "") or "root",
                "type": e.get("type", ""),
            })
    return ifaces


def _cmdb_secondaries(results):
    """cmdb 인터페이스 결과에서 secondary IP 목록 추출.

    {인터페이스명: ["ip/prefix", ...]} — 같은 인터페이스의 primary 행에 병합한다.
    """
    out = {}
    for e in (results or []):
        if not isinstance(e, dict):
            continue
        name = e.get("name", "")
        for sec in (e.get("secondaryip") or []):
            if not isinstance(sec, dict):
                continue
            ip, mask = _split_ip_mask(sec.get("ip", ""))
            if ip and ip != "0.0.0.0":
                out.setdefault(name, []).append(ip + (("/" + mask) if mask else ""))
    return out


def _fetch_interfaces(s, base, host):
    """열린 세션으로 인터페이스 조회(monitor 우선 + cmdb 폴백 + 429 재시도).

    secondary IP까지 포함: monitor에는 secondary가 없으므로 cmdb에서
    secondaryip 목록을 병합해 '(2nd)' 행으로 추가한다.
    """
    ifaces = None
    # 1) monitor: 실제 유효 IP
    try:
        r = _get_with_retry(s, f"{base}/api/v2/monitor/system/interface")
        if r.status_code == 200:
            parsed = _parse_monitor_interfaces(r.json().get("results"))
            if parsed:
                logger.info("fortigate_interfaces(monitor) host=%s count=%d", host, len(parsed))
                ifaces = parsed
    except Exception as e:
        logger.warning("fortigate monitor interface failed host=%s err=%s", host, e)

    # 2) cmdb: (monitor 실패 시) 기본 IP + (항상) secondary IP 병합
    try:
        r = _get_with_retry(s, f"{base}/api/v2/cmdb/system/interface")
        if ifaces is None:
            r.raise_for_status()
        results = r.json().get("results", []) if r.status_code == 200 else []
        if ifaces is None:
            ifaces = []
            for e in results:
                ip, mask = _split_ip_mask(e.get("ip", "0.0.0.0 0.0.0.0"))
                if ip and ip != "0.0.0.0":
                    ifaces.append({
                        "name": e.get("name", ""),
                        "ip": ip, "mask": mask,
                        "vdom_zone": e.get("vdom", "root"),
                        "type": e.get("type", ""),
                    })
            logger.info("fortigate_interfaces(cmdb) host=%s count=%d", host, len(ifaces))
        secs = _cmdb_secondaries(results)
        if secs:
            # secondary IP를 같은 인터페이스의 primary 행에 secondary_ips로 병합
            n = 0
            for it in ifaces:
                extra = secs.get(it.get("name"))
                if extra:
                    it["secondary_ips"] = extra
                    n += len(extra)
            logger.info("fortigate_secondary_ips host=%s count=%d", host, n)
    except Exception as e:
        if ifaces is None:
            raise
        logger.warning("fortigate cmdb secondary fetch failed host=%s err=%s", host, e)
    return ifaces


def get_interfaces(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """FortiGate 인터페이스 목록 및 IP 대역 수집(단독 호출용 — 세션 1개 생성)."""
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    return _fetch_interfaces(s, base, host)


def _parse_hbdev(raw):
    """FortiOS hbdev 표현 → 포트 이름 목록.

    버전에 따라 '"ha1" 50 "ha2" 50 ' 문자열 / [["ha1",50],...] / [{"name":"ha1"},...] 형태.
    """
    ports = []
    if isinstance(raw, str):
        ports = re.findall(r'"([^"]+)"', raw) or [t for t in raw.split() if not t.isdigit()]
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and not item.isdigit():
                ports.append(item)
            elif isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                ports.append(item[0])
            elif isinstance(item, dict) and item.get("name"):
                ports.append(item["name"])
    return [p for p in ports if p]


def _fetch_ha(s, base, host):
    """HA 구성 조회(cmdb/system/ha) → {mode, group_name, hbdev, monitor} | None.

    standalone(비 HA)·권한/버전 문제로 실패하면 None(수집 흐름에 영향 없음).
    hbdev = HA heartbeat 포트(이중화 연결선에 표기).
    """
    try:
        r = _get_with_retry(s, f"{base}/api/v2/cmdb/system/ha")
        if r is None or r.status_code != 200:
            return None
        res = r.json().get("results") or {}
        if isinstance(res, list):
            res = res[0] if res else {}
        mode = (res.get("mode") or "").lower()
        if mode in ("", "standalone"):
            return None
        info = {"mode": mode,
                "group_name": res.get("group-name") or "",
                "hbdev": _parse_hbdev(res.get("hbdev")),
                "monitor": _parse_hbdev(res.get("monitor"))}
        logger.info("fortigate_ha host=%s mode=%s hbdev=%s", host, mode, info["hbdev"])
        return info
    except Exception:
        return None


def collect(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """인터페이스 + ARP + HA 구성을 '세션 1개'로 수집.

    이전엔 인터페이스/ARP가 각자 로그인해 세션 2개를 만들었고, FortiGate의
    로그인·API 속도 제한에 걸려 429(Too Many Requests)가 발생했다.
    Returns: {"interfaces": [...], "arp": [...], "ha": {...}|None}
    """
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    interfaces = _fetch_interfaces(s, base, host)
    arp = _fetch_arp(s, base, host)
    ha = _fetch_ha(s, base, host)
    return {"interfaces": interfaces, "arp": arp, "ha": ha}


def parse_arp_cli(output):
    """FortiGate 'get system arp' CLI 출력 파싱.

    형식:
      Address          Age(min)   Hardware Addr      Interface
      10.0.0.100       0          00:50:56:a1:b2:c3  port3
    """
    entries = []
    pat = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([0-9a-fA-F:]{17})\s+(\S+)', re.MULTILINE)
    for m in pat.finditer(output or ""):
        mac = m.group(2).upper()
        if mac != "00:00:00:00:00:00":
            entries.append({"ip": m.group(1), "mac": mac, "interface": m.group(3)})
    return entries


def get_arp_table_ssh(host, username, password, port=22, timeout=15):
    """FortiGate SSH로 ARP 테이블 수집 (REST API 대체). CLI: get system arp."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        _, stdout, _ = client.exec_command("get system arp", timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
    finally:
        client.close()
    entries = parse_arp_cli(output)
    logger.info("fortigate_arp_ssh host=%s collected=%d", host, len(entries))
    return entries
