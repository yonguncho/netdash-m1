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


def _split_ip_mask(val):
    """'10.0.0.1 255.255.255.0' / '10.0.0.1/24' / '10.0.0.1' → (ip, mask)."""
    if not val:
        return "", ""
    val = str(val).strip()
    if " " in val:
        p = val.split()
        return p[0], (p[1] if len(p) > 1 else "")
    if "/" in val:
        p = val.split("/")
        return p[0], p[1]
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
            mask = str(e.get("mask"))
        if ip and ip != "0.0.0.0":
            ifaces.append({
                "name": e.get("name", "") or e.get("interface_name", ""),
                "ip": ip, "mask": mask,
                "vdom_zone": e.get("vdom", "") or "root",
                "type": e.get("type", ""),
            })
    return ifaces


def _cmdb_secondaries(results):
    """cmdb 인터페이스 결과에서 secondary IP 행 추출.

    FortiGate는 인터페이스당 secondaryip 목록을 가질 수 있다 —
    [{"name":"port1 (2nd)","ip":...,"mask":...,"type":"secondary"}] 형태로 반환.
    """
    rows = []
    for e in (results or []):
        if not isinstance(e, dict):
            continue
        for sec in (e.get("secondaryip") or []):
            if not isinstance(sec, dict):
                continue
            ip, mask = _split_ip_mask(sec.get("ip", ""))
            if ip and ip != "0.0.0.0":
                rows.append({
                    "name": "%s (2nd)" % e.get("name", ""),
                    "ip": ip, "mask": mask,
                    "vdom_zone": e.get("vdom", "root"),
                    "type": "secondary",
                })
    return rows


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
            ifaces.extend(secs)
            logger.info("fortigate_secondary_ips host=%s count=%d", host, len(secs))
    except Exception as e:
        if ifaces is None:
            raise
        logger.warning("fortigate cmdb secondary fetch failed host=%s err=%s", host, e)
    return ifaces


def get_interfaces(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """FortiGate 인터페이스 목록 및 IP 대역 수집(단독 호출용 — 세션 1개 생성)."""
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    return _fetch_interfaces(s, base, host)


def collect(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """인터페이스 + ARP를 '세션 1개'로 수집.

    이전엔 인터페이스/ARP가 각자 로그인해 세션 2개를 만들었고, FortiGate의
    로그인·API 속도 제한에 걸려 429(Too Many Requests)가 발생했다.
    Returns: {"interfaces": [...], "arp": [...]}
    """
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    interfaces = _fetch_interfaces(s, base, host)
    arp = _fetch_arp(s, base, host)
    return {"interfaces": interfaces, "arp": arp}


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
