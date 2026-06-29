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


def get_arp_table(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """FortiGate 전체 ARP 테이블 수집.

    Returns: [{"ip", "mac", "interface"}, ...]
    """
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    r = s.get(f"{base}/api/v2/monitor/router/arp", timeout=15)
    r.raise_for_status()

    entries = []
    for e in r.json().get("results", []):
        ip = (e.get("ip") or "").strip()
        mac = (e.get("mac") or "").strip().upper()
        iface = (e.get("interface") or "").strip()
        if ip and mac and mac != "00:00:00:00:00:00":
            entries.append({"ip": ip, "mac": mac, "interface": iface})
    logger.info("fortigate_arp host=%s collected=%d", host, len(entries))
    return entries


def get_interfaces(host, port=443, token="", username="", password="", verify_ssl=False, source_ip=None):
    """FortiGate 인터페이스 목록 및 IP 대역 수집.

    Returns: [{"name", "ip", "mask", "vdom_zone", "type"}, ...]
    """
    s, base = _make_session(host, port, token, username, password, verify_ssl, source_ip)
    r = s.get(f"{base}/api/v2/cmdb/system/interface", timeout=15)
    r.raise_for_status()

    ifaces = []
    for e in r.json().get("results", []):
        parts = (e.get("ip", "0.0.0.0 0.0.0.0")).split()
        ip = parts[0] if parts else ""
        mask = parts[1] if len(parts) > 1 else ""
        if ip and ip != "0.0.0.0":
            ifaces.append({
                "name": e.get("name", ""),
                "ip": ip,
                "mask": mask,
                "vdom_zone": e.get("vdom", "root"),
                "type": e.get("type", ""),
            })
    return ifaces


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
