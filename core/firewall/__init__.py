# -*- coding: utf-8 -*-
"""M10: 방화벽 수집 디스패치 (Palo Alto / Fortinet)."""
import logging

from . import fortigate, paloalto

logger = logging.getLogger(__name__)

SUPPORTED_VENDORS = ("fortigate", "paloalto")


def collect_firewall(vendor, host, port=None, token="", username="",
                     password="", verify_ssl=False, source_ip=None):
    """벤더별 방화벽에서 인터페이스 + ARP를 수집.

    Args:
        vendor: 'fortigate' | 'paloalto'
        host: 방화벽 관리 IP
        port: 포트 (fortigate 기본 443, paloalto 기본 22)
        token: FortiGate API 토큰 (선택)
        username/password: 계정 인증
        verify_ssl: FortiGate TLS 검증

    Returns:
        {"interfaces": [{"name","ip","mask","vdom_zone"}],
         "arp": [{"ip","mac","interface"}]}
    """
    vendor = (vendor or "").lower()
    if vendor == "fortigate":
        p = port or 443
        interfaces = fortigate.get_interfaces(host, p, token, username, password, verify_ssl, source_ip=source_ip)
        arp = fortigate.get_arp_table(host, p, token, username, password, verify_ssl, source_ip=source_ip)
        return {"interfaces": interfaces, "arp": arp}
    if vendor == "paloalto":
        if not (username and password):
            raise ValueError("Palo Alto는 username/password가 필요합니다")
        return paloalto.collect(host, username, password, port or 22, source_ip=source_ip)
    raise ValueError(f"지원하지 않는 방화벽 벤더: {vendor} (지원: {SUPPORTED_VENDORS})")
