# -*- coding: utf-8 -*-
"""M11: 장비 연결 테스트 (수집 전 선검증).

스위치/방화벽에 '지금 이 IP+계정으로 접근 가능한가'를 단계적으로 확인:
  1) reachable: TCP 포트 연결 가능 여부
  2) auth: 자격증명으로 로그인 성공 여부
자격증명은 결과/로그에 노출하지 않는다.
"""
import socket
import logging

from . import collector  # _sanitize_error_msg 재사용

logger = logging.getLogger(__name__)

# UI vendor 값 → netmiko device_type 매핑
_NETMIKO_TYPE = {
    "cisco": "cisco_ios", "arista": "arista_eos", "extreme": "extreme_exos",
    "juniper": "juniper_junos", "paloalto": "paloalto_panos",
    "nexus": "cisco_nxos", "cisco_nexus": "cisco_nxos",
    "unknown": "cisco_ios", "": "cisco_ios",  # 미지정 → IOS로 시도
    "cisco_ios": "cisco_ios", "arista_eos": "arista_eos", "extreme_exos": "extreme_exos",
    "cisco_nxos": "cisco_nxos", "paloalto_panos": "paloalto_panos",
}


def test_tcp(host, port, timeout=3, source_ip=None):
    """TCP 포트 reachability (source_ip 지정 시 그 출발지로 바인딩)."""
    try:
        src = (source_ip, 0) if source_ip else None
        with socket.create_connection((host, int(port)), timeout=timeout, source_address=src):
            return True
    except (OSError, ValueError):
        return False


def test_switch(ip, vendor, username, password, port=22, timeout=8, source_ip=None):
    """스위치 연결 테스트: TCP(22) → netmiko 인증. source_ip로 출발지 바인딩.

    Returns: {"ok": bool, "stage": "reachable"|"auth", "detail": str}
    """
    if not test_tcp(ip, port, 3, source_ip):
        return {"ok": False, "stage": "reachable", "detail": f"TCP {port} 포트에 연결할 수 없습니다"}
    if not (username and password):
        # 포트는 열렸으나 인증 정보 없음 → reachable까지만 확인
        return {"ok": True, "stage": "reachable", "detail": f"TCP {port} 연결 가능 (인증 미검증)"}
    device_type = _NETMIKO_TYPE.get((vendor or "").lower(), vendor or "cisco_ios")
    try:
        from netmiko import ConnectHandler
        from . import netbind
        device = {"device_type": device_type, "ip": ip, "username": username,
                  "password": password, "port": port, "conn_timeout": timeout, "fast_cli": False}
        if source_ip:
            device["sock"] = netbind.bind_socket(ip, port, source_ip, timeout)
        with ConnectHandler(**device):
            pass
        return {"ok": True, "stage": "auth", "detail": "연결 및 인증 성공"}
    except Exception as e:
        return {"ok": False, "stage": "auth", "detail": collector._sanitize_error_msg(str(e))}


def test_firewall(vendor, host, port=None, token="", username="", password="",
                  verify_ssl=False, source_ip=None):
    """방화벽 연결 테스트 (source_ip로 출발지 바인딩).

    FortiGate: TCP(port/443) → REST 인증 호출. Palo Alto: TCP(port/22) → netmiko 인증.
    Returns: {"ok": bool, "stage": "reachable"|"auth", "detail": str}
    """
    vendor = (vendor or "").lower()
    if vendor == "fortigate":
        p = int(port) if port else 443
        if not test_tcp(host, p, 3, source_ip):
            return {"ok": False, "stage": "reachable", "detail": f"TCP {p} 포트에 연결할 수 없습니다"}
        if not (token or (username and password)):
            return {"ok": True, "stage": "reachable", "detail": f"TCP {p} 연결 가능 (인증 미검증)"}
        try:
            from .firewall import fortigate
            fortigate.get_interfaces(host, p, token, username, password, verify_ssl, source_ip=source_ip)
            return {"ok": True, "stage": "auth", "detail": "연결 및 인증 성공"}
        except Exception as e:
            return {"ok": False, "stage": "auth", "detail": collector._sanitize_error_msg(str(e))}
    if vendor == "paloalto":
        p = int(port) if port else 22
        if not test_tcp(host, p, 3, source_ip):
            return {"ok": False, "stage": "reachable", "detail": f"TCP {p} 포트에 연결할 수 없습니다"}
        if not (username and password):
            return {"ok": True, "stage": "reachable", "detail": f"TCP {p} 연결 가능 (인증 미검증)"}
        try:
            from netmiko import ConnectHandler
            from . import netbind
            device = {"device_type": "paloalto_panos", "ip": host, "username": username,
                      "password": password, "port": p, "conn_timeout": 8, "fast_cli": False}
            if source_ip:
                device["sock"] = netbind.bind_socket(host, p, source_ip, 8)
            with ConnectHandler(**device):
                pass
            return {"ok": True, "stage": "auth", "detail": "연결 및 인증 성공"}
        except Exception as e:
            return {"ok": False, "stage": "auth", "detail": collector._sanitize_error_msg(str(e))}
    return {"ok": False, "stage": "reachable", "detail": f"지원하지 않는 벤더: {vendor}"}
