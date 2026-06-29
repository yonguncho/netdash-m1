# -*- coding: utf-8 -*-
"""M11: PC 로컬 네트워크 정보 조회 (표준 socket만 사용).

장비(스위치/방화벽)에 접근할 때 사용하는 PC 이더넷 IP를 사용자가 인지하도록
로컬 IPv4 주소 목록을 제공한다. (127.0.0.1 루프백은 외부 장비에 도달하지 못함)
"""
import socket
import logging

logger = logging.getLogger(__name__)


def _primary_ip():
    """기본 라우트로 나가는 source IP를 UDP 트릭으로 얻는다(실제 전송 없음)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 사설/임의 대상에 'connect'만 — 패킷 전송 없이 라우팅 결정만 일어남.
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def get_local_ipv4_addresses():
    """PC의 IPv4 주소 목록 반환 (루프백 제외, 정렬).

    Returns: ["192.168.0.10", "10.0.0.5", ...]
    """
    ips = set()

    # 1) hostname 기반 조회
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except (socket.gaierror, OSError) as e:
        logger.info("getaddrinfo failed: %s", e)

    # 2) 기본 라우트 source IP (가장 유력한 '장비 접근용' IP)
    primary = _primary_ip()
    if primary and not primary.startswith("127."):
        ips.add(primary)

    return sorted(ips)


def get_network_info():
    """로컬 네트워크 정보 요약.

    Returns: {"hostname": str, "local_ips": [str], "primary_ip": str|None}
    """
    primary = _primary_ip()
    if primary and primary.startswith("127."):
        primary = None
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = ""
    return {
        "hostname": hostname,
        "local_ips": get_local_ipv4_addresses(),
        "primary_ip": primary,
    }
