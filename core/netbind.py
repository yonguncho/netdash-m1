# -*- coding: utf-8 -*-
"""M12: 출발지(source) IP 바인딩 유틸.

PC에 NIC가 여럿일 때 장비 ACL을 통과하도록, 사용자가 선택한 이더넷 IP를
SSH/REST/TCP 접근의 출발지로 바인딩한다. source_ip가 falsy면 OS 기본 라우팅.
"""
import socket
import logging

logger = logging.getLogger(__name__)


def bind_socket(host, port, source_ip=None, timeout=10):
    """source_ip로 바인딩된 TCP socket 반환 (netmiko의 sock 인자용).

    source_ip가 없으면 일반 create_connection.
    """
    src = (source_ip, 0) if source_ip else None
    return socket.create_connection((host, int(port)), timeout=timeout, source_address=src)


def requests_session(source_ip=None, verify=False):
    """source_ip로 바인딩된 requests.Session 반환 (FortiGate REST용)."""
    import requests
    s = requests.Session()
    s.verify = verify
    if source_ip:
        from requests.adapters import HTTPAdapter
        try:
            from urllib3.poolmanager import PoolManager
        except ImportError:  # 일부 환경
            from requests.packages.urllib3.poolmanager import PoolManager

        class _SourceAdapter(HTTPAdapter):
            def init_poolmanager(self, connections, maxsize, block=False, **kw):
                self.poolmanager = PoolManager(
                    num_pools=connections, maxsize=maxsize, block=block,
                    source_address=(source_ip, 0), **kw)

        adapter = _SourceAdapter()
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        logger.info("requests source bind to %s", source_ip)
    return s
