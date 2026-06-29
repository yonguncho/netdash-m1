"""M11 F3: PC 로컬 네트워크 정보(이더넷 IP) 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import netinfo

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"


def test_get_local_ipv4_addresses_returns_list():
    ips = netinfo.get_local_ipv4_addresses()
    assert isinstance(ips, list)
    # 루프백은 제외되어야 함
    assert all(not ip.startswith("127.") for ip in ips)
    # IPv4 형식
    for ip in ips:
        parts = ip.split(".")
        assert len(parts) == 4
        assert all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def test_get_network_info_shape():
    info = netinfo.get_network_info()
    assert "hostname" in info
    assert "local_ips" in info
    assert "primary_ip" in info
    assert isinstance(info["local_ips"], list)
    # primary_ip는 루프백이 아니어야 함(있다면)
    if info["primary_ip"]:
        assert not info["primary_ip"].startswith("127.")


def test_api_netinfo_endpoint(client):
    r = client.get("/api/netinfo")
    assert r.status_code == 200
    data = r.get_json()
    assert "local_ips" in data
    assert "hostname" in data
    assert "primary_ip" in data


def test_index_has_pc_ip_element(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="pc-ip"' in body


def test_appjs_loadnetinfo():
    src = APP_JS.read_text(encoding="utf-8")
    assert "function loadNetInfo" in src
    assert "/api/netinfo" in src
    assert "loadNetInfo()" in src  # 초기화에서 호출
