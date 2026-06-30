"""M12: 출발지 IP 바인딩 + 설정 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, netbind, netinfo, connectivity

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"


# ── DB 설정 ────────────────────────────────────────────────────────
def test_set_get_setting(temp_db):
    assert db.get_setting(temp_db, "source_ip") is None
    db.set_setting(temp_db, "source_ip", "192.168.1.50")
    assert db.get_setting(temp_db, "source_ip") == "192.168.1.50"
    # upsert
    db.set_setting(temp_db, "source_ip", "10.0.0.9")
    assert db.get_setting(temp_db, "source_ip") == "10.0.0.9"
    # 빈값(해제)
    db.set_setting(temp_db, "source_ip", "")
    assert db.get_setting(temp_db, "source_ip") == ""


# ── netbind ────────────────────────────────────────────────────────
def test_requests_session_no_source():
    s = netbind.requests_session(None, verify=False)
    assert s.verify is False


def test_bind_socket_invalid_source_raises():
    # 존재하지 않는 source IP로 바인딩 시 OSError (실제 연결 전 bind 단계)
    with pytest.raises(OSError):
        netbind.bind_socket("10.255.255.255", 9, "203.0.113.123", timeout=2)


# ── connectivity source_ip 전달 ────────────────────────────────────
def test_test_tcp_with_source_unreachable():
    # 잘못된 source로는 연결 실패(False) — 예외 없이 처리
    assert connectivity.test_tcp("10.255.255.255", 9, timeout=2, source_ip="203.0.113.123") is False


# ── 설정 API ───────────────────────────────────────────────────────
def test_api_set_source_ip_rejects_foreign(client):
    # PC 이더넷 IP 목록에 없는 임의 IP는 거부
    r = client.post("/api/settings/source_ip", json={"ip": "203.0.113.50"})
    assert r.status_code == 400


def test_api_set_source_ip_empty_ok(client):
    # 빈값(자동)은 허용
    r = client.post("/api/settings/source_ip", json={"ip": ""})
    assert r.status_code == 200
    assert r.get_json()["source_ip"] == ""


def test_api_set_source_ip_local_ok(client):
    ips = netinfo.get_local_ipv4_addresses()
    if not ips:
        pytest.skip("로컬 IPv4 없음")
    r = client.post("/api/settings/source_ip", json={"ip": ips[0]})
    assert r.status_code == 200
    assert r.get_json()["source_ip"] == ips[0]


def test_api_netinfo_includes_source_ip(client):
    r = client.get("/api/netinfo")
    assert r.status_code == 200
    assert "source_ip" in r.get_json()


def test_appjs_source_select():
    src = APP_JS.read_text(encoding="utf-8")
    assert "source-ip-select" in src
    assert "/api/settings/source_ip" in src


def test_test_switch_response_includes_source_ip(client):
    """연결 테스트 응답에 실제 사용한 출발지 IP가 포함돼야(화면 표시용)."""
    r = client.post("/api/switches/test", json={"ip": "10.0.0.50", "vendor": "cisco"})
    assert "source_ip" in r.get_json()


def test_test_switch_uses_configured_source_ip(client):
    """헤더에서 설정한 접근 IP가 연결 테스트 출발지로 반영돼야."""
    ips = netinfo.get_local_ipv4_addresses()
    if not ips:
        pytest.skip("로컬 IPv4 없음")
    client.post("/api/settings/source_ip", json={"ip": ips[0]})
    r = client.post("/api/switches/test", json={"ip": "10.0.0.50", "vendor": "cisco"})
    assert r.get_json().get("source_ip") == ips[0]


def test_appjs_shows_source_ip_note():
    src = APP_JS.read_text(encoding="utf-8")
    assert "출발지" in src
