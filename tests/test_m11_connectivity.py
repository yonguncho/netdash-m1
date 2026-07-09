"""M11 F1: 연결 테스트 (선검증) 테스트. 네트워크는 mock."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import connectivity


# ── 코어 ───────────────────────────────────────────────────────────
def test_switch_unreachable(monkeypatch):
    monkeypatch.setattr(connectivity, "test_tcp", lambda *a, **k: False)
    res = connectivity.test_switch("10.0.0.1", "cisco", "admin", "pw")
    assert res["ok"] is False
    assert res["stage"] == "reachable"


def test_switch_reachable_no_creds(monkeypatch):
    monkeypatch.setattr(connectivity, "test_tcp", lambda *a, **k: True)
    res = connectivity.test_switch("10.0.0.1", "cisco", "", "")
    assert res["ok"] is True
    assert res["stage"] == "reachable"  # 인증 미검증


def test_firewall_fortigate_unreachable(monkeypatch):
    monkeypatch.setattr(connectivity, "test_tcp", lambda *a, **k: False)
    res = connectivity.test_firewall("fortigate", "10.0.0.2", 443, token="x")
    assert res["ok"] is False
    assert res["stage"] == "reachable"


def test_firewall_unsupported_vendor():
    res = connectivity.test_firewall("checkpoint", "10.0.0.3")
    assert res["ok"] is False


# ── 엔드포인트 ─────────────────────────────────────────────────────
def test_api_switch_test_endpoint(client, monkeypatch):
    monkeypatch.setattr(connectivity, "test_switch",
                        lambda *a, **k: {"ok": True, "stage": "auth", "detail": "ok"})
    r = client.post("/api/switches/test",
                    json={"ip": "10.0.0.1", "vendor": "cisco", "username": "a", "password": "b"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_api_switch_test_ssrf(client):
    # 정책: 공인 IP는 허용(도달성으로 판단), 위험 대역(루프백/링크로컬 등)만 차단
    r = client.post("/api/switches/test", json={"ip": "127.0.0.1", "username": "a", "password": "b"})
    assert r.status_code == 400  # 루프백 차단


def test_public_ip_allowed_without_whitelist():
    """정적 화이트리스트 없으면 공인 IP 허용, 위험 대역만 차단."""
    import pytest
    from app import validate_ipv4
    assert validate_ipv4("208.97.24.195", None) == "208.97.24.195"   # 공인 허용
    assert validate_ipv4("208.97.24.195", []) == "208.97.24.195"     # 빈 목록도 허용
    with pytest.raises(ValueError):
        validate_ipv4("127.0.0.1", [])                                # 루프백 차단
    with pytest.raises(ValueError):
        validate_ipv4("169.254.169.254", [])                          # 링크로컬(메타데이터) 차단


def test_alarm_messages_include_ip():
    """알람/변경 이벤트 메시지에 이름+IP 표기(사용자가 장비를 즉시 특정)."""
    from pathlib import Path
    reach = (Path(__file__).parent.parent / "core" / "reachability.py").read_text(encoding="utf-8")
    assert 'sw_disp = "%s (%s)"' in reach          # 스위치: 이름 (IP)
    assert 'fw_disp = "%s (%s)"' in reach          # 방화벽: 이름 (host)
    coll = (Path(__file__).parent.parent / "core" / "collector.py").read_text(encoding="utf-8")
    assert 'sw_disp = ("%s (%s)"' in coll          # 수집 알람(복구/실패/설정변경/루프)도 IP 포함
    assert '"스위치 복구: " + sw_disp' in coll


def test_is_reachable_gate(monkeypatch):
    """등록 게이트: TCP 또는 ICMP 중 하나라도 응답하면 도달 가능."""
    from core import collector
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: False)
    monkeypatch.setattr(collector, "_icmp_ping", lambda *a, **k: False)
    assert collector.is_reachable("208.97.24.195") is False
    monkeypatch.setattr(collector, "_icmp_ping", lambda *a, **k: True)
    assert collector.is_reachable("208.97.24.195") is True


def test_api_firewall_test_endpoint(client, monkeypatch):
    monkeypatch.setattr(connectivity, "test_firewall",
                        lambda *a, **k: {"ok": True, "stage": "auth", "detail": "ok"})
    r = client.post("/api/firewalls/test",
                    json={"vendor": "fortigate", "host": "10.0.0.2", "token": "x"})
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_api_firewall_test_bad_vendor(client):
    r = client.post("/api/firewalls/test", json={"vendor": "checkpoint", "host": "10.0.0.2"})
    assert r.status_code == 400
