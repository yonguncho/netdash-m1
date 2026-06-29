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
    r = client.post("/api/switches/test", json={"ip": "8.8.8.8", "username": "a", "password": "b"})
    assert r.status_code == 400  # 공인 IP 차단


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
