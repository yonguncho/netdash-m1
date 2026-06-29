"""M10 2단계: 방화벽 API 엔드포인트 테스트 (네트워크는 mock)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import firewall as fw_mod


def test_add_firewall(client):
    r = client.post("/api/firewalls",
                    json={"vendor": "fortigate", "host": "10.0.0.1", "name": "FW1", "port": 443})
    assert r.status_code == 201
    assert r.get_json()["ok"] is True


def test_add_firewall_bad_vendor(client):
    r = client.post("/api/firewalls", json={"vendor": "checkpoint", "host": "10.0.0.1"})
    assert r.status_code == 400


def test_add_firewall_missing_host(client):
    r = client.post("/api/firewalls", json={"vendor": "fortigate"})
    assert r.status_code == 400


def test_list_firewalls(client):
    client.post("/api/firewalls", json={"vendor": "paloalto", "host": "10.0.0.2", "name": "PA1"})
    r = client.get("/api/firewalls")
    assert r.status_code == 200
    assert any(f["host"] == "10.0.0.2" for f in r.get_json()["firewalls"])


def test_collect_firewall_success(client, monkeypatch):
    monkeypatch.setattr(fw_mod, "collect_firewall", lambda *a, **k: {
        "interfaces": [{"name": "port1", "ip": "10.0.0.1", "mask": "", "vdom_zone": "root"}],
        "arp": [{"ip": "10.0.0.50", "mac": "AA:BB", "interface": "port1"}],
    })
    fid = client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.3"}).get_json()["firewall_id"]
    r = client.post(f"/api/firewalls/{fid}/collect", json={"token": "x"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["interfaces"] == 1 and body["arp"] == 1
    detail = client.get(f"/api/firewalls/{fid}").get_json()
    assert detail["firewall"]["status"] == "done"
    assert len(detail["interfaces"]) == 1
    assert detail["arp"][0]["mac"] == "AA:BB"


def test_collect_firewall_failure_sets_failed(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("connection refused")
    monkeypatch.setattr(fw_mod, "collect_firewall", boom)
    fid = client.post("/api/firewalls", json={"vendor": "paloalto", "host": "10.0.0.4"}).get_json()["firewall_id"]
    r = client.post(f"/api/firewalls/{fid}/collect", json={"username": "a", "password": "b"})
    assert r.status_code == 502
    detail = client.get(f"/api/firewalls/{fid}").get_json()
    assert detail["firewall"]["status"] == "failed"


def test_collect_firewall_not_found(client):
    r = client.post("/api/firewalls/9999/collect", json={})
    assert r.status_code == 404


def test_get_firewall_not_found(client):
    r = client.get("/api/firewalls/9999")
    assert r.status_code == 404


# ── SSRF 회귀 (Opus R1 critical) ───────────────────────────────────
def test_add_firewall_rejects_string_port(client):
    """C1: port 문자열('443@evil') 거부 — URL 주입 차단."""
    r = client.post("/api/firewalls",
                    json={"vendor": "fortigate", "host": "10.0.0.1", "port": "443@evil.com"})
    assert r.status_code == 400


def test_add_firewall_rejects_out_of_range_port(client):
    r = client.post("/api/firewalls",
                    json={"vendor": "fortigate", "host": "10.0.0.1", "port": 99999})
    assert r.status_code == 400


def test_collect_revalidates_host_ssrf(client):
    """C2: DB에 우회 저장된 공인 IP 방화벽도 collect 시점에 재검증으로 차단."""
    from config import get_config
    from core import db as _db
    db_path = get_config(demo_mode=True).get_db_path()
    # DB 레이어로 직접 공인 IP 저장(엔드포인트 검증 우회 시뮬레이션)
    fid = _db.save_firewall(db_path, "EVIL", "fortigate", "8.8.8.8", 443)
    r = client.post(f"/api/firewalls/{fid}/collect", json={"token": "x"})
    assert r.status_code == 400
    assert "rejected" in r.get_json()["error"]
