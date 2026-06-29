"""M11+: 스위치/방화벽 삭제 기능 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


# ── DB 레이어 ──────────────────────────────────────────────────────
def test_delete_switch_db(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    assert db.delete_switch(temp_db, sid) is True
    assert db.get_switch(temp_db, sid) is None
    # 없는 id 삭제 → False
    assert db.delete_switch(temp_db, 9999) is False


def test_delete_switch_cleans_related(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_ports(temp_db, snap, sid, [{"name": "Gi1", "status": "up"}])
    # hosts: 측정 위치 보유
    db.save_hosts(temp_db, {"10.0.1.5": {"mac": "aa", "switch_id": sid, "port": "Gi1", "located": True}})
    db.delete_switch(temp_db, sid)
    # 스냅샷/포트 정리됨
    assert db.latest_snapshot_id(temp_db, sid) is None
    # hosts는 보존되되 위치 무효화
    rows = {h["ip"]: h for h in db.list_hosts(temp_db)}
    assert rows["10.0.1.5"]["switch_id"] is None
    assert rows["10.0.1.5"]["located"] == 0


def test_delete_firewall_db(temp_db):
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.2", 443)
    db.save_firewall_interfaces(temp_db, fid, [{"name": "port1", "ip": "10.0.0.2"}])
    db.save_firewall_arp(temp_db, fid, [{"ip": "10.0.1.1", "mac": "aa", "interface": "port1"}])
    assert db.delete_firewall(temp_db, fid) is True
    assert db.get_firewall(temp_db, fid) is None
    assert db.get_firewall_interfaces(temp_db, fid) == []
    assert db.get_firewall_arp(temp_db, fid) == []
    assert db.delete_firewall(temp_db, 9999) is False


# ── 엔드포인트 ─────────────────────────────────────────────────────
def test_api_delete_switch(client):
    sid = client.post("/api/switches/manual", json={"ip": "10.0.0.5", "name": "SW", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.delete(f"/api/switches/{sid}")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    # 재삭제 → 404
    assert client.delete(f"/api/switches/{sid}").status_code == 404


def test_api_delete_firewall(client):
    fid = client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.6", "name": "FW"}).get_json()["firewall_id"]
    r = client.delete(f"/api/firewalls/{fid}")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    assert client.delete(f"/api/firewalls/{fid}").status_code == 404
