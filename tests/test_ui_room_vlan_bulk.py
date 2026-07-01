# -*- coding: utf-8 -*-
"""서버실 랙 파서 + VLAN hostname + 스위치 일괄삭제 + UI 요소 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, serverroom

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


# ─── 서버실 랙 위치 파서 ─────────────────────────────
def test_parse_rack_basic():
    r = serverroom.parse_rack("A09U27")
    assert r["rack"] == "A09" and r["unit"] == 27
    assert "A09" in r["label"] and "27" in r["label"]


def test_parse_rack_variants():
    assert serverroom.parse_rack("b12u4")["rack"] == "B12"
    assert serverroom.parse_rack("b12u4")["unit"] == 4
    assert serverroom.parse_rack(" A01 U 5 ")["unit"] == 5  # 공백 허용


def test_parse_rack_rejects_non_rack():
    assert serverroom.parse_rack("1공장 Assembly") is None
    assert serverroom.parse_rack("") is None
    assert serverroom.parse_rack(None) is None
    assert serverroom.parse_rack("A09") is None       # 유닛 없음
    assert serverroom.parse_rack("U27") is None        # 랙 없음


# ─── 일괄 삭제 ─────────────────────────────
def test_delete_switches_bulk(temp_db):
    a = db.save_switch(temp_db, "SW-A", "10.0.0.1", "cisco_ios")
    b = db.save_switch(temp_db, "SW-B", "10.0.0.2", "cisco_ios")
    c = db.save_switch(temp_db, "SW-C", "10.0.0.3", "cisco_ios")
    n = db.delete_switches_bulk(temp_db, [a, b])
    assert n == 2
    remaining = {s["id"] for s in db.get_switches(temp_db)}
    assert a not in remaining and b not in remaining and c in remaining


def test_delete_switches_bulk_ignores_bad_ids(temp_db):
    a = db.save_switch(temp_db, "SW-A", "10.0.0.1", "cisco_ios")
    n = db.delete_switches_bulk(temp_db, [a, 99999, "x", None])
    assert n == 1


def test_bulk_delete_endpoint(client):
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.5.5.5", "name": "SW-X", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.post("/api/switches/bulk-delete", json={"ids": [sid]})
    assert r.status_code == 200 and r.get_json()["deleted"] == 1
    # 빈 목록은 400
    assert client.post("/api/switches/bulk-delete", json={"ids": []}).status_code == 400


# ─── VLAN 요약에 hostname 포함 ─────────────────────────────
def test_vlan_summary_has_hostname(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.update_switch(temp_db, sid, hostname="TPS-F1B02_1F01_SW1")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [
        {"switch_id": sid, "vlan": 100, "mac": "00:00:00:00:00:01", "port": "Gi1/0/1", "type": "dynamic"}])
    summary = db.get_vlan_summary(temp_db)
    row = [r for r in summary if r["vlan"] == 100][0]
    assert row["switch_hostname"] == "TPS-F1B02_1F01_SW1"


# ─── /api/state 서버실 랙 주입 ─────────────────────────────
def test_state_injects_room_rack(client):
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.6.6.6", "name": "SRV-SW", "vendor": "cisco",
                            "location": "A09U27"}).get_json()["switch_id"]
    switches = client.get("/api/state").get_json()["switches"]
    sw = [s for s in switches if s["id"] == sid][0]
    assert sw["room_rack"] == "A09" and sw["room_unit"] == 27


# ─── UI 요소 존재 ─────────────────────────────
def test_ui_elements_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-tab="room"' in html
    assert 'id="tab-room"' in html
    assert 'id="vlan-accordion"' in html
    assert 'id="sw-check-all"' in html
    assert 'id="btn-sw-bulk-delete"' in html
    assert "<th>구분</th>" in html          # 이름 → 구분
    js = APP_JS.read_text(encoding="utf-8")
    assert "function renderRoom" in js
    assert "function renderVlanAccordion" in js
    assert "/api/switches/bulk-delete" in js
    assert "switch_hostname" in js
