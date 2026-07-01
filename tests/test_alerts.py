# -*- coding: utf-8 -*-
"""장비 변경/알람 이벤트 — 저장·조회·확인 + 설비 스캔 diff(새/오프라인/복구)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility


# ─── 이벤트 저장/조회/확인 ─────────────────────────────
def test_event_save_list_count_ack(temp_db):
    db.save_device_event(temp_db, "new_device", "warning", subnet="10.0.0.0/24",
                         ip="10.0.0.5", message="새 설비")
    db.save_device_event(temp_db, "switch_unreachable", "warning", switch_id=1,
                         label="SW1", message="연결 실패")
    assert db.count_unacked_events(temp_db) == 2
    evs = db.list_device_events(temp_db)
    assert len(evs) == 2 and evs[0]["kind"] == "switch_unreachable"  # 최신순
    # 전체 확인
    assert db.ack_device_events(temp_db) == 2
    assert db.count_unacked_events(temp_db) == 0


def test_event_ack_by_ids(temp_db):
    db.save_device_event(temp_db, "new_device")
    db.save_device_event(temp_db, "new_device")
    ev = db.list_device_events(temp_db)[0]
    assert db.ack_device_events(temp_db, [ev["id"]]) == 1
    assert db.count_unacked_events(temp_db) == 1


# ─── 설비 스캔 diff ─────────────────────────────
def test_apply_scan_new_and_offline(temp_db):
    subnet = "10.9.0.0/24"
    # 1차: A, B 온라인
    db.save_facility_hosts(temp_db, [
        {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa", "online": 1},
        {"subnet": subnet, "ip": "10.9.0.11", "mac": "bb", "online": 1}])
    # 2차 스캔: B는 사라지고(오프라인), C가 새로 등장
    by_ip = {
        "10.9.0.10": {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa", "online": 1},
        "10.9.0.12": {"subnet": subnet, "ip": "10.9.0.12", "mac": "cc", "online": 1},
    }
    saved, new_cnt, off_cnt = facility._apply_scan(temp_db, subnet, by_ip)
    assert new_cnt == 1 and off_cnt == 1
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.9.0.11"]["online"] == 0     # 삭제 안 되고 오프라인으로 유지
    assert hosts["10.9.0.12"]["online"] == 1     # 새 설비
    kinds = [e["kind"] for e in db.list_device_events(temp_db)]
    assert "new_device" in kinds and "device_offline" in kinds


def test_apply_scan_recovery(temp_db):
    subnet = "10.9.0.0/24"
    db.save_facility_hosts(temp_db, [
        {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa", "online": 0}])  # 오프라인 상태
    by_ip = {"10.9.0.10": {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa", "online": 1}}
    facility._apply_scan(temp_db, subnet, by_ip)
    kinds = [e["kind"] for e in db.list_device_events(temp_db)]
    assert "device_online" in kinds
    assert db.get_facility_hosts(temp_db)[0]["online"] == 1


# ─── API ─────────────────────────────
def test_alerts_api(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_device_event(dbp, "new_device", "warning", ip="10.0.0.9", message="x")
    r = client.get("/api/alerts")
    b = r.get_json()
    assert b["unacked"] >= 1 and any(e["kind"] == "new_device" for e in b["events"])
    r2 = client.post("/api/alerts/ack", json={})
    assert r2.get_json()["ok"]
    assert client.get("/api/alerts").get_json()["unacked"] == 0


def test_alerts_ui_present():
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="btn-alerts"' in html and 'id="modal-alerts"' in html
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "/api/alerts" in js and "function loadAlerts" in js
