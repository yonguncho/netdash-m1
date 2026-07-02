# -*- coding: utf-8 -*-
"""v3.28 모니터링 스위트: 도달성 감시·알람 보존/필터·설비 이동·자동 스캔·config 백업."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility, reachability

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


# ─── 도달성 감시 ─────────────────────────────
def test_reachability_transition_events(temp_db, monkeypatch):
    """도달→불가 전이에서 이벤트 1회, 첫 관측은 이벤트 없음."""
    sid = db.save_switch(temp_db, "SW-R", "10.0.0.99", "cisco_ios")
    reachability._state.clear()
    results = {"ok": True}
    monkeypatch.setattr(reachability, "_check_tcp", lambda ip, port=22, timeout=3: results["ok"])
    reachability._sweep(temp_db)                       # 첫 관측(도달) → 이벤트 없음
    assert db.count_unacked_events(temp_db) == 0
    results["ok"] = False
    reachability._sweep(temp_db)                       # 도달→불가 → 이벤트 1
    evs = db.list_device_events(temp_db)
    assert len(evs) == 1 and evs[0]["kind"] == "switch_unreachable"
    reachability._sweep(temp_db)                       # 불가 유지 → 추가 이벤트 없음
    assert len(db.list_device_events(temp_db)) == 1
    results["ok"] = True
    reachability._sweep(temp_db)                       # 복구 → recovered
    kinds = [e["kind"] for e in db.list_device_events(temp_db)]
    assert "switch_recovered" in kinds
    reachability._state.clear()


# ─── 알람 보존/필터 ─────────────────────────────
def test_purge_old_events(temp_db):
    db.save_device_event(temp_db, "new_device", message="recent")
    # 과거 이벤트 주입
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO device_events (ts, kind, message) "
                     "VALUES (datetime('now', '-100 days'), 'new_device', 'old')")
    assert db.purge_device_events(temp_db, 90) == 1
    evs = db.list_device_events(temp_db)
    assert len(evs) == 1 and evs[0]["message"] == "recent"


def test_list_events_filters(temp_db):
    db.save_device_event(temp_db, "new_device", message="a")
    db.save_device_event(temp_db, "device_moved", message="b")
    assert len(db.list_device_events(temp_db, kind="device_moved")) == 1
    assert len(db.list_device_events(temp_db, days=1)) == 2


def test_alerts_api_filters(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_device_event(dbp, "device_moved", message="mv")
    r = client.get("/api/alerts?kind=device_moved&days=1")
    b = r.get_json()
    assert all(e["kind"] == "device_moved" for e in b["events"])


# ─── 설비 이동 감지 ─────────────────────────────
def test_apply_scan_detects_move(temp_db):
    subnet = "10.9.0.0/24"
    db.save_facility_hosts(temp_db, [
        {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa:bb", "online": 1,
         "direct": 1, "switch_name": "SW-A", "port": "Gi1/0/1"}])
    by_ip = {"10.9.0.10": {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa:bb", "online": 1,
                           "direct": 1, "switch_name": "SW-B", "port": "Gi1/0/9", "switch_id": 2}}
    facility._apply_scan(temp_db, subnet, by_ip)
    evs = db.list_device_events(temp_db, kind="device_moved")
    assert len(evs) == 1 and "SW-A" in evs[0]["message"] and "SW-B" in evs[0]["message"]


def test_apply_scan_no_move_event_same_port(temp_db):
    subnet = "10.9.0.0/24"
    db.save_facility_hosts(temp_db, [
        {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa:bb", "online": 1,
         "direct": 1, "switch_name": "SW-A", "port": "Gi1/0/1"}])
    by_ip = {"10.9.0.10": {"subnet": subnet, "ip": "10.9.0.10", "mac": "aa:bb", "online": 1,
                           "direct": 1, "switch_name": "SW-A", "port": "Gi1/0/1", "switch_id": 1}}
    facility._apply_scan(temp_db, subnet, by_ip)
    assert db.list_device_events(temp_db, kind="device_moved") == []


# ─── 자동 스캔 대역 기억 ─────────────────────────────
def test_remember_band_map(temp_db):
    facility.remember_band(temp_db, "10.1.0.0/24", 3)
    facility.remember_band(temp_db, "10.2.0.0/24", 5)
    m = facility.get_band_map(temp_db)
    assert m == {"10.1.0.0/24": 3, "10.2.0.0/24": 5}


# ─── config 백업 + 변경 감지 ─────────────────────────────
def test_config_backup_change_detection(temp_db):
    sid = db.save_switch(temp_db, "SW-C", "10.0.0.7", "cisco_ios")
    c1 = "hostname SW-C\ninterface Gi1/0/1\n description uplink"
    changed, first = db.save_config_backup(temp_db, sid, c1)
    assert changed and first
    # 동일 config(휘발성 라인만 다름) → 변경 아님
    c1b = "Current configuration : 999 bytes\n" + c1
    changed, first = db.save_config_backup(temp_db, sid, c1b)
    assert not changed
    # 실제 변경 → changed, not first
    c2 = c1 + "\ninterface Gi1/0/2\n shutdown"
    changed, first = db.save_config_backup(temp_db, sid, c2)
    assert changed and not first
    backups = db.get_config_backups(temp_db, sid)
    assert len(backups) == 2
    content = db.get_config_backup_content(temp_db, backups[0]["id"])
    assert "Gi1/0/2" in content["content"]


def test_config_api(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SW-API", "10.0.0.71", "cisco_ios")
    db.save_config_backup(dbp, sid, "hostname SW-API")
    r = client.get("/api/switches/%d/configs" % sid)
    backups = r.get_json()["backups"]
    assert len(backups) >= 1
    r2 = client.get("/api/configs/%d" % backups[0]["id"])
    assert r2.status_code == 200 and b"SW-API" in r2.data


# ─── 설정 API 확장 ─────────────────────────────
def test_auto_collect_settings_extended(client):
    r = client.post("/api/settings/auto_collect", json={
        "enabled": True, "times": "06:00", "facility_enabled": True,
        "facility_time": "07:30", "retention_days": 30, "reach_enabled": False})
    assert r.get_json()["ok"]
    g = client.get("/api/settings/auto_collect").get_json()
    assert g["facility_enabled"] is True and g["facility_time"] == "07:30"
    assert g["retention_days"] == "30" and g["reach_enabled"] is False


# ─── UI ─────────────────────────────
def test_monitoring_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="ac-fac-enabled"' in html and 'id="ac-retention"' in html
    assert 'id="alert-filter-kind"' in html and 'id="alert-filter-days"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "device_moved" in js and "config_changed" in js
    assert "도달불가" in js
