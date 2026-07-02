# -*- coding: utf-8 -*-
"""v3.30: 월보드 + 접근(감사) 로그 + 포트 이력 테스트."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
HTML = ROOT / "web" / "templates" / "index.html"


# ─── 접근 로그 ─────────────────────────────
def test_audit_save_and_list(temp_db):
    db.save_audit(temp_db, "10.0.0.5", "수집 실행", target="/api/switches/1/collect", method="POST")
    logs = db.list_audit(temp_db)
    assert len(logs) == 1
    assert logs[0]["client_ip"] == "10.0.0.5" and logs[0]["action"] == "수집 실행"


def test_audit_recorded_on_mutating_request(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    before = len(db.list_audit(dbp))
    client.post("/api/switches/manual", json={"ip": "10.44.0.1", "name": "AUD-SW", "vendor": "cisco"})
    logs = db.list_audit(dbp)
    assert len(logs) > before
    assert any(l["action"] == "스위치 등록" for l in logs)


def test_audit_not_recorded_on_polling(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    before = len(db.list_audit(dbp))
    client.get("/api/state")
    client.get("/api/alerts")
    assert len(db.list_audit(dbp)) == before  # 조회 폴링은 기록 안 함


def test_audit_api(client):
    r = client.get("/api/audit")
    assert r.status_code == 200 and "logs" in r.get_json()


# ─── 포트 이력 ─────────────────────────────
def test_port_history_tracks_changes(temp_db):
    sid = db.save_switch(temp_db, "SW-H", "10.0.0.8", "cisco_ios")
    s1 = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, s1, sid, [
        {"vlan": 1, "mac": "aa:aa:aa:aa:aa:01", "port": "Gi1/0/5", "type": "dynamic"}])
    time.sleep(1.1)  # collected_at 초 단위 차이 확보
    s2 = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, s2, sid, [
        {"vlan": 1, "mac": "bb:bb:bb:bb:bb:02", "port": "Gi1/0/5", "type": "dynamic"}])  # 교체됨
    hist = db.get_port_history(temp_db, sid, port="Gi1/0/5")
    by = {h["mac"]: h for h in hist}
    assert by["aa:aa:aa:aa:aa:01"]["current"] == 0   # 뽑힘(과거)
    assert by["bb:bb:bb:bb:bb:02"]["current"] == 1   # 현재 연결
    assert by["aa:aa:aa:aa:aa:01"]["seen_count"] == 1


def test_port_history_api(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SW-H2", "10.0.0.81", "cisco_ios")
    snap = db.save_snapshot(dbp, sid)
    db.save_mac_entries(dbp, snap, sid, [
        {"vlan": 1, "mac": "cc:cc:cc:cc:cc:03", "port": "Gi1/0/7", "type": "dynamic"}])
    r = client.get("/api/switches/%d/port-history?port=Gi1/0/7" % sid)
    h = r.get_json()["history"]
    assert len(h) == 1 and h[0]["mac"] == "cc:cc:cc:cc:cc:03"


# ─── 월보드 ─────────────────────────────
def test_wall_page(client):
    r = client.get("/wall")
    assert r.status_code == 200
    assert "NetDash 관제".encode("utf-8") in r.data
    assert b"/static/wall.js" in r.data


def test_wall_data_api(client):
    r = client.get("/api/wall")
    b = r.get_json()
    for key in ("total_switches", "unreachable", "failed", "problems", "recent_events", "unacked_alerts"):
        assert key in b


# ─── config 일괄 다운로드(ZIP) ─────────────────────────────
def test_configs_export_all(client):
    import io
    import zipfile
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    s1 = db.save_switch(dbp, "ZIP-SW1", "10.55.0.1", "cisco_ios")
    s2 = db.save_switch(dbp, "ZIP-SW2", "10.55.0.2", "cisco_ios")
    db.save_config_backup(dbp, s1, "hostname ZIP-SW1")
    db.save_config_backup(dbp, s2, "hostname ZIP-SW2")
    r = client.get("/api/configs/export-all")
    assert r.status_code == 200
    assert "zip" in r.headers.get("Content-Type", "")
    zf = zipfile.ZipFile(io.BytesIO(r.data))
    names = zf.namelist()
    assert any("ZIP-SW1" in n for n in names) and any("ZIP-SW2" in n for n in names)
    assert b"hostname ZIP-SW1" in zf.read([n for n in names if "ZIP-SW1" in n][0])


# ─── UI ─────────────────────────────
def test_new_ui_elements():
    html = HTML.read_text(encoding="utf-8")
    assert 'href="/wall"' in html
    assert 'id="btn-audit"' in html and 'id="modal-audit"' in html
    assert 'data-dtab="history"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "function loadPortHistory" in js and "/api/audit" in js
    # 월보드 정적 파일 존재
    assert (ROOT / "web" / "static" / "wall.js").exists()
    assert (ROOT / "web" / "static" / "wall.css").exists()
    assert (ROOT / "web" / "templates" / "wall.html").exists()
