"""스위치 메모(note) 기능 + 이벤트 로그 탭 제거 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
HTML = ROOT / "web" / "templates" / "index.html"


def test_update_and_get_note(temp_db):
    sid = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    db.update_switch(temp_db, sid, note="점검 완료 2026-06")
    assert db.get_switch(temp_db, sid)["note"] == "점검 완료 2026-06"
    # 빈 메모(비우기)
    db.update_switch(temp_db, sid, note="")
    assert db.get_switch(temp_db, sid)["note"] == ""
    # None이면 변경 안 함
    db.update_switch(temp_db, sid, note="유지")
    db.update_switch(temp_db, sid, name="SW2")
    assert db.get_switch(temp_db, sid)["note"] == "유지"


def test_manual_add_with_note(client):
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.0.0.5", "name": "SW", "vendor": "cisco",
                            "note": "초기 메모"}).get_json()["switch_id"]
    s = next(x for x in client.get("/api/state").get_json()["switches"] if x["id"] == sid)
    assert s.get("note") == "초기 메모"


def test_api_update_note(client):
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.0.0.6", "name": "SW", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.put("/api/switches/%d" % sid, json={"note": "수정 메모"})
    assert r.status_code == 200
    s = next(x for x in client.get("/api/state").get_json()["switches"] if x["id"] == sid)
    assert s["note"] == "수정 메모"


def test_note_ui_present():
    js = APP_JS.read_text(encoding="utf-8")
    assert "add-note" in js
    html = HTML.read_text(encoding="utf-8")
    assert 'id="add-note"' in html


def test_events_tab_removed():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-dtab="events"' not in html
    assert 'id="dtab-events"' not in html
