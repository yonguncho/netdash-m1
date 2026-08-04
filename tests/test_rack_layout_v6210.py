# -*- coding: utf-8 -*-
"""서버실 랙 배치 저장/업데이트 + 높이 저장 실패 하드닝 (v6.21.0).

사용자 신고 2건:
① 랙 높이 저장 시 "TypeError: failed to fetch" — 서버 API는 정상(curl 재현 전
  구간 200). 요청이 도달하기 전 연결이 끊긴 것이라, 멱등 PUT을 1회 자동 재시도
  하고 실패 시 화면을 서버 상태로 복원하게 했다.
② 서버실 현황이 "자동 업데이트되며 삭제"됨 — 랙뷰는 장비 location에서 파생되므로
  장비를 삭제·재등록하면 위치가 같이 사라진다. 배치 스냅샷 보관 + 업데이트 버튼.
"""
from core import db, racklayout


def _seed(p):
    sw = db.save_switch(p, "SW-A", "10.0.0.1", "cisco_ios")
    db.update_switch(p, sw, location="A09U27")
    with db.get_db(p) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, location) VALUES (?,?,?,?)",
                     ("FW-01", "fortigate", "10.0.0.2", "A09U20-U21"))
    with db.get_db(p) as conn:
        conn.execute("INSERT INTO servers (name, ip, location) VALUES (?,?,?)",
                     ("SRV-01", "10.0.0.3", "B01U10"))
    return sw


def test_snapshot_saves_only_rack_locations(temp_db):
    sw = _seed(temp_db)
    db.save_switch(temp_db, "SW-OFFICE", "10.0.0.9", "cisco_ios")
    db.update_switch(temp_db, db.get_switches(temp_db)[-1]["id"], location="3층 사무실")
    n = racklayout.save_snapshot(temp_db)
    assert n == 3, "랙 형식(A09U27)이 아닌 위치는 보관 대상이 아니다"
    keys = {(e["kind"], e["ip"]) for e in racklayout.get_layout(temp_db)}
    assert keys == {("sw", "10.0.0.1"), ("fw", "10.0.0.2"), ("srv", "10.0.0.3")}
    assert sw


def test_restore_revives_location_after_reregistration(temp_db):
    """핵심 시나리오 — 삭제 후 같은 IP로 재등록하면 위치가 되살아난다."""
    sw = _seed(temp_db)
    racklayout.save_snapshot(temp_db)
    db.delete_switch(temp_db, sw)
    sw2 = db.save_switch(temp_db, "SW-A-NEW", "10.0.0.1", "cisco_ios")  # id 바뀜
    assert not (db.get_switch(temp_db, sw2).get("location") or "")
    r = racklayout.restore(temp_db)
    assert len(r["applied"]) == 1 and r["applied"][0]["ip"] == "10.0.0.1"
    assert db.get_switch(temp_db, sw2)["location"] == "A09U27"


def test_restore_does_not_overwrite_moved_devices(temp_db):
    """사용자가 그 사이 옮긴 장비를 보관본이 덮으면 안 된다."""
    sw = _seed(temp_db)
    racklayout.save_snapshot(temp_db)
    db.update_switch(temp_db, sw, location="B02U05")   # 사용자가 이동
    r = racklayout.restore(temp_db)
    assert not r["applied"] and r["kept"] >= 1
    assert db.get_switch(temp_db, sw)["location"] == "B02U05"


def test_ghosts_are_layout_entries_missing_from_live(temp_db):
    sw = _seed(temp_db)
    racklayout.save_snapshot(temp_db)
    db.delete_switch(temp_db, sw)
    g = racklayout.ghosts(temp_db)
    assert len(g) == 1 and g[0]["ip"] == "10.0.0.1" and g[0]["location"] == "A09U27"
    r = racklayout.restore(temp_db)
    assert len(r["ghosts"]) == 1, "복원 결과에도 유령이 보고돼야 한다"


def test_empty_snapshot_replaces_old_one(temp_db):
    """0건 저장도 유효 — 옛 보관본이 몰래 남으면 안 된다."""
    _seed(temp_db)
    racklayout.save_snapshot(temp_db)
    assert len(racklayout.get_layout(temp_db)) == 3
    # 전부 랙에서 뺀 상태로 다시 저장
    for s in db.get_switches(temp_db):
        db.update_switch(temp_db, s["id"], location="")
    with db.get_db(temp_db) as conn:
        conn.execute("UPDATE firewalls SET location=''")
        conn.execute("UPDATE servers SET location=''")
    assert racklayout.save_snapshot(temp_db) == 0
    assert racklayout.get_layout(temp_db) == []


def test_firewall_matched_by_host_column(temp_db):
    """방화벽은 ip가 아니라 host 컬럼이다 — 키 대조가 host로도 되는지."""
    _seed(temp_db)
    racklayout.save_snapshot(temp_db)
    with db.get_db(temp_db) as conn:
        conn.execute("UPDATE firewalls SET location=''")
    r = racklayout.restore(temp_db)
    assert any(a["kind"] == "fw" and a["ip"] == "10.0.0.2" for a in r["applied"])
    assert db.list_firewalls(temp_db)[0]["location"] == "A09U20-U21"


# --- API ---------------------------------------------------------------------

def test_layout_endpoints(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sw = db.save_switch(dbp, "SW-RACK", "10.7.0.1", "cisco_ios")
    db.update_switch(dbp, sw, location="A01U01")
    c = application.test_client()

    r = c.post("/api/room/layout/save").get_json()
    assert r["ok"] is True and r["saved"] >= 1
    r = c.get("/api/room/layout").get_json()
    assert r["ok"] is True and any(e["ip"] == "10.7.0.1" for e in r["layout"])
    assert r["saved_at"]
    r = c.post("/api/room/layout/restore").get_json()
    assert r["ok"] is True and "applied" in r and "ghosts" in r


# --- 화면 --------------------------------------------------------------------

def test_ui_has_save_update_buttons_and_ghost_strip():
    from pathlib import Path
    root = Path(__file__).parent.parent
    html = (root / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="btn-room-save-layout"' in html and 'id="btn-room-update-layout"' in html
    assert "/api/room/layout/save" in js and "/api/room/layout/restore" in js
    assert "_roomGhosts" in js and "보관된 배치에만 있는 장비" in js


def test_rack_save_put_retries_once():
    """높이/위치 저장이 순간 단절에 1회 재시도하고, 실패 시 서버 상태로 복원한다."""
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function _ruSavePut" in js
    assert '_ruSavePut(kind, devId, loc, "높이 저장")' in js
    assert '_ruSavePut(kind, devId, loc, "위치 저장")' in js, \
        "리사이즈·이동 두 경로 모두 공용 저장을 써야 한다"
    assert "attempt(retryLeft - 1)" in js
    assert "저장되지 않았습니다" in js
