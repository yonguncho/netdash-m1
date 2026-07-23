# -*- coding: utf-8 -*-
"""전체 수집(방화벽/서버/설비) 엔드포인트 + 진행률 + 관제 재수집 + 현황판 구역 파싱(소스)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
WALL_JS = ROOT / "web" / "static" / "wall.js"
HTML = ROOT / "web" / "templates" / "index.html"


# ── 진행률 엔드포인트 ───────────────────────────────────────────
def test_server_progress_snapshot():
    p = server_collector.get_progress()
    assert set(["running", "done", "total", "message"]) <= set(p.keys())


def test_servers_collect_all_status_endpoint(client):
    r = client.get("/api/servers/collect-all/status")
    assert r.status_code == 200
    assert "running" in r.get_json()


def test_firewalls_collect_all_status_endpoint(client):
    r = client.get("/api/firewalls/collect-all/status")
    assert r.status_code == 200
    j = r.get_json()
    assert "running" in j and "done" in j and "total" in j


def test_firewalls_collect_all_starts(client):
    r = client.post("/api/firewalls/collect-all")
    assert r.status_code in (202, 409)  # 시작 or 이미 진행 중


# ── 설비 전체 스캔 / 재수집 ─────────────────────────────────────
def test_facility_scan_all_no_bands(client):
    """기억된 대역이 없으면 400."""
    r = client.post("/api/facility/scan-all")
    assert r.status_code == 400
    assert "대역" in r.get_json()["error"]


def test_facility_recollect_unknown_ip(client):
    r = client.post("/api/facility/recollect", json={"ip": "10.99.99.99"})
    assert r.status_code == 400   # 대역 못 찾음


def test_facility_recollect_no_gateway(tmp_path, monkeypatch):
    """설비 IP의 대역은 알지만 게이트웨이가 기억되지 않았으면 400 안내."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_facility_hosts(dbp, [
        {"subnet": "10.11.0.0/24", "ip": "10.11.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0}])
    r = application.test_client().post("/api/facility/recollect", json={"ip": "10.11.0.5"})
    assert r.status_code == 400
    assert "게이트웨이" in r.get_json()["error"]


# ── 프론트 소스 가드 ────────────────────────────────────────────
def test_progressbar_and_zone_helpers_present():
    js = APP_JS.read_text(encoding="utf-8")
    assert "function renderProgressBar" in js
    assert "function pollProgress" in js
    assert "function _hostnameZone" in js
    # 진행바 폴링 배선
    assert "/api/servers/collect-all/status" in js
    assert "/api/firewalls/collect-all/status" in js


def test_hostname_zone_examples_in_source():
    """구역 파싱 정규식이 SKBA_RC_4F_SW1/SKBA_DETROIT_SW1 형식을 다룬다(예시 주석)."""
    js = APP_JS.read_text(encoding="utf-8")
    assert "_SW(?:ITCH)?" in js
    assert "RC_4F" in js and "DETROIT" in js


def test_wall_recollect_button_present():
    wall = WALL_JS.read_text(encoding="utf-8")
    assert "pcard__recollect" in wall
    assert "/api/facility/recollect" in wall


def test_bulk_buttons_and_progress_containers_in_html():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="btn-fac-scan-all"' in html
    assert 'id="btn-firewall-collect-all"' in html
    assert 'id="firewall-progress"' in html
    assert 'id="server-progress"' in html
    assert 'id="diag-progress"' in html


# ── TPS 구역 전원다운 감지 ──────────────────────────────────────
def _mk_zone_switches(dbp):
    a = db.save_switch(dbp, "TPS-A", "10.20.0.1", "cisco_ios")
    b = db.save_switch(dbp, "TPS-B", "10.20.0.2", "cisco_ios")
    db.update_switch(dbp, a, hostname="TPS-F1B02_1F01_SW1")   # 1공장 Assembly(B02) 1층
    db.update_switch(dbp, b, hostname="TPS-F1B02_1F02_SW2")
    return a, b


def test_zone_outage_detected_when_all_down(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector, reachability
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    a, b = _mk_zone_switches(dbp)
    monkeypatch.setattr(reachability, "get_state", lambda: {a: False, b: False})
    data = application.test_client().get("/api/state").get_json()
    zos = data.get("zone_outages") or []
    assert any("Assembly" in z["group"] for z in zos)
    assert len([s for s in data["switches"] if s.get("zone_outage")]) == 2
    # 관제 카테고리
    cats = application.test_client().get("/api/wall").get_json()["categories"]
    zone = [c for c in cats if c["key"] == "zone"][0]
    assert zone["items"] and "전원" in zone["items"][0]["detail"]


def test_zone_outage_not_flagged_when_one_up(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector, reachability
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    a, b = _mk_zone_switches(dbp)
    monkeypatch.setattr(reachability, "get_state", lambda: {a: False, b: True})
    data = application.test_client().get("/api/state").get_json()
    assert not (data.get("zone_outages") or [])   # 한 대라도 살아있으면 정전 아님


def test_zone_outage_ui_present():
    js = APP_JS.read_text(encoding="utf-8")
    assert "_notifyZoneOutages" in js and "zone_outage" in js
    css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert "rack-group--outage" in css and "zone-outage-badge" in css


# ── 행별/서버실 수집 + 진행바 자동숨김(소스 가드) ────────────────
def test_switch_row_collect_button():
    js = APP_JS.read_text(encoding="utf-8")
    assert "data-action='collect-switch'" in js
    assert 'case "collect-switch"' in js


def test_serverroom_cards_collectable():
    js = APP_JS.read_text(encoding="utf-8")
    # 방화벽/서버 카드에 id 부여 + 서버실 그리드에서 클릭 수집 배선
    assert "id='fwcard-" in js and "id='srvcard-" in js
    assert "_openServerCollect" in js
    assert "collectFirewallDirect(f.id)" in js


def test_progress_autohide_present():
    js = APP_JS.read_text(encoding="utf-8")
    assert "_autoHideProgress" in js
    assert "_hideTimer" in js


def test_db_error_banner_ui_present():
    js = APP_JS.read_text(encoding="utf-8")
    assert "showDbErrorBanner" in js and "dberr-banner" in js
    assert "/api/health" in js


# ── 관제 성능: MAC 이력 배치 조회 ───────────────────────────────
def test_get_mac_last_seen_batch(temp_db):
    sid = db.save_switch(temp_db, "SW-L", "10.9.0.11", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid,
                        [{"mac": "AA:BB:CC:DD:EE:01", "port": "Gi1/0/1", "vlan": 10}])
    m = db.get_mac_last_seen(temp_db, ["aabb.ccdd.ee01"])   # 형식 무관
    assert m.get("aabbccddee01", {}).get("switch_name") == "SW-L"
    assert m["aabbccddee01"]["port"] == "Gi1/0/1"
    # want 필터: 관심 밖 MAC만 주면 빈 dict
    assert db.get_mac_last_seen(temp_db, ["00:00:00:00:00:99"]) == {}


def test_facility_list_injects_history(tmp_path, monkeypatch):
    """오프라인·연결미확인 설비에 과거 스냅샷 연결 이력(hist_*)이 주입된다."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    # 과거 스냅샷에 이 MAC이 SW-EDGE Gi1/0/7에 있었음
    sid = db.save_switch(dbp, "SW-EDGE", "10.4.0.9", "cisco_ios")
    snap = db.save_snapshot(dbp, sid)
    db.save_mac_entries(dbp, snap, sid, [{"mac": "CC:CC:CC:00:00:77", "port": "Gi1/0/7", "vlan": 5}])
    # 위치 미확인 설비 2건: 오프라인 + 온라인(둘 다 과거 이력 주입돼야 함)
    db.save_facility_hosts(dbp, [
        {"subnet": "10.4.0.0/24", "ip": "10.4.0.77", "mac": "CC:CC:CC:00:00:77",
         "switch_name": "", "port": "", "online": 0},
        {"subnet": "10.4.0.0/24", "ip": "10.4.0.78", "mac": "CC:CC:CC:00:00:77",
         "switch_name": "", "port": "", "online": 1}])
    hosts = application.test_client().get("/api/facility").get_json()["hosts"]
    by_ip = {x["ip"]: x for x in hosts}
    assert by_ip["10.4.0.77"].get("hist_switch") == "SW-EDGE"      # 오프라인
    assert by_ip["10.4.0.78"].get("hist_switch") == "SW-EDGE"      # 온라인 미확인도


def test_wall_uses_batch_mac_lookup():
    """/api/wall 요약이 호스트별 find_mac_history가 아니라 배치(get_mac_last_seen)를 쓴다."""
    import inspect
    import app as _app
    src = inspect.getsource(_app.create_app)
    assert "get_mac_last_seen" in src
    # 오프라인 설비마다 find_mac_history를 부르는 패턴은 제거됨
    assert "db.find_mac_history(db_path, h.get" not in src


# ── 방화벽 수집 오류 시 JSON 응답 + 잠금 해제(영구 409 방지) ─────
def test_firewall_collect_error_frees_lock(client, monkeypatch):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    fid = db.save_firewall(dbp, "FW-T", "fortigate", "10.7.7.7", 443)
    from core import firewall as fwmod

    def boom(*a, **k):
        raise RuntimeError("collect failed")

    monkeypatch.setattr(fwmod, "collect_firewall", boom)
    r1 = client.post("/api/firewalls/%d/collect" % fid, json={})
    assert r1.status_code in (502, 503)
    assert r1.get_json() is not None            # HTML 500 아님(→ 프론트 '서버 오류' 방지)
    r2 = client.post("/api/firewalls/%d/collect" % fid, json={})
    assert r2.status_code != 409                 # fid 잔류 없음(영구 409 아님)


# ── DB 오류 상세 힌트 ───────────────────────────────────────────
def test_db_error_hint_classifies():
    import sqlite3
    h1 = db.db_error_hint(sqlite3.OperationalError("unable to open database file"), r"\\srv\share\netdash.db")
    assert "열 수 없" in h1["reason"] and h1["hint"]
    h2 = db.db_error_hint(sqlite3.OperationalError("database is locked"))
    assert "잠금" in h2["reason"]
    h3 = db.db_error_hint(sqlite3.OperationalError("disk I/O error"))
    assert "입출력" in h3["reason"]


def test_health_endpoint_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_state_returns_db_error_detail(client, monkeypatch):
    """DB 접근 실패 시 /api/state가 원인/힌트를 담아 503 반환."""
    import sqlite3
    from core import db as dbmod
    def boom(dbp):
        dbmod._record_db_error(dbmod.db_error_hint(
            sqlite3.OperationalError("unable to open database file"), dbp))
        raise sqlite3.OperationalError("unable to open database file")
    monkeypatch.setattr(dbmod, "get_switches", boom)
    r = client.get("/api/state")
    assert r.status_code == 503
    j = r.get_json()
    assert j["error"] == "db_error" and j["db_error"]["reason"]
    assert j["db_error"]["hint"]


# ── DB 회복력(재시도) ───────────────────────────────────────────
def test_get_db_retries_transient_open_error(temp_db, monkeypatch):
    import sqlite3
    real = db._open_conn
    calls = {"n": 0}

    def flaky(p):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("unable to open database file")
        return real(p)

    monkeypatch.setattr(db, "_open_conn", flaky)
    with db.get_db(temp_db) as conn:      # 첫 시도 실패 → 재시도 성공
        conn.execute("SELECT 1")
    assert calls["n"] >= 2


# ── 관제 설비 실패 스위치별 요약(+위치) ────────────────────────
def test_wall_facility_switch_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    # 연결 스위치 등록(위치 파악용 — hostname 구역 RC_4F)
    sa = db.save_switch(dbp, "SW-A", "10.1.0.11", "cisco_ios")
    db.update_switch(dbp, sa, hostname="SKBA_RC_4F_SW1")
    db.save_switch(dbp, "SW-B", "10.2.0.11", "cisco_ios")
    hosts = []
    for i in range(5):
        hosts.append({"subnet": "10.1.0.0/24", "ip": "10.1.0.%d" % (i + 1),
                      "mac": "AA:00:00:00:01:%02d" % i, "switch_name": "SW-A", "port": "Gi1/0/%d" % i,
                      "direct": 1, "online": 0})
    for i in range(3):
        hosts.append({"subnet": "10.2.0.0/24", "ip": "10.2.0.%d" % (i + 1),
                      "mac": "BB:00:00:00:02:%02d" % i, "switch_name": "SW-B", "port": "Gi1/0/%d" % i,
                      "direct": 1, "online": 0})
    db.save_facility_hosts(dbp, hosts)
    cats = application.test_client().get("/api/wall").get_json()["categories"]
    fac = [c for c in cats if c["key"] == "facility"][0]
    assert fac["total"] == 8
    summ = {s["switch"]: s for s in fac["summary"]}
    assert summ["SW-A"]["count"] == 5 and summ["SW-B"]["count"] == 3
    assert summ["SW-A"]["location"] == "RC_4F"          # hostname 구역 위치
    assert fac["summary"][0]["count"] >= fac["summary"][-1]["count"]   # 내림차순
    # 각 항목에 연결 스위치(switch) 필드 — 관제 칩 클릭 필터용
    assert all("switch" in it for it in fac["items"])
    assert {it["switch"] for it in fac["items"]} == {"SW-A", "SW-B"}


def test_wall_chip_filter_ui_present():
    wall = WALL_JS.read_text(encoding="utf-8")
    assert "renderProblems" in wall and "wallFacFilter" in wall
    assert "wall-sumchip--click" in wall and "data-fswitch" in wall


def test_wall_summary_ui_present():
    wall = WALL_JS.read_text(encoding="utf-8")
    assert "wall-sumchip" in wall and "wall-cat__summary" in wall
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    assert "overflow-y: auto" in css and "wall-sumchip" in css
