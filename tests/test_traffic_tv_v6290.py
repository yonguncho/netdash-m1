# -*- coding: utf-8 -*-
"""v6.29.0 — 업링크 트래픽·임계값 알람·위젯 드래그 순서·TV 모드.

사용자 승인 항목(SNMP 연동 전제): ① IF-MIB 64bit 카운터 델타로 업링크 bps 추이
② CPU/MEM/세션 임계 초과 알람(히스테리시스) ③ 편집 모드 카드 드래그 재배치
④ TV 관제 모드(탭 로테이션 + 알람 탭 점프).
"""
from pathlib import Path

from core import db, metrics_poller

ROOT = Path(__file__).parent.parent


# --- bps 계산(순수 함수) ------------------------------------------------------

def test_compute_bps_baseline_then_delta():
    prev = {}
    # 첫 관측 — 기준선만, 점 없음
    assert metrics_poller.compute_bps(prev, {"Gi1/0/1": (1000, 2000)}, 100.0) == {}
    # 300초 후 in +3000000 octets → 3000000*8/300 = 80000 bps
    out = metrics_poller.compute_bps(prev, {"Gi1/0/1": (3001000, 302000)}, 400.0)
    assert out["Gi1/0/1"] == (80000, 8000)
    assert prev["Gi1/0/1"] == (400.0, 3001000, 302000)


def test_compute_bps_counter_reset_skipped():
    """장비 재부팅으로 카운터가 줄면 그 점은 버린다 — 가짜 스파이크 금지."""
    prev = {"Gi1/0/1": (100.0, 999999, 999999)}
    out = metrics_poller.compute_bps(prev, {"Gi1/0/1": (10, 10)}, 400.0)
    assert out == {}
    # 기준선은 새 값으로 교체돼 다음 주기부터 정상 계산
    assert prev["Gi1/0/1"] == (400.0, 10, 10)


def test_compute_bps_zero_dt_skipped():
    prev = {"p": (100.0, 0, 0)}
    assert metrics_poller.compute_bps(prev, {"p": (999, 999)}, 100.0) == {}


# --- 수집·저장 ----------------------------------------------------------------

def _mk_switch(p, name="SW-T", ip="10.0.0.1"):
    return db.save_switch(p, name, ip, "cisco_ios")


def test_collect_traffic_uplinks_only(temp_db, monkeypatch):
    """업링크 포트만 저장 — 전 포트를 쌓으면 이력이 폭주한다."""
    sid = _mk_switch(temp_db)
    metrics_poller._prev_traffic.clear()
    monkeypatch.setattr(db, "uplinks_for",
                        lambda p: frozenset({(sid, "gi1/0/48")}))
    samples = [
        {"Gi1/0/1": (100, 100), "Gi1/0/48": (1000, 1000)},
        {"Gi1/0/1": (200, 200), "Gi1/0/48": (601000, 301000)},
    ]
    it = iter(samples)
    monkeypatch.setattr(metrics_poller, "_walk_traffic",
                        lambda ip, c, budget=8.0: next(it))
    _clock = iter([1000.0, 1300.0])          # 두 주기 사이 300초
    monkeypatch.setattr(metrics_poller.time, "time", lambda: next(_clock))
    assert metrics_poller.collect_traffic(temp_db, "public") == 0   # 기준선
    assert metrics_poller.collect_traffic(temp_db, "public") == 1   # 업링크만
    rows = db.get_traffic_series(temp_db, hours=1)
    assert len(rows) == 1 and rows[0]["port"] == "Gi1/0/48"
    assert rows[0]["in_bps"] > 0 and rows[0]["out_bps"] > 0


def test_collect_traffic_standalone_falls_back_to_busiest(temp_db, monkeypatch):
    """업링크가 안 잡힌 단독 스위치는 바쁜 포트 3개 — 화면이 비지 않게."""
    _mk_switch(temp_db, "SW-ALONE", "10.0.0.2")
    metrics_poller._prev_traffic.clear()
    monkeypatch.setattr(db, "uplinks_for", lambda p: frozenset())
    base = {"Gi0/%d" % i: (0, 0) for i in range(1, 6)}
    nxt = {"Gi0/%d" % i: (i * 1000000, i * 1000000) for i in range(1, 6)}
    it = iter([base, nxt])
    monkeypatch.setattr(metrics_poller, "_walk_traffic",
                        lambda ip, c, budget=8.0: next(it))
    _clock = iter([1000.0, 1300.0])          # 위와 같은 이유(dt=0 방지)
    monkeypatch.setattr(metrics_poller.time, "time", lambda: next(_clock))
    metrics_poller.collect_traffic(temp_db, "public")
    assert metrics_poller.collect_traffic(temp_db, "public") == 3
    ports = {r["port"] for r in db.get_traffic_series(temp_db, hours=1)}
    assert ports == {"Gi0/5", "Gi0/4", "Gi0/3"}, "가장 바쁜 3개"


def test_collect_traffic_snmp_dead_skipped(temp_db, monkeypatch):
    _mk_switch(temp_db, "SW-DEAD", "10.0.0.3")
    metrics_poller._prev_traffic.clear()
    monkeypatch.setattr(metrics_poller, "_walk_traffic",
                        lambda ip, c, budget=8.0: (_ for _ in ()).throw(
                            RuntimeError("no snmp")))
    assert metrics_poller.collect_traffic(temp_db, "public") == 0


def test_traffic_roundtrip_and_prune(temp_db):
    db.save_traffic_points(temp_db, [(1, "Gi1/0/48", 80000, 8000)])
    rows = db.get_traffic_series(temp_db, hours=1)
    assert rows[0]["in_bps"] == 80000 and rows[0]["out_bps"] == 8000
    with db.get_db(temp_db) as conn:
        conn.execute("UPDATE traffic_history SET ts = datetime('now','localtime','-40 days')")
    assert db.prune_traffic_history(temp_db, days=30) == 1
    assert db.get_traffic_series(temp_db, hours=24 * 60) == []


def test_save_traffic_never_raises(tmp_path):
    db.save_traffic_points(str(tmp_path / "no_schema.db"), [(1, "p", 1, 1)])


# --- 임계값 알람 --------------------------------------------------------------

def _events(p, kind):
    return [e for e in db.list_device_events(p, limit=100) if e["kind"] == kind]


def test_threshold_over_and_hysteresis(temp_db):
    metrics_poller._over_state.clear()
    # 기본 임계 80% — 85%는 초과
    assert metrics_poller.check_thresholds(temp_db, 1, "FW-A", 85, 50, None) == 1
    ev = _events(temp_db, "threshold_over")
    assert len(ev) == 1 and "CPU" in ev[0]["message"] and "FW-A" in ev[0]["message"]
    # 같은 초과 상태 지속 — 재알람 금지
    assert metrics_poller.check_thresholds(temp_db, 1, "FW-A", 90, 50, None) == 0
    # 78%: 임계(80) 아래지만 해제선(75) 위 — 히스테리시스로 아직 해제 아님
    assert metrics_poller.check_thresholds(temp_db, 1, "FW-A", 78, 50, None) == 0
    # 70% — 해제
    assert metrics_poller.check_thresholds(temp_db, 1, "FW-A", 70, 50, None) == 1
    assert len(_events(temp_db, "threshold_clear")) == 1


def test_threshold_sessions_default_off(temp_db):
    """세션 임계 기본 0 = 끔 — 세션 수는 환경마다 정상 범위가 달라 기본 알람 부적절."""
    metrics_poller._over_state.clear()
    assert metrics_poller.check_thresholds(temp_db, 2, "FW-B", None, None, 999999) == 0
    db.set_setting(temp_db, "alert_sessions", "500000")
    assert metrics_poller.check_thresholds(temp_db, 2, "FW-B", None, None, 999999) == 1
    assert "세션" in _events(temp_db, "threshold_over")[0]["message"]


def test_threshold_disabled_by_zero(temp_db):
    metrics_poller._over_state.clear()
    db.set_setting(temp_db, "alert_cpu_pct", "0")
    db.set_setting(temp_db, "alert_mem_pct", "0")
    assert metrics_poller.check_thresholds(temp_db, 3, "FW-C", 99, 99, None) == 0
    assert _events(temp_db, "threshold_over") == []


def test_threshold_wired_into_poll(temp_db, monkeypatch):
    """폴러 경로에서 실제로 호출되는지 — 지표 저장과 같은 주기."""
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")   # v6.34: 기본 꺼짐
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW-P','fortigate','10.0.0.9')")
    from core import snmp_fortigate, snmp_env, collector
    metrics_poller._over_state.clear()
    metrics_poller._prev_traffic.clear()
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health",
                        lambda ip, c, budget=8.0: {"cpu_pct": 95, "mem_pct": 40,
                                                   "sessions": 10})
    monkeypatch.setattr(snmp_env, "collect_env",
                        lambda ip, c, budget=6.0, **kw: {})
    monkeypatch.setattr(metrics_poller, "collect_traffic", lambda p, c: 0)
    metrics_poller.poll_once(temp_db, demo_mode=False)
    assert len(_events(temp_db, "threshold_over")) == 1


# --- API ---------------------------------------------------------------------

def test_series_endpoint_includes_traffic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SW-API", "10.9.9.9", "cisco_ios")
    db.save_traffic_points(dbp, [(sid, "Gi1/0/48", 80000, 8000)])
    d = application.test_client().get("/api/wall/series?hours=24").get_json()
    t = d["traffic"]["%s:Gi1/0/48" % sid]
    assert t["name"] == "SW-API Gi1/0/48"
    assert t["points"][0][1] == 80000 and t["points"][0][2] == 8000


def test_settings_roundtrip_thresholds(client):
    r = client.post("/api/settings/auto_collect", json={
        "enabled": False, "alert_cpu_pct": 90, "alert_mem_pct": 85,
        "alert_sessions": 1000000})
    assert r.status_code == 200
    d = client.get("/api/settings/auto_collect").get_json()
    assert d["alert_cpu_pct"] == "90" and d["alert_mem_pct"] == "85"
    assert d["alert_sessions"] == "1000000"


# --- 화면 마커 ----------------------------------------------------------------

def test_wall_ui_markers_v6290():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    # 트래픽 위젯
    assert "ch-sw-traffic" in js and "function chartTraffic" in js
    assert "function _fmtBps" in js
    # 임계값 알람 티커 문구
    assert "threshold_over" in js and "임계 초과" in js and "threshold_clear" in js
    # 드래그 순서 — CSS order 방식(재렌더에도 유지)
    assert "dragstart" in js and "dragend" in js and "style.order" in js
    # TV 모드
    assert "wall-tv-btn" in js and "wall_tv_mode" in js
    assert "function wallShowTab" in js and "function tvMaybeJump" in js
    assert ".wcard--drag" in css


def test_settings_ui_markers_v6290():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    for m in ('id="ac-alert-cpu"', 'id="ac-alert-mem"', 'id="ac-alert-sessions"'):
        assert m in html, m
    for m in ("alert_cpu_pct", "alert_mem_pct", "alert_sessions"):
        assert m in js, m
