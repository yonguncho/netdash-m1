# -*- coding: utf-8 -*-
"""지표 이력 + 폴러 + 시계열 그래프 (v6.26.0).

승인된 설계: metrics_history 테이블(30일 보존) + 5분 폴러(설정 변경/끔 가능) +
uPlot 번들(폐쇄망 — exe 포함) + 관제 3탭 시계열 위젯.
"""
from pathlib import Path

from core import db, metrics_poller

ROOT = Path(__file__).parent.parent


# --- 저장·조회·보존 ----------------------------------------------------------

def test_point_roundtrip(temp_db):
    db.save_metrics_point(temp_db, "firewall", 7, cpu=34, mem=61, sessions=48210,
                          temp_c=41.5)
    rows = db.get_metrics_series(temp_db, "firewall", hours=1)
    assert len(rows) == 1
    r = rows[0]
    assert r["device_id"] == 7 and r["cpu"] == 34 and r["sessions"] == 48210
    assert r["temp_c"] == 41.5 and r["ts"]


def test_series_filters_by_kind_and_device(temp_db):
    db.save_metrics_point(temp_db, "firewall", 1, cpu=10)
    db.save_metrics_point(temp_db, "switch", 1, temp_c=40)
    db.save_metrics_point(temp_db, "firewall", 2, cpu=20)
    assert len(db.get_metrics_series(temp_db, "firewall", hours=1)) == 2
    assert len(db.get_metrics_series(temp_db, "firewall", device_id=1, hours=1)) == 1
    assert len(db.get_metrics_series(temp_db, "switch", hours=1)) == 1


def test_old_points_pruned(temp_db):
    db.save_metrics_point(temp_db, "facility", 0, online=10, total=12)
    with db.get_db(temp_db) as conn:
        conn.execute("UPDATE metrics_history SET ts = datetime('now','localtime','-40 days')")
    assert db.prune_metrics_history(temp_db, days=30) == 1
    assert db.get_metrics_series(temp_db, "facility", hours=24 * 60) == []


def test_save_point_never_raises(tmp_path):
    """폴러가 부르는 함수 — 한 점 손실이 스레드 죽음보다 낫다."""
    db.save_metrics_point(str(tmp_path / "no_schema.db"), "firewall", 1, cpu=1)


# --- 폴러 --------------------------------------------------------------------

def test_poll_once_records_db_aggregates_without_snmp(temp_db, monkeypatch):
    """설비·포트 점은 SNMP 없이(데모 포함) 기록된다."""
    sw = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sw)
    db.save_ports(temp_db, snap, sw, [
        {"switch_id": sw, "name": "Gi1/0/1", "status": "connected", "vlan": 1,
         "speed": "1000", "description": ""},
        {"switch_id": sw, "name": "Gi1/0/2", "status": "notconnect", "vlan": 1,
         "speed": "1000", "description": ""}])
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.5", "mac": "aa:01",
         "online": 1, "direct": 1, "switch_name": "SW", "port": "Gi1/0/1"}])
    n = metrics_poller.poll_once(temp_db, demo_mode=True)
    assert n == 2
    fac = db.get_metrics_series(temp_db, "facility", hours=1)
    assert fac[0]["online"] == 1 and fac[0]["total"] == 1
    ports = db.get_metrics_series(temp_db, "ports", hours=1)
    assert ports[0]["online"] == 1 and ports[0]["total"] == 2


def test_poll_once_records_firewall_snmp(temp_db, monkeypatch):
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")   # v6.34: 기본 꺼짐
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW','fortigate','10.0.0.9')")
    from core import snmp_fortigate, snmp_env, collector
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health",
                        lambda ip, c, budget=8.0: {"cpu_pct": 12, "mem_pct": 40,
                                                   "sessions": 100})
    monkeypatch.setattr(snmp_env, "collect_env",
                        lambda ip, c, budget=6.0: {"max_temp_c": 45.0})
    n = metrics_poller.poll_once(temp_db, demo_mode=False)
    rows = db.get_metrics_series(temp_db, "firewall", hours=1)
    assert len(rows) == 1 and rows[0]["cpu"] == 12 and rows[0]["temp_c"] == 45.0
    assert n >= 1


def test_poll_once_survives_dead_device(temp_db, monkeypatch):
    """장비 하나가 죽어도 나머지는 기록된다 — 폴러 필수 성질."""
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")   # v6.34: 기본 꺼짐
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW-A','fortigate','10.0.0.1')")
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW-B','fortigate','10.0.0.2')")
    from core import snmp_fortigate, snmp_env, collector
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")

    def health(ip, c, budget=8.0):
        if ip == "10.0.0.1":
            raise snmp_fortigate.SnmpSilent("dead")
        return {"cpu_pct": 30, "mem_pct": 50, "sessions": 5}
    monkeypatch.setattr(snmp_fortigate, "collect_health", health)
    monkeypatch.setattr(snmp_env, "collect_env",
                        lambda ip, c, budget=6.0: (_ for _ in ()).throw(
                            snmp_env.SnmpSilent("dead")))
    metrics_poller.poll_once(temp_db, demo_mode=False)
    rows = db.get_metrics_series(temp_db, "firewall", hours=1)
    assert len(rows) == 1 and rows[0]["cpu"] == 30


def test_poll_minutes_setting(temp_db):
    assert metrics_poller.poll_minutes(temp_db) == 5      # 기본
    db.set_setting(temp_db, "metrics_poll_minutes", "0")
    assert metrics_poller.poll_minutes(temp_db) == 0      # 끔
    db.set_setting(temp_db, "metrics_poll_minutes", "잘못된값")
    assert metrics_poller.poll_minutes(temp_db) == 5      # 복원


# --- API ---------------------------------------------------------------------

def test_series_endpoint(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    with db.get_db(dbp) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW-S','fortigate','10.0.0.1')")
    fid = db.list_firewalls(dbp)[-1]["id"]
    db.save_metrics_point(dbp, "firewall", fid, cpu=22, sessions=999)
    db.save_metrics_point(dbp, "facility", 0, online=5, total=6)
    d = application.test_client().get("/api/wall/series?hours=24").get_json()
    assert d["hours"] == 24
    dev = d["firewalls"][str(fid)]
    assert dev["name"] == "FW-S" and dev["points"][0][1] == 22
    assert d["facility"][0][1] == 5 and d["facility"][0][2] == 6


def test_series_endpoint_clamps_hours(client):
    d = client.get("/api/wall/series?hours=999999").get_json()
    assert d["hours"] == 24 * 30


# --- 번들·화면 ----------------------------------------------------------------

def test_uplot_bundled_locally():
    """폐쇄망 — 차트 라이브러리는 exe 안에 있어야 하고 CDN 참조가 없어야 한다."""
    js = ROOT / "web" / "static" / "vendor" / "uplot.iife.min.js"
    css = ROOT / "web" / "static" / "vendor" / "uplot.min.css"
    assert js.exists() and js.stat().st_size > 30000
    assert css.exists()
    html = (ROOT / "web" / "templates" / "wall.html").read_text(encoding="utf-8")
    assert "/static/vendor/uplot.iife.min.js" in html
    assert "cdn." not in html and "unpkg" not in html


def test_wall_has_series_widgets():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    for marker in ("ch-fw-sess", "ch-fw-cpu", "ch-sw-temp", "ch-ports", "ch-fac",
                   "function chartMulti", "function chartTotal", "refreshSeries",
                   "기록 수집 중"):
        assert marker in js, marker
    # 기간 전환(1h/24h/7d) — 버튼은 동적 생성이라 옵션 정의로 확인
    assert '"168", "7일"' in js and "data-hours" in js


def test_settings_expose_poll_interval():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="ac-metrics-minutes"' in html
    assert "metrics_poll_minutes" in js
