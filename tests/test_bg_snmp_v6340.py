# -*- coding: utf-8 -*-
"""백그라운드 SNMP 폴링 게이트 (v6.34.0 도입 → v6.34.1 정책 확정).

사용자 확정: **스위치·방화벽은 주기 SNMP+ping 체크 허용(기본 켜짐), 설비는
ping만.** 주기 SNMP 대상은 switches·firewalls 테이블뿐 — 설비(facility_hosts)에는
어떤 경우에도 SNMP를 보내지 않는다. 토글로 전체를 끌 수도 있다.
"""
import inspect
from pathlib import Path

from core import db, metrics_poller, status_monitor

ROOT = Path(__file__).parent.parent


def test_bg_snmp_enabled_by_default(temp_db):
    """기본 켜짐(사용자 확정) — 끄면 게이트가 닫힌다."""
    assert metrics_poller.bg_snmp_enabled(temp_db) is True
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "0")
    assert metrics_poller.bg_snmp_enabled(temp_db) is False


def test_poller_sends_no_snmp_when_disabled(temp_db, monkeypatch):
    """토글을 끄면 poll_once는 SNMP를 한 번도 부르지 않는다."""
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "0")
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW','fortigate','10.0.0.9')")
    db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    from core import snmp_fortigate, snmp_env, collector

    def _boom(*a, **k):
        raise AssertionError("폴링을 껐는데 SNMP 조회가 나갔다")
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health", _boom)
    monkeypatch.setattr(snmp_env, "collect_env", _boom)
    monkeypatch.setattr(metrics_poller, "_walk_traffic", _boom)
    metrics_poller.poll_once(temp_db, demo_mode=False)   # 예외 없이 DB 집계만


def test_poller_snmp_runs_by_default(temp_db, monkeypatch):
    """기본 상태에서 스위치·방화벽 SNMP 지표가 쌓인다."""
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW','fortigate','10.0.0.9')")
    from core import snmp_fortigate, snmp_env, collector
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health",
                        lambda ip, c, budget=8.0: {"cpu_pct": 11})
    monkeypatch.setattr(snmp_env, "collect_env", lambda ip, c, budget=6.0: {})
    monkeypatch.setattr(metrics_poller, "collect_traffic", lambda p, c: 0)
    metrics_poller.poll_once(temp_db, demo_mode=False)
    rows = db.get_metrics_series(temp_db, "firewall", hours=1)
    assert rows and rows[0]["cpu"] == 11


def test_status_monitor_port_walk_gated(temp_db, monkeypatch):
    """포트 감시(SNMP walk)도 게이트를 따른다 — 설비 ping은 게이트 무관 유지."""
    db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    from core import collector
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "0")

    def _boom(*a, **k):
        raise AssertionError("포트 SNMP walk가 게이트를 무시했다")
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(status_monitor, "check_ports", _boom)
    monkeypatch.setattr(status_monitor, "check_facility", lambda p: (0, 0, 0))
    assert status_monitor.poll_once(temp_db) == (0, 0, 0, 0, 0)
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")
    monkeypatch.setattr(status_monitor, "check_ports", lambda p, c: (1, 0))
    assert status_monitor.poll_once(temp_db)[0] == 1


def test_facility_monitoring_is_ping_only():
    """설비는 ping만(사용자 확정) — check_facility 경로에 SNMP가 섞이면 안 된다."""
    src = inspect.getsource(status_monitor.check_facility)
    assert "_ping" in src
    assert "snmp" not in src.lower(), "설비 감시에 SNMP 조회가 끼어들었다"
    src2 = inspect.getsource(status_monitor._ping)
    assert "ping" in src2 and "snmp" not in src2.lower()


def test_settings_roundtrip_bg_snmp(client):
    d = client.get("/api/settings/auto_collect").get_json()
    assert d["snmp_bg_poll_enabled"] is True, "기본 켜짐(스위치·방화벽만 조회)"
    r = client.post("/api/settings/auto_collect",
                    json={"enabled": False, "snmp_bg_poll_enabled": False})
    assert r.status_code == 200
    assert client.get("/api/settings/auto_collect").get_json()["snmp_bg_poll_enabled"] is False
    # 공유 데모 DB — 다른 테스트를 위해 기본값 복원
    client.post("/api/settings/auto_collect",
                json={"enabled": False, "snmp_bg_poll_enabled": True})


def test_series_endpoint_exposes_flag(client):
    d = client.get("/api/wall/series?hours=1").get_json()
    assert "bg_snmp" in d


def test_ui_markers_v6340():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    wall = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert 'id="ac-snmp-bg"' in html and "설비는 ping만" in html
    assert "snmp_bg_poll_enabled" in js
    assert "백그라운드 SNMP 폴링이 꺼져 있어" in wall, "관제가 정확한 사유를 안내"


def test_master_snmp_off_stops_everything(temp_db, monkeypatch):
    """'SNMP 수집 사용'(마스터)을 끄면 백그라운드 폴링이 켜져 있어도 SNMP 0회.

    사용자 요구: 장비 쪽 SNMP 설정 전에는 꺼두고, 설정 후 켜면 동작.
    모든 경로가 _snmp_community_if_enabled(snmp_enabled 게이트)를 거친다.
    """
    db.set_setting(temp_db, "snmp_enabled", "0")
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW','fortigate','10.0.0.9')")
    db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    from core import snmp_fortigate, snmp_env

    def _boom(*a, **k):
        raise AssertionError("마스터 SNMP를 껐는데 조회가 나갔다")
    monkeypatch.setattr(snmp_fortigate, "collect_health", _boom)
    monkeypatch.setattr(snmp_env, "collect_env", _boom)
    monkeypatch.setattr(metrics_poller, "_walk_traffic", _boom)
    metrics_poller.poll_once(temp_db, demo_mode=False)
    monkeypatch.setattr(status_monitor, "check_ports", _boom)
    monkeypatch.setattr(status_monitor, "check_facility", lambda p: (0, 0, 0))
    assert status_monitor.poll_once(temp_db) == (0, 0, 0, 0, 0)
