# -*- coding: utf-8 -*-
"""v6.34.0 — 백그라운드 SNMP 폴링 기본 꺼짐(사용자: "자동 SNMP 쿼리 멈춰줘 — 장비 부하").

툴을 켜두는 것만으로 주기 SNMP(지표 5분·트래픽·포트 감시 10분)가 나가면 안 된다.
수집 버튼·자동 수집·진단 등 사용자가 시킨 조회는 이 설정과 무관하게 동작한다.
"""
from pathlib import Path

from core import db, metrics_poller, status_monitor

ROOT = Path(__file__).parent.parent


def test_bg_snmp_disabled_by_default(temp_db):
    assert metrics_poller.bg_snmp_enabled(temp_db) is False
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")
    assert metrics_poller.bg_snmp_enabled(temp_db) is True


def test_poller_sends_no_snmp_when_disabled(temp_db, monkeypatch):
    """기본 상태에서 poll_once는 SNMP를 한 번도 부르지 않는다(핵심 요구)."""
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES "
                     "('FW','fortigate','10.0.0.9')")
    db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    from core import snmp_fortigate, snmp_env, collector

    def _boom(*a, **k):
        raise AssertionError("백그라운드 폴링이 꺼졌는데 SNMP 조회가 나갔다")
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health", _boom)
    monkeypatch.setattr(snmp_env, "collect_env", _boom)
    monkeypatch.setattr(metrics_poller, "_walk_traffic", _boom)
    metrics_poller.poll_once(temp_db, demo_mode=False)   # 예외 없이 DB 집계만


def test_poller_snmp_runs_when_enabled(temp_db, monkeypatch):
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")
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
    """포트 감시(SNMP walk)도 게이트를 따른다 — 설비 ping(ICMP)은 유지."""
    db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    from core import collector

    def _boom(*a, **k):
        raise AssertionError("포트 SNMP walk가 게이트를 무시했다")
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(status_monitor, "check_ports", _boom)
    monkeypatch.setattr(status_monitor, "check_facility", lambda p: (0, 0, 0))
    assert status_monitor.poll_once(temp_db) == (0, 0, 0, 0, 0)
    # 켜면 포트 감시 동작
    db.set_setting(temp_db, "snmp_bg_poll_enabled", "1")
    monkeypatch.setattr(status_monitor, "check_ports", lambda p, c: (1, 0))
    assert status_monitor.poll_once(temp_db)[0] == 1


def test_settings_roundtrip_bg_snmp(client):
    d = client.get("/api/settings/auto_collect").get_json()
    assert d["snmp_bg_poll_enabled"] is False, "기본 꺼짐"
    r = client.post("/api/settings/auto_collect",
                    json={"enabled": False, "snmp_bg_poll_enabled": True})
    assert r.status_code == 200
    assert client.get("/api/settings/auto_collect").get_json()["snmp_bg_poll_enabled"] is True


def test_series_endpoint_exposes_flag(client):
    d = client.get("/api/wall/series?hours=1").get_json()
    assert "bg_snmp" in d and d["bg_snmp"] is False


def test_ui_markers_v6340():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    wall = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert 'id="ac-snmp-bg"' in html and "기본 꺼짐" in html
    assert "snmp_bg_poll_enabled" in js
    assert "백그라운드 SNMP 폴링이 꺼져 있어" in wall, "관제가 정확한 사유를 안내"
