# -*- coding: utf-8 -*-
"""v6.39.x — 온도 임계 설정화·임계 초과 알람 + 스위치 SNMP 진단.

사용자 방향(v6.39.1): 관제는 '연결 실패 설비 + 포트/장비 다운'이 핵심이다.
상태값을 관제에 나열하지 않는다 — **온도는 스위치 상세보기에서 보고,
임계를 넘은 것만 알람으로 관제에 올린다.**
"""
from core import metrics_poller as mp
import os
import tempfile

import pytest

from core import collector, db, snmp_env, wallstats


@pytest.fixture()
def dbf():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def _sw(dbf, name, ip):
    db.save_switch(dbf, name, ip, "cisco_ios")
    return [s for s in db.get_switches(dbf) if s["ip"] == ip][0]


def _env(dbf, kind, did, temp=None, metrics=None):
    if temp is not None:
        db.save_device_env(dbf, kind, did, {
            "max_temp_c": temp, "level": "warning", "temp_count": 1,
            "fan_count": 0, "sensors": [{"name": "t", "type": "celsius",
                                         "value": temp, "status": "ok"}]})
    if metrics:
        db.save_device_metrics(dbf, kind, did, metrics)


# ── 온도 임계 설정화 ──────────────────────────────────────────────

def test_temp_level_uses_given_thresholds():
    """장비마다 정상 온도가 달라 고정값이면 오탐·미탐이 난다."""
    assert snmp_env.temp_level(60) == "warning"          # 기본 55/70
    assert snmp_env.temp_level(60, warn_c=50, crit_c=55) == "critical"
    assert snmp_env.temp_level(60, warn_c=70, crit_c=80) == "normal"
    assert snmp_env.temp_level(None, 10, 20) is None


def test_temp_thresholds_default_and_setting(dbf):
    assert collector.temp_thresholds(dbf) == (snmp_env.WARN_C, snmp_env.CRIT_C)
    db.set_setting(dbf, "temp_warn_c", "40")
    db.set_setting(dbf, "temp_crit_c", "50")
    assert collector.temp_thresholds(dbf) == (40.0, 50.0)


def test_temp_thresholds_swapped_input_is_corrected(dbf):
    """경고가 위험보다 높으면 등급이 뒤집힌다 — 잘못 넣어도 동작은 지킨다."""
    db.set_setting(dbf, "temp_warn_c", "80")
    db.set_setting(dbf, "temp_crit_c", "60")
    assert collector.temp_thresholds(dbf) == (60.0, 80.0)


def test_temp_thresholds_bad_value_falls_back(dbf):
    db.set_setting(dbf, "temp_warn_c", "뜨거움")
    assert collector.temp_thresholds(dbf)[0] == snmp_env.WARN_C


def test_summarize_respects_thresholds():
    sensors = [{"name": "t", "type": "celsius", "value": 58.0, "status": "ok"}]
    assert snmp_env.summarize(sensors)["level"] == "warning"
    assert snmp_env.summarize(sensors, 30, 50)["level"] == "critical"


# ── 스위치 SNMP 진단 ──────────────────────────────────────────────

class _FakeSess:
    def __init__(self, scalars=None, walks=None):
        self._s = scalars or {}
        self._w = walks or {}

    def get(self, oids):
        return [(o, self._s[o]) for o in oids if o in self._s]

    def walk(self, base, max_rows=256):
        return list(self._w.get(base, []))


def test_probe_switch_reports_each_check(monkeypatch):
    sess = _FakeSess(
        scalars={"1.3.6.1.2.1.1.1.0": b"Cisco IOS Software",
                 "1.3.6.1.2.1.1.5.0": b"SW-CORE"},
        walks={"1.3.6.1.2.1.31.1.1.1.1": [("1.1", b"Gi1/0/1"), ("1.2", b"Gi1/0/2")],
               "1.3.6.1.2.1.31.1.1.1.6": [("1.1", 100)],
               "1.3.6.1.2.1.2.2.1.14": [("1.1", 0)]})
    monkeypatch.setattr("core.snmp_collect._Session", lambda *a, **k: sess)
    out = snmp_env.probe_switch("10.0.0.1", "public")
    assert out["reachable"] is True
    assert "Cisco" in out["sysdescr"] and out["sysname"] == "SW-CORE"
    by = {c["name"]: c for c in out["checks"]}
    assert by["SNMP 응답"]["ok"] is True
    assert by["포트 이름 (IF-MIB ifName)"]["ok"] is True
    # CRC(EtherLike-MIB)는 walk 결과가 없으니 '없음'으로 남아야 한다
    assert by["CRC 카운터 (EtherLike-MIB)"]["ok"] is False


def test_probe_switch_no_reply_stops_early(monkeypatch):
    monkeypatch.setattr("core.snmp_collect._Session",
                        lambda *a, **k: _FakeSess(scalars={}))
    out = snmp_env.probe_switch("10.0.0.1", "public")
    assert out["reachable"] is False
    assert out["checks"][0]["name"] == "SNMP 응답"


# ── 화면 배선 ─────────────────────────────────────────────────────

def _read(*parts):
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), *parts)
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_wall_has_no_status_listing_cards():
    """사용자 방향(v6.39.1): 관제는 '연결 실패 설비 + 포트/장비 다운'이 핵심이다.
    상태값 나열(임계 근접·이상치·SNMP 무응답)은 관제에서 뺀다 —
    온도는 스위치 상세보기에서 보고, 임계 초과만 알람으로 올린다."""
    js = _read("web", "static", "wall.js")
    html = _read("web", "templates", "wall.html")
    for gone in ("renderRisk(", "임계 근접 장비", "평소와 다른 장비", "SNMP 무응답 장비"):
        assert gone not in js, "관제에서 뺀 항목이 남아 있다: %s" % gone
    assert 'id="wall-risk"' not in html
    # 장애 목록은 관제의 본래 목적이라 그대로 있어야 한다
    assert 'id="wall-problems"' in html


def test_wall_ticker_labels_temp_alarm():
    js = _read("web", "static", "wall.js")
    assert 'temp_over: "온도 임계 초과"' in js


def test_detail_panel_shows_temperature():
    """온도를 보는 곳은 스위치 상세보기다 — 값이 없으면 사유도 알려야 한다."""
    js = _read("web", "static", "app.js")
    i = js.index("function renderDetailEnv(")
    blk = js[i:i + 2200]
    assert "현재 최고 온도" in blk
    assert "SNMP 허용 호스트" in blk


def test_app_js_wires_switch_probe():
    js = _read("web", "static", "app.js")
    assert "function snmpProbeSwitch(" in js
    assert "snmp-probe-switch" in js
    assert "/api/switches/" in js


def test_settings_expose_temp_thresholds():
    html = _read("web", "templates", "index.html")
    assert "ac-temp-warn" in html and "ac-temp-crit" in html
    js = _read("web", "static", "app.js")
    assert "temp_warn_c" in js and "temp_crit_c" in js


# ── 임계 초과 알람 ────────────────────────────────────────────────

def test_temp_alarm_fires_only_over_limit(dbf):
    """관제에는 '몇 도인가'가 아니라 '임계를 넘었나'만 올린다."""
    mp._over_state.clear()
    assert mp.check_temp(dbf, "switch", 1, "SW1", 65.0, 70.0) == 0   # 아직 아래
    assert mp.check_temp(dbf, "switch", 1, "SW1", 72.0, 70.0) == 1   # 초과
    evs = [e for e in db.list_device_events(dbf, limit=50) if e["kind"] == "temp_over"]
    assert len(evs) == 1 and "72" in evs[0]["message"]


def test_temp_alarm_not_repeated_while_over(dbf):
    """같은 초과 상태에서 매 주기 알리면 티커가 그 장비로 도배된다."""
    mp._over_state.clear()
    mp.check_temp(dbf, "switch", 1, "SW1", 72.0, 70.0)
    assert mp.check_temp(dbf, "switch", 1, "SW1", 75.0, 70.0) == 0


def test_temp_alarm_clears_with_hysteresis(dbf):
    """임계 언저리를 오르내릴 때 초과/복귀가 번갈아 쏟아지지 않게."""
    mp._over_state.clear()
    mp.check_temp(dbf, "switch", 1, "SW1", 72.0, 70.0)
    assert mp.check_temp(dbf, "switch", 1, "SW1", 69.0, 70.0) == 0    # 아직 복귀 아님
    assert mp.check_temp(dbf, "switch", 1, "SW1", 66.0, 70.0) == 1    # 임계-3 이하
    evs = [e for e in db.list_device_events(dbf, limit=50) if e["kind"] == "temp_clear"]
    assert len(evs) == 1


def test_temp_alarm_ignores_missing_values(dbf):
    mp._over_state.clear()
    assert mp.check_temp(dbf, "switch", 1, "SW1", None, 70.0) == 0
    assert mp.check_temp(dbf, "switch", 1, "SW1", 90.0, 0) == 0       # 임계 0 = 끔


def test_poller_checks_temp():
    import inspect
    src = inspect.getsource(mp.poll_once)
    assert "check_temp(" in src
