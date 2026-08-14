# -*- coding: utf-8 -*-
"""v6.39.0 — 관제 통계 강화(2순위) + 수집 실패 가시화(3순위).

2순위: 온도 임계 설정화 / 임계 근접 통합 순위 / 평소 대비 이상치
3순위: 스위치 SNMP 진단 / SNMP 무응답 장비 목록
"""
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


# ── 임계 근접 통합 순위 ───────────────────────────────────────────

def test_risk_ranks_by_pct_of_limit(dbf):
    """단위가 다른 지표(%·°C)를 한 줄에 세우려면 임계 대비로 환산해야 한다."""
    db.set_setting(dbf, "temp_crit_c", "70")
    hot = _sw(dbf, "SW-HOT", "10.0.0.1")
    warm = _sw(dbf, "SW-WARM", "10.0.0.2")
    _env(dbf, "switch", hot["id"], temp=68)     # 97%
    _env(dbf, "switch", warm["id"], temp=56)    # 80%
    top = wallstats.build(dbf)["risk"]["top"]
    assert [x["name"] for x in top] == ["SW-HOT", "SW-WARM"]
    assert top[0]["pct_of_limit"] == 97
    assert top[0]["metric"] == "온도" and top[0]["unit"] == "°C"


def test_risk_skips_comfortable_devices(dbf):
    """여유 있는 장비까지 나열하면 순위가 묻힌다 — 70% 미만은 뺀다."""
    db.set_setting(dbf, "temp_crit_c", "70")
    cool = _sw(dbf, "SW-COOL", "10.0.0.3")
    _env(dbf, "switch", cool["id"], temp=30)    # 43%
    assert wallstats.build(dbf)["risk"]["top"] == []


def test_risk_marks_critical_over_limit(dbf):
    db.set_setting(dbf, "temp_crit_c", "60")
    s = _sw(dbf, "SW-BURN", "10.0.0.4")
    _env(dbf, "switch", s["id"], temp=65)
    r = wallstats.build(dbf)["risk"]
    assert r["top"][0]["level"] == "critical"
    assert r["critical"] == 1


def test_risk_excludes_deleted_devices(dbf):
    """현황에서 지운 장비의 지표가 device_env에 남는다 — 이름 대신 id 숫자가
    뜨고, 이미 없는 장비를 '위험'이라 알리게 된다(실화면에서 발견)."""
    db.set_setting(dbf, "temp_crit_c", "70")
    _env(dbf, "switch", 9999, temp=69)          # 존재하지 않는 스위치 id
    top = wallstats.build(dbf)["risk"]["top"]
    assert top == [], "삭제된 장비가 위험도 순위에 남으면 안 된다"


def test_risk_uses_configured_cpu_limit(dbf):
    db.set_setting(dbf, "alert_cpu_pct", "50")
    db.save_firewall(dbf, "FW1", "fortigate", "10.1.0.1")
    fws = db.list_firewalls(dbf)
    assert fws
    _env(dbf, "firewall", fws[0]["id"], metrics={"cpu_pct": 45})   # 90%
    top = wallstats.build(dbf)["risk"]["top"]
    assert top and top[0]["metric"] == "CPU" and top[0]["pct_of_limit"] == 90


# ── 평소 대비 이상치 ──────────────────────────────────────────────

def _hist(dbf, fid, hours_ago, sessions):
    with db.get_db(dbf) as conn:
        conn.execute(
            "INSERT INTO metrics_history (kind, device_id, ts, sessions) "
            "VALUES ('firewall', ?, datetime('now','localtime', ?), ?)",
            (fid, "-%d hours" % hours_ago, sessions))
        conn.commit()


def test_anomaly_detects_surge(dbf):
    fws = db.list_firewalls(dbf)
    fid = fws[0]["id"] if fws else 1
    for h in range(30, 24, -1):
        _hist(dbf, fid, h, 1000)
    for h in range(20, 0, -2):
        _hist(dbf, fid, h, 3000)
    ano = wallstats.build(dbf)["risk"]["anomalies"]
    assert ano and ano[0]["direction"] == "급증"
    assert ano[0]["ratio"] == 3.0


def test_anomaly_ignores_normal_variation(dbf):
    fid = 1
    for h in range(30, 24, -1):
        _hist(dbf, fid, h, 1000)
    for h in range(20, 0, -2):
        _hist(dbf, fid, h, 1200)        # 1.2배 — 평소 범위
    assert wallstats.build(dbf)["risk"]["anomalies"] == []


def test_anomaly_needs_enough_samples(dbf):
    """점 두어 개로 '평소'를 정하면 오탐이 쏟아진다."""
    fid = 1
    _hist(dbf, fid, 30, 1000)
    _hist(dbf, fid, 2, 9000)
    assert wallstats.build(dbf)["risk"]["anomalies"] == []


# ── SNMP 무응답 목록 ──────────────────────────────────────────────

def test_no_snmp_lists_devices_without_env(dbf):
    quiet = _sw(dbf, "SW-QUIET", "10.0.0.7")
    loud = _sw(dbf, "SW-LOUD", "10.0.0.8")
    _env(dbf, "switch", loud["id"], temp=40)
    r = wallstats.build(dbf)["risk"]
    names = [x["name"] for x in r["no_snmp"]]
    assert "SW-QUIET" in names and "SW-LOUD" not in names


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


def test_wall_js_renders_risk():
    js = _read("web", "static", "wall.js")
    assert "function renderRisk(" in js
    assert "renderRisk(_WSTAT.risk)" in js
    assert "임계 근접 장비" in js and "평소와 다른 장비" in js
    assert "SNMP 무응답 장비" in js


def test_wall_html_has_risk_container():
    html = _read("web", "templates", "wall.html")
    assert 'id="wall-risk"' in html
    # 기존 장애 목록은 관제의 본래 목적이라 남아 있어야 한다
    assert 'id="wall-problems"' in html


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
