# -*- coding: utf-8 -*-
"""FortiGate SNMP 상태 지표 (v6.18.0).

실장비가 없으므로 get/walk 응답을 바꿔 끼우는 가짜 세션으로 검증한다.
OID 자체가 맞는지는 장비에서 probe()로 확인해야 한다 — 여기서 검증하는 것은
'응답이 왔을 때 올바르게 해석하는가'다.
"""
import pytest

from core import snmp_fortigate as fg


class FakeSession:
    def __init__(self, scalars=None, tables=None, fail=None):
        self.scalars = scalars or {}
        self.tables = tables or {}
        self.fail = fail

    def get(self, oids):
        if self.fail:
            raise self.fail
        return [(o, self.scalars[o]) for o in oids if o in self.scalars]

    def walk(self, base, max_rows=64):
        return [(base + "." + i, v) for i, v in self.tables.get(base, [])]


_HEALTHY = {
    fg._SYS_NAME: b"FW-HQ-01.corp.local",
    fg._SYS_UPTIME: 123456789,          # 1/100초
    fg._FG_VERSION: b"v7.2.5,build1517",
    fg._FG_CPU: 12,
    fg._FG_MEM: 43,
    fg._FG_MEM_CAP: 2097152,            # KB = 2048 MB
    fg._FG_DISK_USED: 4096,
    fg._FG_DISK_CAP: 16384,
    fg._FG_SESSIONS: 8231,
    fg._FG_HA_MODE: 1,
}


def _patch(monkeypatch, sess):
    monkeypatch.setattr(fg, "_Session", lambda *a, **k: sess)


def test_health_scalars(monkeypatch):
    _patch(monkeypatch, FakeSession(scalars=_HEALTHY))
    h = fg.collect_health("10.0.0.1", "public")
    assert h["cpu_pct"] == 12 and h["mem_pct"] == 43
    assert h["sessions"] == 8231
    # v6.37.0: SNMP도 SSH·REST와 같은 표기로 정규화한다. 예전엔 여기만 원문
    # (빌드 번호 포함)이라 같은 화면에 'v7.2.5'와 'v7.2.5,build1517'이 섞였다.
    assert h["version"] == "v7.2.5"
    assert h["hostname"] == "FW-HQ-01"          # FQDN 꼬리 제거
    assert h["uptime_sec"] == 1234567           # 1/100초 → 초
    assert h["mem_total_mb"] == 2048            # KB → MB
    assert h["disk_total_mb"] == 16384 and h["disk_pct"] == 25
    assert h["ha_mode"] == "standalone"
    assert h["level"] == "normal"


def test_level_follows_worst_metric(monkeypatch):
    """하나만 90%여도 눈에 띄어야 한다."""
    s = dict(_HEALTHY, **{fg._FG_CPU: 5, fg._FG_MEM: 93})
    _patch(monkeypatch, FakeSession(scalars=s))
    assert fg.collect_health("10.0.0.1")["level"] == "critical"
    s2 = dict(_HEALTHY, **{fg._FG_MEM: 82})
    _patch(monkeypatch, FakeSession(scalars=s2))
    assert fg.collect_health("10.0.0.1")["level"] == "warning"


def test_missing_oids_do_not_fail_whole_collection(monkeypatch):
    """지원하지 않는 항목이 있어도 나머지는 살아야 한다."""
    _patch(monkeypatch, FakeSession(scalars={fg._FG_CPU: 7, fg._FG_SESSIONS: 100}))
    h = fg.collect_health("10.0.0.1")
    assert h["cpu_pct"] == 7 and h["sessions"] == 100
    assert "mem_pct" not in h and "version" not in h


def test_disk_pct_needs_capacity(monkeypatch):
    """용량을 모르면 사용률을 만들어내지 않는다(0으로 나누기·허위 수치 방지)."""
    _patch(monkeypatch, FakeSession(scalars={fg._FG_DISK_USED: 500}))
    h = fg.collect_health("10.0.0.1")
    assert h["disk_used_mb"] == 500 and "disk_pct" not in h


def test_ha_members_collected_when_ha_enabled(monkeypatch):
    s = dict(_HEALTHY, **{fg._FG_HA_MODE: 3, fg._FG_HA_GROUP: b"HQ-CLUSTER"})
    tables = {
        fg._HA_HOSTNAME: [("1", b"FW-A"), ("2", b"FW-B")],
        fg._HA_SERIAL: [("1", b"FG100F111"), ("2", b"FG100F222")],
        fg._HA_CPU: [("1", 11), ("2", 9)],
        fg._HA_MEM: [("1", 40), ("2", 38)],
        fg._HA_SESSIONS: [("1", 5000), ("2", 12)],
        fg._HA_SYNC: [("1", 1), ("2", 1)],
    }
    _patch(monkeypatch, FakeSession(scalars=s, tables=tables))
    h = fg.collect_health("10.0.0.1")
    assert h["ha_mode"] == "active-passive" and h["ha_group"] == "HQ-CLUSTER"
    assert len(h["ha_members"]) == 2
    a = h["ha_members"][0]
    assert a["hostname"] == "FW-A" and a["serial"] == "FG100F111"
    assert a["cpu_pct"] == 11 and a["sessions"] == 5000


def test_standalone_skips_ha_member_walk(monkeypatch):
    """단독 장비에서 HA 테이블을 훑으면 시간만 버린다."""
    _patch(monkeypatch, FakeSession(scalars=_HEALTHY, tables={
        fg._HA_HOSTNAME: [("1", b"FW-A")]}))
    assert "ha_members" not in fg.collect_health("10.0.0.1")


def test_no_reply_raises(monkeypatch):
    """무응답은 조용히 빈 값이 아니라 예외 — 호출부가 원인을 구분해야 한다."""
    _patch(monkeypatch, FakeSession(fail=fg.SnmpSilent("no reply")))
    with pytest.raises(fg.SnmpError):
        fg.collect_health("10.0.0.1")


def test_probe_reports_missing_oids(monkeypatch):
    """실장비에서 어떤 OID가 없는지 눈으로 확인할 수 있어야 한다."""
    _patch(monkeypatch, FakeSession(scalars={fg._FG_CPU: 7}))
    r = fg.probe("10.0.0.1")
    by = {x["oid"]: x["value"] for x in r["scalars"]}
    assert by[fg._FG_CPU] == "7"
    assert by[fg._FG_MEM] == "(응답 없음)"


def test_thresholds_are_shared_constants():
    assert fg.WARN_PCT < fg.CRIT_PCT
    assert fg.pct_level(fg.CRIT_PCT) == "critical"
    assert fg.pct_level(fg.WARN_PCT) == "warning"
    assert fg.pct_level(fg.WARN_PCT - 1) == "normal"
    assert fg.pct_level(None) is None


# --- 저장·연동 ---------------------------------------------------------------

def _fw(dbp, vendor="fortigate", host="10.0.0.1", name="FW-01"):
    from core import db
    with db.get_db(dbp) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                           (name, vendor, host))
        return cur.lastrowid


_M = {"cpu_pct": 12, "mem_pct": 43, "sessions": 8231, "level": "normal",
      "version": "v7.2.5", "ha_mode": "standalone"}


def test_metrics_saved_and_read(temp_db):
    from core import db
    fid = _fw(temp_db)
    db.save_device_metrics(temp_db, "firewall", fid, _M)
    got = db.get_device_env(temp_db, "firewall", fid)
    assert got["metrics"]["cpu_pct"] == 12 and got["metrics"]["sessions"] == 8231


def test_metrics_and_temperature_coexist(temp_db):
    """온도와 지표는 수집 경로가 달라 서로를 지우면 안 된다."""
    from core import db
    fid = _fw(temp_db)
    env = {"sensors": [{"name": "Inlet", "type": "celsius", "value": 40.0,
                        "status": "ok", "level": "normal"}],
           "temp_count": 1, "fan_count": 1, "max_temp_c": 40.0, "level": "normal"}
    db.save_device_env(temp_db, "firewall", fid, env)
    db.save_device_metrics(temp_db, "firewall", fid, _M)
    got = db.get_device_env(temp_db, "firewall", fid)
    assert got["max_temp_c"] == 40.0, "지표 저장이 온도를 지웠다"
    assert got["metrics"]["cpu_pct"] == 12
    # 순서를 바꿔도 마찬가지여야 한다
    db.save_device_env(temp_db, "firewall", fid, env)
    got2 = db.get_device_env(temp_db, "firewall", fid)
    assert got2["metrics"]["cpu_pct"] == 12, "온도 저장이 지표를 지웠다"


def test_env_map_carries_metrics(temp_db):
    from core import db
    fid = _fw(temp_db)
    db.save_device_metrics(temp_db, "firewall", fid, _M)
    m = db.get_device_env_map(temp_db, "firewall")
    assert m[fid]["metrics"]["mem_pct"] == 43


def test_collector_skips_non_fortigate(temp_db):
    """벤더 전용 MIB이라 다른 벤더에는 시도하지 않는다."""
    from core import collector
    assert collector.collect_fw_metrics_snmp(
        temp_db, {"id": 1, "vendor": "paloalto", "host": "10.0.0.2"}) is None


def test_collector_skips_when_snmp_disabled(temp_db):
    """설정에서 SNMP를 끄면 시도하지 않는다.

    커뮤니티 '미설정'으로는 안 막힌다 — snmp_community()가 기본값 public을
    돌려주기 때문(서버 사양 수집 때부터의 동작). 끄는 스위치는 snmp_enabled뿐이다.
    """
    from core import db, collector
    db.set_setting(temp_db, "snmp_enabled", "0")
    assert collector._snmp_community_if_enabled(temp_db) is None
    assert collector.collect_fw_metrics_snmp(
        temp_db, {"id": 1, "vendor": "fortigate", "host": "10.0.0.1"}) is None


def test_community_defaults_to_public_when_unset(temp_db):
    """기본값 동작을 명시해 둔다 — '설정해야만 시도한다'가 아니다."""
    from core import collector
    assert collector._snmp_community_if_enabled(temp_db) == "public"


def test_probe_endpoint_requires_snmp_enabled(tmp_path, monkeypatch):
    """SNMP를 꺼둔 상태면 400과 함께 무엇을 해야 하는지 알려준다."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    from core import db
    db.set_setting(dbp, "snmp_enabled", "0")
    fid = _fw(dbp)
    r = application.test_client().post("/api/firewalls/%d/snmp-probe" % fid)
    assert r.status_code == 400
    assert "SNMP" in r.get_json()["error"]


def test_probe_endpoint_unknown_firewall(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    r = application.test_client().post("/api/firewalls/9999/snmp-probe")
    assert r.status_code == 404


def test_firewall_ui_shows_load_and_probe():
    from pathlib import Path
    root = Path(__file__).parent.parent
    js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")
    html = (root / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    # v6.25.0: 방화벽 표의 부하 컬럼 제거(통계는 관제 전담) — SNMP 확인 버튼은 유지
    assert "snmp-probe-fw" in js and "function snmpProbeFirewall" in js
    assert ">부하</th>" not in html[html.index('id="fw-check-all"'):
                                    html.index('id="fw-check-all"') + 900]


# --- v6.24.0: CPU 코어 폴백 · 디스크 없음 구분 -------------------------------

def test_cpu_falls_back_to_per_core_average(monkeypatch):
    """fgSysCpuUsage를 안 주는 펌웨어 — 코어별 테이블 평균으로 폴백.

    실장비에서 'MEM만 나오고 CPU가 빈' 신고의 원인 후보다.
    """
    s = dict(_HEALTHY)
    del s[fg._FG_CPU]
    sess = FakeSession(scalars=s, tables={
        fg._FG_PROC_USAGE: [("1", 10), ("2", 20), ("3", 30), ("4", 20)]})
    _patch(monkeypatch, sess)
    assert fg.collect_health("10.0.0.1")["cpu_pct"] == 20


def test_cpu_scalar_wins_over_core_table(monkeypatch):
    _patch(monkeypatch, FakeSession(scalars=_HEALTHY, tables={
        fg._FG_PROC_USAGE: [("1", 99)]}))
    assert fg.collect_health("10.0.0.1")["cpu_pct"] == 12


def test_disk_capacity_zero_means_absent_not_missing(monkeypatch):
    """로그 디스크 없는 모델(용량 0)은 '수집 실패'가 아니라 '디스크 없음'이다."""
    s = dict(_HEALTHY, **{fg._FG_DISK_USED: 0, fg._FG_DISK_CAP: 0})
    _patch(monkeypatch, FakeSession(scalars=s))
    h = fg.collect_health("10.0.0.1")
    assert h.get("disk_absent") is True and "disk_pct" not in h
