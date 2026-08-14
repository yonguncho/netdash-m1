# -*- coding: utf-8 -*-
"""v6.38.0 — 포트 에러 '증가분' 감지 (SNMP IF-MIB + EtherLike-MIB).

배경: ports 테이블에 crc/in/out error가 이미 있지만 **장비 부팅 이후 누적값**이라
100만이 3년 전 것인지 어제 것인지 구분되지 않았고, 상세보기 한 곳에서만 쓰였다.
주기적으로 읽어 증가분을 보면 '끊어지기 전' 물리 계층 열화를 잡을 수 있다.
"""
import os
import tempfile

import pytest

from core import db, metrics_poller as mp


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


# ── 델타 계산 ─────────────────────────────────────────────────────

def test_first_sample_is_baseline_only():
    """첫 관측을 증가로 세면 툴을 켠 순간 과거 누적이 통째로 '증가'가 된다."""
    prev = {}
    got = mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 100, "crc": 50}})
    assert got == {}
    assert prev["Gi1/0/1"]["in_err"] == 100      # 기준선은 잡혔다


def test_increase_is_reported():
    prev = {}
    mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 100, "crc": 50}})
    got = mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 150, "crc": 70}})
    assert got == {"Gi1/0/1": {"in_err": 50, "crc": 20}}


def test_no_change_reports_nothing():
    """대부분의 포트는 항상 0이다 — 변화 없으면 저장할 것도 없다."""
    prev = {}
    mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 7}})
    assert mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 7}}) == {}


def test_counter_reset_is_discarded():
    """32bit 카운터 리셋/랩을 증가로 세면 멀쩡한 포트가 수십억 에러가 된다."""
    prev = {}
    mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 4000000000}})
    got = mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 12}})
    assert got == {}                              # 음수 증가는 버린다
    # 리셋 이후 기준선이 갱신돼 다음 증가는 정상 계산
    assert mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 20}}) == \
        {"Gi1/0/1": {"in_err": 8}}


def test_missing_key_is_skipped_not_zeroed():
    """CRC 미지원 장비(EtherLike-MIB 없음)에서 crc 키가 빠져도 나머지는 센다."""
    prev = {}
    mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 10}})
    got = mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 15}})
    assert got == {"Gi1/0/1": {"in_err": 5}}
    assert "crc" not in got["Gi1/0/1"]


def test_new_port_appearing_later_is_baseline():
    prev = {}
    mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 1}})
    got = mp.compute_error_delta(prev, {"Gi1/0/1": {"in_err": 1},
                                        "Gi1/0/9": {"in_err": 500}})
    assert got == {}                              # 새 포트는 기준선만


# ── 저장·집계 ─────────────────────────────────────────────────────

def test_save_and_totals(dbf):
    db.save_port_error_points(dbf, [
        (1, "Gi1/0/1", 10, 0, 0, 0, 5),
        (1, "Gi1/0/1", 3, 0, 0, 0, 2),           # 같은 포트 두 주기 → 합산
        (1, "Gi1/0/2", 0, 0, 4, 0, 0),
    ])
    tot = db.get_port_error_totals(dbf, hours=24)
    by_port = {r["port"]: r for r in tot}
    assert by_port["Gi1/0/1"]["in_err"] == 13
    assert by_port["Gi1/0/1"]["crc"] == 7
    assert by_port["Gi1/0/1"]["total"] == 20
    assert by_port["Gi1/0/2"]["total"] == 4
    assert tot[0]["port"] == "Gi1/0/1"           # 많은 순 정렬


def test_totals_excludes_zero_rows(dbf):
    db.save_port_error_points(dbf, [(1, "Gi1/0/3", 0, 0, 0, 0, 0)])
    assert db.get_port_error_totals(dbf, hours=24) == []


def test_save_empty_is_noop(dbf):
    db.save_port_error_points(dbf, [])
    assert db.get_port_error_totals(dbf, hours=24) == []


def test_prune_keeps_recent(dbf):
    db.save_port_error_points(dbf, [(1, "Gi1/0/1", 5, 0, 0, 0, 0)])
    db.prune_port_error_history(dbf, days=7)
    assert len(db.get_port_error_totals(dbf, hours=24)) == 1   # 방금 것은 남는다


# ── 임계값 ────────────────────────────────────────────────────────

def test_alert_limit_default_and_setting(dbf):
    assert mp.error_alert_limit(dbf) == 10
    db.set_setting(dbf, "alert_port_errors", "50")
    assert mp.error_alert_limit(dbf) == 50
    db.set_setting(dbf, "alert_port_errors", "0")
    assert mp.error_alert_limit(dbf) == 0          # 0 = 알람 끔


def test_alert_limit_bad_value_falls_back(dbf):
    db.set_setting(dbf, "alert_port_errors", "이상한값")
    assert mp.error_alert_limit(dbf) == 10


# ── 수집 흐름 ─────────────────────────────────────────────────────

def _switch(dbf, name="SW1", ip="10.0.0.1"):
    db.save_switch(dbf, name, ip, "cisco_ios")
    return [s for s in db.get_switches(dbf) if s["ip"] == ip][0]


def test_collect_records_only_increases(dbf, monkeypatch):
    sw = _switch(dbf)
    seq = [
        {"Gi1/0/1": {"in_err": 100, "crc": 10}, "Gi1/0/2": {"in_err": 0}},
        {"Gi1/0/1": {"in_err": 130, "crc": 15}, "Gi1/0/2": {"in_err": 0}},
    ]
    calls = {"n": 0}

    def fake_walk(ip, community, budget=10.0):
        i = min(calls["n"], len(seq) - 1)
        calls["n"] += 1
        return seq[i]

    monkeypatch.setattr(mp, "_walk_errors", fake_walk)
    mp._prev_errors.clear()
    assert mp.collect_port_errors(dbf, "public") == 0      # 1주기: 기준선
    assert mp.collect_port_errors(dbf, "public") == 1      # 2주기: 늘어난 1포트만
    tot = db.get_port_error_totals(dbf, hours=24)
    assert len(tot) == 1 and tot[0]["port"] == "Gi1/0/1"
    assert tot[0]["in_err"] == 30 and tot[0]["crc"] == 5


def test_collect_raises_event_over_threshold(dbf, monkeypatch):
    _switch(dbf)
    db.set_setting(dbf, "alert_port_errors", "10")
    seq = [{"Gi1/0/1": {"in_err": 0}}, {"Gi1/0/1": {"in_err": 40}}]
    calls = {"n": 0}

    def fake(ip, c, budget=10.0):
        v = seq[min(calls["n"], 1)]
        calls["n"] += 1
        return v

    monkeypatch.setattr(mp, "_walk_errors", fake)
    mp._prev_errors.clear()
    mp.collect_port_errors(dbf, "public")
    mp.collect_port_errors(dbf, "public")
    evs = [e for e in db.list_device_events(dbf, limit=50)
           if e.get("kind") == "port_errors"]
    assert len(evs) == 1
    assert "Gi1/0/1" in evs[0]["message"] and "수신오류" in evs[0]["message"]


def test_collect_no_event_under_threshold(dbf, monkeypatch):
    _switch(dbf)
    db.set_setting(dbf, "alert_port_errors", "100")
    seq = [{"Gi1/0/1": {"in_err": 0}}, {"Gi1/0/1": {"in_err": 5}}]
    calls = {"n": 0}

    def fake(ip, c, budget=10.0):
        v = seq[min(calls["n"], 1)]
        calls["n"] += 1
        return v

    monkeypatch.setattr(mp, "_walk_errors", fake)
    mp._prev_errors.clear()
    mp.collect_port_errors(dbf, "public")
    mp.collect_port_errors(dbf, "public")
    assert [e for e in db.list_device_events(dbf, limit=50)
            if e.get("kind") == "port_errors"] == []
    # 알람은 안 나가도 이력은 남는다(관제 카드용)
    assert len(db.get_port_error_totals(dbf, hours=24)) == 1


def test_snmp_failure_is_silent(dbf, monkeypatch):
    """SNMP 미지원·차단 스위치가 있어도 나머지 수집은 계속돼야 한다."""
    _switch(dbf)

    def boom(ip, c, budget=10.0):
        raise RuntimeError("no snmp")

    monkeypatch.setattr(mp, "_walk_errors", boom)
    mp._prev_errors.clear()
    assert mp.collect_port_errors(dbf, "public") == 0


# ── 관제 집계·화면 ────────────────────────────────────────────────

def test_wallstats_exposes_port_errors(dbf):
    from core import wallstats
    sw = _switch(dbf, "SW-CORE", "10.0.0.9")
    db.save_port_error_points(dbf, [(sw["id"], "Gi1/0/5", 20, 0, 0, 0, 8)])
    s = wallstats.build(dbf)["switches"]
    assert s["port_errors"], "관제에 포트 에러가 실려야 한다"
    row = s["port_errors"][0]
    assert row["name"] == "SW-CORE" and row["port"] == "Gi1/0/5"
    assert row["total"] == 28
    assert row.get("id") == sw["id"]              # 클릭 → 상세 연동


def test_wall_js_renders_card():
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "web", "static", "wall.js")
    with open(p, encoding="utf-8") as f:
        js = f.read()
    assert "function portErrCard(" in js
    assert "portErrCard(s.port_errors" in js
    assert 'port_errors: "포트 에러 증가"' in js      # 관제 티커 표기


def test_poller_runs_error_step():
    import inspect
    src = inspect.getsource(mp.poll_once)
    assert "collect_port_errors" in src
