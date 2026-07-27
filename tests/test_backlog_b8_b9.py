# -*- coding: utf-8 -*-
"""백로그 B-8·B-9.

B-8 스케줄러가 지정 시각을 통째로 건너뛰었다(로그도 없음).
    루프 본문이 11초만 넘으면 주기가 60초를 넘어 특정 분이 관측되지 않았다.
B-9 기본 경로 NIC가 바뀌면 PC 프로필 계정이 조용히 사라졌다.
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, pcprofile, scheduler


def _dt(h, m, s=0):
    return datetime(2026, 7, 27, h, m, s)


# ── B-8: 놓친 슬롯 따라잡기 ───────────────────────────────────────
def test_slot_fires_when_minute_observed():
    due = scheduler.due_slots(["06:00"], _dt(5, 59, 30), _dt(6, 0, 20))
    assert [t for t, _ in due] == ["06:00"]


def test_slot_not_missed_when_loop_is_slow():
    """루프가 늦어 06:00을 한 번도 '현재 분'으로 못 봐도 실행돼야 한다."""
    # 05:59:50 → 06:01:10 (80초 주기 — 06:00분을 통째로 건너뜀)
    due = scheduler.due_slots(["06:00"], _dt(5, 59, 50), _dt(6, 1, 10))
    assert [t for t, _ in due] == ["06:00"], \
        "그날의 자동 수집이 실행되지 않고 로그도 남지 않는다"


def test_slot_fires_once_only():
    """이미 지나간 구간을 다시 보면 또 실행되면 안 된다."""
    assert scheduler.due_slots(["06:00"], _dt(6, 0, 20), _dt(6, 1, 10)) == []


def test_multiple_times():
    due = scheduler.due_slots(["06:00", "18:00"], _dt(5, 59), _dt(6, 1))
    assert [t for t, _ in due] == ["06:00"]
    due = scheduler.due_slots(["06:00", "18:00"], _dt(17, 59), _dt(18, 1))
    assert [t for t, _ in due] == ["18:00"]


def test_midnight_rollover():
    """23:59 예약을 00:00 이후에 확인해도 잡힌다."""
    due = scheduler.due_slots(["23:59"], _dt(23, 58, 40), _dt(0, 0, 30) + timedelta(days=0))
    # now가 같은 날 00:00:30 이라면 어제 23:59가 대상
    assert due == [] or due[0][0] == "23:59"
    due2 = scheduler.due_slots(["23:59"],
                               datetime(2026, 7, 26, 23, 58, 40),
                               datetime(2026, 7, 27, 0, 0, 30))
    assert [t for t, _ in due2] == ["23:59"]


def test_long_gap_does_not_backfire():
    """앱이 몇 시간 멈춰 있었으면 과거 슬롯을 소급 실행하지 않는다."""
    assert scheduler.due_slots(["06:00"], _dt(3, 0), _dt(9, 0)) == []


def test_first_iteration_does_not_fire():
    assert scheduler.due_slots(["06:00"], None, _dt(6, 0, 10)) == []


def test_invalid_time_is_ignored():
    assert scheduler.due_slots(["", "abc", "25:99"], _dt(5, 59), _dt(6, 1)) == []


def test_loop_sleep_is_adaptive():
    import inspect
    src = inspect.getsource(scheduler._loop)
    assert "time.monotonic() - t0" in src, "본문 소요를 빼지 않으면 주기가 60초를 넘긴다"
    assert "due_slots(" in src
    assert "last_check = now" in src


def test_late_fire_is_logged():
    import inspect
    src = inspect.getsource(scheduler._fire)
    assert "late_sec" in src, "늦게 실행된 사실이 로그에 남지 않는다"


# ── B-9: NIC 전환 시 계정 폴백 ────────────────────────────────────
def test_credential_survives_nic_change(temp_db, monkeypatch):
    from core import credentials
    blob = credentials.encrypt_credential("admin", "pw123")
    if not blob:
        import pytest
        pytest.skip("DPAPI 미지원 환경")
    # NIC A로 저장
    db.upsert_pc_profile(temp_db, "AA:AA:AA:AA:AA:AA", "MY-PC", "10.1.1.5", blob)
    # 기본 경로가 NIC B로 바뀐 상황
    monkeypatch.setattr(pcprofile, "get_local_identity",
                        lambda: {"mac": "BB:BB:BB:BB:BB:BB", "ip": "10.2.2.9",
                                 "hostname": "MY-PC"})
    assert pcprofile.get_credential(temp_db) == ("admin", "pw123"), \
        "NIC이 바뀌었다고 계정이 사라지면 자동 수집이 전 장비를 건너뛴다"


def test_other_pc_profile_is_not_used(temp_db, monkeypatch):
    from core import credentials
    blob = credentials.encrypt_credential("admin", "pw123")
    if not blob:
        import pytest
        pytest.skip("DPAPI 미지원 환경")
    db.upsert_pc_profile(temp_db, "CC:CC:CC:CC:CC:CC", "OTHER-PC", "10.3.3.3", blob)
    monkeypatch.setattr(pcprofile, "get_local_identity",
                        lambda: {"mac": "BB:BB:BB:BB:BB:BB", "ip": "10.2.2.9",
                                 "hostname": "MY-PC"})
    assert pcprofile.get_credential(temp_db) is None, \
        "다른 PC의 프로필 계정을 가져다 쓴다"


def test_exact_match_still_preferred(temp_db, monkeypatch):
    from core import credentials
    b1 = credentials.encrypt_credential("exact", "pw1")
    b2 = credentials.encrypt_credential("fallback", "pw2")
    if not b1:
        import pytest
        pytest.skip("DPAPI 미지원 환경")
    db.upsert_pc_profile(temp_db, "AA:AA:AA:AA:AA:AA", "MY-PC", "10.1.1.5", b2)
    db.upsert_pc_profile(temp_db, "BB:BB:BB:BB:BB:BB", "MY-PC", "10.2.2.9", b1)
    monkeypatch.setattr(pcprofile, "get_local_identity",
                        lambda: {"mac": "BB:BB:BB:BB:BB:BB", "ip": "10.2.2.9",
                                 "hostname": "MY-PC"})
    assert pcprofile.get_credential(temp_db) == ("exact", "pw1")


def test_no_profile_returns_none(temp_db, monkeypatch):
    monkeypatch.setattr(pcprofile, "get_local_identity",
                        lambda: {"mac": "ZZ", "ip": None, "hostname": "NOPE"})
    assert pcprofile.get_credential(temp_db) is None
