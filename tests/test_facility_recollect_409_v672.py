# -*- coding: utf-8 -*-
"""관제 재수집이 409로 막히던 문제 (v6.7.2).

사용자 보고: "관제에서 연결 실패한 설비의 재수집 버튼을 누르면
POST /api/facility/recollect 409 가 난다."

409 자체는 정상 동작이다 — 대역 수집은 스위치 제어평면 부담 때문에 동시에
하나만 돈다. 문제는 두 가지였다.

① **잔류 플래그**: 수집 스레드가 비정상 종료하면 `running=True`가 남아, 그 뒤
   모든 재수집이 영영 409가 됐다. 되돌릴 방법이 exe 재시작뿐이었다.
② **쓸모없는 메시지**: '이미 수집 중입니다' 한 줄뿐이라 무엇이 왜 막는지 알 수
   없었다. 사용자에겐 버튼이 고장난 것으로 보인다.
"""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import facility  # noqa: E402

ROOT = Path(__file__).parent.parent


def _reset():
    with facility._lock:
        facility._status.update(running=False, subnet=None, done=0, total=0,
                                message="", started_at=None)
        facility._worker = None
        facility._stop_requested = False


# ── ① 잔류 플래그 자가 복구 ─────────────────────────────────────
def test_dead_worker_flag_is_cleared():
    """스레드가 이미 끝났으면 '수집 중'이라고 우길 근거가 없다."""
    _reset()
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()
    with facility._lock:
        facility._status["running"] = True
        facility._worker = t
    assert facility.get_status()["running"] is False, \
        "죽은 스레드의 잔류 플래그가 안 풀린다 — 재수집이 영영 409가 된다"
    _reset()          # 죽은 _worker를 남기면 다음 테스트의 상태가 오염된다


def test_finished_run_does_not_leave_dead_owner(monkeypatch, temp_db):
    """끝난 스레드를 주인으로 남기면, 나중에 켜진 running이 엉뚱하게 초기화된다."""
    _reset()
    monkeypatch.setattr(facility, "collect_band", lambda *a, **k: {"subnet": "x"})
    try:
        facility.start_collect_band(temp_db, 1, "10.0.0.0/24", "u", "p")
        for _ in range(60):
            if not facility.get_status()["running"]:
                break
            time.sleep(0.05)
        with facility._lock:
            assert facility._worker is None, "끝난 스레드가 주인으로 남아 있다"
    finally:
        _reset()


def test_live_worker_flag_is_kept():
    """진행 중인 수집을 '끝났다'고 단정하면 두 개가 동시에 돈다."""
    _reset()
    go = threading.Event()
    t = threading.Thread(target=go.wait, daemon=True)
    t.start()
    try:
        with facility._lock:
            facility._status["running"] = True
            facility._worker = t
        assert facility.get_status()["running"] is True
    finally:
        go.set()
        t.join(2)
    _reset()


def test_unknown_owner_flag_is_kept():
    """주인 스레드를 모르면 판단 근거가 없다 — 함부로 풀지 않는다."""
    _reset()
    with facility._lock:
        facility._status["running"] = True
        facility._worker = None
    assert facility.get_status()["running"] is True
    _reset()


def test_start_clears_stale_flag_and_proceeds(monkeypatch, temp_db):
    """잔류 플래그가 있어도 새 수집은 시작돼야 한다."""
    _reset()
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    with facility._lock:
        facility._status["running"] = True
        facility._worker = dead
    done = threading.Event()
    monkeypatch.setattr(facility, "collect_band",
                        lambda *a, **k: done.set() or {"subnet": "10.0.0.0/24"})
    try:
        assert facility.start_collect_band(temp_db, 1, "10.0.0.0/24", "u", "p") is True
        assert done.wait(5), "수집이 시작되지 않았다"
    finally:
        for _ in range(50):
            if not facility.get_status()["running"]:
                break
            time.sleep(0.05)
        _reset()


def test_running_flag_cleared_even_if_collect_band_forgets(monkeypatch, temp_db):
    """collect_band가 running=False를 놓치는 경로가 있어도 남으면 안 된다."""
    _reset()
    monkeypatch.setattr(facility, "collect_band", lambda *a, **k: {"subnet": "x"})
    try:
        assert facility.start_collect_band(temp_db, 1, "10.0.0.0/24", "u", "p") is True
        for _ in range(60):
            if not facility.get_status()["running"]:
                break
            time.sleep(0.05)
        assert facility.get_status()["running"] is False
    finally:
        _reset()


def test_exception_does_not_strand_flag(monkeypatch, temp_db):
    _reset()

    def boom(*a, **k):
        raise RuntimeError("연결 실패")

    monkeypatch.setattr(facility, "collect_band", boom)
    try:
        assert facility.start_collect_band(temp_db, 1, "10.0.0.0/24", "u", "p") is True
        for _ in range(60):
            if not facility.get_status()["running"]:
                break
            time.sleep(0.05)
        assert facility.get_status()["running"] is False
    finally:
        _reset()


# ── ② 무엇이 막는지 알려준다 ────────────────────────────────────
def test_busy_reason_names_subnet_and_progress():
    _reset()
    alive = threading.Event()
    t = threading.Thread(target=alive.wait, daemon=True)
    t.start()
    try:
        with facility._lock:
            facility._status.update(running=True, subnet="10.20.30.0/24",
                                    done=120, total=254,
                                    started_at=time.time() - 95)
            facility._worker = t
        why = facility.busy_reason()
        assert "10.20.30.0/24" in why and "120/254" in why, why
        assert "분" in why, "얼마나 걸렸는지 없으면 기다릴지 멈출지 판단이 안 된다: %s" % why
    finally:
        alive.set()
        t.join(2)
        _reset()


def test_busy_reason_empty_when_idle():
    _reset()
    assert facility.busy_reason() == ""


# v6.9.0 추가 개선: 애초에 '재수집' 버튼이 대역 전체를 다시 스캔하는 것 자체가
# 409의 근본 원인이었다(사용자 요청 — 재수집 버튼을 누른 설비 하나만 재확인해야
# 한다). facility_recollect를 단일 설비 재확인(recollect_single_host)으로
# 바꾸면서, 대역 전체 스캔과 경합할 일이 없어져 busy/409/재시도 UX 자체가
# 필요 없어졌다. 아래 두 테스트는 그 재설계를 검증한다(예전 assertion은
# git 이력에 남아 있다).
def test_recollect_route_no_longer_competes_with_band_scan():
    """단일 설비 재확인은 대역 전체 스캔(_status.running)과 경합하지 않는다."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index("def facility_recollect():")
    block = src[i:i + 2200]
    assert "recollect_single_host" in block, "단일 설비 재확인 경로를 쓰지 않는다"
    assert "start_collect_band" not in block, \
        "대역 전체 스캔을 다시 트리거하면 busy/409 문제가 재발한다"
    assert "busy_reason" not in block


def test_frontend_no_longer_needs_stop_and_retry():
    """대역 전체와 경합하지 않으니 '중지 후 재시도' UX가 필요 없다."""
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    i = js.index("function startRecollect(")
    block = js[i:i + 900]
    assert "/api/facility/stop" not in block
    assert "confirm(" not in block, "더 이상 물어볼 필요가 없는 동작이다"


def test_status_exposes_elapsed():
    """진행 시간이 없으면 '기다릴지 멈출지'를 사용자가 못 정한다."""
    _reset()
    st = facility.get_status()
    assert "elapsed_sec" in st and st["elapsed_sec"] == 0
