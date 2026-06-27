"""M5: 비동기 자격증명 처리 테스트.

검증 목표:
- 큐 페이로드에 평문 자격증명이 들어가지 않는다 (CWE-522).
- 자격증명은 세션 저장소를 경유한다.
- 워커가 수집 완료/실패와 무관하게 세션 자격증명을 폐기한다.
"""
import queue as _queue
import time
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, credentials, db
from core.config_loader import Config


@pytest.fixture
def isolated_collector():
    """워커 없는 큐와 깨끗한 자격증명 저장소를 제공 (페이로드 직접 검사용)."""
    saved_queue = collector._worker_queue
    saved_set = collector._collecting_switches
    collector._worker_queue = _queue.Queue(maxsize=100)
    collector._collecting_switches = set()
    credentials.clear_session()
    yield collector._worker_queue
    credentials.clear_session()
    collector._worker_queue = saved_queue
    collector._collecting_switches = saved_set


def _make_cfg(temp_db, raw_dir, demo_mode):
    return Config(
        db_path=str(temp_db),
        app={"demo_mode": demo_mode},
        collector={"max_concurrent": 1},
        raw_outputs={"path": str(raw_dir)},
        database={"path": str(temp_db)},
    )


def _wait_for_status(temp_db, switch_id, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sw = db.get_switch(temp_db, switch_id)
        if sw and sw["status"] in ("done", "failed"):
            return sw["status"]
        time.sleep(0.1)
    sw = db.get_switch(temp_db, switch_id)
    return sw["status"] if sw else None


# 1. 큐 페이로드에 자격증명 미포함 (2-튜플)
def test_collect_switch_payload_excludes_credentials(isolated_collector, temp_db):
    q = isolated_collector
    result = collector.collect_switch(temp_db, 7, "admin", "secret-pass")
    assert result["status"] == "queued"
    payload = q.get_nowait()
    assert payload == (temp_db, 7)
    assert len(payload) == 2


# 2. 직접 전달한 자격증명이 세션 저장소에 보관됨
def test_collect_switch_stores_credential_in_session(isolated_collector, temp_db):
    collector.collect_switch(temp_db, 8, "admin", "secret-pass")
    cred = credentials.load_credential(8)
    assert cred is not None
    assert cred["username"] == "admin"
    assert cred["password"] == "secret-pass"


# 3. 큐 페이로드 어디에도 평문 비밀번호 문자열이 없음
def test_collect_switch_payload_has_no_plaintext_password(isolated_collector, temp_db):
    q = isolated_collector
    collector.collect_switch(temp_db, 9, "admin", "topsecret123")
    payload = q.get_nowait()
    assert "topsecret123" not in repr(payload)


# 4. 큐가 가득 차면 세션 자격증명을 즉시 폐기
def test_queue_full_clears_credential(temp_db):
    saved_queue = collector._worker_queue
    saved_set = collector._collecting_switches
    collector._worker_queue = _queue.Queue(maxsize=1)
    collector._collecting_switches = set()
    credentials.clear_session()
    try:
        r1 = collector.collect_switch(temp_db, 1, "u1", "p1")
        assert r1["status"] == "queued"
        r2 = collector.collect_switch(temp_db, 2, "u2", "p2")
        assert r2["status"] == "error"
        assert credentials.load_credential(2) is None
    finally:
        credentials.clear_session()
        collector._worker_queue = saved_queue
        collector._collecting_switches = saved_set


# 5. 동일 스위치 중복 수집 요청 거부
def test_already_in_progress_returns_error(isolated_collector, temp_db):
    r1 = collector.collect_switch(temp_db, 3, "u", "p")
    assert r1["status"] == "queued"
    r2 = collector.collect_switch(temp_db, 3, "u", "p")
    assert r2["status"] == "error"
    assert "already" in r2["message"].lower()


# 6. 워커가 수집 완료 후 세션 자격증명을 폐기 (demo 통합)
def test_worker_clears_credential_after_collection(monkeypatch, temp_db, tmp_path):
    cfg = _make_cfg(temp_db, tmp_path / "raw", demo_mode=True)
    monkeypatch.setattr(collector, "get_config", lambda: cfg)
    credentials.clear_session()
    collector._worker_queue = None
    collector._collecting_switches = set()

    switch_id = db.save_switch(temp_db, "SW-DEMO", "10.0.0.10", "cisco_ios")
    collector.collect_switch(temp_db, switch_id, "admin", "pass")

    status = _wait_for_status(temp_db, switch_id)
    assert status == "done"
    assert credentials.load_credential(switch_id) is None


# 7. 실서버 모드 + 자격증명 부재 → 명시적 실패 (크래시 없음)
def test_worker_missing_credential_fails_gracefully(monkeypatch, temp_db, tmp_path):
    cfg = _make_cfg(temp_db, tmp_path / "raw", demo_mode=False)
    monkeypatch.setattr(collector, "get_config", lambda: cfg)
    credentials.clear_session()
    collector._worker_queue = None
    collector._collecting_switches = set()

    switch_id = db.save_switch(temp_db, "SW-PROD", "10.0.0.20", "cisco_ios")
    # 자격증명 없이 큐잉 → 워커가 세션에서 로드 실패 → failed
    collector.collect_switch(temp_db, switch_id)

    status = _wait_for_status(temp_db, switch_id)
    assert status == "failed"
    assert credentials.load_credential(switch_id) is None


# 8. [Codex R1 Critical-1 회귀] 중복 요청이 진행 중인 작업의 자격증명을 훼손하지 않음
def test_duplicate_request_preserves_active_credential(isolated_collector, temp_db):
    r1 = collector.collect_switch(temp_db, 11, "admin", "first-pass")
    assert r1["status"] == "queued"
    # 동일 switch에 다른 자격증명으로 재요청 → in-progress 거부 (저장 전에 반환)
    r2 = collector.collect_switch(temp_db, 11, "attacker", "second-pass")
    assert r2["status"] == "error"
    # 첫 요청의 자격증명이 덮어써지거나 삭제되지 않고 그대로 유지되어야 함
    cred = credentials.load_credential(11)
    assert cred is not None
    assert cred["username"] == "admin"
    assert cred["password"] == "first-pass"


# 9. [Codex R1 W2 회귀] load_credential은 방어적 복사본을 반환 (원본 불변)
def test_load_credential_returns_defensive_copy(temp_db):
    credentials.clear_session()
    try:
        credentials.save_credential(20, "user", "pass")
        c1 = credentials.load_credential(20)
        c1["password"] = "TAMPERED"
        c1["username"] = "TAMPERED"
        c2 = credentials.load_credential(20)
        assert c2["password"] == "pass"
        assert c2["username"] == "user"
    finally:
        credentials.clear_session()
