"""읽기 전용 모드 테스트 — 다중 PC 동시접속(조회 허용 + 쓰기 알림).

주 서버가 인스턴스 락을 보유 중일 때 두 번째 인스턴스는 readonly_info와 함께
기동한다. 검증 목표:
- GET(조회)은 정상 동작, /api/state에 readonly/primary_host 포함.
- POST/PUT/DELETE(수집·수정·삭제)는 423 + 한국어 안내 메시지.
- 수집 워커·스케줄러 등 쓰기 백그라운드가 시작되지 않음.
- DB 연결이 query_only — 코드 실수로도 쓰기 불가(안전벨트).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, db


@pytest.fixture
def readonly_app(tmp_path, monkeypatch):
    """주 서버가 만든 DB 위에서 읽기 전용 인스턴스를 기동."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    # 1) 주 서버 역할: 스키마 생성 (demo 데이터 포함)
    primary = app_module.create_app(demo_mode=True)
    # 주 서버 워커는 이 테스트와 무관 — 종료해 격리
    collector.shutdown_workers()
    # 2) 읽기 전용 인스턴스 기동 (주 서버 정보 전달)
    ro = app_module.create_app(
        demo_mode=True, readonly_info={"hostname": "PRIMARY-PC",
                                       "url": "http://10.0.0.1:8082"})
    yield ro
    db.READONLY = False  # 전역 플래그 원복 (다른 테스트 오염 방지)


def test_readonly_get_state_works_and_flagged(readonly_app):
    client = readonly_app.test_client()
    r = client.get("/api/state")
    assert r.status_code == 200
    data = r.get_json()
    assert data["readonly"] is True
    assert data["primary_host"] == "PRIMARY-PC"
    assert isinstance(data["switches"], list)  # 조회는 정상


def test_readonly_write_blocked_with_message(readonly_app):
    client = readonly_app.test_client()
    for method, path in [
        ("post", "/api/switches/manual"),
        ("post", "/api/switches/1/collect"),
        ("post", "/api/switches/bulk-collect"),
        ("put", "/api/switches/1"),
        ("delete", "/api/switches/1"),
    ]:
        r = getattr(client, method)(path, json={})
        assert r.status_code == 423, f"{method} {path} → {r.status_code}"
        body = r.get_json()
        assert "PRIMARY-PC" in body["error"]
        assert body["readonly"] is True


def test_readonly_skips_write_background_threads(tmp_path, monkeypatch):
    """읽기 전용 기동은 수집 워커/스케줄러/도달성/알림을 시작하지 않는다."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    app_module.create_app(demo_mode=True)  # 스키마 준비
    collector.shutdown_workers()

    called = []
    monkeypatch.setattr(collector, "init_collector",
                        lambda: called.append("collector"))
    from core import scheduler, reachability, notifier
    monkeypatch.setattr(scheduler, "start_scheduler",
                        lambda dbp: called.append("scheduler"))
    monkeypatch.setattr(reachability, "start_monitor",
                        lambda dbp: called.append("reachability"))
    monkeypatch.setattr(notifier, "start_notifier",
                        lambda dbp: called.append("notifier"))
    try:
        app_module.create_app(demo_mode=True,
                              readonly_info={"hostname": "P"})
        assert called == []
    finally:
        db.READONLY = False


def test_readonly_connection_is_query_only(tmp_path, monkeypatch):
    """READONLY 플래그가 켜지면 get_db 연결로 쓰기 시도 시 실패(안전벨트)."""
    import sqlite3
    dbf = tmp_path / "t.db"
    db.init_schema(dbf)
    monkeypatch.setattr(db, "READONLY", True)
    with pytest.raises(sqlite3.OperationalError):
        with db.get_db(dbf) as conn:
            conn.execute("INSERT INTO app_settings(key,value) VALUES('x','y')")
