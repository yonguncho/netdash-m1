"""타임스탬프 로컬시간 일원화 테스트 — v3.97.

과거: SQLite CURRENT_TIMESTAMP/datetime('now')=UTC 저장 → 화면 시간이
PC 시간보다 9시간(KST) 이전으로 표시. 검증 목표:
- 신규 기록(알람/감사/스냅샷/백업)의 ts가 PC 로컬 시간(±2분).
- 기존 UTC 데이터가 1회 마이그레이션으로 로컬 시간 변환 + 플래그로 재실행 방지.
"""
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


@pytest.fixture
def temp_db(tmp_path):
    p = tmp_path / "test.db"
    db.init_schema(p)
    return p


def _close_to_now(ts_str, tol_min=2):
    ts = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
    return abs((datetime.now() - ts).total_seconds()) < tol_min * 60


def test_new_records_use_local_time(temp_db):
    """알람/감사 로그의 ts = PC 로컬 시간(UTC가 아님)."""
    db.save_device_event(temp_db, "flapping", "warning", label="SW1",
                         message="플래핑 감지")
    db.save_audit(temp_db, "10.0.0.5", "수집 실행")
    ev = db.list_device_events(temp_db, limit=1)[0]
    au = db.list_audit(temp_db, limit=1)[0]
    assert _close_to_now(ev["ts"]), "device_events.ts가 로컬 시간이 아님: %s" % ev["ts"]
    assert _close_to_now(au["ts"]), "audit_log.ts가 로컬 시간이 아님: %s" % au["ts"]


def test_snapshot_and_config_backup_local_time(temp_db):
    sid = db.save_switch(temp_db, "TSW", "10.0.0.7", "cisco_ios")
    snap_id = db.save_snapshot(temp_db, sid, 3)
    db.save_config_backup(temp_db, sid, "hostname TSW\ninterface Gi1/0/1")
    conn = sqlite3.connect(str(temp_db))
    try:
        snap_ts = conn.execute("SELECT collected_at FROM snapshots WHERE id=?",
                               (snap_id,)).fetchone()[0]
        cfg_ts = conn.execute("SELECT ts FROM config_backups WHERE switch_id=?",
                              (sid,)).fetchone()[0]
    finally:
        conn.close()
    assert _close_to_now(snap_ts)
    assert _close_to_now(cfg_ts)


def test_migration_converts_existing_utc_rows(tmp_path):
    """구버전 DB의 UTC ts가 init_schema 1회 마이그레이션으로 로컬 시간이 된다."""
    p = tmp_path / "old.db"
    db.init_schema(p)
    # 마이그레이션이 다시 돌도록 플래그 제거 + UTC 행 주입(구버전 저장 모사)
    conn = sqlite3.connect(str(p))
    conn.execute("DELETE FROM app_settings WHERE key='ts_localtime_migrated'")
    conn.execute("INSERT INTO device_events (kind, severity, ts) "
                 "VALUES ('flapping', 'warning', datetime('now'))")   # UTC
    utc_ts = conn.execute("SELECT ts FROM device_events").fetchone()[0]
    expected_local = conn.execute("SELECT datetime(?, 'localtime')",
                                  (utc_ts,)).fetchone()[0]
    conn.commit()
    conn.close()

    db.init_schema(p)   # 마이그레이션 실행
    conn = sqlite3.connect(str(p))
    try:
        got = conn.execute("SELECT ts FROM device_events").fetchone()[0]
        flag = conn.execute("SELECT value FROM app_settings "
                            "WHERE key='ts_localtime_migrated'").fetchone()
    finally:
        conn.close()
    assert got == expected_local     # UTC → 로컬 변환됨
    assert flag and flag[0] == "1"   # 플래그 설정 — 재실행 방지


def test_migration_runs_only_once(temp_db):
    """플래그가 있으면 재변환하지 않는다(이중 변환으로 +18시간 밀림 방지)."""
    db.save_device_event(temp_db, "flapping", "warning", label="SW1")
    before = db.list_device_events(temp_db, limit=1)[0]["ts"]
    db.init_schema(temp_db)   # 재기동 모사 — 플래그 존재 → 변환 없음
    after = db.list_device_events(temp_db, limit=1)[0]["ts"]
    assert before == after
