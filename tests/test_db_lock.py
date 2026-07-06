# -*- coding: utf-8 -*-
"""database is locked 대책 — WAL 모드 + busy timeout + 동시 쓰기 스트레스."""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


def test_wal_mode_enabled(temp_db):
    """연결이 WAL 저널 모드로 동작(읽기/쓰기 병행 → 락 경합 감소)."""
    with db.get_db(temp_db) as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        bt = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert int(bt) >= 30000


def test_concurrent_writes_no_lock_error(temp_db):
    """스레드 8개가 동시에 읽고 쓰기 반복 — 'database is locked' 미발생.

    실장비 증상: 수집 워커·설비 수집·도달성 체크 동시 쓰기 중 수집 중단.
    """
    errors = []

    def writer(n):
        try:
            for i in range(30):
                sid = db.save_switch(temp_db, "SW-%d-%d" % (n, i),
                                     "10.%d.%d.%d" % (n % 200 + 1, (i // 250) % 250, i % 250 + 1),
                                     "cisco_ios")
                db.set_switch_status(temp_db, sid, "done")
                db.get_switches(temp_db)   # 읽기 병행
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, "동시 쓰기 오류: %s" % errors[:3]
    assert len(db.get_switches(temp_db)) == 240
