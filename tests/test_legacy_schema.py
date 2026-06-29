"""구버전 DB(스키마 마이그레이션 전) 호환 테스트.

증상: 수동 추가 시 'ON CONFLICT clause does not match any unique constraint'.
원인: 구버전 switches 테이블에 name UNIQUE 제약이 없는데 import_switches_bulk가
      ON CONFLICT(name)을 사용했음. → 수동 UPSERT로 수정.
"""
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


def _make_legacy_switches_db(db_path):
    """name에 UNIQUE 제약이 없는 구버전 switches 테이블 생성."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE switches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL,
            hostname TEXT,
            vendor TEXT DEFAULT 'unknown',
            model TEXT,
            location TEXT,
            status TEXT DEFAULT 'new',
            alert TEXT DEFAULT 'none',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_collected TIMESTAMP,
            cred_blob TEXT
        )
    """)
    conn.commit()
    conn.close()


def test_import_switches_bulk_legacy_db_no_unique(tmp_path):
    """name UNIQUE 제약이 없는 구버전 DB에서도 수동 추가가 성공한다."""
    db_path = tmp_path / "legacy.db"
    _make_legacy_switches_db(db_path)

    # 첫 등록 (이전엔 여기서 ON CONFLICT 오류 → 500)
    ids = db.import_switches_bulk(str(db_path), [
        {"name": "SW1", "ip": "10.0.0.1", "vendor": "cisco"},
    ])
    assert ids[0] is not None

    # 재등록(동일 name) → 멱등 UPDATE, 같은 id, ip 갱신
    ids2 = db.import_switches_bulk(str(db_path), [
        {"name": "SW1", "ip": "10.0.0.2", "vendor": "cisco"},
    ])
    assert ids2[0] == ids[0]

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT ip FROM switches WHERE name='SW1'").fetchall()
    conn.close()
    assert len(rows) == 1          # 중복 INSERT 없음
    assert rows[0][0] == "10.0.0.2"  # ip 갱신됨


def test_import_switches_bulk_current_schema(temp_db):
    """현재 스키마(name UNIQUE)에서도 정상 동작."""
    ids = db.import_switches_bulk(temp_db, [{"name": "SW-A", "ip": "10.0.0.5", "vendor": "arista"}])
    assert ids[0] is not None
    ids2 = db.import_switches_bulk(temp_db, [{"name": "SW-A", "ip": "10.0.0.6", "vendor": "arista"}])
    assert ids2[0] == ids[0]
