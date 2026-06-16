import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_lock = threading.Lock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS switches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    ip            TEXT NOT NULL UNIQUE,
    vendor        TEXT,
    model         TEXT,
    grp           TEXT,
    service       TEXT,
    location      TEXT,
    status        TEXT DEFAULT 'pending'
                  CHECK(status IN ('pending','collecting','done','failed','unsupported')),
    last_collected TEXT,
    error         TEXT,
    cred_blob     BLOB
);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id   INTEGER NOT NULL REFERENCES switches(id),
    collected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    switch_id   INTEGER NOT NULL REFERENCES switches(id),
    name        TEXT,
    link        TEXT,
    vlan        TEXT,
    speed       TEXT,
    descr       TEXT,
    flap_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mac_entries (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    switch_id   INTEGER NOT NULL REFERENCES switches(id),
    vlan        TEXT,
    mac         TEXT,
    port        TEXT
);

CREATE TABLE IF NOT EXISTS arp_entries (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    switch_id   INTEGER NOT NULL REFERENCES switches(id),
    ip          TEXT,
    mac         TEXT,
    interface   TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL UNIQUE,
    hostname      TEXT,
    grp           TEXT,
    building      TEXT,
    service       TEXT,
    note          TEXT,
    ledger_switch TEXT,
    ledger_port   TEXT,
    ping          INTEGER,
    ping_at       TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id  INTEGER REFERENCES switches(id),
    port       TEXT,
    type       TEXT CHECK(type IN ('flapping','disconnected')),
    detail     TEXT,
    created_at TEXT NOT NULL
);
"""


def _connect(db_path: str) -> sqlite3.Connection:
    # Use check_same_thread=True and timeout=10s for thread-safe concurrent access
    # WAL mode improves concurrency for multi-threaded Flask apps
    conn = sqlite3.connect(db_path, check_same_thread=True, timeout=10)
    conn.row_factory = sqlite3.Row
    # Enable WAL (Write-Ahead Logging) for better concurrency
    conn.execute("PRAGMA journal_mode=WAL")
    # Enable foreign key constraint enforcement
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str) -> None:
    with _lock:
        try:
            conn = _connect(db_path)
            conn.executescript(SCHEMA_SQL)
            conn.commit()
            conn.close()
            logger.info(json.dumps({"event": "db_initialized", "db_path": db_path}))
        except sqlite3.Error as e:
            logger.error(json.dumps({"event": "db_init_error", "db_path": db_path, "error": str(e)}))
            raise


def get_switches(db_path: str) -> list[dict[str, Any]]:
    """Fetch all switches. Raises sqlite3.Error if DB operation fails."""
    # Protect read with lock to prevent race conditions with concurrent upserts
    with _lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute("SELECT * FROM switches ORDER BY id").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def upsert_switch(db_path: str, row: dict[str, Any]) -> int:
    """Upsert a switch and return its ID (using INSERT RETURNING to avoid N+1 query)."""
    if not row.get("ip"):
        raise ValueError("upsert_switch: ip is required")
    with _lock:
        conn = None
        try:
            conn = _connect(db_path)
            cur = conn.execute(
                """
                INSERT INTO switches (name, ip, vendor, model, grp, service, location, status)
                VALUES (:name, :ip, :vendor, :model, :grp, :service, :location, :status)
                ON CONFLICT(ip) DO UPDATE SET
                    name=excluded.name,
                    vendor=excluded.vendor,
                    model=excluded.model,
                    grp=excluded.grp,
                    service=excluded.service,
                    location=excluded.location,
                    status=excluded.status
                RETURNING id
                """,
                {
                    "name": row.get("name", ""),
                    "ip": row["ip"],
                    "vendor": row.get("vendor"),
                    "model": row.get("model"),
                    "grp": row.get("grp"),
                    "service": row.get("service"),
                    "location": row.get("location"),
                    "status": row.get("status", "pending"),
                },
            )
            switch_id = cur.fetchone()[0]
            conn.commit()
            logger.info(json.dumps({"event": "upsert_switch", "ip": row["ip"], "switch_id": switch_id}))
            return switch_id
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(json.dumps({"event": "upsert_switch_error", "ip": row.get("ip"), "error": str(e)}))
            raise
        finally:
            if conn:
                conn.close()


def save_snapshot(db_path: str, switch_id: int, parsed: dict) -> int:
    if parsed is None:
        raise ValueError("save_snapshot: parsed cannot be None")
    with _lock:
        conn = None
        try:
            conn = _connect(db_path)
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.execute(
                "INSERT INTO snapshots (switch_id, collected_at) VALUES (?, ?)",
                (switch_id, now),
            )
            snapshot_id = cur.lastrowid

            for p in parsed.get("ports") or []:
                conn.execute(
                    "INSERT INTO ports (snapshot_id, switch_id, name, link, vlan, speed, descr, flap_count) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (snapshot_id, switch_id,
                     p.get("name"), p.get("link"), p.get("vlan"),
                     p.get("speed"), p.get("descr"), p.get("flap_count", 0)),
                )

            for m in parsed.get("mac_entries") or []:
                conn.execute(
                    "INSERT INTO mac_entries (snapshot_id, switch_id, vlan, mac, port) VALUES (?, ?, ?, ?, ?)",
                    (snapshot_id, switch_id, m.get("vlan"), m.get("mac"), m.get("port")),
                )

            for a in parsed.get("arp_entries") or []:
                conn.execute(
                    "INSERT INTO arp_entries (snapshot_id, switch_id, ip, mac, interface) VALUES (?, ?, ?, ?, ?)",
                    (snapshot_id, switch_id, a.get("ip"), a.get("mac"), a.get("interface")),
                )

            conn.commit()
            logger.info(json.dumps({"event": "save_snapshot", "switch_id": switch_id, "snapshot_id": snapshot_id}))
            return snapshot_id
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(json.dumps({"event": "save_snapshot_error", "switch_id": switch_id, "error": str(e)}))
            raise
        finally:
            if conn:
                conn.close()


def latest_snapshot_id(db_path: str, switch_id: int) -> int | None:
    """Fetch latest snapshot ID for a switch. Raises sqlite3.Error if DB operation fails."""
    # Protect read with lock to prevent race conditions with concurrent saves
    with _lock:
        conn = _connect(db_path)
        try:
            row = conn.execute(
                "SELECT id FROM snapshots WHERE switch_id=? ORDER BY id DESC LIMIT 1",
                (switch_id,),
            ).fetchone()
            return row["id"] if row else None
        finally:
            conn.close()


def get_ports(db_path: str, snapshot_id: int) -> list[dict[str, Any]]:
    """Fetch ports for a snapshot. Raises sqlite3.Error if DB operation fails."""
    # Protect read with lock to prevent race conditions with concurrent inserts
    with _lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM ports WHERE snapshot_id=?", (snapshot_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_mac_count(db_path: str, snapshot_id: int) -> int:
    """Count MAC entries for a snapshot. Raises sqlite3.Error if DB operation fails."""
    # Protect read with lock to prevent race conditions with concurrent inserts
    with _lock:
        conn = _connect(db_path)
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM mac_entries WHERE snapshot_id=?", (snapshot_id,)
            ).fetchone()
            return row["cnt"] if row else 0
        finally:
            conn.close()


def get_switches_with_snapshot_info(db_path: str) -> list[dict[str, Any]]:
    """Fetch all switches with their latest snapshot info (snapshot_id, port_count, mac_count) in a single query.
    Optimizes N+1 query pattern by using SQL aggregation instead of multiple individual queries."""
    # Fix for WARNING: N+1 Query Pattern in /api/state endpoint
    with _lock:
        conn = _connect(db_path)
        try:
            rows = conn.execute("""
                WITH latest_snapshots AS (
                  SELECT switch_id, MAX(id) as id
                  FROM snapshots
                  GROUP BY switch_id
                ),
                port_counts AS (
                  SELECT snapshot_id, COUNT(*) as port_count
                  FROM ports
                  GROUP BY snapshot_id
                ),
                mac_counts AS (
                  SELECT snapshot_id, COUNT(*) as mac_count
                  FROM mac_entries
                  GROUP BY snapshot_id
                )
                SELECT
                  s.id, s.name, s.ip, s.vendor, s.model, s.status, s.last_collected,
                  ls.id as snapshot_id,
                  COALESCE(pc.port_count, 0) as port_count,
                  COALESCE(mc.mac_count, 0) as mac_count
                FROM switches s
                LEFT JOIN latest_snapshots ls ON s.id = ls.switch_id
                LEFT JOIN port_counts pc ON ls.id = pc.snapshot_id
                LEFT JOIN mac_counts mc ON ls.id = mc.snapshot_id
                ORDER BY s.id
            """).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def update_switch_status(db_path: str, switch_id: int, status: str, error: str | None = None) -> None:
    with _lock:
        conn = None
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn = _connect(db_path)
            conn.execute(
                "UPDATE switches SET status=?, last_collected=?, error=? WHERE id=?",
                (status, now, error, switch_id),
            )
            conn.commit()
            logger.info(json.dumps({"event": "update_switch_status", "switch_id": switch_id, "status": status}))
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(json.dumps({"event": "update_switch_status_error", "switch_id": switch_id, "error": str(e)}))
            raise
        finally:
            if conn:
                conn.close()
