import sqlite3
import logging
import threading
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from . import utils

logger = logging.getLogger(__name__)

_db_lock = threading.Lock()
_UNSET = object()  # Sentinel value to distinguish default None from explicit None


CREATE_SWITCHES_TABLE = """
CREATE TABLE IF NOT EXISTS switches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    hostname TEXT,
    vendor TEXT NOT NULL DEFAULT 'unknown',
    model TEXT,
    location TEXT,
    status TEXT DEFAULT 'new',
    alert TEXT DEFAULT 'none',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_collected TIMESTAMP,
    cred_blob TEXT
)
"""

CREATE_PORT_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS port_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL,
    port_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (switch_id) REFERENCES switches(id)
)
"""

CREATE_SNAPSHOTS_TABLE = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    duration_seconds INTEGER,
    FOREIGN KEY (switch_id) REFERENCES switches(id)
)
"""

CREATE_PORTS_TABLE = """
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    switch_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT,
    vlan INTEGER,
    speed TEXT,
    description TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id),
    FOREIGN KEY (switch_id) REFERENCES switches(id),
    UNIQUE(snapshot_id, switch_id, name)
)
"""

CREATE_MAC_ENTRIES_TABLE = """
CREATE TABLE IF NOT EXISTS mac_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    switch_id INTEGER NOT NULL,
    vlan INTEGER,
    mac TEXT NOT NULL,
    port TEXT NOT NULL,
    entry_type TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id),
    FOREIGN KEY (switch_id) REFERENCES switches(id),
    UNIQUE(snapshot_id, switch_id, vlan, mac, port)
)
"""

CREATE_ARP_ENTRIES_TABLE = """
CREATE TABLE IF NOT EXISTS arp_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    switch_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    interface TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id),
    FOREIGN KEY (switch_id) REFERENCES switches(id),
    UNIQUE(snapshot_id, switch_id, ip)
)
"""

CREATE_HOSTS_TABLE = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    mac TEXT,
    switch_id INTEGER,
    port TEXT,
    located BOOLEAN DEFAULT 0,
    confidence REAL DEFAULT 0.0,
    reason TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (switch_id) REFERENCES switches(id)
)
"""

CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    event_name TEXT NOT NULL,
    switch_id INTEGER,
    snapshot_id INTEGER,
    data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (switch_id) REFERENCES switches(id),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
)
"""


@contextmanager
def get_db(db_path):
    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        # CRITICAL FIX (CWE-276): Restrict database file permissions to owner-only
        # Prevents unauthorized access to sensitive network topology data
        try:
            os.chmod(str(db_path), 0o600)
        except (OSError, NotImplementedError):
            # Windows or systems without chmod support; skip gracefully
            pass
        conn.row_factory = sqlite3.Row
        # Enable FOREIGN KEY constraints: SQLite defaults to OFF, explicit ON required (data integrity fix)
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        utils.log_event("error", "db_error", error=str(e))
        raise
    finally:
        if conn:
            conn.close()


def init_schema(db_path):
    utils.log_event("info", "db_init", db_path=str(db_path))
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for table_sql in [
                CREATE_SWITCHES_TABLE,
                CREATE_SNAPSHOTS_TABLE,
                CREATE_PORTS_TABLE,
                CREATE_MAC_ENTRIES_TABLE,
                CREATE_ARP_ENTRIES_TABLE,
                CREATE_HOSTS_TABLE,
                CREATE_EVENTS_TABLE,
                CREATE_PORT_EVENTS_TABLE,
            ]:
                cursor.execute(table_sql)
            # 기존 DB 마이그레이션: hostname, location, alert 컬럼 추가
            for col, definition in [
                ("hostname", "TEXT"),
                ("location", "TEXT"),
                ("alert", "TEXT DEFAULT 'none'"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE switches ADD COLUMN {col} {definition}")
                except Exception:
                    pass
            conn.commit()
            utils.log_event("info", "schema_created", tables=8)


def init_db(db_path):
    """Alias for init_schema (backward compatibility)."""
    return init_schema(db_path)


def validate_schema(db_path):
    required_tables = {"switches", "snapshots", "ports", "mac_entries", "arp_entries", "hosts", "events", "port_events"}
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing = {row[0] for row in cursor.fetchall()}
        missing = required_tables - existing
        if missing:
            raise RuntimeError(f"Missing tables: {missing}")
    utils.log_event("info", "schema_validated", tables=len(required_tables))


def import_switches_bulk(db_path, rows):
    """엑셀에서 파싱한 스위치 목록을 DB에 일괄 등록. rows: [{name, ip, hostname, vendor, location}]"""
    results = []
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for row in rows:
                name = row.get("name") or row.get("hostname") or row.get("ip")
                ip = row.get("ip", "")
                hostname = row.get("hostname", "")
                vendor = row.get("vendor", "unknown")
                location = row.get("location", "")
                cursor.execute(
                    """INSERT INTO switches (name, ip, hostname, vendor, location, status, alert)
                       VALUES (?, ?, ?, ?, ?, 'new', 'none')
                       ON CONFLICT(name) DO UPDATE SET
                         ip=excluded.ip, hostname=excluded.hostname,
                         vendor=excluded.vendor, location=excluded.location""",
                    (name, ip, hostname, vendor, location),
                )
                cursor.execute("SELECT id FROM switches WHERE name = ?", (name,))
                row_id = cursor.fetchone()
                results.append(row_id[0] if row_id else None)
    utils.log_event("info", "import_switches_bulk", count=len(rows))
    return results


def search_host_by_ip(db_path, ip):
    """IP로 호스트 위치(어느 스위치·포트)를 조회."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT h.ip, h.mac, h.port, h.confidence, h.reason,
                      s.id as switch_id, s.name as switch_name, s.ip as switch_ip, s.hostname
               FROM hosts h
               LEFT JOIN switches s ON h.switch_id = s.id
               WHERE h.ip = ?""",
            (ip,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_vlan_summary(db_path):
    """전체 VLAN 목록과 스위치별 사용 현황."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT m.vlan, s.name as switch_name, s.ip as switch_ip, COUNT(*) as mac_count
               FROM mac_entries m
               JOIN switches s ON m.switch_id = s.id
               GROUP BY m.vlan, m.switch_id
               ORDER BY m.vlan, s.name""",
        )
        return [dict(row) for row in cursor.fetchall()]


def upsert_port_event(db_path, switch_id, port_name, event_type):
    """포트 이벤트(flapping/looping) 기록 및 카운트 증가."""
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT id, count FROM port_events
                   WHERE switch_id=? AND port_name=? AND event_type=?""",
                (switch_id, port_name, event_type),
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE port_events SET count=count+1, last_seen=CURRENT_TIMESTAMP WHERE id=?",
                    (existing[0],),
                )
            else:
                cursor.execute(
                    """INSERT INTO port_events (switch_id, port_name, event_type)
                       VALUES (?, ?, ?)""",
                    (switch_id, port_name, event_type),
                )


def get_port_events(db_path, switch_id):
    """스위치의 포트 이벤트 목록 조회."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT port_name, event_type, count, first_seen, last_seen
               FROM port_events WHERE switch_id=? ORDER BY last_seen DESC""",
            (switch_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


def set_switch_alert(db_path, switch_id, alert):
    """스위치 alert 상태 설정 (none / warning / critical)."""
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE switches SET alert=? WHERE id=?", (alert, switch_id)
            )


def save_switch(db_path, name, ip, vendor):
    utils.log_event("info", "save_switch", name=name, vendor=vendor)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO switches (name, ip, vendor) VALUES (?, ?, ?)",
                (name, ip, vendor)
            )
            cursor.execute("SELECT id FROM switches WHERE name = ?", (name,))
            row = cursor.fetchone()
            return row[0] if row else None


def upsert_switch(db_path, row):
    # upsert_switch updates or inserts a switch record
    utils.log_event("info", "upsert_switch", name=row.get("name"))

    if "ip" not in row:
        raise ValueError("ip is required for upsert_switch")

    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            # CRITICAL FIX (data integrity): INSERT OR REPLACE deletes + inserts atomically, losing original created_at.
            # Use UPDATE + INSERT OR IGNORE to preserve created_at for existing switches, create new created_at for new ones.
            switch_name = row.get("name")
            cursor.execute(
                """UPDATE switches SET ip = ?, vendor = ?, model = ?, status = ?, last_collected = CURRENT_TIMESTAMP
                   WHERE name = ?""",
                (row.get("ip"), row.get("vendor", ""), row.get("model"), row.get("status", "new"), switch_name)
            )
            # If no rows updated (switch doesn't exist), insert new with auto-created_at
            if cursor.rowcount == 0:
                cursor.execute(
                    """INSERT INTO switches (name, ip, vendor, model, status)
                       VALUES (?, ?, ?, ?, ?)""",
                    (switch_name, row.get("ip"), row.get("vendor", ""), row.get("model"), row.get("status", "new"))
                )


def get_switch(db_path, switch_id):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, ip, hostname, vendor, model, location, status, alert, last_collected FROM switches WHERE id = ?",
            (switch_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def latest_snapshot_id(db_path, switch_id):
    # latest_snapshot_id returns the most recent snapshot ID for a switch
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM snapshots WHERE switch_id = ? ORDER BY id DESC LIMIT 1",
            (switch_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else None


def get_switches(db_path):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, ip, hostname, vendor, model, location, status, alert, last_collected FROM switches ORDER BY id"
        )
        return [dict(row) for row in cursor.fetchall()]


def set_switch_status(db_path, switch_id, status, error=None):
    utils.log_event("info", "set_switch_status", switch_id=switch_id, status=status)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE switches SET status = ? WHERE id = ?",
                (status, switch_id)
            )


def update_switch_status(db_path, switch_id, status, error=None):
    # update_switch_status updates status and last_collected timestamp
    utils.log_event("info", "update_switch_status", switch_id=switch_id, status=status)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE switches SET status = ?, last_collected = CURRENT_TIMESTAMP WHERE id = ?",
                (status, switch_id)
            )


def update_cred_blob(db_path, switch_id, cred_blob):
    """Update DPAPI-encrypted credential blob for a switch."""
    utils.log_event("info", "update_cred_blob", switch_id=switch_id)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE switches SET cred_blob = ? WHERE id = ?",
                (cred_blob, switch_id)
            )


def get_macs_by_snapshot(db_path, snapshot_id):
    """Get MAC entries for a snapshot: list of (vlan, mac, port) tuples."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT vlan, mac, port FROM mac_entries WHERE snapshot_id = ? ORDER BY mac, port",
            (snapshot_id,)
        )
        return [(row[0], row[1], row[2]) for row in cursor.fetchall()]


def _detect_disconnected(db_path, switch_id, prev_snapshot_id, curr_macs):
    """Detect disconnected MAC entries (prev_macs - curr_macs) and record events.

    prev_snapshot_id: snapshot ID from previous collection
    curr_macs: list of (vlan, mac, port) from current snapshot
    """
    if prev_snapshot_id is None:
        # No previous snapshot to compare
        return

    prev_macs_set = set(get_macs_by_snapshot(db_path, prev_snapshot_id))
    curr_macs_set = set(curr_macs)

    # Find MACs that disappeared
    disconnected_macs = prev_macs_set - curr_macs_set

    # Record each disconnected MAC as an event
    if disconnected_macs:
        utils.log_event("info", "disconnected_macs_detected",
                       switch_id=switch_id, count=len(disconnected_macs))
        with _db_lock:
            with get_db(db_path) as conn:
                cursor = conn.cursor()
                for vlan, mac, port in disconnected_macs:
                    cursor.execute(
                        """INSERT INTO events (event_type, event_name, switch_id, data, created_at)
                           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                        ("disconnected", f"disconnected:{mac}:{port}", switch_id,
                         f'{{"vlan":{vlan},"mac":"{mac}","port":"{port}"}}')
                    )


def save_snapshot(db_path, switch_id, parsed_or_duration=_UNSET, duration_seconds=None):
    """Create a snapshot and optionally save parsed data.

    Backward compatibility note: This function supports multiple signatures:
    1. save_snapshot(db_path, switch_id)           → creates empty snapshot
    2. save_snapshot(db_path, switch_id, parsed)   → creates snapshot + saves ports/macs/arps
    3. save_snapshot(db_path, switch_id, duration) → legacy: creates snapshot with duration only

    Complexity note: Uses sentinel value to distinguish default (empty snapshot) from explicit None (error).
    Consider splitting into separate functions in future refactor (e.g., save_snapshot() + save_snapshot_with_data()).
    Current approach maintains backward compatibility with existing call sites.
    """
    if parsed_or_duration is _UNSET:
        # Default case: no args provided, create empty snapshot
        parsed = None
        duration = None
    elif parsed_or_duration is None:
        # Explicit None provided: treat as error (caller must provide dict or duration)
        raise ValueError("save_snapshot requires either parsed dict or duration_seconds, not explicit None")
    elif isinstance(parsed_or_duration, dict):
        # New signature: save_snapshot(db_path, switch_id, parsed)
        parsed = parsed_or_duration
        duration = duration_seconds
    else:
        # Legacy signature: save_snapshot(db_path, switch_id, duration_seconds)
        parsed = None
        duration = parsed_or_duration

    utils.log_event("info", "save_snapshot", switch_id=switch_id)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO snapshots (switch_id, duration_seconds) VALUES (?, ?)",
                (switch_id, duration)
            )
            snapshot_id = cursor.lastrowid

            # If parsed data provided, save all related entries
            if parsed:
                if "ports" in parsed and parsed["ports"]:
                    for port in parsed["ports"]:
                        cursor.execute(
                            """INSERT OR REPLACE INTO ports
                               (snapshot_id, switch_id, name, status, vlan, speed, description)
                               VALUES (?, ?, ?, ?, ?, ?, ?)""",
                            (snapshot_id, switch_id, port.get("name"), port.get("status") or port.get("link"),
                             port.get("vlan"), port.get("speed"), port.get("descr", ""))
                        )

                # Support both "macs" (actual code) and "mac_entries" (test code)
                mac_entries = parsed.get("mac_entries") or parsed.get("macs") or []
                if mac_entries:
                    for mac_entry in mac_entries:
                        cursor.execute(
                            """INSERT OR REPLACE INTO mac_entries
                               (snapshot_id, switch_id, vlan, mac, port, entry_type)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (snapshot_id, switch_id, mac_entry.get("vlan"), mac_entry.get("mac"),
                             mac_entry.get("port"), mac_entry.get("type"))
                        )

                # Support both "arp_entries" (test code) and "arps" (actual code)
                arp_entries = parsed.get("arp_entries") or parsed.get("arps") or []
                if arp_entries:
                    for arp_entry in arp_entries:
                        cursor.execute(
                            """INSERT OR REPLACE INTO arp_entries
                               (snapshot_id, switch_id, ip, mac, interface)
                               VALUES (?, ?, ?, ?, ?)""",
                            (snapshot_id, switch_id, arp_entry.get("ip"), arp_entry.get("mac"),
                             arp_entry.get("interface"))
                        )

            return snapshot_id


def save_ports(db_path, snapshot_id, switch_id, ports):
    if not ports:
        return 0
    utils.log_event("info", "save_ports", snapshot_id=snapshot_id, count=len(ports))
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for port in ports:
                cursor.execute(
                    """INSERT OR REPLACE INTO ports
                       (snapshot_id, switch_id, name, status, vlan, speed, description)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (snapshot_id, switch_id, port.get("name"), port.get("status"),
                     port.get("vlan"), port.get("speed"), port.get("description"))
                )
            return len(ports)


def save_mac_entries(db_path, snapshot_id, switch_id, macs):
    if not macs:
        return 0
    utils.log_event("info", "save_mac_entries", snapshot_id=snapshot_id, count=len(macs))
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for mac_entry in macs:
                cursor.execute(
                    """INSERT OR REPLACE INTO mac_entries
                       (snapshot_id, switch_id, vlan, mac, port, entry_type)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (snapshot_id, switch_id, mac_entry.get("vlan"), mac_entry.get("mac"),
                     mac_entry.get("port"), mac_entry.get("type"))
                )
            return len(macs)


def save_arp_entries(db_path, snapshot_id, switch_id, arps):
    if not arps:
        return 0
    utils.log_event("info", "save_arp_entries", snapshot_id=snapshot_id, count=len(arps))
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for arp_entry in arps:
                cursor.execute(
                    """INSERT OR REPLACE INTO arp_entries
                       (snapshot_id, switch_id, ip, mac, interface)
                       VALUES (?, ?, ?, ?, ?)""",
                    (snapshot_id, switch_id, arp_entry.get("ip"), arp_entry.get("mac"),
                     arp_entry.get("interface"))
                )
            return len(arps)


def save_hosts(db_path, hosts):
    if not hosts:
        return 0
    utils.log_event("info", "save_hosts", count=len(hosts))
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for ip, host_data in hosts.items():
                cursor.execute(
                    """INSERT OR REPLACE INTO hosts
                       (ip, mac, switch_id, port, located, confidence, reason)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (ip, host_data.get("mac"), host_data.get("switch_id"),
                     host_data.get("port"), host_data.get("located", False),
                     host_data.get("confidence", 0.0), host_data.get("reason"))
                )
            return len(hosts)


def get_ports(db_path, snapshot_id):
    # get_ports retrieves ports for a specific snapshot
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM ports WHERE snapshot_id = ? ORDER BY id",
            (snapshot_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_ports_by_switch(db_path, switch_id):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM ports WHERE switch_id = ? ORDER BY id DESC LIMIT 1000",
            (switch_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_mac_count(db_path, snapshot_id):
    # get_mac_count returns the number of MAC entries in a snapshot
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM mac_entries WHERE snapshot_id = ?",
            (snapshot_id,)
        )
        row = cursor.fetchone()
        return row[0] if row else 0


def get_mac_entries_by_switch(db_path, switch_id):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM mac_entries WHERE switch_id = ? ORDER BY id DESC LIMIT 1000",
            (switch_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_arp_entries_by_switch(db_path, switch_id):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM arp_entries WHERE switch_id = ? ORDER BY id DESC LIMIT 1000",
            (switch_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_arp_entries(db_path):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM arp_entries ORDER BY id DESC LIMIT 10000")
        return [dict(row) for row in cursor.fetchall()]


def get_mac_entries(db_path):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM mac_entries ORDER BY id DESC LIMIT 10000")
        return [dict(row) for row in cursor.fetchall()]


def get_hosts_by_switch(db_path, switch_id):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM hosts WHERE switch_id = ? OR switch_id IS NULL ORDER BY ip",
            (switch_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_snapshots(db_path, limit=100):
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, switch_id, collected_at, duration_seconds FROM snapshots ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
