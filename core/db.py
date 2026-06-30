import sqlite3
import logging
import threading
import os
import json
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
    hostname TEXT,
    ledger_switch TEXT,
    ledger_port TEXT,
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

# M10: 방화벽 (Palo Alto / Fortinet)
CREATE_FIREWALLS_TABLE = """
CREATE TABLE IF NOT EXISTS firewalls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    host TEXT NOT NULL UNIQUE,
    port INTEGER,
    auth_type TEXT DEFAULT 'token',
    status TEXT DEFAULT 'new',
    last_collected TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cred_blob TEXT
)
"""

CREATE_FIREWALL_INTERFACES_TABLE = """
CREATE TABLE IF NOT EXISTS firewall_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firewall_id INTEGER NOT NULL,
    name TEXT,
    ip TEXT,
    mask TEXT,
    vdom_zone TEXT,
    FOREIGN KEY (firewall_id) REFERENCES firewalls(id)
)
"""

CREATE_FIREWALL_ARP_TABLE = """
CREATE TABLE IF NOT EXISTS firewall_arp (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firewall_id INTEGER NOT NULL,
    ip TEXT,
    mac TEXT,
    interface TEXT,
    FOREIGN KEY (firewall_id) REFERENCES firewalls(id)
)
"""

# M12: 앱 전역 설정(key-value) — source_ip 등
CREATE_APP_SETTINGS_TABLE = """
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT
)
"""

# VLAN 이름(show vlan brief) — 스위치별 VLAN ID→Name
CREATE_VLAN_NAMES_TABLE = """
CREATE TABLE IF NOT EXISTS vlan_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL,
    vlan INTEGER NOT NULL,
    name TEXT,
    status TEXT
)
"""

# show logging/show log — 스위치별 최근 로그 + 탐지 이벤트
CREATE_SWITCH_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS switch_logs (
    switch_id INTEGER PRIMARY KEY,
    recent_lines TEXT,
    events_json TEXT,
    log_alert TEXT,
    updated TEXT
)
"""


# 동일 DB 경로에 ACL을 반복 적용하지 않도록 1회만 시도 (성능 + 콘솔 호출 최소화)
_acl_applied = set()


def _restrict_db_permissions(db_path):
    """HARDENING (CWE-276): Restrict database file permissions to owner-only.

    Supports both Unix (chmod 0o600) and Windows (NTFS ACL via icacls).
    동일 경로는 프로세스 수명 동안 1회만 적용한다.
    """
    import platform
    db_path_str = str(db_path)

    if db_path_str in _acl_applied:
        return
    _acl_applied.add(db_path_str)

    if platform.system() == "Windows":
        # Windows: Use icacls to set owner-only ACL
        try:
            import subprocess
            # CREATE_NO_WINDOW: console=False(windowed) exe에서 icacls가 콘솔 창을
            # 깜빡 띄우는 것을 방지한다.
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            # Remove inheritance and set explicit owner-only permissions
            subprocess.run(
                ["icacls", db_path_str, "/inheritance:r", "/grant:r", f"{os.getenv('USERNAME', 'SYSTEM')}:F"],
                check=True, capture_output=True, creationflags=creationflags
            )
            utils.log_event("info", "db_windows_acl_set", path=db_path_str)
        except Exception as e:
            utils.log_event("warning", "db_windows_acl_failed", path=db_path_str, error=str(e))
    else:
        # Unix-like systems: Use chmod
        try:
            os.chmod(db_path_str, 0o600)
            utils.log_event("info", "db_unix_chmod_set", path=db_path_str, mode="0o600")
        except (OSError, NotImplementedError) as e:
            utils.log_event("warning", "db_chmod_failed", path=db_path_str, error=str(e))


@contextmanager
def get_db(db_path):
    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        # HARDENING (CWE-276): Restrict database file permissions to owner-only
        # Prevents unauthorized access to sensitive network topology data
        _restrict_db_permissions(db_path)
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
                CREATE_FIREWALLS_TABLE,
                CREATE_FIREWALL_INTERFACES_TABLE,
                CREATE_FIREWALL_ARP_TABLE,
                CREATE_APP_SETTINGS_TABLE,
                CREATE_VLAN_NAMES_TABLE,
                CREATE_SWITCH_LOGS_TABLE,
            ]:
                cursor.execute(table_sql)
            # 기존 DB 마이그레이션: hostname, location, alert 컬럼 추가
            for col, definition in [
                ("hostname", "TEXT"),
                ("location", "TEXT"),
                ("alert", "TEXT DEFAULT 'none'"),
                ("subnet", "TEXT"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE switches ADD COLUMN {col} {definition}")
                except Exception:
                    pass
            # M7: hosts 테이블 장부(ledger) 컬럼 마이그레이션
            for col, definition in [
                ("hostname", "TEXT"),
                ("ledger_switch", "TEXT"),
                ("ledger_port", "TEXT"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE hosts ADD COLUMN {col} {definition}")
                except Exception:
                    pass
            # M11: firewalls 테이블 자격증명 blob(DPAPI 암호화) 컬럼 마이그레이션
            try:
                cursor.execute("ALTER TABLE firewalls ADD COLUMN cred_blob TEXT")
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
            # FIX: 구버전 스키마 DB는 일부 컬럼(hostname/vendor/location/status/alert 등)이
            # 없을 수 있어 고정 INSERT/UPDATE가 "no such column"으로 실패했다. 실제 존재하는
            # 컬럼만 골라 동적으로 INSERT/UPDATE한다(name 기준 수동 UPSERT, ON CONFLICT 비의존).
            existing_cols = {r[1] for r in cursor.execute("PRAGMA table_info(switches)").fetchall()}
            for row in rows:
                name = row.get("name") or row.get("hostname") or row.get("ip")
                candidate = {
                    "name": name,
                    "ip": row.get("ip", ""),
                    "hostname": row.get("hostname", ""),
                    "vendor": row.get("vendor", "unknown"),
                    "location": row.get("location", ""),
                }
                # 실제 테이블에 존재하는 컬럼만 사용 (키는 하드코딩 → SQL 인젝션 없음)
                vals = {k: v for k, v in candidate.items() if k in existing_cols}
                cursor.execute("SELECT id FROM switches WHERE name = ?", (name,))
                existing = cursor.fetchone()
                if existing:
                    set_cols = [k for k in vals if k != "name"]
                    if set_cols:
                        assignments = ", ".join(f"{c}=?" for c in set_cols)
                        cursor.execute(
                            f"UPDATE switches SET {assignments} WHERE name=?",
                            [vals[c] for c in set_cols] + [name],
                        )
                    results.append(existing[0])
                else:
                    ins_cols = list(vals.keys())
                    placeholders = ", ".join("?" for _ in ins_cols)
                    cursor.execute(
                        f"INSERT INTO switches ({', '.join(ins_cols)}) VALUES ({placeholders})",
                        [vals[c] for c in ins_cols],
                    )
                    results.append(cursor.lastrowid)
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


def search_everywhere(db_path, query):
    """IP/이름으로 모든 소스를 종합 검색: 등록 스위치·방화벽, 수집 ARP, 장부 호스트.

    Returns: [{source, ip, label, detail}] (각 매치). 부분 일치(LIKE) 지원.
    """
    q = (query or "").strip()
    if not q:
        return []
    like = "%" + q + "%"
    results = []
    with get_db(db_path) as conn:
        cur = conn.cursor()

        def _try(sql, params, mapper):
            try:
                for r in cur.execute(sql, params):
                    results.append(mapper(r))
            except Exception:
                pass  # 구버전 DB에 테이블/컬럼이 없을 수 있음

        # 1) 등록 스위치 (장비 자체)
        _try("SELECT name, ip, hostname FROM switches "
             "WHERE ip LIKE ? OR name LIKE ? OR IFNULL(hostname,'') LIKE ? LIMIT 50",
             (like, like, like),
             lambda r: {"source": "등록 스위치", "ip": r["ip"], "label": r["name"],
                        "detail": "hostname: " + (r["hostname"] or "-")})
        # 2) 등록 방화벽 (장비 자체)
        _try("SELECT name, host, vendor FROM firewalls WHERE host LIKE ? OR name LIKE ? LIMIT 50",
             (like, like),
             lambda r: {"source": "등록 방화벽", "ip": r["host"], "label": r["name"],
                        "detail": "vendor: " + (r["vendor"] or "-")})
        # 3) 스위치 수집 ARP (어느 스위치에서 IP가 보이는지)
        _try("SELECT a.ip, a.mac, a.interface, s.name AS sw FROM arp_entries a "
             "JOIN switches s ON a.switch_id = s.id WHERE a.ip LIKE ? LIMIT 100",
             (like,),
             lambda r: {"source": "스위치 ARP", "ip": r["ip"], "label": r["sw"],
                        "detail": "MAC " + (r["mac"] or "-") + " · 포트 " + (r["interface"] or "-")})
        # 4) 방화벽 수집 ARP
        _try("SELECT fa.ip, fa.mac, fa.interface, f.name AS fw FROM firewall_arp fa "
             "JOIN firewalls f ON fa.firewall_id = f.id WHERE fa.ip LIKE ? LIMIT 100",
             (like,),
             lambda r: {"source": "방화벽 ARP", "ip": r["ip"], "label": r["fw"],
                        "detail": "MAC " + (r["mac"] or "-") + " · " + (r["interface"] or "-")})
        # 5) 장부 호스트 (대조 위치)
        _try("SELECT h.ip, h.hostname, h.port, s.name AS sw FROM hosts h "
             "LEFT JOIN switches s ON h.switch_id = s.id "
             "WHERE h.ip LIKE ? OR IFNULL(h.hostname,'') LIKE ? LIMIT 100",
             (like, like),
             lambda r: {"source": "장부 호스트", "ip": r["ip"], "label": r["hostname"] or "-",
                        "detail": "스위치 " + (r["sw"] or "-") + " · 포트 " + (r["port"] or "-")})
    return results


def save_switch_logs(db_path, switch_id, recent_lines, events_json, log_alert):
    """show logging 분석 결과 저장(스위치별 교체). recent_lines/events_json은 문자열."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT OR REPLACE INTO switch_logs
                       (switch_id, recent_lines, events_json, log_alert, updated)
                       VALUES (?, ?, ?, ?, datetime('now'))""",
                    (switch_id, recent_lines, events_json, log_alert))
            except Exception as e:
                log_event("warning", "save_switch_logs_skipped", error=str(e))


def get_switch_logs(db_path, switch_id):
    """스위치 최근 로그/이벤트 반환(없으면 None)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT recent_lines, events_json, log_alert, updated FROM switch_logs WHERE switch_id=?",
                (switch_id,))
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception:
            return None


def save_vlan_names(db_path, switch_id, vlans):
    """show vlan brief 파싱 결과 저장(스위치별 전체 교체). vlans=[{vlan,name,status}]."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            # vlan_names 테이블이 구버전 DB에 없을 수 있으므로 보호
            try:
                cur.execute("DELETE FROM vlan_names WHERE switch_id=?", (switch_id,))
                for v in vlans:
                    cur.execute(
                        "INSERT INTO vlan_names (switch_id, vlan, name, status) VALUES (?, ?, ?, ?)",
                        (switch_id, v.get("vlan"), v.get("name"), v.get("status")))
            except Exception as e:
                log_event("warning", "save_vlan_names_skipped", error=str(e))


def get_vlan_summary(db_path):
    """전체 VLAN 목록과 스위치별 사용 현황 + VLAN 이름(show vlan brief).

    MAC이 학습된 VLAN(mac_entries)과 show vlan brief로 수집한 VLAN(vlan_names)을
    합집합으로 보여준다(MAC 0개인 VLAN도 이름과 함께 표시).
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT v.vlan AS vlan, s.name AS switch_name, s.ip AS switch_ip,
                      v.name AS vlan_name, v.status AS vlan_status,
                      (SELECT COUNT(*) FROM mac_entries m
                       WHERE m.switch_id = v.switch_id AND m.vlan = v.vlan) AS mac_count
               FROM vlan_names v
               JOIN switches s ON v.switch_id = s.id
               UNION
               SELECT m.vlan AS vlan, s.name AS switch_name, s.ip AS switch_ip,
                      (SELECT vn.name FROM vlan_names vn
                       WHERE vn.switch_id = m.switch_id AND vn.vlan = m.vlan) AS vlan_name,
                      (SELECT vn.status FROM vlan_names vn
                       WHERE vn.switch_id = m.switch_id AND vn.vlan = m.vlan) AS vlan_status,
                      COUNT(*) AS mac_count
               FROM mac_entries m
               JOIN switches s ON m.switch_id = s.id
               WHERE NOT EXISTS (SELECT 1 FROM vlan_names vn2
                                 WHERE vn2.switch_id = m.switch_id AND vn2.vlan = m.vlan)
               GROUP BY m.vlan, m.switch_id
               ORDER BY vlan, switch_name""",
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
                    # HARDENING (CWE-1025 JSON Injection): Use json.dumps for safe serialization
                    event_data = json.dumps({"vlan": vlan, "mac": mac, "port": port})
                    cursor.execute(
                        """INSERT INTO events (event_type, event_name, switch_id, data, created_at)
                           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                        ("disconnected", f"disconnected:{mac}:{port}", switch_id, event_data)
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
    """호스트 목록을 DB에 일괄 등록 (upsert by IP).

    입력:
      hosts: Union[List[Dict], Dict[ip, host_data]]
        - List[Dict]: 각 호스트 레코드 [{ip, mac, switch_id, port, ...}, ...]
        - Dict[ip, host_data]: {ip: {mac, switch_id, port, ...}, ...}

    반환:
      저장된 호스트 ID 리스트 (import_switches_bulk과 호환성 유지)

    호환성:
      - excel_loader (M4): List[Dict] 형식
      - correlator: Dict[ip, host_data] 형식 (legacy)
    """
    if not hosts:
        return []

    # Dict 형식 감지: dict.items()가 있으면 Dict[ip, host_data] 형식
    if isinstance(hosts, dict) and hasattr(hosts, "items"):
        # Legacy format: Dict[ip, host_data] → List[Dict]로 변환
        hosts_list = []
        for ip, host_data in hosts.items():
            record = {"ip": ip}
            if isinstance(host_data, dict):
                record.update(host_data)
            hosts_list.append(record)
        hosts = hosts_list

    utils.log_event("info", "save_hosts", count=len(hosts))
    results = []
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for host_data in hosts:
                ip = host_data.get("ip")
                if not ip:
                    continue
                # FIX: ON CONFLICT(ip) 의존 제거(구버전 DB에 ip UNIQUE 없을 수 있음).
                # 측정 컬럼만 갱신, ledger 컬럼(hostname/ledger_*)은 보존하는 수동 UPSERT.
                cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
                existing = cursor.fetchone()
                if existing:
                    cursor.execute(
                        """UPDATE hosts SET mac=?, switch_id=?, port=?, located=?,
                               confidence=?, reason=?, updated_at=CURRENT_TIMESTAMP
                           WHERE ip=?""",
                        (host_data.get("mac"), host_data.get("switch_id"),
                         host_data.get("port"), host_data.get("located", False),
                         host_data.get("confidence", 0.0), host_data.get("reason"), ip),
                    )
                    results.append(existing[0])
                else:
                    cursor.execute(
                        """INSERT INTO hosts
                           (ip, mac, switch_id, port, located, confidence, reason)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (ip, host_data.get("mac"), host_data.get("switch_id"),
                         host_data.get("port"), host_data.get("located", False),
                         host_data.get("confidence", 0.0), host_data.get("reason")),
                    )
                    results.append(cursor.lastrowid)
            return results


def save_ledger_hosts(db_path, rows):
    """M7: 장부(엑셀) 호스트를 hosts 테이블에 UPSERT (장부 + mac 갱신).

    입력:
      rows: [{ip, mac?, hostname?, ledger_switch?, ledger_port?}, ...]

    - 장부 컬럼(hostname, ledger_switch, ledger_port)을 갱신한다.
    - mac은 IP의 위치-무관 속성이므로 COALESCE로 갱신(값이 있을 때만, 기존값 보존).
    - 측정 위치 컬럼(switch_id, port, located, confidence, reason)은 절대 건드리지
      않는다 → 수집(save_hosts)과 적재 순서 무관하게 측정 데이터 보존(멱등).

    반환:
      저장된 호스트 ID 리스트
    """
    if not rows:
        return []

    utils.log_event("info", "save_ledger_hosts", count=len(rows))
    results = []
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            for row in rows:
                ip = row.get("ip")
                if not ip:
                    continue
                # FIX: ON CONFLICT(ip) 의존 제거(구버전 DB에 ip UNIQUE 없을 수 있음).
                # 빈값/None이면 기존값 보존(COALESCE+NULLIF와 동등: `new or old`). 측정
                # 위치 컬럼(switch_id/port/located 등)은 건드리지 않는 수동 UPSERT.
                new_mac = row.get("mac")
                new_hostname = row.get("hostname", "")
                new_lsw = row.get("ledger_switch")
                new_lport = row.get("ledger_port")
                cursor.execute(
                    "SELECT id, mac, hostname, ledger_switch, ledger_port FROM hosts WHERE ip = ?",
                    (ip,))
                ex = cursor.fetchone()
                if ex:
                    cursor.execute(
                        """UPDATE hosts SET mac=?, hostname=?, ledger_switch=?, ledger_port=?,
                               updated_at=CURRENT_TIMESTAMP WHERE ip=?""",
                        (new_mac or ex[1], new_hostname or ex[2],
                         new_lsw or ex[3], new_lport or ex[4], ip),
                    )
                    results.append(ex[0])
                else:
                    cursor.execute(
                        """INSERT INTO hosts (ip, mac, hostname, ledger_switch, ledger_port)
                           VALUES (?, ?, ?, ?, ?)""",
                        (ip, new_mac, new_hostname, new_lsw, new_lport),
                    )
                    results.append(cursor.lastrowid)
            return results


def list_hosts(db_path):
    """M7: 전체 호스트(측정 + 장부 컬럼) 조회."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hosts ORDER BY ip LIMIT 100000")
        return [dict(row) for row in cursor.fetchall()]


def get_switches(db_path):
    """M7: 전체 스위치 조회 (reconcile의 switch_id→name 매핑용).

    SECURITY: cred_blob(DPAPI 자격증명)은 조회/UI로 절대 노출하지 않는다.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM switches ORDER BY id LIMIT 100000")
        return [_strip_cred(dict(row)) for row in cursor.fetchall()]


def get_switch_credential(db_path, switch_id):
    """자동 수집용: 저장된 스위치 자격증명 blob 반환(없으면 None)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT cred_blob FROM switches WHERE id=?", (switch_id,))
        row = cur.fetchone()
        return row["cred_blob"] if row and row["cred_blob"] else None


def update_switch(db_path, switch_id, name=None, ip=None, hostname=None, vendor=None, location=None):
    """스위치 등록 정보 수정(제공된 필드만, 존재 컬럼만). 반환: 성공 여부."""
    fields = {"name": name, "ip": ip, "hostname": hostname, "vendor": vendor, "location": location}
    fields = {k: v for k, v in fields.items() if v is not None}
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM switches WHERE id=?", (switch_id,))
            if not cur.fetchone():
                return False
            cols = {r[1] for r in cur.execute("PRAGMA table_info(switches)").fetchall()}
            sets = {k: v for k, v in fields.items() if k in cols}
            if sets:
                assignments = ", ".join(f"{k}=?" for k in sets)
                cur.execute(f"UPDATE switches SET {assignments} WHERE id=?",
                            list(sets.values()) + [switch_id])
            return True


def update_firewall(db_path, firewall_id, name=None, vendor=None, host=None, port=None):
    """방화벽 등록 정보 수정(제공된 필드만). 반환: 성공 여부."""
    fields = {"name": name, "vendor": vendor, "host": host, "port": port}
    fields = {k: v for k, v in fields.items() if v is not None}
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM firewalls WHERE id=?", (firewall_id,))
            if not cur.fetchone():
                return False
            if fields:
                assignments = ", ".join(f"{k}=?" for k in fields)
                cur.execute(f"UPDATE firewalls SET {assignments} WHERE id=?",
                            list(fields.values()) + [firewall_id])
            return True


def delete_switch(db_path, switch_id):
    """스위치 1대 삭제 + 관련 수집 데이터 정리. 반환: 삭제 여부(bool)."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM switches WHERE id=?", (switch_id,))
            if not cur.fetchone():
                return False
            # 수집 데이터 정리 (존재하는 테이블만 안전 시도)
            for sql, params in [
                ("DELETE FROM ports WHERE switch_id=?", (switch_id,)),
                ("DELETE FROM mac_entries WHERE switch_id=?", (switch_id,)),
                ("DELETE FROM arp_entries WHERE switch_id=?", (switch_id,)),
                ("DELETE FROM snapshots WHERE switch_id=?", (switch_id,)),
                ("DELETE FROM port_events WHERE switch_id=?", (switch_id,)),
                # hosts는 인벤토리이므로 보존하되 위치(측정) 무효화
                ("UPDATE hosts SET switch_id=NULL, located=0 WHERE switch_id=?", (switch_id,)),
                ("DELETE FROM switches WHERE id=?", (switch_id,)),
            ]:
                try:
                    cur.execute(sql, params)
                except Exception:
                    pass
            return True


def delete_firewall(db_path, firewall_id):
    """방화벽 1대 삭제 + 인터페이스/ARP 정리. 반환: 삭제 여부(bool)."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM firewalls WHERE id=?", (firewall_id,))
            if not cur.fetchone():
                return False
            # 관련 테이블이 구버전 DB에 없을 수 있으므로 각 DELETE를 개별 보호.
            for sql in [
                "DELETE FROM firewall_interfaces WHERE firewall_id=?",
                "DELETE FROM firewall_arp WHERE firewall_id=?",
                "DELETE FROM firewalls WHERE id=?",
            ]:
                try:
                    cur.execute(sql, (firewall_id,))
                except Exception:
                    pass
            return True


# ── M10: 방화벽 (Palo Alto / Fortinet) ────────────────────────────
def save_firewall(db_path, name, vendor, host, port=None, auth_type="token"):
    """방화벽 장비 등록 (host 기준 upsert). 반환: firewall id."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            # FIX: ON CONFLICT(host) 의존 제거. host 기준 수동 UPSERT.
            cur.execute("SELECT id FROM firewalls WHERE host=?", (host,))
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    "UPDATE firewalls SET name=?, vendor=?, port=?, auth_type=? WHERE host=?",
                    (name, vendor, port, auth_type, host),
                )
                return existing[0]
            cur.execute(
                """INSERT INTO firewalls (name, vendor, host, port, auth_type)
                   VALUES (?, ?, ?, ?, ?)""",
                (name, vendor, host, port, auth_type),
            )
            return cur.lastrowid


def _strip_cred(d):
    """SECURITY: 자격증명 blob은 API/UI로 절대 노출하지 않는다(get_firewall_credential 전용)."""
    if d is not None:
        d.pop("cred_blob", None)
    return d


def list_firewalls(db_path):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM firewalls ORDER BY id LIMIT 10000")
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            # 저장된 자격증명 보유 여부만 노출(blob 자체는 _strip_cred로 제거).
            d["has_credential"] = bool(d.get("cred_blob"))
            rows.append(_strip_cred(d))
        return rows


def get_firewall(db_path, firewall_id):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM firewalls WHERE id=?", (firewall_id,))
        row = cur.fetchone()
        return _strip_cred(dict(row)) if row else None


def set_firewall_status(db_path, firewall_id, status):
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute(
                "UPDATE firewalls SET status=?, last_collected=datetime('now') WHERE id=?",
                (status, firewall_id),
            )


def save_firewall_interfaces(db_path, firewall_id, interfaces):
    """방화벽 인터페이스 교체 저장 (firewall_id 기준 전체 갱신)."""
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("DELETE FROM firewall_interfaces WHERE firewall_id=?", (firewall_id,))
            for it in interfaces:
                conn.execute(
                    "INSERT INTO firewall_interfaces (firewall_id, name, ip, mask, vdom_zone) VALUES (?,?,?,?,?)",
                    (firewall_id, it.get("name"), it.get("ip"), it.get("mask"),
                     it.get("vdom_zone") or it.get("vdom") or it.get("zone")),
                )


def save_firewall_arp(db_path, firewall_id, arp_entries):
    """방화벽 ARP 교체 저장 (firewall_id 기준 전체 갱신)."""
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("DELETE FROM firewall_arp WHERE firewall_id=?", (firewall_id,))
            for a in arp_entries:
                conn.execute(
                    "INSERT INTO firewall_arp (firewall_id, ip, mac, interface) VALUES (?,?,?,?)",
                    (firewall_id, a.get("ip"), a.get("mac"), a.get("interface")),
                )


def get_firewall_interfaces(db_path, firewall_id):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM firewall_interfaces WHERE firewall_id=? ORDER BY id", (firewall_id,))
        return [dict(r) for r in cur.fetchall()]


def get_firewall_arp(db_path, firewall_id):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM firewall_arp WHERE firewall_id=? ORDER BY id LIMIT 100000", (firewall_id,))
        return [dict(r) for r in cur.fetchall()]


def save_firewall_credential(db_path, firewall_id, cred_blob):
    """M11: 방화벽 자격증명(DPAPI 암호화 blob) 저장."""
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE firewalls SET cred_blob=? WHERE id=?", (cred_blob, firewall_id))


def get_firewall_credential(db_path, firewall_id):
    """M11: 저장된 방화벽 자격증명 blob 반환(없으면 None)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT cred_blob FROM firewalls WHERE id=?", (firewall_id,))
        row = cur.fetchone()
        return row["cred_blob"] if row and row["cred_blob"] else None


# ── M12: 앱 전역 설정 (key-value) ──────────────────────────────────
def set_setting(db_path, key, value):
    """앱 설정 저장(upsert). value=None/''이면 빈 문자열 저장."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            # ON CONFLICT 비의존 수동 upsert (구버전 DB 호환 정책)
            cur.execute("SELECT key FROM app_settings WHERE key=?", (key,))
            if cur.fetchone():
                cur.execute("UPDATE app_settings SET value=? WHERE key=?", (value or "", key))
            else:
                cur.execute("INSERT INTO app_settings (key, value) VALUES (?, ?)", (key, value or ""))


def get_setting(db_path, key, default=None):
    """앱 설정 조회(없으면 default)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM app_settings WHERE key=?", (key,))
        row = cur.fetchone()
        if row is None:
            return default
        return row["value"]


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
