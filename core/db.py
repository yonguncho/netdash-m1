import sqlite3
import logging
import threading
import os
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from . import utils
from .utils import log_event  # 다수 호출부가 짧은 이름 사용(미정의 NameError 잠복 버그 수정)

logger = logging.getLogger(__name__)

_db_lock = threading.Lock()
_UNSET = object()  # Sentinel value to distinguish default None from explicit None
_SNAPSHOT_KEEP = 50  # 스위치당 보존할 스냅샷 세대 수(초과분은 save_snapshot이 정리)


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
    created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
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
    first_seen TIMESTAMP DEFAULT (datetime('now','localtime')),
    last_seen TIMESTAMP DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (switch_id) REFERENCES switches(id)
)
"""

CREATE_SNAPSHOTS_TABLE = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL,
    collected_at TIMESTAMP DEFAULT (datetime('now','localtime')),
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
    crc_errors INTEGER DEFAULT 0,
    in_errors INTEGER DEFAULT 0,
    out_errors INTEGER DEFAULT 0,
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
    updated_at TIMESTAMP DEFAULT (datetime('now','localtime')),
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
    created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
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
    host TEXT NOT NULL,
    port INTEGER,
    auth_type TEXT DEFAULT 'token',
    status TEXT DEFAULT 'new',
    last_collected TIMESTAMP,
    created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
    cred_blob TEXT,
    location TEXT
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

# 툴 접근(감사) 로그 — 어느 PC가 언제 무엇을 했는지
CREATE_AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now','localtime')),
    client_ip TEXT,
    action TEXT,
    target TEXT,
    method TEXT,
    path TEXT
)
"""


# 스위치 설정(running-config) 백업 — 변경 diff 알람용
CREATE_CONFIG_BACKUPS_TABLE = """
CREATE TABLE IF NOT EXISTS config_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER,
    ts TEXT DEFAULT (datetime('now','localtime')),
    hash TEXT,
    content TEXT
)
"""


# 장비 변경/알람 이벤트(새 설비·오프라인·스위치 연결실패·flapping/looping)
CREATE_DEVICE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS device_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now','localtime')),
    kind TEXT,
    severity TEXT DEFAULT 'info',
    subnet TEXT,
    ip TEXT,
    mac TEXT,
    switch_id INTEGER,
    label TEXT,
    message TEXT,
    ack INTEGER DEFAULT 0
)
"""


# NX-OS 포트채널 멤버(설비/TPS 직결이 Po로 보일 때 실제 물리포트 해석용)
CREATE_PORT_CHANNELS_TABLE = """
CREATE TABLE IF NOT EXISTS port_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER,
    switch_id INTEGER,
    port_channel TEXT,
    members TEXT
)
"""


# CDP/LLDP 이웃(물리 연결) — 로컬포트↔원격장비/포트
CREATE_NEIGHBORS_TABLE = """
CREATE TABLE IF NOT EXISTS neighbors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER,
    local_port TEXT,
    remote_name TEXT,
    remote_port TEXT,
    remote_ip TEXT,
    platform TEXT,
    updated TEXT
)
"""


# 설비 현황: 대역 ping sweep + ARP + MAC 대조 결과
CREATE_FACILITY_HOSTS_TABLE = """
CREATE TABLE IF NOT EXISTS facility_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet TEXT,
    ip TEXT,
    mac TEXT,
    switch_id INTEGER,
    switch_name TEXT,
    port TEXT,
    online INTEGER DEFAULT 0,
    direct INTEGER DEFAULT 1,
    via TEXT,
    updated TEXT,
    UNIQUE(subnet, ip)
)
"""

# 서버(리눅스/윈도우) 현황 — 스위치와 별도 수명주기.
# 수집: 무자격(포트스캔+역DNS+스위치 ARP/MAC 대조) + SSH 상세(자격증명 시).
# is_vm=0(물리) + location이 랙 형식(A09U27)이면 서버실 현황에 포함.
CREATE_SERVERS_TABLE = """
CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip TEXT NOT NULL UNIQUE,
    os_type TEXT DEFAULT 'linux',
    hostname TEXT,
    mac TEXT,
    is_vm INTEGER DEFAULT 0,
    location TEXT,
    open_ports TEXT,
    os_info TEXT,
    cpu_model TEXT,
    cpu_cores INTEGER,
    mem_total_mb INTEGER,
    disk_total_gb REAL,
    disk_used_gb REAL,
    mem_modules TEXT,
    mem_slots_total INTEGER,
    disk_devices TEXT,
    switch_name TEXT,
    switch_port TEXT,
    status TEXT DEFAULT 'new',
    last_error TEXT,
    last_collected TIMESTAMP,
    cred_blob TEXT,
    created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
)
"""

# PC 프로필: 수집 PC(MAC) 단위 출발지 IP·계정 — 다중 PC 운영 시 각 PC가
# 자기 IP/계정으로 수집하도록 함(core/pcprofile.py 참조)
CREATE_PC_PROFILES_TABLE = """
CREATE TABLE IF NOT EXISTS pc_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE,
    hostname TEXT,
    source_ip TEXT,
    cred_blob TEXT,
    updated_at TEXT DEFAULT (datetime('now', 'localtime'))
)
"""


# 성능 인덱스: hot 쿼리의 풀 테이블 스캔 제거(스냅샷이 쌓일수록 느려지던 원인).
# UNIQUE 제약이 만드는 암시적 인덱스로 이미 커버되는 컬럼(예: mac_entries.snapshot_id는
# UNIQUE(snapshot_id,...)의 최좌측)은 제외하고, 커버 안 되는 것만 추가한다. idempotent.
_PERF_INDEXES = [
    # 거의 모든 hot 경로가 쓰는 'SELECT MAX(id) FROM snapshots GROUP BY switch_id'
    "CREATE INDEX IF NOT EXISTS idx_snapshots_switch_id ON snapshots(switch_id, id)",
    # MAC 검색/상관(비-최좌측이라 UNIQUE 인덱스로 커버 안 됨)
    "CREATE INDEX IF NOT EXISTS idx_mac_mac ON mac_entries(mac)",
    "CREATE INDEX IF NOT EXISTS idx_mac_switch_port ON mac_entries(switch_id, port)",
    # 'MAC이 실제로 담긴 최신 스냅샷'(스위치별) 조회 — 설비 대조의 hot 경로
    "CREATE INDEX IF NOT EXISTS idx_mac_switch_snapshot ON mac_entries(switch_id, snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_arp_switch ON arp_entries(switch_id)",
    "CREATE INDEX IF NOT EXISTS idx_arp_mac ON arp_entries(mac)",
    "CREATE INDEX IF NOT EXISTS idx_portchan_snapshot ON port_channels(snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_neighbors_switch ON neighbors(switch_id)",
    "CREATE INDEX IF NOT EXISTS idx_config_backups_switch ON config_backups(switch_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_port_events_switch ON port_events(switch_id, port_name, event_type)",
    "CREATE INDEX IF NOT EXISTS idx_vlan_names_switch ON vlan_names(switch_id)",
]


# 읽기 전용 인스턴스 모드 — 다른 PC의 주 서버가 DB를 소유 중일 때 True.
# 이 프로세스의 모든 연결이 query_only로 열려 실수로도 쓰기가 불가능하다.
# 저널 모드 변경(쓰기 동작)도 시도하지 않는다.
READONLY = False

# 동일 DB 경로에 ACL을 반복 적용하지 않도록 1회만 시도 (성능 + 콘솔 호출 최소화)
_acl_applied = set()


def _is_under_user_profile(path_str):
    """경로가 현재 사용자 프로필(%USERPROFILE% / $HOME) 안에 있는가.

    프로필 안 = 그 사용자 전용 위치이므로 owner-only ACL이 안전하다.
    밖(공유 폴더 호스트, C:\\NetDash, Program 폴더 등)이면 다른 계정·PC가 함께
    쓸 수 있으므로 권한을 좁히면 안 된다.
    """
    try:
        home = os.path.expanduser("~")
        if not home or home == "~":
            return False
        return os.path.normcase(os.path.abspath(path_str)).startswith(
            os.path.normcase(os.path.abspath(home)) + os.sep)
    except Exception:
        return False


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

    # 네트워크 경로(UNC/원격 드라이브)에는 owner-only ACL을 적용하지 않는다.
    # 공유폴더에서 처음 실행한 PC의 계정에만 권한이 남아 다른 PC에서
    # 'unable to open database file'(db_error)이 나던 문제. 공유폴더의
    # 접근 통제는 파일서버의 NTFS/공유 권한이 담당한다.
    if utils.is_network_path(db_path_str):
        utils.log_event("info", "db_acl_skip_network_path", path=db_path_str)
        return

    # 사용자 프로필 밖(= 여러 계정·여러 PC가 함께 쓸 수 있는 위치)에는 적용하지 않는다.
    # is_network_path는 **클라이언트 쪽**만 감지한다. 공유 폴더를 들고 있는 PC에서는
    # 같은 경로가 로컬 C:\... 이라 가드를 통과했고, icacls /inheritance:r 이
    # SYSTEM·Administrators·Users·Authenticated Users 를 전부 제거해 **나머지 PC와
    # 다른 Windows 계정, 백업·백신(SYSTEM)까지 DB에 접근하지 못했다.**
    # 그런 위치의 접근 통제는 폴더 자체의 NTFS 권한이 담당한다.
    if not _is_under_user_profile(db_path_str):
        utils.log_event("info", "db_acl_skip_shared_location", path=db_path_str)
        return

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


_last_db_error = {}
_dberr_lock = threading.Lock()


def _record_db_error(info):
    with _dberr_lock:
        _last_db_error.clear()
        _last_db_error.update(info)


def get_last_db_error():
    """가장 최근 DB 오류 정보(없으면 빈 dict). 화면 배너·health용."""
    with _dberr_lock:
        return dict(_last_db_error)


def clear_last_db_error():
    with _dberr_lock:
        _last_db_error.clear()


def db_error_hint(exc, db_path=None):
    """DB 예외를 사용자 친화적 한국어 원인 힌트로 분류. (로그·화면 표시용)

    반환: {reason, hint, detail, path, path_kind}
    """
    detail = str(exc)
    m = detail.lower()
    try:
        net = utils.is_network_path(db_path) if db_path is not None else False
    except Exception:
        net = False
    path_kind = "네트워크(공유폴더/원격드라이브)" if net else "로컬"
    if "unable to open" in m:
        reason = "DB 파일/폴더를 열 수 없음"
        hint = ("DB 경로에 접근이 안 됩니다. ① 공유폴더/드라이브 연결이 끊겼는지 "
                "② 폴더·파일 권한(다른 PC에서 처음 열 때 owner-only) — icacls로 권한 초기화 "
                "③ 백신 실시간검사가 netdash.db를 잠갔는지 ④ 경로가 실제로 존재하는지 확인하세요.")
    elif "database is locked" in m or "locked" in m:
        reason = "DB 잠금(사용 중)"
        hint = ("다른 프로세스/다른 PC가 DB에 쓰는 중입니다. 잠시 후 자동 재시도되며, "
                "지속되면 다른 PC의 수집을 끝내거나 앱을 하나만 실행하세요.")
    elif "disk i/o" in m or "i/o error" in m:
        reason = "디스크/네트워크 입출력 오류"
        hint = "공유폴더·네트워크 연결 또는 디스크 상태를 확인하세요(SMB 순단 가능)."
    elif "readonly" in m or "read-only" in m or "attempt to write a readonly" in m:
        reason = "읽기 전용 상태"
        hint = "이 인스턴스는 읽기 전용(주 서버가 따로 있음)이거나 파일이 읽기전용입니다."
    elif "no such table" in m or "malformed" in m or "not a database" in m:
        reason = "DB 파일 손상/스키마 이상"
        hint = "DB 파일이 손상됐거나 다른 파일일 수 있습니다. 백업에서 복구하거나 새 DB로 초기화하세요."
    elif "disk full" in m or "full" in m:
        reason = "저장 공간 부족"
        hint = "디스크 여유 공간을 확보하세요."
    else:
        reason = "DB 오류"
        hint = "상세 메시지를 확인하세요. 지속되면 netdash_error.log를 확인하세요."
    return {"reason": reason, "hint": hint, "detail": detail[:300],
            "path": str(db_path) if db_path is not None else "",
            "path_kind": path_kind}


def _open_conn(db_path):
    """SQLite 연결 + PRAGMA 설정을 열어 반환. 실패 시 예외(호출부에서 재시도)."""
    conn = None
    try:
        # 부모 디렉터리 확보 — 네트워크 순단으로 폴더가 잠깐 사라졌다 복구되는 경우
        # 'unable to open database file'이 나므로 열기 전에 보장한다.
        try:
            _d = os.path.dirname(str(db_path))
            if _d and not os.path.isdir(_d):
                os.makedirs(_d, exist_ok=True)
        except Exception:
            pass
        # timeout=30: 락 경합 시 즉시 'database is locked'로 터지지 않고 최대 30초 대기.
        conn = sqlite3.connect(str(db_path), timeout=30)
        _restrict_db_permissions(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # 저널 모드: 로컬=WAL, 네트워크 경로(UNC/원격 드라이브)=DELETE(SMB에서 -shm 불가).
        if READONLY:
            conn.execute("PRAGMA query_only=ON")
        elif utils.is_network_path(db_path):
            conn.execute("PRAGMA journal_mode=DELETE")
        else:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn
    except Exception:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        raise


@contextmanager
def get_db(db_path):
    conn = None
    try:
        # 일시적 'unable to open database file'/locked(공유폴더 순단·AV 잠금 등)에
        # 대비해 짧은 backoff로 재시도. 진짜 오류(경로·권한 영구 문제)면 재시도 후 raise.
        import time as _t
        last = None
        for _i in range(4):
            try:
                conn = _open_conn(db_path)
                break
            except sqlite3.OperationalError as e:
                last = e
                _m = str(e).lower()
                if _i < 3 and ("unable to open" in _m or "locked" in _m or "busy" in _m):
                    _t.sleep(0.25 * (_i + 1))
                    continue
                raise
        if conn is None and last is not None:
            raise last
        yield conn
        conn.commit()
        clear_last_db_error()   # 성공 → 이전 오류 배너 해제
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        info = db_error_hint(e, db_path)
        _record_db_error(info)
        utils.log_event("error", "db_error", reason=info["reason"],
                        error=info["detail"], path=info["path"], path_kind=info["path_kind"])
        raise
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


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
                CREATE_FACILITY_HOSTS_TABLE,
                CREATE_SERVERS_TABLE,
                CREATE_PC_PROFILES_TABLE,
                CREATE_PORT_CHANNELS_TABLE,
                CREATE_NEIGHBORS_TABLE,
                CREATE_DEVICE_EVENTS_TABLE,
                CREATE_CONFIG_BACKUPS_TABLE,
                CREATE_AUDIT_LOG_TABLE,
            ]:
                cursor.execute(table_sql)
            # 성능 인덱스 생성(idempotent) — 기존 DB에도 다음 기동 때 자동 적용
            for idx_sql in _PERF_INDEXES:
                try:
                    cursor.execute(idx_sql)
                except Exception:
                    pass
            # 기존 DB 마이그레이션: hostname, location, alert 컬럼 추가
            for col, definition in [
                ("hostname", "TEXT"),
                ("location", "TEXT"),
                ("alert", "TEXT DEFAULT 'none'"),
                ("subnet", "TEXT"),
                ("note", "TEXT"),
                ("os_version", "TEXT"),
                ("model", "TEXT"),
                ("last_error", "TEXT"),
                ("device_type", "TEXT"),
                ("serial", "TEXT"),
                ("zone", "TEXT"),   # 토폴로지 존(구성도) 그룹 — 사용자 지정

                # BUGFIX: cred_blob이 신규 스키마엔 있으나 마이그레이션 목록에 빠져
                # 레거시 DB에서 get_switch_credential/update_cred_blob이
                # 'no such column: cred_blob' → diagnose 500 + persist 저장 실패.
                ("cred_blob", "TEXT"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE switches ADD COLUMN {col} {definition}")
                except Exception:
                    pass
            # ports 테이블 errors 컬럼 마이그레이션(CRC/입출력 오류)
            for col in ("crc_errors", "in_errors", "out_errors"):
                try:
                    cursor.execute(f"ALTER TABLE ports ADD COLUMN {col} INTEGER DEFAULT 0")
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
            # 방화벽 위치(서버실 랙 A09U27 등) 컬럼 마이그레이션
            try:
                cursor.execute("ALTER TABLE firewalls ADD COLUMN location TEXT")
            except Exception:
                pass
            # 설비 현황: 직접연결(direct) + 업링크 경유(via) + 연결 포트 설명(port_desc)
            for col, definition in [
                ("direct", "INTEGER DEFAULT 1"),
                ("via", "TEXT"),
                ("port_desc", "TEXT"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE facility_hosts ADD COLUMN {col} {definition}")
                except Exception:
                    pass
            # 방화벽 인터페이스: secondary IP 목록(JSON 배열 문자열)
            try:
                cursor.execute("ALTER TABLE firewall_interfaces ADD COLUMN secondary_ips TEXT")
            except Exception:
                pass
            # 방화벽 HA 구성(JSON: mode/hbdev/monitor) — 이중화 연결선에 HA 포트 표기용
            try:
                cursor.execute("ALTER TABLE firewalls ADD COLUMN ha_info TEXT")
            except Exception:
                pass
            # 서버 하드웨어 사양(CPU/메모리/디스크) — SSH 상세 수집에서 채움
            for col, definition in [
                ("cpu_model", "TEXT"),
                ("cpu_cores", "INTEGER"),
                ("mem_total_mb", "INTEGER"),
                ("disk_total_gb", "REAL"),
                ("disk_used_gb", "REAL"),
                # 장착 구성(JSON 문자열) — 메모리 모듈 목록 / 물리 디스크 목록
                ("mem_modules", "TEXT"),
                ("mem_slots_total", "INTEGER"),
                ("disk_devices", "TEXT"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE servers ADD COLUMN {col} {definition}")
                except Exception:
                    pass
            # HA/VRRP 이중화(같은 VIP) 방화벽을 Active/Backup 둘 다 등록할 수 있도록
            # firewalls.host의 UNIQUE 제약 제거. SQLite 정석 절차:
            # FK OFF → 새 테이블(_new) 생성 → 복사 → 기존 DROP → _new RENAME.
            # (RENAME이 자식 FK를 따라가지 않도록 기존 테이블은 rename 대신 drop)
            try:
                # ① 지난 버전(RENAME 방식) 마이그레이션이 남긴 잔해 복구:
                #    firewalls_old가 남아 있고 자식 FK가 firewalls_old를 참조하는 상태
                #    → 자식 테이블 재구성으로 FK를 firewalls로 복원.
                cursor.execute("PRAGMA foreign_keys=OFF")
                leftover = cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='firewalls_old'").fetchone()
                if leftover:
                    for child, create_sql in (
                            ("firewall_interfaces", CREATE_FIREWALL_INTERFACES_TABLE),
                            ("firewall_arp", CREATE_FIREWALL_ARP_TABLE)):
                        csql = cursor.execute(
                            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (child,)).fetchone()
                        if csql and csql[0] and "firewalls_old" in csql[0]:
                            cursor.execute("ALTER TABLE %s RENAME TO %s_bak" % (child, child))
                            cursor.execute(create_sql)
                            ccols = [r[1] for r in cursor.execute(
                                "PRAGMA table_info(%s_bak)" % child).fetchall()]
                            # 후기 마이그레이션으로 추가된 컬럼(secondary_ips 등)을 새 테이블에 보강
                            newcols = {r[1] for r in cursor.execute(
                                "PRAGMA table_info(%s)" % child).fetchall()}
                            for col in ccols:
                                if col not in newcols:
                                    cursor.execute("ALTER TABLE %s ADD COLUMN %s TEXT" % (child, col))
                            clist = ", ".join(ccols)
                            cursor.execute("INSERT INTO %s (%s) SELECT %s FROM %s_bak"
                                           % (child, clist, clist, child))
                            cursor.execute("DROP TABLE %s_bak" % child)
                    cursor.execute("DROP TABLE firewalls_old")
                    utils.log_event("info", "firewalls_old_leftover_repaired")
                # ② UNIQUE 제약 제거(정석: _new 생성→복사→기존 drop→rename)
                row = cursor.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='firewalls'").fetchone()
                if row and row[0] and "UNIQUE" in row[0].upper():
                    cursor.execute(CREATE_FIREWALLS_TABLE.replace(
                        "CREATE TABLE IF NOT EXISTS firewalls", "CREATE TABLE firewalls_new"))
                    cols = [r[1] for r in cursor.execute("PRAGMA table_info(firewalls)").fetchall()]
                    # 후기 마이그레이션 컬럼(ha_info 등)이 기존에 있으면 새 테이블에도 보강
                    newcols = {r[1] for r in cursor.execute("PRAGMA table_info(firewalls_new)").fetchall()}
                    for col in cols:
                        if col not in newcols:
                            cursor.execute("ALTER TABLE firewalls_new ADD COLUMN %s TEXT" % col)
                    collist = ", ".join(cols)
                    cursor.execute("INSERT INTO firewalls_new (%s) SELECT %s FROM firewalls"
                                   % (collist, collist))
                    cursor.execute("DROP TABLE firewalls")   # 자식 FK는 'firewalls' 참조 유지(잠시 무효)
                    cursor.execute("ALTER TABLE firewalls_new RENAME TO firewalls")
                    utils.log_event("info", "firewalls_host_unique_dropped")
            except Exception as _e:
                utils.log_event("warning", "firewalls_migration_skip", error=str(_e))
            finally:
                try:
                    cursor.execute("PRAGMA foreign_keys=ON")
                except Exception:
                    pass
            # ── 타임스탬프 로컬시간 일원화(1회 마이그레이션) ────────────
            # 과거 버전은 CURRENT_TIMESTAMP/datetime('now') = UTC로 저장해
            # 화면 시간이 PC 시간보다 9시간(KST) 이전으로 표시됐다.
            # 기존 행을 datetime(col,'localtime')으로 변환하고 플래그로 재실행 방지.
            # (pc_profiles.updated_at은 처음부터 localtime — 변환 대상 제외)
            try:
                done = cursor.execute(
                    "SELECT value FROM app_settings WHERE key='ts_localtime_migrated'"
                ).fetchone()
                if not done:
                    for table, cols in [
                        ("switches", ("created_at", "last_collected")),
                        ("port_events", ("first_seen", "last_seen")),
                        ("snapshots", ("collected_at",)),
                        ("hosts", ("updated_at",)),
                        ("events", ("created_at",)),
                        ("firewalls", ("created_at", "last_collected")),
                        ("device_events", ("ts",)),
                        ("audit_log", ("ts",)),
                        ("config_backups", ("ts",)),
                        ("switch_logs", ("updated",)),
                        ("neighbors", ("updated",)),
                        ("facility_hosts", ("updated",)),
                    ]:
                        for col in cols:
                            try:
                                cursor.execute(
                                    "UPDATE %s SET %s = datetime(%s, 'localtime') "
                                    "WHERE %s IS NOT NULL AND datetime(%s) IS NOT NULL"
                                    % (table, col, col, col, col))
                            except Exception:
                                pass   # 구버전 스키마에 없는 테이블/컬럼은 스킵
                    cursor.execute(
                        "INSERT INTO app_settings (key, value) "
                        "VALUES ('ts_localtime_migrated', '1')")
                    utils.log_event("info", "ts_localtime_migrated")
            except Exception as _e:
                utils.log_event("warning", "ts_localtime_migrate_skip", error=str(_e))
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
                    "subnet": row.get("subnet", ""),
                    "note": row.get("note", ""),
                }
                # 실제 테이블에 존재하는 컬럼만 사용 (키는 하드코딩 → SQL 인젝션 없음)
                vals = {k: v for k, v in candidate.items() if k in existing_cols}
                cursor.execute("SELECT id FROM switches WHERE name = ?", (name,))
                existing = cursor.fetchone()
                if existing:
                    # BUGFIX: 엑셀 재업로드 시 값 없는 컬럼이 기존 note/location/vendor를
                    # 빈값/'unknown'으로 덮어써 데이터 손실. 새 값이 의미 있을 때만 갱신
                    # (save_ledger_hosts의 'new or 기존값' 보존 패턴과 일치).
                    cand_cols = [k for k in vals if k != "name"]
                    old = {}
                    if cand_cols:
                        cursor.execute(
                            f"SELECT {', '.join(cand_cols)} FROM switches WHERE name=?", (name,))
                        orow = cursor.fetchone()
                        if orow:
                            old = {c: orow[i] for i, c in enumerate(cand_cols)}
                    set_cols = []
                    for c in cand_cols:
                        newv = vals[c]
                        # 빈 값이거나 vendor 자리표시자('unknown')면 기존값 보존
                        if newv in (None, ""):
                            continue
                        if c == "vendor" and str(newv).strip().lower() == "unknown" \
                                and old.get(c):
                            continue
                        set_cols.append(c)
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


def import_firewalls_bulk(db_path, rows):
    """엑셀 장비 목록 중 방화벽 행을 일괄 등록(host 기준 upsert).

    vendor는 엑셀에서 알 수 없어 'unknown'으로 저장(사용자가 이후 수정·수집).
    rows: [{ip/host, name, hostname, location}]
    """
    results = []
    for row in rows:
        host = (row.get("ip") or row.get("host") or "").strip()
        if not host:
            continue
        name = row.get("name") or row.get("hostname") or host
        loc = row.get("location", "") or ""
        try:
            fid = save_firewall(db_path, name, "unknown", host, None, "token", location=loc)
            results.append(fid)
        except Exception as e:
            utils.log_event("warning", "import_firewall_skipped", error=str(e))
    utils.log_event("info", "import_firewalls_bulk", count=len(results))
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
    # MAC은 구분자(:.- )가 형식마다 달라, 질의·저장값 모두 16진수만 남겨 비교(형식 무관 검색).
    import re as _re
    qhex = _re.sub(r"[^0-9a-f]", "", q.lower())
    use_mac = len(qhex) >= 4
    machex = "%" + qhex + "%"

    def _mac_clause(col):
        """MAC 컬럼을 구분자 제거 후 비교하는 조건 조각. (sql조각, 파라미터리스트)"""
        if not use_mac:
            return "", []
        return (" OR REPLACE(REPLACE(REPLACE(LOWER(%s),':',''),'.',''),'-','') LIKE ?" % col), [machex]

    results = []
    with get_db(db_path) as conn:
        cur = conn.cursor()

        def _try(sql, params, mapper):
            try:
                for r in cur.execute(sql, params):
                    results.append(mapper(r))
            except Exception:
                pass  # 구버전 DB에 테이블/컬럼이 없을 수 있음

        # 1) 등록 스위치 (IP/이름/호스트네임)
        _try("SELECT name, ip, hostname FROM switches "
             "WHERE ip LIKE ? OR name LIKE ? OR IFNULL(hostname,'') LIKE ? LIMIT 50",
             (like, like, like),
             lambda r: {"source": "등록 스위치", "ip": r["ip"], "label": r["name"],
                        "detail": "hostname: " + (r["hostname"] or "-")})
        # 2) 등록 방화벽 (IP/이름/위치)
        _try("SELECT name, host, vendor, IFNULL(location,'') AS location FROM firewalls "
             "WHERE host LIKE ? OR name LIKE ? OR IFNULL(location,'') LIKE ? LIMIT 50",
             (like, like, like),
             lambda r: {"source": "등록 방화벽", "ip": r["host"], "label": r["name"],
                        "detail": "vendor: " + (r["vendor"] or "-") +
                                  (" · 위치 " + r["location"] if r["location"] else "")})
        # 3) 스위치 수집 ARP (IP/MAC — 형식 무관)
        mc, mp = _mac_clause("a.mac")
        _try("SELECT a.ip, a.mac, a.interface, s.name AS sw FROM arp_entries a "
             "JOIN switches s ON a.switch_id = s.id "
             "WHERE a.ip LIKE ? OR IFNULL(a.mac,'') LIKE ?" + mc + " LIMIT 100",
             [like, like] + mp,
             lambda r: {"source": "스위치 ARP", "ip": r["ip"], "label": r["sw"],
                        "detail": "MAC " + (r["mac"] or "-") + " · 포트 " + (r["interface"] or "-")})
        # 4) 방화벽 수집 ARP
        mc, mp = _mac_clause("fa.mac")
        _try("SELECT fa.ip, fa.mac, fa.interface, f.name AS fw FROM firewall_arp fa "
             "JOIN firewalls f ON fa.firewall_id = f.id "
             "WHERE fa.ip LIKE ? OR IFNULL(fa.mac,'') LIKE ?" + mc + " LIMIT 100",
             [like, like] + mp,
             lambda r: {"source": "방화벽 ARP", "ip": r["ip"], "label": r["fw"],
                        "detail": "MAC " + (r["mac"] or "-") + " · " + (r["interface"] or "-")})
        # 5) 스위치 MAC 테이블 (MAC — 형식 무관, 최신 스냅샷)
        mc, mp = _mac_clause("m.mac")
        _try("SELECT DISTINCT m.mac, m.port, m.vlan, s.name AS sw FROM mac_entries m "
             "JOIN switches s ON m.switch_id = s.id "
             "WHERE m.snapshot_id IN (SELECT MAX(id) FROM snapshots GROUP BY switch_id) "
             "AND (m.mac LIKE ?" + mc + ") LIMIT 100",
             [like] + mp,
             lambda r: {"source": "MAC 테이블", "ip": "-", "label": r["sw"],
                        "detail": "MAC " + (r["mac"] or "-") + " · 포트 " + (r["port"] or "-") +
                                  " · VLAN " + str(r["vlan"] if r["vlan"] is not None else "-")})
        # 6) 설비 현황(facility_hosts) — IP/MAC(형식 무관)
        mc, mp = _mac_clause("mac")
        _try("SELECT ip, mac, switch_name, port, subnet FROM facility_hosts "
             "WHERE ip LIKE ? OR IFNULL(mac,'') LIKE ?" + mc + " LIMIT 100",
             [like, like] + mp,
             lambda r: {"source": "설비 현황", "ip": r["ip"],
                        "label": r["switch_name"] or "설비(연결 스위치 미확인)",
                        "detail": "MAC " + (r["mac"] or "-") +
                                  (" · 포트 " + r["port"] if r["port"] else
                                   " · 연결 스위치 미수집(해당 스위치 수집 후 새로고침)") +
                                  " · 대역 " + (r["subnet"] or "-")})
        # 7) 장부 호스트 (대조 위치)
        _try("SELECT h.ip, h.hostname, h.port, s.name AS sw FROM hosts h "
             "LEFT JOIN switches s ON h.switch_id = s.id "
             "WHERE h.ip LIKE ? OR IFNULL(h.hostname,'') LIKE ? LIMIT 100",
             (like, like),
             lambda r: {"source": "장부 호스트", "ip": r["ip"], "label": r["hostname"] or "-",
                        "detail": "스위치 " + (r["sw"] or "-") + " · 포트 " + (r["port"] or "-")})
    return results


def find_mac_history(db_path, mac):
    """MAC을 전체 스냅샷(과거 포함)에서 찾아 '가장 최근 확인 위치'를 반환.

    설비가 현재 오프라인이라 최신 MAC 테이블에는 없어도, 과거에 어느 스위치/포트에서
    학습됐는지(=이전 연결 이력)를 알려준다. 최신만 보는 get_mac_to_switchport의 보완.
    Returns: {switch_name, port, ts} | None.
    """
    import re as _re
    h = _re.sub(r"[^0-9a-f]", "", (mac or "").lower())
    if len(h) < 12:
        return None
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT s.name AS sw, m.port AS port, snap.collected_at AS ts "
                "FROM mac_entries m JOIN switches s ON m.switch_id = s.id "
                "JOIN snapshots snap ON m.snapshot_id = snap.id "
                "WHERE REPLACE(REPLACE(REPLACE(LOWER(IFNULL(m.mac,'')),':',''),'.',''),'-','') = ? "
                "ORDER BY snap.id DESC LIMIT 1", (h,))
            r = cur.fetchone()
            if r:
                return {"switch_name": r["sw"], "port": r["port"], "ts": r["ts"]}
        except Exception:
            pass
    return None


# 전체 MAC 최근위치 맵 캐시 — DB 경로별로 분리(다른 DB 결과 오염 방지)
_mac_last_cache = {}          # {str(db_path): {"built": float, "map": dict}}
_mac_cache_lock = threading.Lock()
_MAC_LAST_TTL = 45.0          # 초 — 이 시간 내 재호출은 캐시 재사용


#  MAC 정규화용 변환표(구분자 제거) — re.sub보다 수 배 빠르다(수만 행 순회 경로)
_MAC_STRIP = {ord(c): None for c in ":-. \t"}


def _build_mac_last_map(db_path):
    """{정규화MAC: {switch_name, port, ts}} 전체 맵(과거 스냅샷 포함).

    SQL 집계(GROUP BY mac + 자기조인)는 SQLite에서 오히려 느려(측정 2.8s vs 0.2s)
    전체 행을 한 번 읽고 파이썬에서 최신 스냅샷을 고른다. 정렬 대신 단순 비교라 O(n).
    호출은 캐시·백그라운드 갱신 뒤에 있어 사용자 요청을 막지 않는다.
    """
    out, best = {}, {}
    with get_db(db_path) as conn:
        conn.row_factory = None          # 튜플 접근이 Row보다 빠름
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT m.mac, m.port, s.name, snap.collected_at, m.snapshot_id "
                "FROM mac_entries m JOIN switches s ON m.switch_id = s.id "
                "JOIN snapshots snap ON m.snapshot_id = snap.id")
            for mac, port, sw, ts, sid in cur.fetchall():
                if not mac:
                    continue
                h = mac.lower().translate(_MAC_STRIP)
                if len(h) != 12:
                    continue
                if h not in best or (sid or 0) > best[h]:
                    best[h] = sid or 0
                    out[h] = {"switch_name": sw, "port": port, "ts": ts}
        except Exception:
            pass
    return out


def warm_mac_last_cache(db_path):
    """앱 기동 직후 백그라운드로 MAC 최근위치 맵을 미리 구축(관제 첫 진입 지연 제거)."""
    def _work():
        try:
            m = _build_mac_last_map(db_path)
            import time as _t
            with _mac_cache_lock:
                _mac_last_cache[str(db_path)] = {"built": _t.monotonic(), "map": m,
                                                 "refreshing": False}
            utils.log_event("info", "mac_last_cache_warmed", entries=len(m))
        except Exception as e:
            utils.log_event("warning", "mac_last_cache_warm_failed", error=str(e)[:120])
    threading.Thread(target=_work, daemon=True).start()


def invalidate_mac_last_cache(db_path=None):
    """MAC 스냅샷이 바뀌면(수집·삭제·세대정리) 캐시 무효화 → 다음 호출에서 재구성.

    db_path를 주면 그 DB만, 없으면 전체 무효화.
    """
    with _mac_cache_lock:
        if db_path is None:
            _mac_last_cache.clear()
        else:
            _mac_last_cache.pop(str(db_path), None)


def get_mac_last_seen(db_path, want_macs=None):
    """MAC별 '가장 최근 관측 위치' {정규화MAC: {switch_name, port, ts}}.

    전체 스캔은 무거우므로 DB별 TTL(45초) 캐시를 재사용하고 want_macs로 필터한다.
    (관제 10초 폴링·설비 로드에서 반복 풀스캔 → 시작 지연/느림을 방지)
    """
    import re as _re
    import time as _t
    # want_macs가 있고 유효 MAC이 하나도 없으면 풀맵 구축조차 불필요
    want = None
    if want_macs is not None:
        want = set()
        for m in want_macs:
            h = _re.sub(r"[^0-9a-f]", "", (m or "").lower())
            if len(h) == 12:
                want.add(h)
        if not want:
            return {}
    key = str(db_path)
    now = _t.monotonic()
    with _mac_cache_lock:
        ent = _mac_last_cache.get(key)
        full = ent["map"] if ent else None
        stale = ent is None or (now - ent["built"]) > _MAC_LAST_TTL
        refreshing = bool(ent and ent.get("refreshing"))
        if ent and stale and not refreshing:
            ent["refreshing"] = True         # 이 호출이 갱신 담당
            need_bg = True
        else:
            need_bg = False
    if full is None:
        # 최초 1회만 동기 구축(이후에는 항상 캐시를 즉시 반환)
        built = _build_mac_last_map(db_path)
        with _mac_cache_lock:
            _mac_last_cache[key] = {"built": now, "map": built, "refreshing": False}
        full = built
    elif need_bg:
        # 만료됐어도 옛 값을 즉시 반환하고 갱신은 백그라운드로(관제 폴링 지연 제거)
        def _refresh():
            try:
                m = _build_mac_last_map(db_path)
                with _mac_cache_lock:
                    _mac_last_cache[key] = {"built": _t.monotonic(), "map": m, "refreshing": False}
            except Exception:
                with _mac_cache_lock:
                    e = _mac_last_cache.get(key)
                    if e:
                        e["refreshing"] = False
        threading.Thread(target=_refresh, daemon=True).start()
    if want is None:
        return dict(full)
    return {k: v for k, v in full.items() if k in want}


def get_mac_to_switchport(db_path):
    """전체 스위치의 최신 MAC→(switch_id, switch_name, port) 매핑.

    설비 현황: 11번 ARP의 MAC이 어느 스위치 어느 포트에 있는지 대조용.

    스위치별로 'MAC이 실제로 담긴 가장 최근 스냅샷'을 쓴다. 그냥 최신 스냅샷을 쓰면,
    MAC 명령만 실패한 수집(status는 done, MAC 0건)이 새 스냅샷을 만드는 순간
    그 스위치의 MAC이 전부 사라져 → 뒤에 붙은 설비가 한꺼번에 '연결 끊김'으로
    오탐되고 연결 스위치도 비어 버린다. MAC 0건은 '아무것도 없음'이 아니라
    '이번엔 못 읽음'으로 취급하고 마지막으로 읽힌 결과를 유지한다.
    Returns: {mac: [(switch_id, switch_name, port), ...]}
    """
    mapping = {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT m.mac, m.port, m.switch_id, s.name AS sname
               FROM mac_entries m
               JOIN switches s ON m.switch_id = s.id
               WHERE m.snapshot_id IN (
                   SELECT MAX(snapshot_id) FROM mac_entries GROUP BY switch_id
               )""")
        for r in cur.fetchall():
            mac = (r["mac"] or "").lower()
            if not mac:
                continue
            mapping.setdefault(mac, []).append((r["switch_id"], r["sname"], r["port"]))
    return mapping


def get_port_mac_counts(db_path):
    """최신 스냅샷 기준 (switch_id, 소문자 포트) → 해당 포트에서 학습된 MAC 수.

    설비 직접연결 판별용: 액세스(엣지) 포트는 보통 MAC 1~소수,
    트렁크/업링크 포트는 다수 MAC을 학습한다.
    get_mac_to_switchport와 같은 기준(MAC이 담긴 최신 스냅샷)을 써야 한다 —
    기준이 어긋나면 매칭은 되는데 포트 MAC 수가 0으로 잡혀 직접연결 판정이 뒤틀린다.
    Returns: {(switch_id, port_lower): count}
    """
    counts = {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT switch_id, port, COUNT(*) AS c
                   FROM mac_entries
                   WHERE snapshot_id IN (
                       SELECT MAX(snapshot_id) FROM mac_entries GROUP BY switch_id)
                   GROUP BY switch_id, port""")
            for r in cur.fetchall():
                counts[(r["switch_id"], (r["port"] or "").lower())] = r["c"]
        except Exception:
            pass
    return counts


def save_neighbors(db_path, switch_id, neighbors):
    """CDP/LLDP 이웃 저장(스위치별 전체 교체). neighbors=[{local_port,remote_name,...}]."""
    with _db_lock:
        with get_db(db_path) as conn:
            try:
                conn.execute("DELETE FROM neighbors WHERE switch_id=?", (switch_id,))
                for n in neighbors or []:
                    conn.execute(
                        "INSERT INTO neighbors (switch_id, local_port, remote_name, remote_port, "
                        "remote_ip, platform, updated) VALUES (?,?,?,?,?,?,datetime('now','localtime'))",
                        (switch_id, n.get("local_port"), n.get("remote_name"),
                         n.get("remote_port"), n.get("remote_ip"), n.get("platform")))
            except Exception as e:
                log_event("warning", "save_neighbors_skipped", error=str(e))


def get_all_neighbors(db_path):
    """전체 이웃 반환 [{switch_id, local_port, remote_name, remote_port, remote_ip, platform}]."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT switch_id, local_port, remote_name, remote_port, remote_ip, platform "
                        "FROM neighbors")
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def get_port_descriptions(db_path):
    """최신 스냅샷 기준 (switch_id, 소문자 포트) → 포트 Description.

    설비 현황에서 '연결 스위치 포트가 실제로 무엇인지'를 스위치가 수집한
    포트 설명으로 보여주기 위함(예: 'AP-3F-회의실', 'CCTV-정문').
    Returns: {(switch_id, port_lower): description}
    """
    descs = {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT switch_id, name, description FROM ports
                   WHERE snapshot_id IN (SELECT MAX(snapshot_id) FROM ports GROUP BY switch_id)
                     AND description IS NOT NULL AND description != ''""")
            from .parsers.cisco_ios import _abbr as _abbrev
            for r in cur.fetchall():
                name = (r["name"] or "")
                descs[(r["switch_id"], name.lower())] = r["description"]
                # 축약형 키도 함께 등록한다. Arista 상세 파서는 'Ethernet1'로
                # 저장하는데 MAC 테이블은 'Et1'로 오므로, 조회 키가 어긋나
                # 설비 현황의 '연결 포트 설명'이 Arista에서 항상 비어 있었다.
                try:
                    short = _abbrev(name)
                except Exception:
                    short = ""
                if short and short.lower() != name.lower():
                    descs.setdefault((r["switch_id"], short.lower()), r["description"])
        except Exception:
            pass
    return descs


def save_port_channels(db_path, snapshot_id, switch_id, port_channels):
    """포트채널 멤버 저장(스냅샷 단위). port_channels=[{port_channel, members:[...]}]."""
    if not port_channels:
        return
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            for pc in port_channels:
                try:
                    cur.execute(
                        "INSERT INTO port_channels (snapshot_id, switch_id, port_channel, members) "
                        "VALUES (?, ?, ?, ?)",
                        (snapshot_id, switch_id, pc.get("port_channel"),
                         ",".join(pc.get("members") or [])))
                except Exception as e:
                    log_event("warning", "save_port_channel_skipped", error=str(e))


def save_device_event(db_path, kind, severity="info", subnet=None, ip=None,
                      mac=None, switch_id=None, label=None, message=None):
    """장비 변경/알람 이벤트 1건 기록(+이메일 알림 큐 전달)."""
    with _db_lock:
        with get_db(db_path) as conn:
            try:
                # ts를 명시(datetime('now','localtime')): 구버전 DB의 컬럼 DEFAULT는
                # UTC로 남아있으므로 기본값에 의존하면 9시간 어긋난다(전 INSERT 공통).
                conn.execute(
                    """INSERT INTO device_events
                       (kind, severity, subnet, ip, mac, switch_id, label, message, ts)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                    (kind, severity, subnet, ip, mac, switch_id, label, message))
            except Exception as e:
                log_event("warning", "save_device_event_skipped", error=str(e))
                return
    # 이메일 알림 큐(발송 여부는 notifier가 설정 확인) — 지연 import(순환 방지)
    try:
        from . import notifier
        notifier.notify({"kind": kind, "severity": severity, "subnet": subnet,
                         "ip": ip, "label": label, "message": message})
    except Exception:
        pass


def list_device_events(db_path, limit=200, only_unack=False, kind=None, days=None):
    """최근 이벤트 목록(최신순). only_unack=미확인만, kind=종류 필터, days=최근 N일."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            conds, params = [], []
            if only_unack:
                conds.append("ack=0")
            if kind:
                conds.append("kind=?")
                params.append(str(kind))
            if days:
                conds.append("ts >= datetime('now','localtime', ?)")
                params.append("-%d days" % int(days))
            sql = "SELECT * FROM device_events"
            if conds:
                sql += " WHERE " + " AND ".join(conds)
            sql += " ORDER BY id DESC LIMIT ?"
            params.append(int(limit))
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def purge_device_events(db_path, retention_days=90):
    """보존 기간이 지난 알람 이벤트 자동 정리. 반환: 삭제 건수."""
    try:
        days = max(1, int(retention_days))
    except (TypeError, ValueError):
        days = 90
    with _db_lock:
        with get_db(db_path) as conn:
            try:
                cur = conn.execute(
                    "DELETE FROM device_events WHERE ts < datetime('now','localtime', ?)",
                    ("-%d days" % days,))
                return cur.rowcount
            except Exception:
                return 0


# 실제 설정 변경이 아닌데 매 수집마다 바뀌는 휘발성 라인(오탐 방지용 제거 대상)
_VOLATILE_CFG_PREFIXES = (
    "current configuration", "! last configuration change", "! nvram config last",
    "ntp clock-period", "! time:", "!time:", "building configuration",
    "# time:", "/* configuration dump taken",
)


def _normalize_config(text):
    lines = []
    for line in (text or "").splitlines():
        low = line.strip().lower()
        if any(low.startswith(p) for p in _VOLATILE_CFG_PREFIXES):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def save_config_backup(db_path, switch_id, content):
    """running-config 백업 저장. 직전 백업과 다를 때만 저장.

    휘발성 라인(수집 시각 등)은 제거 후 비교해 오탐 방지.
    반환: (changed: bool, first: bool) — changed=True면 새 백업 저장됨.
    """
    import hashlib
    text = _normalize_config(content)
    if not text:
        return False, False
    h = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            try:
                cur.execute("SELECT hash FROM config_backups WHERE switch_id=? "
                            "ORDER BY id DESC LIMIT 1", (switch_id,))
                row = cur.fetchone()
                first = row is None
                if row and row["hash"] == h:
                    return False, False          # 변경 없음 → 저장 생략
                cur.execute("INSERT INTO config_backups (switch_id, hash, content, ts) "
                            "VALUES (?, ?, ?, datetime('now','localtime'))",
                            (switch_id, h, text))
                # 스위치당 최근 20개만 보관(무한 증가 방지)
                cur.execute(
                    "DELETE FROM config_backups WHERE switch_id=? AND id NOT IN "
                    "(SELECT id FROM config_backups WHERE switch_id=? ORDER BY id DESC LIMIT 20)",
                    (switch_id, switch_id))
                return True, first
            except Exception as e:
                log_event("warning", "save_config_backup_skipped", error=str(e))
                return False, False


def get_config_backups(db_path, switch_id, limit=20):
    """스위치의 설정 백업 목록(내용 제외, 최신순)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, ts, hash FROM config_backups WHERE switch_id=? "
                        "ORDER BY id DESC LIMIT ?", (switch_id, int(limit)))
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def get_config_backup_content(db_path, backup_id):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM config_backups WHERE id=?", (int(backup_id),))
            row = cur.fetchone()
            return dict(row) if row else None
        except Exception:
            return None


def get_latest_configs(db_path):
    """스위치별 최신 running-config 백업 내용 {switch_id: content}. L2/L3 자동 분류용."""
    out = {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT c.switch_id AS sid, c.content AS content FROM config_backups c "
                "JOIN (SELECT switch_id, MAX(id) AS mid FROM config_backups GROUP BY switch_id) m "
                "ON c.id = m.mid")
            for r in cur.fetchall():
                out[r["sid"]] = r["content"]
        except Exception:
            pass
    return out


def count_unacked_events(db_path):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM device_events WHERE ack=0")
            return cur.fetchone()[0]
        except Exception:
            return 0


def ack_device_events(db_path, ids=None):
    """이벤트 확인 처리. ids=None이면 전체 확인. 반환: 처리 개수."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            try:
                if ids:
                    ints = [int(i) for i in ids if str(i).strip().lstrip("-").isdigit()]
                    if not ints:
                        return 0
                    qs = ",".join("?" for _ in ints)
                    cur.execute("UPDATE device_events SET ack=1 WHERE id IN (%s)" % qs, ints)
                else:
                    cur.execute("UPDATE device_events SET ack=1 WHERE ack=0")
                return cur.rowcount
            except Exception:
                return 0


def save_audit(db_path, client_ip, action, target="", method="", path=""):
    """툴 접근(감사) 로그 1건 기록 + 오래된 로그 정리(최근 5000건 유지)."""
    with _db_lock:
        with get_db(db_path) as conn:
            try:
                conn.execute(
                    "INSERT INTO audit_log (client_ip, action, target, method, path, ts) "
                    "VALUES (?, ?, ?, ?, ?, datetime('now','localtime'))",
                    (str(client_ip or "")[:64], str(action or "")[:100],
                     str(target or "")[:200], str(method or "")[:10], str(path or "")[:200]))
                conn.execute(
                    "DELETE FROM audit_log WHERE id NOT IN "
                    "(SELECT id FROM audit_log ORDER BY id DESC LIMIT 5000)")
            except Exception as e:
                log_event("warning", "save_audit_skipped", error=str(e))


def list_audit(db_path, limit=300):
    """접근 로그 최신순 조회."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),))
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def get_port_history(db_path, switch_id, port=None, limit=500):
    """포트 이력: 스냅샷 시계열에서 (포트, MAC)별 최초/최근 관측 시각.

    추가 수집 없이 기존 mac_entries 이력 재활용(수집 주기 해상도).
    현재(최신 스냅샷)에 존재하면 current=1.
    Returns: [{port, mac, first_seen, last_seen, current, seen_count}]
    """
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            latest = latest_snapshot_id(db_path, switch_id)
            params = [switch_id]
            port_cond = ""
            if port:
                port_cond = " AND LOWER(m.port)=LOWER(?)"
                params.append(port)
            params.append(int(limit))
            cur.execute(
                """SELECT m.port AS port, m.mac AS mac,
                          MIN(s.collected_at) AS first_seen,
                          MAX(s.collected_at) AS last_seen,
                          COUNT(DISTINCT m.snapshot_id) AS seen_count,
                          MAX(m.snapshot_id) AS last_snap
                   FROM mac_entries m
                   JOIN snapshots s ON m.snapshot_id = s.id
                   WHERE m.switch_id = ?%s
                   GROUP BY m.port, m.mac
                   ORDER BY MAX(s.collected_at) DESC, m.port
                   LIMIT ?""" % port_cond, params)
            rows = []
            for r in cur.fetchall():
                d = dict(r)
                last_snap = d.pop("last_snap", None)
                d["current"] = 1 if (latest and last_snap == latest) else 0
                rows.append(d)
            return rows
        except Exception:
            return []


def get_port_channel_members(db_path):
    """전체 스위치 최신 스냅샷의 포트채널 멤버 매핑.

    Returns: {(switch_id, port_channel소문자): [member_port, ...]}
    설비 대조: MAC이 Po로 보일 때 실제 물리 멤버포트로 해석하는 데 사용.
    """
    mapping = {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            # 기준 세대를 get_mac_to_switchport와 맞춘다(= 데이터가 실제로 담긴
            # 최신 세대). MAC 명령만 실패한 수집이 새 스냅샷을 만들면 기준이
            # 어긋나 Po → 물리 멤버 해석이 통째로 실패했다.
            cur.execute(
                "SELECT switch_id, port_channel, members FROM port_channels "
                "WHERE snapshot_id IN (SELECT MAX(snapshot_id) FROM port_channels "
                "                      GROUP BY switch_id)")
            for r in cur.fetchall():
                pc = (r["port_channel"] or "").lower()
                if not pc:
                    continue
                members = [m for m in (r["members"] or "").split(",") if m]
                mapping[(r["switch_id"], pc)] = members
        except Exception:
            pass
    return mapping


def save_facility_hosts(db_path, hosts):
    """설비 현황 저장(subnet+ip 기준 upsert).
    hosts=[{subnet,ip,mac,switch_id,switch_name,port,online,direct,via,port_desc}]."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            # port_desc 컬럼 유무에 따라 SQL 분기(구버전 DB 호환)
            has_desc = False
            try:
                cols = {r[1] for r in cur.execute("PRAGMA table_info(facility_hosts)").fetchall()}
                has_desc = "port_desc" in cols
            except Exception:
                pass
            for h in hosts:
                try:
                    if has_desc:
                        cur.execute(
                            """INSERT OR REPLACE INTO facility_hosts
                               (subnet, ip, mac, switch_id, switch_name, port, online, direct, via, port_desc, updated)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                            (h.get("subnet"), h.get("ip"), h.get("mac"), h.get("switch_id"),
                             h.get("switch_name"), h.get("port"), 1 if h.get("online") else 0,
                             1 if h.get("direct", 1) else 0, h.get("via"), h.get("port_desc")))
                    else:
                        cur.execute(
                            """INSERT OR REPLACE INTO facility_hosts
                               (subnet, ip, mac, switch_id, switch_name, port, online, direct, via, updated)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                            (h.get("subnet"), h.get("ip"), h.get("mac"), h.get("switch_id"),
                             h.get("switch_name"), h.get("port"), 1 if h.get("online") else 0,
                             1 if h.get("direct", 1) else 0, h.get("via")))
                except Exception as e:
                    log_event("warning", "save_facility_skipped", error=str(e))


def clear_facility_subnet(db_path, subnet):
    """재수집 전 해당 대역의 기존 설비 결과 삭제(중복 누적 방지)."""
    with _db_lock:
        with get_db(db_path) as conn:
            try:
                conn.execute("DELETE FROM facility_hosts WHERE subnet=?", (subnet,))
            except Exception:
                pass


def replace_facility_subnet(db_path, subnet, hosts):
    """대역의 설비 목록을 **한 트랜잭션에서** 교체한다.

    예전에는 clear_facility_subnet() 후 save_facility_hosts()를 따로 호출했는데,
    둘이 별도 트랜잭션이라 삭제만 성공하고 저장이 실패하면(공유폴더 SQLite 경합)
    그 대역 설비가 통째로 사라졌다. 게다가 호출부는 예외를 삼켜 정상값을 반환해
    60초마다 도는 감시 루프에서 **아무도 모르게** 이력이 날아갔다.

    실패하면 예외를 그대로 올린다 — 호출부가 '이전 상태 유지'를 선택할 수 있도록.
    """
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            has_desc = False
            try:
                cols = {r[1] for r in cur.execute("PRAGMA table_info(facility_hosts)").fetchall()}
                has_desc = "port_desc" in cols
            except Exception:
                pass
            cur.execute("DELETE FROM facility_hosts WHERE subnet=?", (subnet,))
            for h in (hosts or []):
                if has_desc:
                    cur.execute(
                        """INSERT OR REPLACE INTO facility_hosts
                           (subnet, ip, mac, switch_id, switch_name, port, online, direct, via, port_desc, updated)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                        (h.get("subnet"), h.get("ip"), h.get("mac"), h.get("switch_id"),
                         h.get("switch_name"), h.get("port"), 1 if h.get("online") else 0,
                         1 if h.get("direct", 1) else 0, h.get("via"), h.get("port_desc")))
                else:
                    cur.execute(
                        """INSERT OR REPLACE INTO facility_hosts
                           (subnet, ip, mac, switch_id, switch_name, port, online, direct, via, updated)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
                        (h.get("subnet"), h.get("ip"), h.get("mac"), h.get("switch_id"),
                         h.get("switch_name"), h.get("port"), 1 if h.get("online") else 0,
                         1 if h.get("direct", 1) else 0, h.get("via")))


def get_facility_hosts(db_path):
    """설비 현황 전체 조회(대역·IP 정렬)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT * FROM facility_hosts ORDER BY subnet, ip LIMIT 100000")
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def save_switch_logs(db_path, switch_id, recent_lines, events_json, log_alert):
    """show logging 분석 결과 저장(스위치별 교체). recent_lines/events_json은 문자열."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    """INSERT OR REPLACE INTO switch_logs
                       (switch_id, recent_lines, events_json, log_alert, updated)
                       VALUES (?, ?, ?, ?, datetime('now','localtime'))""",
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


def get_switch_vlan_ids(db_path, switch_id):
    """스위치가 나르는 VLAN ID 집합(show vlan brief 기준). 없으면 빈 set."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT DISTINCT vlan FROM vlan_names WHERE switch_id=?", (switch_id,))
            return {r["vlan"] for r in cur.fetchall() if r["vlan"] is not None}
        except Exception:
            return set()


def get_vlan_summary(db_path):
    """전체 VLAN 목록과 스위치별 사용 현황 + VLAN 이름(show vlan brief).

    MAC이 학습된 VLAN(mac_entries)과 show vlan brief로 수집한 VLAN(vlan_names)을
    합집합으로 보여준다(MAC 0개인 VLAN도 이름과 함께 표시).

    MAC 수는 **최신 스냅샷 1세대만** 센다. 예전엔 스냅샷 필터가 없어 보관 중인
    세대(최대 50) 전부를 합산해 실제의 최대 50배로 표시됐다(화면에 그대로 노출되는 값).
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT v.vlan AS vlan, s.name AS switch_name, s.ip AS switch_ip,
                      IFNULL(s.hostname, '') AS switch_hostname,
                      v.name AS vlan_name, v.status AS vlan_status,
                      (SELECT COUNT(*) FROM mac_entries m
                       WHERE m.switch_id = v.switch_id AND m.vlan = v.vlan
                         AND m.snapshot_id = (SELECT MAX(m2.snapshot_id) FROM mac_entries m2
                                              WHERE m2.switch_id = v.switch_id)) AS mac_count
               FROM vlan_names v
               JOIN switches s ON v.switch_id = s.id
               UNION
               SELECT m.vlan AS vlan, s.name AS switch_name, s.ip AS switch_ip,
                      IFNULL(s.hostname, '') AS switch_hostname,
                      (SELECT vn.name FROM vlan_names vn
                       WHERE vn.switch_id = m.switch_id AND vn.vlan = m.vlan) AS vlan_name,
                      (SELECT vn.status FROM vlan_names vn
                       WHERE vn.switch_id = m.switch_id AND vn.vlan = m.vlan) AS vlan_status,
                      COUNT(*) AS mac_count
               FROM mac_entries m
               JOIN switches s ON m.switch_id = s.id
               WHERE NOT EXISTS (SELECT 1 FROM vlan_names vn2
                                 WHERE vn2.switch_id = m.switch_id AND vn2.vlan = m.vlan)
                 AND m.snapshot_id = (SELECT MAX(m3.snapshot_id) FROM mac_entries m3
                                      WHERE m3.switch_id = m.switch_id)
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
                    "UPDATE port_events SET count=count+1, last_seen=(datetime('now','localtime')) WHERE id=?",
                    (existing[0],),
                )
            else:
                cursor.execute(
                    """INSERT INTO port_events (switch_id, port_name, event_type,
                                                first_seen, last_seen)
                       VALUES (?, ?, ?, datetime('now','localtime'),
                               datetime('now','localtime'))""",
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
                """UPDATE switches SET ip = ?, vendor = ?, model = ?, status = ?, last_collected = (datetime('now','localtime'))
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
            "SELECT id, name, ip, hostname, vendor, model, os_version, serial, device_type, location, zone, status, alert, note, last_error, last_collected FROM switches WHERE id = ?",
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


# NOTE: get_switches는 아래(M7 섹션)에 단일 정의만 존재한다.
# (과거 이 위치에 중복 정의가 있어 첫 정의가 사장되던 버그 — Opus 검증에서 제거)


def normalize_vendor_values(db_path):
    """기존 DB의 벤더 별칭(cisco/extreme/nexus...)을 표준 값으로 일괄 정규화.

    자동 학습은 표준 값(extreme_exos 등)으로 저장하는데 수동 등록은 별칭이라
    화면·수정 모달에서 값이 섞여 보이던 문제 해결. 앱 시작 시 1회 호출.
    """
    from .collector import canonical_vendor
    n = 0
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            try:
                cur.execute("SELECT DISTINCT vendor FROM switches WHERE vendor IS NOT NULL")
                for (v,) in cur.fetchall():
                    canon = canonical_vendor(v)
                    if canon != v:
                        cur.execute("UPDATE switches SET vendor=? WHERE vendor=?", (canon, v))
                        n += cur.rowcount
            except Exception:
                pass
    if n:
        log_event("info", "vendor_values_normalized", count=n)
    return n


def backfill_versions_from_config(db_path):
    """버전이 빈 스위치를 기존 config 백업의 'version' 줄로 백필(재수집 불필요).

    IOS/NX-OS running-config 첫머리에 'version 15.2(7)E3' 형식이 있다.
    이전 버전에서 수집돼 os_version이 비어 있던 장비를 시작 시 채운다.
    """
    import re as _re
    n = 0
    prefix = {"cisco_ios": "IOS ", "cisco_nxos": "NX-OS "}
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "SELECT id, vendor FROM switches "
                    "WHERE (os_version IS NULL OR os_version='')")
                targets = cur.fetchall()
            except Exception:
                return 0
            for row in targets:
                sid, vendor = row["id"], (row["vendor"] or "").lower()
                if vendor not in prefix:
                    continue
                try:
                    cur.execute("SELECT content FROM config_backups WHERE switch_id=? "
                                "ORDER BY id DESC LIMIT 1", (sid,))
                    cb = cur.fetchone()
                    if not cb or not cb["content"]:
                        continue
                    m = _re.search(r"(?m)^version\s+(\S+)", cb["content"][:2000])
                    if m:
                        cur.execute("UPDATE switches SET os_version=? WHERE id=?",
                                    (prefix[vendor] + m.group(1), sid))
                        n += 1
                except Exception:
                    continue
    if n:
        log_event("info", "versions_backfilled_from_config", count=n)
    return n


def reset_stale_collecting(db_path):
    """앱 시작 시 '수집중' 고착 상태 복구.

    이전 실행이 수집 도중 종료(강제 종료/크래시)되면 DB에 status='collecting'이
    박제되어, 재시작 후 실제로는 아무것도 돌지 않는데 영원히 '수집중'으로 보였다.
    시작 시 이런 행을 '실패(중단됨)'로 정리해 재수집 대상으로 만든다.
    반환: 복구된 개수.
    """
    with _db_lock:
        with get_db(db_path) as conn:
            try:
                cur = conn.execute(
                    "UPDATE switches SET status='failed', "
                    "last_error='이전 실행이 수집 도중 중단됨(앱 재시작) — 재수집 필요' "
                    "WHERE status='collecting'")
                n = cur.rowcount
            except Exception:
                cur = conn.execute(
                    "UPDATE switches SET status='failed' WHERE status='collecting'")
                n = cur.rowcount
            # 서버·방화벽도 같은 고착이 생긴다. 예전엔 스위치만 정리해서
            # 재시작 후에도 '수집중' 뱃지가 영구히 남아 오인을 유발했다.
            for tbl, extra in (("servers", ", last_error='이전 실행이 수집 도중 중단됨(앱 재시작)'"),
                               ("firewalls", "")):
                try:
                    cur = conn.execute(
                        "UPDATE %s SET status='failed'%s WHERE status='collecting'"
                        % (tbl, extra))
                    n += cur.rowcount
                except Exception:
                    try:
                        cur = conn.execute(
                            "UPDATE %s SET status='failed' WHERE status='collecting'" % tbl)
                        n += cur.rowcount
                    except Exception:
                        pass
    if n:
        log_event("info", "stale_collecting_reset", count=n)
    return n


def set_switch_status(db_path, switch_id, status, error=None):
    """상태 갱신 + 실패 사유 저장(실패 시 last_error 기록, 성공/수집중이면 비움).

    이전엔 error 인자를 받고도 버려서 실패 원인을 화면에서 볼 수 없었다.
    """
    utils.log_event("info", "set_switch_status", switch_id=switch_id, status=status)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            try:
                if status == "failed":
                    cursor.execute(
                        "UPDATE switches SET status = ?, last_error = ? WHERE id = ?",
                        (status, (str(error) if error else "")[:300], switch_id))
                elif status == "done":
                    # FIX: 수집 성공 시 last_collected 갱신 — 이전엔 갱신되지 않아
                    # '마지막 수집' 컬럼이 항상 비어 있었음
                    cursor.execute(
                        "UPDATE switches SET status = ?, last_error = NULL, "
                        "last_collected = (datetime('now','localtime')) WHERE id = ?",
                        (status, switch_id))
                else:
                    cursor.execute(
                        "UPDATE switches SET status = ?, last_error = NULL WHERE id = ?",
                        (status, switch_id))
            except Exception:
                # 구버전 DB에 last_error 컬럼이 없으면 상태만 갱신
                cursor.execute(
                    "UPDATE switches SET status = ? WHERE id = ?", (status, switch_id))


def update_switch_status(db_path, switch_id, status, error=None):
    # update_switch_status updates status and last_collected timestamp
    utils.log_event("info", "update_switch_status", switch_id=switch_id, status=status)
    with _db_lock:
        with get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE switches SET status = ?, last_collected = (datetime('now','localtime')) WHERE id = ?",
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
                           VALUES (?, ?, ?, ?, (datetime('now','localtime')))""",
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
                "INSERT INTO snapshots (switch_id, duration_seconds, collected_at) "
                "VALUES (?, ?, datetime('now','localtime'))",
                (switch_id, duration)
            )
            snapshot_id = cursor.lastrowid
            # 세대 정리: 스위치당 최근 _SNAPSHOT_KEEP개만 유지(무한 누적 방지).
            # 초과 스냅샷과 그 파생 데이터(ports/mac/arp/port_channels)를 함께 삭제.
            # 포트 이력(get_port_history)이 시계열을 쓰므로 넉넉히 보존.
            try:
                old = cursor.execute(
                    "SELECT id FROM snapshots WHERE switch_id=? ORDER BY id DESC "
                    "LIMIT -1 OFFSET ?", (switch_id, _SNAPSHOT_KEEP)).fetchall()
                if old:
                    ids = [r[0] for r in old]
                    ph = ",".join("?" * len(ids))
                    # events.snapshot_id 가 snapshots(id)를 FK로 참조한다. 이 테이블을
                    # 빼먹으면 부모 삭제가 IntegrityError로 실패하고, 바깥 except가
                    # 삼켜 그 스위치의 세대 정리가 영구히 멈춘다(자식은 이미 지워진
                    # 뒤라 빈 껍데기 스냅샷이 무한 누적 + IN(...) 플레이스홀더도 계속 증가).
                    for tbl in ("ports", "mac_entries", "arp_entries", "port_channels",
                                "events"):
                        try:
                            cursor.execute("DELETE FROM %s WHERE snapshot_id IN (%s)" % (tbl, ph), ids)
                        except Exception:
                            pass
                    cursor.execute("DELETE FROM snapshots WHERE id IN (%s)" % ph, ids)
            except Exception as _e:
                # 조용히 삼키면 누적을 눈치챌 수 없다 — 원인을 남긴다
                utils.log_event("warning", "snapshot_retention_failed",
                                error=str(_e)[:160])

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
                       (snapshot_id, switch_id, name, status, vlan, speed, description,
                        crc_errors, in_errors, out_errors)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (snapshot_id, switch_id, port.get("name"), port.get("status"),
                     port.get("vlan"), port.get("speed"), port.get("description"),
                     port.get("crc_errors", 0), port.get("in_errors", 0), port.get("out_errors", 0))
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
    invalidate_mac_last_cache(db_path)   # 새 MAC 스냅샷 → 최근위치 캐시 갱신 필요
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
                               confidence=?, reason=?, updated_at=(datetime('now','localtime'))
                           WHERE ip=?""",
                        (host_data.get("mac"), host_data.get("switch_id"),
                         host_data.get("port"), host_data.get("located", False),
                         host_data.get("confidence", 0.0), host_data.get("reason"), ip),
                    )
                    results.append(existing[0])
                else:
                    cursor.execute(
                        """INSERT INTO hosts
                           (ip, mac, switch_id, port, located, confidence, reason,
                            updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'))""",
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
                               updated_at=(datetime('now','localtime')) WHERE ip=?""",
                        (new_mac or ex[1], new_hostname or ex[2],
                         new_lsw or ex[3], new_lport or ex[4], ip),
                    )
                    results.append(ex[0])
                else:
                    cursor.execute(
                        """INSERT INTO hosts (ip, mac, hostname, ledger_switch,
                                              ledger_port, updated_at)
                           VALUES (?, ?, ?, ?, ?, datetime('now','localtime'))""",
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


def update_switch(db_path, switch_id, name=None, ip=None, hostname=None, vendor=None,
                  location=None, note=None, os_version=None, model=None, device_type=None,
                  serial=None, zone=None):
    """스위치 등록 정보 수정(제공된 필드만, 존재 컬럼만). 반환: 성공 여부.

    note/device_type/zone은 빈 문자열("")도 유효(비우기). None이면 변경하지 않음.
    """
    fields = {"name": name, "ip": ip, "hostname": hostname, "vendor": vendor,
              "location": location, "note": note, "os_version": os_version,
              "model": model, "device_type": device_type, "serial": serial,
              "zone": zone}
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


def update_firewall(db_path, firewall_id, name=None, vendor=None, host=None, port=None, location=None):
    """방화벽 등록 정보 수정(제공된 필드만, 존재 컬럼만). 반환: 성공 여부.

    location은 빈 문자열("")도 유효(위치 비우기). None이면 변경하지 않음.
    """
    fields = {"name": name, "vendor": vendor, "host": host, "port": port, "location": location}
    fields = {k: v for k, v in fields.items() if v is not None}
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM firewalls WHERE id=?", (firewall_id,))
            if not cur.fetchone():
                return False
            cols = {r[1] for r in cur.execute("PRAGMA table_info(firewalls)").fetchall()}
            fields = {k: v for k, v in fields.items() if k in cols}
            if fields:
                assignments = ", ".join(f"{k}=?" for k in fields)
                cur.execute(f"UPDATE firewalls SET {assignments} WHERE id=?",
                            list(fields.values()) + [firewall_id])
            return True


# 스위치 삭제 시 정리할 파생 테이블(switch_id 참조). 존재하는 것만 안전 시도.
# BUGFIX: 이전엔 ports/mac/arp/snapshots/port_events만 지워 config_backups(비밀
# 포함 running-config)·neighbors·vlan_names·switch_logs·port_channels·device_events·
# facility_hosts가 잔존 → 삭제된 스위치 config가 /api/configs/<id>로 계속 다운로드
# 가능했다. app_settings의 enable_secret_<id>·nbrsrc_<id> 설정도 함께 제거.
# switches(id)를 FK로 참조하는 테이블은 **빠짐없이** 여기 있어야 한다.
# 하나라도 빠지면 foreign_keys=ON 때문에 DELETE FROM switches가 IntegrityError를
# 내는데, 그 예외를 삼키면 "삭제 성공"을 반환하면서 수집 데이터만 지워진다.
# (events는 _detect_disconnected가 MAC 1개 사라질 때마다 넣으므로 운영 DB엔 항상 있다)
_SWITCH_CHILD_TABLES = [
    "ports", "mac_entries", "arp_entries", "snapshots", "port_events",
    "config_backups", "neighbors", "vlan_names", "switch_logs",
    "port_channels", "device_events", "events",
]


def _purge_switch_children(cur, switch_id):
    for tbl in _SWITCH_CHILD_TABLES:
        try:
            cur.execute("DELETE FROM %s WHERE switch_id=?" % tbl, (switch_id,))
        except Exception:
            pass
    # hosts·facility_hosts는 인벤토리(스캔 결과)이므로 보존하되 위치만 무효화한다.
    # facility_hosts를 행째로 지우면 스위치 1대를 지웠다고 그 스위치에 붙어 있던
    # 설비의 IP·MAC·대역·온라인 여부가 통째로 사라졌다(대역 재스캔 전까지 복구 불가).
    for sql in (
        "UPDATE hosts SET switch_id=NULL, located=0 WHERE switch_id=?",
        "UPDATE facility_hosts SET switch_id=NULL, switch_name=NULL, port=NULL, "
        "direct=0 WHERE switch_id=?",
    ):
        try:
            cur.execute(sql, (switch_id,))
        except Exception:
            pass
    # 스위치별 설정(enable secret·이웃 소스) 제거
    for key in ("enable_secret_%d" % switch_id, "nbrsrc_%d" % switch_id):
        try:
            cur.execute("DELETE FROM app_settings WHERE key=?", (key,))
        except Exception:
            pass


def delete_switch(db_path, switch_id):
    """스위치 1대 삭제 + 관련 수집 데이터 정리. 반환: 삭제 여부(bool)."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM switches WHERE id=?", (switch_id,))
            if not cur.fetchone():
                return False
            _purge_switch_children(cur, switch_id)
            # 실패를 삼키면 안 된다 — 화면은 "삭제 완료"인데 스위치가 그대로 남고
            # 수집 데이터만 사라진 상태가 된다(재시도해도 영원히 같은 결과).
            try:
                cur.execute("DELETE FROM switches WHERE id=?", (switch_id,))
                ok = True
            except Exception as e:
                utils.log_event("error", "switch_delete_failed",
                                switch_id=switch_id, error=str(e)[:200])
                raise
    # mac_entries가 사라졌으므로 '과거 연결' 캐시 무효화(삭제된 스위치명 잔류 방지)
    invalidate_mac_last_cache(db_path)
    return ok


def delete_switches_bulk(db_path, switch_ids):
    """스위치 여러 대 일괄 삭제 + 관련 수집 데이터 정리. 반환: 실제 삭제된 개수."""
    ids = []
    for sid in (switch_ids or []):
        try:
            ids.append(int(sid))
        except (TypeError, ValueError):
            continue
    if not ids:
        return 0
    deleted = 0
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            for sid in ids:
                cur.execute("SELECT id FROM switches WHERE id=?", (sid,))
                if not cur.fetchone():
                    continue
                _purge_switch_children(cur, sid)
                try:
                    cur.execute("DELETE FROM switches WHERE id=?", (sid,))
                except Exception as e:
                    # 개별 실패는 건너뛰되 개수에 세지 않는다(허위 성공 방지)
                    utils.log_event("error", "switch_delete_failed",
                                    switch_id=sid, error=str(e)[:200])
                    continue
                deleted += 1
    if deleted:
        invalidate_mac_last_cache(db_path)   # 삭제된 스위치의 '과거 연결' 잔류 방지
    return deleted


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
def save_firewall(db_path, name, vendor, host, port=None, auth_type="token", location=None):
    """방화벽 장비 등록 ((name, host) 복합 기준 upsert). 반환: firewall id.

    HA/VRRP 이중화(같은 VIP)라도 hostname(name)이 다르면 Active/Backup을 각각 등록.
    location 컬럼이 없는 구버전 DB도 안전하도록 존재 컬럼만 동적 사용.
    """
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cols = {r[1] for r in cur.execute("PRAGMA table_info(firewalls)").fetchall()}
            has_loc = "location" in cols
            # (name, host) 복합 UPSERT — 같은 host라도 name이 다르면 별도 등록(이중화 대응)
            cur.execute("SELECT id FROM firewalls WHERE name=? AND host=?", (name, host))
            existing = cur.fetchone()
            if existing:
                if has_loc and location is not None:
                    cur.execute(
                        "UPDATE firewalls SET vendor=?, port=?, auth_type=?, location=? WHERE id=?",
                        (vendor, port, auth_type, location, existing[0]))
                else:
                    cur.execute(
                        "UPDATE firewalls SET vendor=?, port=?, auth_type=? WHERE id=?",
                        (vendor, port, auth_type, existing[0]))
                return existing[0]
            if has_loc:
                cur.execute(
                    """INSERT INTO firewalls (name, vendor, host, port, auth_type, location)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (name, vendor, host, port, auth_type, location))
            else:
                cur.execute(
                    """INSERT INTO firewalls (name, vendor, host, port, auth_type)
                       VALUES (?, ?, ?, ?, ?)""",
                    (name, vendor, host, port, auth_type))
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
                "UPDATE firewalls SET status=?, last_collected=datetime('now','localtime') WHERE id=?",
                (status, firewall_id),
            )


def set_firewall_ha_info(db_path, firewall_id, ha_json):
    """방화벽 HA 구성(JSON 문자열: mode/hbdev/monitor) 저장 — 이중화 표기용."""
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE firewalls SET ha_info=? WHERE id=?", (ha_json, firewall_id))


def save_firewall_interfaces(db_path, firewall_id, interfaces):
    """방화벽 인터페이스 교체 저장 (firewall_id 기준 전체 갱신). secondary_ips는 JSON 저장."""
    import json as _json
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("DELETE FROM firewall_interfaces WHERE firewall_id=?", (firewall_id,))
            has_sec = False
            try:
                cols = {r[1] for r in conn.execute("PRAGMA table_info(firewall_interfaces)").fetchall()}
                has_sec = "secondary_ips" in cols
            except Exception:
                pass
            for it in interfaces:
                zone = it.get("vdom_zone") or it.get("vdom") or it.get("zone")
                sec = it.get("secondary_ips") or []
                if has_sec:
                    conn.execute(
                        "INSERT INTO firewall_interfaces (firewall_id, name, ip, mask, vdom_zone, secondary_ips) "
                        "VALUES (?,?,?,?,?,?)",
                        (firewall_id, it.get("name"), it.get("ip"), it.get("mask"), zone,
                         _json.dumps(sec) if sec else None))
                else:
                    conn.execute(
                        "INSERT INTO firewall_interfaces (firewall_id, name, ip, mask, vdom_zone) VALUES (?,?,?,?,?)",
                        (firewall_id, it.get("name"), it.get("ip"), it.get("mask"), zone))


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
    import json as _json
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM firewall_interfaces WHERE firewall_id=? ORDER BY id", (firewall_id,))
        rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        raw = r.get("secondary_ips")
        try:
            r["secondary_ips"] = _json.loads(raw) if raw else []
        except (ValueError, TypeError):
            r["secondary_ips"] = []
    return rows


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


# ── PC 프로필 (수집 PC별 출발지 IP·계정 — core/pcprofile.py) ────────
def upsert_pc_profile(db_path, mac, hostname, source_ip, cred_blob=None):
    """PC 프로필 등록/갱신. cred_blob=None이면 기존 계정 blob 유지."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, cred_blob FROM pc_profiles WHERE mac=?", (mac,))
            row = cur.fetchone()
            if row:
                keep_blob = cred_blob if cred_blob is not None else row["cred_blob"]
                cur.execute(
                    "UPDATE pc_profiles SET hostname=?, source_ip=?, cred_blob=?, "
                    "updated_at=datetime('now', 'localtime') WHERE mac=?",
                    (hostname, source_ip or "", keep_blob, mac))
            else:
                cur.execute(
                    "INSERT INTO pc_profiles (mac, hostname, source_ip, cred_blob) "
                    "VALUES (?, ?, ?, ?)",
                    (mac, hostname, source_ip or "", cred_blob))


def get_pc_profile(db_path, mac):
    """MAC으로 PC 프로필 조회. 없으면 None."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT mac, hostname, source_ip, cred_blob, updated_at "
                    "FROM pc_profiles WHERE mac=?", (mac,))
        row = cur.fetchone()
        return dict(row) if row else None


def list_pc_profiles(db_path):
    """등록된 PC 프로필 목록(계정 blob 제외 — 표시용)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT mac, hostname, source_ip, updated_at, "
                    "CASE WHEN cred_blob IS NOT NULL AND cred_blob != '' "
                    "THEN 1 ELSE 0 END AS has_cred "
                    "FROM pc_profiles ORDER BY updated_at DESC")
        return [dict(r) for r in cur.fetchall()]


def delete_pc_profile(db_path, mac):
    """PC 프로필 삭제(계정·출발지 IP 포함). 반환: 삭제 행 수."""
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM pc_profiles WHERE mac=?", (mac,))
            return cur.rowcount


# ── 서버(리눅스/윈도우) 현황 CRUD ───────────────────────────────────
_SERVER_FIELDS = ("name", "ip", "os_type", "hostname", "mac", "is_vm",
                  "location", "open_ports", "os_info", "switch_name",
                  "switch_port", "status", "last_error",
                  # 하드웨어 사양(SSH 상세 수집)
                  "cpu_model", "cpu_cores", "mem_total_mb",
                  "disk_total_gb", "disk_used_gb",
                  "mem_modules", "mem_slots_total", "disk_devices")


def list_servers(db_path):
    """서버 목록(계정 blob 제외, has_cred만 노출)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM servers ORDER BY name LIMIT 10000")
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            d["has_cred"] = bool(d.pop("cred_blob", None))
            rows.append(d)
        return rows


def get_server(db_path, server_id):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM servers WHERE id=?", (server_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_server_by_ip(db_path, ip):
    """IP로 서버 1건 조회(없으면 None). servers.ip는 UNIQUE."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM servers WHERE ip=?", (ip,))
        row = cur.fetchone()
        return dict(row) if row else None


def adopt_server_switches(db_path):
    """구분(device_type)='Server'로 분류된 스위치 행을 servers 테이블로 편입(멱등).

    사용자가 스위치를 'Server'로 분류하면 실제로는 서버이므로 서버 현황에 있어야 한다.
    같은 IP의 서버가 이미 있으면 스위치 행만 제거한다. 반환: 편입한 수.
    """
    adopted = 0
    for sw in get_switches(db_path):
        if (sw.get("device_type") or "") != "Server":
            continue
        ip = sw.get("ip")
        if not ip:
            continue
        try:
            # 같은 IP의 서버가 이미 있으면 스위치 행만 제거한다.
            # (save_server의 UPDATE 분기는 os_type='auto'·is_vm=0·location을 덮어쓰므로
            #  이미 수집해 둔 값이 목록 조회(GET /api/servers)마다 날아간다)
            existing = get_server_by_ip(db_path, ip)
            if existing:
                delete_switch(db_path, sw["id"])
                adopted += 1
                log_event("info", "server_switch_adopted", ip=ip, name=sw.get("name") or ip)
                continue
            sid = save_server(db_path, sw.get("name") or ip, ip,
                              os_type="auto", location=sw.get("location") or None)
            # 스위치가 알던 hostname을 서버로 승계(편입 시 유실 방지)
            if sw.get("hostname"):
                try:
                    update_server(db_path, sid, hostname=sw.get("hostname"))
                except Exception:
                    pass
            delete_switch(db_path, sw["id"])
            adopted += 1
            log_event("info", "server_switch_adopted", ip=ip, name=sw.get("name") or ip)
        except Exception as e:
            log_event("warning", "server_switch_adopt_skip", ip=ip, error=str(e))
    return adopted


def save_server(db_path, name, ip, os_type=None, location=None, is_vm=None):
    """서버 등록(IP 기준 upsert). 반환: server id.

    **None은 '건드리지 않음'이다.** 예전에는 기본값(os_type='linux', location=None,
    is_vm=0)을 무조건 UPDATE해서, 서버를 몇 대 추가하려고 같은 엑셀을 다시 등록하면
    이미 수집·배치해 둔 서버의 위치·VM 여부·OS가 통째로 지워졌다(서버실 현황에서 사라짐).
    호출부가 실제로 지정한 값만 갱신한다.
    """
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM servers WHERE ip=?", (ip,))
            row = cur.fetchone()
            if row:
                sets, params = [], []
                for col, val in (("name", name), ("os_type", os_type),
                                 ("location", location)):
                    if val is not None:
                        sets.append("%s=?" % col)
                        params.append(val)
                if is_vm is not None:
                    sets.append("is_vm=?")
                    params.append(int(bool(is_vm)))
                if sets:
                    params.append(row["id"])
                    cur.execute("UPDATE servers SET %s WHERE id=?" % ", ".join(sets), params)
                return row["id"]
            cur.execute(
                "INSERT INTO servers (name, ip, os_type, location, is_vm) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, ip, os_type or "auto", location, int(bool(is_vm))))
            return cur.lastrowid


def update_server(db_path, server_id, **fields):
    """서버 필드 갱신(None 값은 건너뜀 — 기존값 보존). collected=True면 수집시각 갱신."""
    collected = fields.pop("collected", False)
    sets, params = [], []
    for k, v in fields.items():
        if k in _SERVER_FIELDS and v is not None:
            sets.append("%s=?" % k)
            params.append(v)
    if collected:
        sets.append("last_collected=datetime('now','localtime')")
    if not sets:
        return False
    params.append(server_id)
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE servers SET %s WHERE id=?" % ", ".join(sets), params)
    return True


def delete_server(db_path, server_id):
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM servers WHERE id=?", (server_id,))
            return cur.rowcount


def update_server_cred(db_path, server_id, cred_blob):
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE servers SET cred_blob=? WHERE id=?",
                         (cred_blob, server_id))


def get_server_credential(db_path, server_id):
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT cred_blob FROM servers WHERE id=?", (server_id,))
        row = cur.fetchone()
        return row["cred_blob"] if row and row["cred_blob"] else None


def find_location_by_mac(db_path, mac):
    """MAC만 아는 경우의 연결 위치 조회 → {switch_name, switch_id, port}.

    IP→MAC(arp_entries)이 없어도, 사양 수집(SSH·WMI·SNMP)이나 로컬 ARP 캐시에서
    MAC을 얻었다면 스위치·포트는 찾을 수 있다. 예전에는 이 경로가 없어서
    'MAC은 채워졌는데 연결스위치·포트만 빈' 서버가 많았다.

    mac_entries의 MAC 표기는 벤더마다 다르다(콜론·하이픈·점) → 정규화해 맞춘다.
    """
    if not mac:
        return {}
    import re as _re
    norm = _re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    if len(norm) != 12:
        return {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT m.port, m.switch_id, s.name AS switch_name "
                "FROM mac_entries m JOIN switches s ON s.id = m.switch_id "
                "WHERE REPLACE(REPLACE(REPLACE(LOWER(m.mac),':',''),'-',''),'.','')=? "
                "ORDER BY m.id DESC LIMIT 20", (norm,))
            rows = cur.fetchall()
            if not rows:
                return {}
            # 물리 포트 우선 — 포트채널 집합보다 실제 케이블이 꽂힌 멤버포트가 쓸모 있다.
            loc = None
            for r in rows:
                p = (r["port"] or "").lower()
                if not p.startswith(("po", "port-channel", "vl", "vlan")):
                    loc = r
                    break
            loc = loc or rows[0]
            return {"switch_name": loc["switch_name"], "switch_id": loc["switch_id"],
                    "port": loc["port"]}
        except Exception:
            return {}


def find_mac_location(db_path, ip):
    """이미 수집된 스위치 데이터에서 IP의 MAC과 연결 위치(스위치/포트)를 대조.

    ① 최신 스냅샷 arp_entries에서 IP→MAC ② mac_entries에서 MAC→스위치/포트.
    ③ 폴백: facility_hosts(설비 스캔 결과). 반환: {mac, switch_name, port} (없으면 빈 dict).
    """
    out = {}
    with get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT a.mac FROM arp_entries a WHERE a.ip=? ORDER BY a.id DESC LIMIT 1",
                (ip,))
            row = cur.fetchone()
            if row and row["mac"]:
                out["mac"] = row["mac"]
                # 물리 포트 우선: 같은 MAC이 여러 포트(Po·물리)에 보이면 물리 포트를
                # 고른다(포트채널 집합보다 실제 케이블이 꽂힌 멤버포트를 표시하기 위함).
                cur.execute(
                    "SELECT m.port, m.switch_id, s.name AS switch_name FROM mac_entries m "
                    "JOIN switches s ON s.id = m.switch_id "
                    "WHERE m.mac=? ORDER BY m.id DESC LIMIT 20", (row["mac"],))
                rows = cur.fetchall()
                loc = None
                for r in rows:                      # 물리 포트(Po/Vlan 아님) 우선
                    p = (r["port"] or "").lower()
                    if not p.startswith(("po", "port-channel", "vl", "vlan")):
                        loc = r
                        break
                if loc is None and rows:
                    loc = rows[0]
                if loc:
                    out["switch_name"] = loc["switch_name"]
                    out["switch_id"] = loc["switch_id"]
                    out["port"] = loc["port"]
            if not out:
                cur.execute(
                    "SELECT mac, switch_name, port FROM facility_hosts "
                    "WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,))
                fh = cur.fetchone()
                if fh:
                    out = {"mac": fh["mac"], "switch_name": fh["switch_name"],
                           "port": fh["port"]}
        except Exception:
            pass
    return {k: v for k, v in out.items() if v}


# ── 저장 계정 관리(관리자 화면 — 목록/삭제) ─────────────────────────
def list_switch_credentials(db_path):
    """저장 계정이 있는 스위치 목록(blob 제외 — 표시용)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, ip FROM switches "
                    "WHERE cred_blob IS NOT NULL AND cred_blob != '' ORDER BY name")
        return [dict(r) for r in cur.fetchall()]


def list_firewall_credentials(db_path):
    """저장 계정이 있는 방화벽 목록(blob 제외 — 표시용)."""
    with get_db(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, host FROM firewalls "
                    "WHERE cred_blob IS NOT NULL AND cred_blob != '' ORDER BY name")
        return [dict(r) for r in cur.fetchall()]


def clear_switch_credential(db_path, switch_id):
    """스위치 저장 계정 + enable secret 삭제.

    장비의 IP가 바뀌면 호출한다 — 저장된 계정은 '그 주소의 장비'에 주기로 한
    것이므로, 주소만 바꾸고 계정을 남겨두면 그 계정이 새 주소로 전송된다
    (웹셸·수집 경로). 자격증명 탈취로 이어진다.
    """
    utils.log_event("info", "clear_switch_credential", switch_id=switch_id)
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE switches SET cred_blob=NULL WHERE id=?", (switch_id,))
            conn.execute("DELETE FROM app_settings WHERE key=?",
                         ("enable_secret_%d" % switch_id,))


def clear_server_credential(db_path, server_id):
    """서버 저장 계정 삭제(IP 변경 시 — clear_switch_credential과 같은 이유)."""
    utils.log_event("info", "clear_server_credential", server_id=server_id)
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE servers SET cred_blob=NULL WHERE id=?", (server_id,))


def clear_firewall_credential(db_path, firewall_id):
    """방화벽 저장 계정 삭제."""
    utils.log_event("info", "clear_firewall_credential", firewall_id=firewall_id)
    with _db_lock:
        with get_db(db_path) as conn:
            conn.execute("UPDATE firewalls SET cred_blob=NULL WHERE id=?",
                         (firewall_id,))


def clear_all_credentials(db_path):
    """저장된 계정 전부 삭제 — 스위치·방화벽 blob, PC 프로필 계정,
    enable secret. PC 프로필의 출발지 IP는 유지(계정만 삭제).
    반환: {"switches": n, "firewalls": n, "profiles": n}
    """
    utils.log_event("warning", "clear_all_credentials")
    with _db_lock:
        with get_db(db_path) as conn:
            cur = conn.cursor()
            cur.execute("UPDATE switches SET cred_blob=NULL "
                        "WHERE cred_blob IS NOT NULL AND cred_blob != ''")
            n_sw = cur.rowcount
            cur.execute("UPDATE firewalls SET cred_blob=NULL "
                        "WHERE cred_blob IS NOT NULL AND cred_blob != ''")
            n_fw = cur.rowcount
            cur.execute("UPDATE pc_profiles SET cred_blob=NULL "
                        "WHERE cred_blob IS NOT NULL AND cred_blob != ''")
            n_prof = cur.rowcount
            cur.execute("DELETE FROM app_settings WHERE key LIKE 'enable_secret_%'")
    return {"switches": n_sw, "firewalls": n_fw, "profiles": n_prof}


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
