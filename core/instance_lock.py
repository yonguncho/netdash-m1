"""단일 서버 인스턴스 보장 — 다중 PC 동시 실행으로 인한 DB 오류 차단.

SQLite(WAL) DB는 네트워크 공유 폴더를 통한 다중 호스트 동시 접근을 지원하지
않는다(WAL 인덱스가 같은 머신의 공유 메모리 기반). 두 PC가 같은 데이터
디렉터리로 서버를 띄우면 잠금 충돌·무결성 오류(db_error)가 난다.

해결: 데이터 디렉터리에 락 파일(netdash_server.lock)을 두고 서버는 한 번에
하나만 실행. 두 번째 실행자에게는 기존 서버(호스트명·URL)를 안내한다.
- heartbeat: 실행 중인 서버가 30초마다 락 파일 갱신(mtime).
- stale 판정: 90초 이상 갱신 없으면 죽은 서버로 보고 인수(takeover).
- 같은 호스트면 PID 생존 검사로 즉시 인수 가능(크래시 후 재시작 지연 없음).
"""
import atexit
import json
import os
import socket
import threading
import time
from pathlib import Path

from . import utils

LOCK_FILENAME = "netdash_server.lock"
HEARTBEAT_INTERVAL = 30  # sec — 실행 중 락 갱신 주기
STALE_AFTER = 90         # sec — 이보다 오래 갱신 없으면 죽은 서버로 간주

_lock_path: Path | None = None
_hb_stop = threading.Event()


def _pid_alive_local(pid) -> bool:
    """같은 호스트에서 PID 생존 여부(best-effort)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            h = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h:
                ctypes.windll.kernel32.CloseHandle(h)
                return True
            return False
        except Exception:
            return True  # 판정 불가 시 보수적으로 '살아있음' 간주
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _write_lock(lock: Path, url: str) -> None:
    lock.write_text(json.dumps({
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "url": url,
        "heartbeat": time.time(),
    }), encoding="utf-8")


def read_lock(data_dir) -> dict | None:
    lock = Path(data_dir) / LOCK_FILENAME
    try:
        return json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def acquire(data_dir, url: str):
    """서버 인스턴스 락 획득 시도.

    Returns:
        (True, None)  — 획득 성공. heartbeat 스레드 시작 + atexit 해제 등록.
        (False, info) — 다른 인스턴스 실행 중. info={hostname, pid, url, ...}.
    """
    global _lock_path
    lock = Path(data_dir) / LOCK_FILENAME
    if lock.exists():
        info = read_lock(data_dir) or {}
        # 나이 판정은 mtime 기준 — 파일서버(공유폴더) 시계로 양쪽 PC가 같은 값을 봄
        try:
            age = time.time() - lock.stat().st_mtime
        except OSError:
            age = STALE_AFTER  # stat 실패 시 인수 시도
        same_host = info.get("hostname") == socket.gethostname()
        if age < STALE_AFTER:
            if same_host and not _pid_alive_local(info.get("pid")):
                pass  # 같은 호스트의 죽은 PID → 즉시 인수 (크래시 후 재시작)
            else:
                utils.log_event("warning", "instance_lock_blocked",
                                other_host=info.get("hostname"),
                                other_pid=info.get("pid"), age_sec=int(age))
                return False, info
        utils.log_event("info", "instance_lock_takeover",
                        prev_host=info.get("hostname"), age_sec=int(age))
    try:
        _write_lock(lock, url)
    except OSError as e:
        # 락을 못 쓰는 환경(권한 등)이면 차단하지 않고 통과(best-effort 보호)
        utils.log_event("warning", "instance_lock_write_failed", error=str(e))
        return True, None
    _lock_path = lock
    _hb_stop.clear()
    t = threading.Thread(target=_heartbeat_loop, args=(lock, url),
                         daemon=True, name="instance-lock-heartbeat")
    t.start()
    atexit.register(release)
    utils.log_event("info", "instance_lock_acquired", path=str(lock))
    return True, None


def _heartbeat_loop(lock: Path, url: str) -> None:
    while not _hb_stop.wait(HEARTBEAT_INTERVAL):
        try:
            _write_lock(lock, url)
        except OSError:
            pass  # 일시적 공유폴더 오류 — 다음 주기에 재시도


def release() -> None:
    """내가 잡은 락 해제(정상 종료 시). 내 PID의 락일 때만 삭제."""
    global _lock_path
    _hb_stop.set()
    lock, _lock_path = _lock_path, None
    if not lock:
        return
    try:
        info = json.loads(lock.read_text(encoding="utf-8"))
        if info.get("pid") == os.getpid():
            lock.unlink()
    except (OSError, ValueError):
        pass
