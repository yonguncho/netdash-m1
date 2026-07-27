"""단일 서버 인스턴스 보장 — 다중 PC 동시 실행으로 인한 DB 오류 차단.

SQLite(WAL) DB는 네트워크 공유 폴더를 통한 다중 호스트 동시 접근을 지원하지
않는다(WAL 인덱스가 같은 머신의 공유 메모리 기반). 두 PC가 같은 데이터
디렉터리로 서버를 띄우면 잠금 충돌·무결성 오류(db_error)가 난다.

메커니즘: OS 파일 잠금(byte-range lock).
- 서버는 netdash_server.lock 을 열어 배타 잠금을 프로세스 수명 동안 유지.
- 두 번째 실행자는 잠금 시도 실패 → netdash_server.info(호스트명/URL)를 읽어 안내.
- 프로세스가 죽으면(크래시 포함) OS가 잠금을 자동 해제 → 재시작 대기 없음.
- SMB 공유폴더에서도 파일서버가 잠금을 강제하므로 다중 PC 차단이 정확하다.
  (heartbeat+PID 방식은 PID 재사용·시계 오차로 오판 가능해 채택하지 않음)
"""
import atexit
import json
import os
import re
import socket
from pathlib import Path

from . import utils

LOCK_FILENAME = "netdash_server.lock"
INFO_FILENAME = "netdash_server.info"

_fh = None          # 잠금 파일 핸들 — 프로세스 수명 동안 열어 둔다
_info_path = None


def _try_lock(fh) -> None:
    """열린 파일 핸들의 첫 1바이트에 배타 잠금(논블로킹). 실패 시 OSError."""
    fh.seek(0, 2)
    if fh.tell() == 0:
        fh.write(b"L")  # 잠글 바이트 확보
        fh.flush()
    fh.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _safe_err(e):
    """예외 메시지에서 DB/공유폴더 절대경로를 지운다.

    netdash.log는 DB 옆(공유폴더)에 쌓이므로, 경로가 그대로 남으면 공유 접근
    권한자 전원에게 내부 경로가 노출된다.
    """
    msg = str(e)
    msg = re.sub(r"[A-Za-z]:\\\\[^\s'\"]+", "<path>", msg)
    msg = re.sub(r"\\\\\\\\[^\s'\"]+", "<path>", msg)      # UNC \\server\share
    return msg[:160]


def read_info(data_dir) -> dict | None:
    try:
        return json.loads((Path(data_dir) / INFO_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def acquire(data_dir, url: str, allow_unlocked=True):
    """서버 인스턴스 락 획득 시도.

    Args:
        allow_unlocked: 락 파일을 열지 못했을 때의 처리.
            True(기동 시) — best-effort로 진행을 허용한다. 첫 기동은 막지 않는다.
            False(승격 판단 시) — 락을 확인하지 못했으면 획득 실패로 본다.

    Returns:
        (True, None)  — 획득 성공.
        (False, info) — 다른 인스턴스 실행 중이거나 락 확인 불가.
                        info={hostname, pid, url} (없으면 {}).
    """
    global _fh, _info_path
    lock = Path(data_dir) / LOCK_FILENAME
    try:
        fh = open(lock, "a+b")
    except OSError as e:
        # 공유폴더 순단·권한 오류로 락 파일을 못 여는 상황.
        # 여기서 '획득 성공'을 돌려주면, 진짜 주 서버가 살아 있는데도 읽기 전용
        # 인스턴스가 자기를 주 서버로 승격해 두 PC가 같은 SQLite에 동시 쓰기를 한다.
        # 그래서 승격 판단에서는 반드시 실패로 취급한다(allow_unlocked=False).
        utils.log_event("warning", "instance_lock_open_failed",
                        error=_safe_err(e), allow_unlocked=allow_unlocked)
        if allow_unlocked:
            return True, None
        return False, read_info(data_dir) or {}
    try:
        _try_lock(fh)
    except OSError:
        # 다른 프로세스(다른 PC 포함)가 잠금 보유 중
        try:
            fh.close()
        except OSError:
            pass
        info = read_info(data_dir) or {}
        utils.log_event("warning", "instance_lock_blocked",
                        other_host=info.get("hostname"), other_pid=info.get("pid"))
        return False, info

    _fh = fh
    _info_path = Path(data_dir) / INFO_FILENAME
    try:
        _info_path.write_text(json.dumps({
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "url": url,
        }), encoding="utf-8")
    except OSError:
        pass  # 안내 정보 기록 실패는 치명적이지 않음
    atexit.register(release)
    utils.log_event("info", "instance_lock_acquired", path=str(lock))
    return True, None


def release() -> None:
    """잠금 해제(정상 종료 시). 크래시 시에는 OS가 자동 해제한다."""
    global _fh, _info_path
    fh, _fh = _fh, None
    info_path, _info_path = _info_path, None
    if fh is None:
        return
    try:
        fh.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        fh.close()
    except OSError:
        pass
    if info_path:
        try:
            info_path.unlink()
        except OSError:
            pass
