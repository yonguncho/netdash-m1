"""단일 서버 인스턴스 락 테스트 (다중 PC 동시 실행 → db_error 차단).

검증 목표:
- 빈 디렉터리에서 락 획득 성공 + 락 파일 생성.
- 다른 호스트의 신선한 락이 있으면 차단(안내 정보 반환).
- 오래된(stale) 락은 인수(takeover).
- 같은 호스트의 죽은 PID 락은 즉시 인수.
- release가 내 락을 삭제.
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import instance_lock


@pytest.fixture(autouse=True)
def _clean_lock_state():
    """전역 상태 격리: 각 테스트 후 heartbeat 정지 + 락 해제."""
    yield
    instance_lock.release()


def _write_fake_lock(d, hostname, pid, mtime_ago=0):
    lock = Path(d) / instance_lock.LOCK_FILENAME
    lock.write_text(json.dumps({
        "hostname": hostname, "pid": pid,
        "url": "http://127.0.0.1:8082", "heartbeat": time.time() - mtime_ago,
    }), encoding="utf-8")
    if mtime_ago:
        past = time.time() - mtime_ago
        os.utime(lock, (past, past))
    return lock


def test_acquire_on_empty_dir(tmp_path):
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is True and other is None
    lock = tmp_path / instance_lock.LOCK_FILENAME
    assert lock.exists()
    info = json.loads(lock.read_text(encoding="utf-8"))
    assert info["pid"] == os.getpid()


def test_blocked_by_fresh_lock_from_other_host(tmp_path):
    """다른 PC의 신선한 락 → 차단 + 상대 정보 반환 (핵심 시나리오)."""
    _write_fake_lock(tmp_path, "OTHER-PC", 12345)
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is False
    assert other["hostname"] == "OTHER-PC"
    assert other["url"] == "http://127.0.0.1:8082"


def test_takeover_stale_lock(tmp_path):
    """STALE_AFTER 초과로 갱신 안 된 락 = 죽은 서버 → 인수."""
    _write_fake_lock(tmp_path, "OTHER-PC", 12345,
                     mtime_ago=instance_lock.STALE_AFTER + 5)
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is True and other is None


def test_takeover_same_host_dead_pid(tmp_path, monkeypatch):
    """같은 호스트 + 죽은 PID → stale 대기 없이 즉시 인수 (크래시 후 재시작)."""
    import socket
    _write_fake_lock(tmp_path, socket.gethostname(), 99999)
    monkeypatch.setattr(instance_lock, "_pid_alive_local", lambda pid: False)
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is True and other is None


def test_blocked_same_host_alive_pid(tmp_path, monkeypatch):
    """같은 호스트라도 PID가 살아있으면 차단 (같은 PC 중복 실행)."""
    import socket
    _write_fake_lock(tmp_path, socket.gethostname(), 12345)
    monkeypatch.setattr(instance_lock, "_pid_alive_local", lambda pid: True)
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is False


def test_release_removes_own_lock(tmp_path):
    instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    lock = tmp_path / instance_lock.LOCK_FILENAME
    assert lock.exists()
    instance_lock.release()
    assert not lock.exists()


# ---------------------------------------------------------------------------
# 네트워크 경로 ACL 스킵 — "특정 PC에서만 db_error" 원인 수정
# (공유폴더 DB에 owner-only icacls → 첫 실행 계정 외 접근 거부)
# ---------------------------------------------------------------------------

def test_is_network_path_unc_and_local():
    from core import utils
    assert utils.is_network_path(r"\\fileserver\share\netdash.db") is True
    assert utils.is_network_path("//fileserver/share/netdash.db") is True
    assert utils.is_network_path(r"C:\Users\x\netdash.db") is False
    assert utils.is_network_path("netdash.db") is False


def test_restrict_db_permissions_skips_network_path(monkeypatch):
    """UNC 경로 DB에는 icacls(owner-only)를 실행하지 않아야 한다."""
    import subprocess
    from core import db as db_mod
    calls = []
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: calls.append(a) or None)
    unc = r"\\fileserver\share\netdash_test_acl.db"
    db_mod._acl_applied.discard(unc)
    db_mod._restrict_db_permissions(unc)
    assert calls == []  # icacls 미호출
    # 로컬 경로는 기존대로 icacls 호출됨 (동작 불변 확인)
    local = r"C:\some\local\netdash_test_acl.db"
    db_mod._acl_applied.discard(local)
    db_mod._restrict_db_permissions(local)
    assert len(calls) == 1


def test_frozen_prefers_exe_dir_config(tmp_path, monkeypatch):
    """frozen exe: exe 옆 config.yaml이 번들 기본값보다 우선 (host 오버라이드 경로)."""
    from core import config_loader
    exe_dir = tmp_path / "app_folder"
    exe_dir.mkdir()
    (exe_dir / "config.yaml").write_text("db_path: netdash.db\n", encoding="utf-8")
    monkeypatch.delenv("NETDASH_CONFIG", raising=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "netdash.exe"))
    resolved = config_loader._resolve_config_path("config.yaml")
    assert resolved == str(exe_dir / "config.yaml")
