"""단일 서버 인스턴스 락 테스트 (다중 PC 동시 실행 → db_error 차단).

메커니즘: OS 파일 잠금(byte-range lock). 프로세스 사망 시 OS가 자동 해제하므로
크래시 후 재시작 대기가 없다. 검증 목표:
- 빈 디렉터리에서 락 획득 성공 + info 파일 생성.
- 잠금 보유 중 두 번째 획득 시도(별도 파일 핸들) → 차단 + 상대 정보 반환.
- release 후 재획득 성공(크래시 시 OS 자동 해제와 동일 의미).
- 별도 프로세스가 잠금 보유 → 차단 (실제 크로스 프로세스 검증).
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import instance_lock


@pytest.fixture(autouse=True)
def _clean_lock_state():
    """전역 상태 격리: 각 테스트 후 잠금 해제."""
    yield
    instance_lock.release()


def test_acquire_on_empty_dir(tmp_path):
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is True and other is None
    assert (tmp_path / instance_lock.LOCK_FILENAME).exists()
    info = json.loads((tmp_path / instance_lock.INFO_FILENAME)
                      .read_text(encoding="utf-8"))
    assert info["pid"] == os.getpid()
    assert info["url"] == "http://127.0.0.1:8082"


def test_second_acquire_blocked_with_info(tmp_path):
    """잠금 보유 중 재획득(새 파일 핸들) → 차단 + 기존 서버 정보 반환."""
    ok1, _ = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok1 is True
    import socket
    ok2, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:9999")
    assert ok2 is False
    assert other["hostname"] == socket.gethostname()
    assert other["url"] == "http://127.0.0.1:8082"  # 기존 서버의 URL


def test_release_then_reacquire(tmp_path):
    """해제 후 재획득 성공 — 크래시 시 OS 자동 해제와 동일 의미(대기 없음)."""
    instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    instance_lock.release()
    ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
    assert ok is True and other is None


def test_blocked_by_other_process(tmp_path):
    """실제 별도 프로세스가 잠금 보유 → 차단. 프로세스 kill 후 → 즉시 재획득."""
    holder = (
        "import sys; sys.path.insert(0, r'%s')\n"
        "from core import instance_lock\n"
        "ok, _ = instance_lock.acquire(r'%s', 'http://other:8082')\n"
        "print('LOCKED' if ok else 'FAIL', flush=True)\n"
        "import time; time.sleep(60)\n"
    ) % (str(Path(__file__).parent.parent), str(tmp_path))
    p = subprocess.Popen([sys.executable, "-c", holder],
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout.readline().strip() == "LOCKED"  # 자식이 잠금 확보 대기
        ok, other = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
        assert ok is False
        assert other.get("url") == "http://other:8082"
    finally:
        p.kill()
        p.wait(timeout=10)
    # 프로세스 사망 → OS가 잠금 자동 해제 → 즉시(수 초 내) 재획득 가능
    deadline = time.time() + 10
    ok = False
    while time.time() < deadline:
        ok, _ = instance_lock.acquire(tmp_path, "http://127.0.0.1:8082")
        if ok:
            break
        time.sleep(0.5)
    assert ok is True


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
    import subprocess as sp
    from core import db as db_mod
    calls = []
    monkeypatch.setattr(sp, "run", lambda *a, **k: calls.append(a) or None)
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
