# -*- coding: utf-8 -*-
"""SSH 인증 실패로 사양을 못 가져오던 문제 (v6.6.3).

사용자 보고: "SSH 포트가 열린 서버인데도 사양이 안 잡히고 로그에
`authentication (password) failed` 가 뜬다. 그런데 상태는 정상이고
IP·MAC·OS·열린 포트는 다 수집된다."

원인 두 가지.
① paramiko의 SSHClient.connect()는 비밀번호를 주면 `auth_password` 만 시도한다.
   PAM을 쓰는 리눅스(RHEL·SUSE·Debian)는 `PasswordAuthentication no` +
   `KbdInteractiveAuthentication yes` 로 password 방식을 막아 둔 경우가 흔해,
   **비밀번호가 맞아도** 인증이 실패했다.
② 화면이 `status === "failed"` 일 때만 사유를 보여줘서, 도달은 됐고(열린 포트 존재)
   사양만 못 가져온 경우 **이유가 어디에도 표시되지 않았다**(상태는 '정상').
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import server_collector as sc  # noqa: E402

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


class _FakeTransport:
    def __init__(self, addr, ok_pw="correct-pw"):
        self.addr = addr
        self.authed = False
        self.banner_timeout = None
        self._ok = ok_pw

    def start_client(self, timeout=None):
        pass

    def auth_interactive(self, user, handler):
        import paramiko
        answers = handler("", "", ["Password: "])
        self.authed = answers == [self._ok]
        if not self.authed:
            raise paramiko.AuthenticationException("kbd failed")

    def is_authenticated(self):
        return self.authed

    def close(self):
        pass


class _RejectPasswordClient:
    def __init__(self):
        self._transport = None

    def connect(self, ip, **kw):
        import paramiko
        raise paramiko.AuthenticationException("Authentication (password) failed.")


def test_falls_back_to_keyboard_interactive(monkeypatch):
    """password 방식이 막힌 서버에서도 같은 비밀번호로 접속돼야 한다."""
    import paramiko
    monkeypatch.setattr(paramiko, "Transport", _FakeTransport)
    cli = _RejectPasswordClient()
    assert sc._ssh_connect(cli, "10.1.1.1", 22, "svc", "correct-pw", 15) == \
        "keyboard-interactive"
    assert cli._transport is not None, "이후 명령 실행에 쓸 세션이 없다"


def test_wrong_password_still_fails(monkeypatch):
    """폴백이 틀린 비밀번호를 통과시키면 안 된다."""
    import paramiko
    monkeypatch.setattr(paramiko, "Transport", _FakeTransport)
    with pytest.raises(paramiko.AuthenticationException):
        sc._ssh_connect(_RejectPasswordClient(), "10.1.1.1", 22, "svc", "wrong", 15)


def test_password_success_does_not_use_fallback(monkeypatch):
    """정상 서버는 폴백 없이 password로 붙는다(불필요한 재접속 방지)."""
    used = {"transport": False}

    class _T(_FakeTransport):
        def __init__(self, addr):
            used["transport"] = True
            super().__init__(addr)

    class _OkClient:
        def connect(self, ip, **kw):
            return None

    import paramiko
    monkeypatch.setattr(paramiko, "Transport", _T)
    assert sc._ssh_connect(_OkClient(), "10.1.1.1", 22, "svc", "pw", 15) == "password"
    assert used["transport"] is False


def test_ssh_exec_uses_shared_connect():
    src = (ROOT / "core" / "server_collector.py").read_text(encoding="utf-8")
    assert "_ssh_connect(cli, ip, port, username, password, timeout)" in src
    assert "auth_interactive" in src


# ── 화면: 부분 수집 사유가 보인다 ───────────────────────────────
def test_reason_visible_when_status_is_done():
    i = APPJS.index("function statusBadge(")
    body = APPJS[i:i + 1200]
    assert "부분 수집" in body, "도달했지만 일부만 수집된 사유가 화면에 안 보인다"
    assert 'status === "failed"' in body, "실패 표기는 그대로 유지돼야 한다"


def test_no_extra_badge_when_no_error():
    """정상 수집에는 '부분 수집' 배지를 붙이면 안 된다."""
    i = APPJS.index("function statusBadge(")
    body = APPJS[i:i + 1200]
    assert "if (!lastError) return h;" in body


def test_warn_style_defined():
    css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert ".cell-sub--warn" in css
