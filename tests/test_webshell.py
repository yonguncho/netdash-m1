# -*- coding: utf-8 -*-
"""웹 SSH 터미널(webshell) — 인증/자격증명/UI 테스트(실제 SSH 없이 로직만)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, credentials, webshell

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


class _FakeWS:
    def __init__(self, incoming=None):
        self.sent = []
        self._in = list(incoming or [])
    def send(self, data):
        self.sent.append(data)
    def receive(self, timeout=None):
        return self._in.pop(0) if self._in else None


def test_resolve_credentials_saved(temp_db):
    # 대상이 스위치·방화벽·서버로 확장되면서 (db_path, kind, id, user, pw) 시그니처가 됐다
    sid = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    credentials.save_credential(sid, "admin", "pw123")   # 세션 저장
    try:
        u, p = webshell._resolve_credentials(temp_db, "switch", sid, "", "")
        assert u == "admin" and p == "pw123"
        # 전달된 계정이 우선
        u2, p2 = webshell._resolve_credentials(temp_db, "switch", sid, "other", "x")
        assert u2 == "other" and p2 == "x"
    finally:
        # 세션 저장소는 모듈 전역이라 정리하지 않으면 다음 테스트로 샌다
        credentials.clear_session_switch(sid)


def test_run_shell_rejects_unknown_switch(temp_db):
    ws = _FakeWS()
    webshell.run_shell(ws, temp_db, 99999, "", "", None, client_ip="10.0.0.5")
    assert any("등록되지 않은" in s for s in ws.sent)


def test_run_shell_rejects_no_credentials(temp_db):
    sid = db.save_switch(temp_db, "SW2", "10.0.0.2", "cisco_ios")
    ws = _FakeWS()
    webshell.run_shell(ws, temp_db, sid, "", "", None, client_ip="10.0.0.5")
    assert any("계정 정보가 없습니다" in s for s in ws.sent)


def test_run_shell_ssrf_block(temp_db):
    sid = db.save_switch(temp_db, "SW3", "8.8.8.8", "cisco_ios")
    credentials.save_credential(sid, "admin", "pw")
    ws = _FakeWS()

    def _vip(ip):
        raise ValueError("공인 IP 차단")
    try:
        webshell.run_shell(ws, temp_db, sid, "", "", None, validate_ip=_vip, client_ip="x")
        assert any("허용되지 않는 IP" in s for s in ws.sent)
    finally:
        credentials.clear_session_switch(sid)


def test_webshell_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="modal-terminal"' in html
    assert "/static/vendor/xterm.js" in html
    assert 'id="detail-terminal"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "function openTerminal" in js
    assert "/ws/shell/" in js
    assert "resize:" in js


def test_ws_route_registered(client):
    """create_app에서 웹셸 WS 라우트가 등록됨(flask-sock 있을 때)."""
    import app as _app
    src = __import__("inspect").getsource(_app.create_app)
    assert "/ws/shell/" in src
    assert "flask_sock" in src
