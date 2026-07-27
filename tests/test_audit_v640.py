# -*- coding: utf-8 -*-
"""전체 버그 검증(v6.4.0) 회귀 테스트.

C-1 원격 접속 설정 오류 시 exe가 파이썬 트레이스백만 남기고 즉사
C-2 접속 토큰이 werkzeug 접근 로그(공유폴더 netdash.log)에 평문으로 기록
"""
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import app as app_mod

ROOT = Path(__file__).parent.parent
TOKEN = "Abcdefgh1234567890Abcdefgh1234567890"
REMOTE = {"REMOTE_ADDR": "192.168.10.77"}


def _remote_app(tmp_path, monkeypatch, token=TOKEN):
    from config import reset_config
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "app:\n  host: 0.0.0.0\n  port: 8099\n  demo_mode: false\n"
        "  data_dir: %s\napi_token: %s\n" % (str(tmp_path).replace("\\", "/"), token),
        encoding="utf-8")
    monkeypatch.setenv("NETDASH_CONFIG", str(cfg))
    monkeypatch.delenv("API_TOKEN", raising=False)
    reset_config()
    a = app_mod.create_app()
    a.config["TESTING"] = True
    return a


# ── C-2: 토큰이 로그에 남지 않는다 ───────────────────────────────
def test_access_log_redacts_token():
    """werkzeug는 요청 라인을 그대로 찍는다 — token= 값이 남으면 안 된다."""
    rec = logging.LogRecord("werkzeug", logging.INFO, "", 0,
                            '%s - - [x] "%s" %s -',
                            ("192.168.10.77", "GET /?token=" + TOKEN + " HTTP/1.1", "302"),
                            None)
    assert app_mod._RedactTokenFilter().filter(rec) is True
    line = rec.getMessage()
    assert TOKEN not in line, "공유폴더 netdash.log에 토큰이 평문으로 남는다"
    assert "<redacted>" in line


def test_redaction_filter_is_installed(tmp_path, monkeypatch):
    _remote_app(tmp_path, monkeypatch)
    for name in ("werkzeug", ""):
        lg = logging.getLogger(name)
        assert any(isinstance(f, app_mod._RedactTokenFilter) for f in lg.filters), name


def test_redaction_keeps_normal_lines_intact():
    """정상 요청 라인까지 뭉개면 진단이 불가능해진다."""
    for raw in ('GET /api/state HTTP/1.1', 'POST /api/switches/collect HTTP/1.1',
                'GET /static/app.js HTTP/1.1'):
        rec = logging.LogRecord("werkzeug", logging.INFO, "", 0, "%s", (raw,), None)
        app_mod._RedactTokenFilter().filter(rec)
        assert rec.getMessage() == raw


def test_token_submitted_by_post_not_query(tmp_path, monkeypatch):
    a = _remote_app(tmp_path, monkeypatch)
    c = a.test_client()
    r = c.post("/session", data={"token": TOKEN, "next": "/"}, environ_overrides=REMOTE)
    assert r.status_code == 302
    assert "netdash_token" in r.headers.get("Set-Cookie", "")
    # 리다이렉트 주소에 토큰이 실리면 다시 로그에 남는다
    assert "token" not in r.headers.get("Location", "")
    assert c.get("/", environ_overrides=REMOTE).status_code == 200


def test_login_form_uses_post(tmp_path, monkeypatch):
    a = _remote_app(tmp_path, monkeypatch)
    r = a.test_client().get("/", environ_overrides=REMOTE)
    assert r.status_code == 401
    html = r.data.decode("utf-8")
    assert 'method="post"' in html and 'action="/session"' in html
    assert 'method="get"' not in html.lower()


def test_query_token_is_moved_to_cookie_and_stripped(tmp_path, monkeypatch):
    """하위호환 경로도 URL에 토큰을 남기지 않아야 한다."""
    a = _remote_app(tmp_path, monkeypatch)
    c = a.test_client()
    r = c.get("/?token=" + TOKEN, environ_overrides=REMOTE)
    assert r.status_code == 302
    assert "token" not in r.headers.get("Location", "")
    assert c.get("/", environ_overrides=REMOTE).status_code == 200


def test_bad_token_gets_no_cookie(tmp_path, monkeypatch):
    a = _remote_app(tmp_path, monkeypatch)
    r = a.test_client().post("/session", data={"token": "nope"}, environ_overrides=REMOTE)
    assert r.status_code == 401
    assert "netdash_token" not in r.headers.get("Set-Cookie", "")


def test_session_route_rejects_open_redirect(tmp_path, monkeypatch):
    a = _remote_app(tmp_path, monkeypatch)
    for evil in ("https://evil.example.com/x", "//evil.example.com", "/api/state"):
        r = a.test_client().post("/session", data={"token": TOKEN, "next": evil},
                                 environ_overrides=REMOTE)
        loc = r.headers.get("Location", "")
        assert "evil" not in loc and loc.endswith("/"), evil


def test_session_route_allowed_in_readonly_mode(tmp_path, monkeypatch):
    """읽기 전용 PC에서도 로그인은 돼야 한다(조회조차 못 하면 안 됨)."""
    a = _remote_app(tmp_path, monkeypatch)
    a.config["IS_READONLY"] = True
    a.config["READONLY_PRIMARY"] = "PC-A"
    r = a.test_client().post("/session", data={"token": TOKEN}, environ_overrides=REMOTE)
    assert r.status_code == 302, "423이면 원격 사용자가 아무것도 못 본다"


# ── C-1: 설정 오류 안내 ──────────────────────────────────────────
def test_config_error_is_explained_not_traceback():
    """0.0.0.0 + 토큰 누락은 사용자가 고칠 수 있는 문제 — 안내가 있어야 한다."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    main = src[src.index('if __name__ == "__main__":'):]     # 기동 경로만
    i = main.index("get_config(demo_mode=demo_mode)")
    body = main[max(0, i - 200):i + 1800]
    assert "except (ValueError" in body, "설정 오류를 잡지 않으면 트레이스백만 남는다"
    for exc in ("TypeError", "RuntimeError"):
        assert exc in body, "빈 섹션·YAML 문법오류도 안내 대상이다 (%s)" % exc
    assert "api_token" in body and "config.yaml" in body
    assert "sys.exit(1)" in body
    assert "127.0.0.1" in body, "토큰 없이 쓰는 대안도 알려줘야 한다"


def test_config_error_message_is_korean():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index("app_start_config_error")
    body = src[max(0, i - 1500):i]
    assert "시작할 수 없습니다" in body and "조치:" in body
