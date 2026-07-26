# -*- coding: utf-8 -*-
"""세션 수집 계정(메모리 전용·TTL) 회귀 테스트.

보안 계약:
  1) 비밀번호는 어떤 응답에도 나오지 않는다.
  2) TTL이 지나면 자동 폐기된다.
  3) 잠금(lock)하면 즉시 폐기된다.
  4) 요청자(remote_addr)별로 분리 — 다른 PC가 남의 계정을 못 쓴다.
  5) 디스크에 쓰지 않는다(파일·DB 저장 경로 없음).
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import session_creds

ROOT = Path(__file__).parent.parent


def setup_function():
    session_creds.clear()


def teardown_function():
    session_creds.clear()


# ── 저장소 단위 ───────────────────────────────────────────────────

def test_set_and_get_roundtrip():
    ttl = session_creds.set_credential("10.0.0.5", "admin", "pw123")
    assert ttl == 1800                      # 기본 30분
    assert session_creds.get_credential("10.0.0.5") == ("admin", "pw123")


def test_expired_credential_is_discarded():
    session_creds.set_credential("10.0.0.5", "admin", "pw123", ttl=60)
    # 만료 시각을 과거로 밀어 TTL 경과를 시뮬레이션
    session_creds._store["10.0.0.5"]["exp"] = time.time() - 1
    assert session_creds.get_credential("10.0.0.5") is None
    assert "10.0.0.5" not in session_creds._store    # 조회 시점에 폐기


def test_owner_isolation():
    """다른 PC(remote_addr)는 남의 세션 계정을 쓸 수 없다."""
    session_creds.set_credential("10.0.0.5", "admin", "pw123")
    assert session_creds.get_credential("10.0.0.9") is None


def test_ttl_clamped():
    assert session_creds.set_credential("a", "u", "p", ttl=1) == 60          # 하한
    assert session_creds.set_credential("b", "u", "p", ttl=99999) == 8 * 3600  # 상한 8시간


def test_status_never_leaks_password():
    session_creds.set_credential("10.0.0.5", "administrator", "s3cr3t")
    st = session_creds.status("10.0.0.5")
    assert st["active"] is True
    assert "s3cr3t" not in str(st)
    assert st["username"].startswith("ad") and "*" in st["username"]   # 마스킹


def test_clear_owner_only():
    session_creds.set_credential("a", "u1", "p1")
    session_creds.set_credential("b", "u2", "p2")
    session_creds.clear("a")
    assert session_creds.get_credential("a") is None
    assert session_creds.get_credential("b") == ("u2", "p2")


def test_incomplete_input_rejected():
    assert session_creds.set_credential("a", "", "p") == 0
    assert session_creds.set_credential("a", "u", "") == 0
    assert session_creds.get_credential("a") is None


def test_no_disk_write_in_module():
    """디스크 저장 경로가 없어야 한다(open/sqlite/json.dump 미사용)."""
    src = (ROOT / "core" / "session_creds.py").read_text(encoding="utf-8")
    for banned in ("open(", "sqlite3", "json.dump", "Path(", "credentials."):
        assert banned not in src, "session_creds에 영속화 흔적: %s" % banned


# ── HTTP 엔드포인트 ───────────────────────────────────────────────

def test_endpoint_status_set_lock(client):
    r = client.get("/api/session/credential")
    assert r.status_code == 200 and r.get_json()["active"] is False

    r = client.post("/api/session/credential",
                    json={"username": "admin", "password": "pw123"})
    assert r.status_code == 200 and r.get_json()["ok"] is True

    r = client.get("/api/session/credential")
    body = r.get_json()
    assert body["active"] is True and body["remaining"] > 0
    assert "pw123" not in r.get_data(as_text=True)      # 비밀번호 누출 없음

    assert client.post("/api/session/credential/lock").status_code == 200
    assert client.get("/api/session/credential").get_json()["active"] is False


def test_endpoint_rejects_empty(client):
    r = client.post("/api/session/credential", json={"username": "", "password": ""})
    assert r.status_code == 400


def test_collect_uses_session_credential(client):
    """계정 없이 수집을 요청해도 세션 계정이 있으면 400이 아니다."""
    from core import db
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SW-SESS", "10.30.0.9", vendor="cisco_ios")

    client.post("/api/session/credential",
                json={"username": "admin", "password": "pw123"})
    r = client.post("/api/switches/%d/collect" % sid, json={})
    assert r.status_code != 400          # 계정 미입력이어도 세션 계정으로 진행


def test_ui_has_session_indicator_and_remember():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="sess-cred"' in html and 'id="btn-sess-lock"' in html
    assert 'id="bulk-remember"' in html and 'id="srv-remember"' in html
    assert "sessCredRemember" in js and "/api/session/credential/lock" in js
