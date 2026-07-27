# -*- coding: utf-8 -*-
"""세션 수집 계정을 장비 종류별로 분리 — 스위치·서버·방화벽 계정 체계가 다르다.

증상(수정 전): 세션 계정이 요청자(IP)당 하나뿐이라, 스위치 계정을 '기억'시킨 뒤
서버를 수집하면 그 스위치 계정이 등록된 전 서버에 SSH로 시도됐다.
수집이 실패할 뿐 아니라 반복 인증 실패로 계정이 잠길 수 있다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import session_creds as sc

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
APPPY = (ROOT / "app.py").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _clean():
    sc.clear()
    yield
    sc.clear()


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── 저장소 분리 ───────────────────────────────────────────────────
def test_kinds_do_not_leak_into_each_other():
    sc.set_credential("1.2.3.4", "sw-admin", "sw-pw", kind="switch")
    assert sc.get_credential("1.2.3.4", "switch") == ("sw-admin", "sw-pw")
    assert sc.get_credential("1.2.3.4", "server") is None, \
        "스위치 계정이 서버 수집에 쓰인다(계정 잠김 위험)"
    assert sc.get_credential("1.2.3.4", "firewall") is None


def test_three_kinds_coexist():
    for kind, u in (("switch", "swu"), ("server", "srvu"), ("firewall", "fwu")):
        sc.set_credential("1.2.3.4", u, "pw", kind=kind)
    assert sc.get_credential("1.2.3.4", "switch")[0] == "swu"
    assert sc.get_credential("1.2.3.4", "server")[0] == "srvu"
    assert sc.get_credential("1.2.3.4", "firewall")[0] == "fwu"
    assert set(sc.active_kinds("1.2.3.4")) == {"switch", "server", "firewall"}


def test_owner_still_separated():
    sc.set_credential("1.1.1.1", "a", "p", kind="server")
    assert sc.get_credential("2.2.2.2", "server") is None, "다른 PC가 남의 계정을 쓴다"


def test_unknown_kind_falls_back_to_switch():
    sc.set_credential("1.2.3.4", "u", "p", kind="bogus")
    assert sc.get_credential("1.2.3.4", "switch") == ("u", "p")


def test_status_reports_each_kind():
    sc.set_credential("1.2.3.4", "administrator", "p", kind="server")
    s = sc.status("1.2.3.4")
    assert s["active"] is True
    assert s["kinds"]["server"]["active"] is True
    assert s["kinds"]["switch"]["active"] is False
    assert "p" not in str(s), "비밀번호가 상태 응답에 새면 안 된다"
    assert s["kinds"]["server"]["username"].startswith("ad")
    assert "administrator" not in str(s), "계정명이 마스킹되지 않았다"


def test_clear_by_kind_keeps_others():
    sc.set_credential("1.2.3.4", "u1", "p", kind="switch")
    sc.set_credential("1.2.3.4", "u2", "p", kind="server")
    sc.clear("1.2.3.4", "switch")
    assert sc.get_credential("1.2.3.4", "switch") is None
    assert sc.get_credential("1.2.3.4", "server") is not None
    sc.clear("1.2.3.4")
    assert sc.get_credential("1.2.3.4", "server") is None


# ── API ───────────────────────────────────────────────────────────
def test_api_stores_and_reports_per_kind(cli):
    assert cli.post("/api/session/credential",
                    json={"username": "fwadmin", "password": "pw",
                          "kind": "firewall"}).status_code == 200
    body = cli.get("/api/session/credential").get_json()
    assert body["kinds"]["firewall"]["active"] is True
    assert body["kinds"]["switch"]["active"] is False
    one = cli.get("/api/session/credential?kind=firewall").get_json()
    assert one["active"] is True and one["kind"] == "firewall"


def test_api_lock_can_target_one_kind(cli):
    for k in ("switch", "server"):
        cli.post("/api/session/credential", json={"username": "u", "password": "p", "kind": k})
    cli.post("/api/session/credential/lock", json={"kind": "switch"})
    body = cli.get("/api/session/credential").get_json()
    assert body["kinds"]["switch"]["active"] is False
    assert body["kinds"]["server"]["active"] is True


def test_switch_session_cred_not_used_for_servers(cli, monkeypatch):
    """핵심 회귀: 스위치 계정을 기억시킨 뒤 서버 일괄 수집을 해도 그 계정이 안 쓰인다."""
    cli.post("/api/session/credential",
             json={"username": "sw-admin", "password": "sw-pw", "kind": "switch"})
    cli.post("/api/servers", json={"name": "S", "ip": "10.60.0.1"})
    captured = {}
    from core import server_collector
    monkeypatch.setattr(server_collector, "collect_all_servers",
                        lambda **kw: captured.update(kw) or {"done": 0})
    assert cli.post("/api/servers/collect-all", json={}).status_code == 202
    import time
    time.sleep(0.3)
    assert captured.get("common_user") is None, \
        "스위치 계정이 서버 수집에 넘어갔다: %r" % (captured.get("common_user"),)


def test_server_session_cred_is_used_for_servers(cli, monkeypatch):
    """분리했다고 해서 제 종류에도 안 쓰이면 안 된다."""
    cli.post("/api/session/credential",
             json={"username": "srv-admin", "password": "srv-pw", "kind": "server"})
    cli.post("/api/servers", json={"name": "S", "ip": "10.60.1.1"})
    captured = {}
    from core import server_collector
    monkeypatch.setattr(server_collector, "collect_all_servers",
                        lambda **kw: captured.update(kw) or {"done": 0})
    cli.post("/api/servers/collect-all", json={})
    import time
    time.sleep(0.3)
    assert captured.get("common_user") == "srv-admin"


# ── 호출부가 종류를 지정하는가 ────────────────────────────────────
def test_every_call_site_specifies_kind():
    assert "_session_cred()" not in APPPY, "종류를 지정하지 않은 세션 계정 사용이 남아 있다"
    for kind in ('"server"', '"switch"', '"firewall"'):
        assert "_session_cred(%s)" % kind in APPPY, kind


# ── 화면 ─────────────────────────────────────────────────────────
def test_ui_remembers_credentials_per_kind():
    assert 'sessCredRemember(username, password, "switch")' in APPJS
    assert 'sessCredRemember(body.username, body.password, "server")' in APPJS
    assert 'sessCredRemember(payload.username, payload.password, "firewall")' in APPJS


def test_switch_modal_checks_switch_kind_only():
    """서버 계정이 기억돼 있다고 스위치 수집에서 계정 입력을 건너뛰면 안 된다."""
    assert 'sessCredActive("switch")' in APPJS
    i = APPJS.index('sessCredActive("switch")')
    assert "window._sessCredActive" not in APPJS[i - 400:i], \
        "종류 무관 플래그로 계정 입력을 건너뛰고 있다"


def test_firewall_page_prompts_for_credentials():
    """방화벽 계정은 스위치·서버와 다르다 — 이 화면에서 입력받아야 한다."""
    assert "_openFwBulkCollect" in APPJS
    assert 'id="fw-remember"' in HTML
    assert "방화벽 계정" in HTML


def test_firewall_bulk_endpoint_accepts_credentials():
    assert "common_token" in APPPY
    assert 'data.get("token")' in APPPY
