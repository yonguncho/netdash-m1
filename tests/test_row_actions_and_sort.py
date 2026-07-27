# -*- coding: utf-8 -*-
"""방화벽·서버 행별 작업 버튼(수집·수정·진단·SSH 터미널·삭제) + 컬럼 정렬 확장.

스위치 현황의 작업 컬럼 구성을 방화벽·서버에도 동일하게 맞춘 변경의 회귀 테스트.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, webshell

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")


@pytest.fixture
def dev_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── 화면: 세 표가 같은 작업 버튼 구성을 갖는다 ─────────────────────
def _row_block(marker, end):
    i, j = APPJS.index(marker), APPJS.index(end)
    assert i < j
    return APPJS[i:j]


def test_firewall_row_has_all_actions():
    block = _row_block("tbody.innerHTML = firewalls.map", "var _editFirewallId")
    for action in ("collect-fw", "detail-fw", "edit-fw", "diagnose-fw",
                   "terminal-fw", "delete-fw"):
        assert "data-action='%s'" % action in block, action


def test_server_row_has_all_actions():
    block = _row_block("body.innerHTML = rows.map",
                       'var addBtn = document.getElementById("btn-server-add")')
    for action in ("collect-server", "edit-server", "diagnose-server",
                   "terminal-server", "delete-server"):
        assert "data-action='%s'" % action in block, action


def test_new_actions_are_routed():
    """버튼만 있고 위임 핸들러가 없으면 클릭이 무반응이 된다."""
    for case in ("diagnose-fw", "terminal-fw", "diagnose-server", "terminal-server"):
        assert 'case "%s":' % case in APPJS, case
    assert "function diagnoseFirewall(" in APPJS
    assert "function diagnoseServer(" in APPJS
    assert 'openTerminal(nid, "firewall")' in APPJS
    assert 'openTerminal(nid, "server")' in APPJS


def test_server_table_action_column_merged():
    """수집 컬럼을 작업 컬럼으로 합쳐 스위치와 같은 구성이 된다(17→16열)."""
    head = HTML[HTML.index('id="srv-check-all"'):HTML.index('id="server-table-body"')]
    assert head.count("</th>") == 16
    assert ">작업</th>" in head
    assert ">수집</th>" not in head, "수집 전용 컬럼이 남아 있다"
    assert 'colspan="16"' in HTML and "colspan='16'" in APPJS


def test_terminal_url_includes_kind():
    """WS 경로에 장비 종류가 들어가야 방화벽·서버 터미널이 열린다."""
    assert '"/ws/shell/" + kind + "/" + targetId' in APPJS


# ── 화면: 정렬 대상 컬럼 확장 ─────────────────────────────────────
def test_sortable_headers_include_new_columns():
    block = APPJS[APPJS.index("function sortBy(tbl"):APPJS.index("function setupAll() { document")]
    for header in ("MAC", "OS", "구분", "연결 스위치"):
        assert '"%s"' % header in block, header


def test_sort_helper_still_handles_ip_and_location():
    """기존 IP·위치 정렬이 유지된다(회귀)."""
    block = APPJS[APPJS.index("function sortBy(tbl"):APPJS.index("function setupAll() { document")]
    assert 'mode = "ip"' in block and '"위치"' in block


# ── 백엔드: 터미널 대상 해석 ──────────────────────────────────────
def test_resolve_target_switch_firewall_server(temp_db):
    swid = db.save_switch(temp_db, "SW1", "10.60.0.1", "cisco_ios")
    fwid = db.save_firewall(temp_db, "FW1", "fortigate", "10.60.0.2", 443)
    svid = db.save_server(temp_db, "SRV1", "10.60.0.3")

    t = webshell.resolve_target(temp_db, "switch", swid)
    assert t["host"] == "10.60.0.1" and t["port"] == 22

    # 방화벽 port 컬럼은 관리/REST 포트(443)다 — 터미널은 SSH(22)로 붙어야 한다
    t = webshell.resolve_target(temp_db, "firewall", fwid)
    assert t["host"] == "10.60.0.2" and t["port"] == 22, t

    t = webshell.resolve_target(temp_db, "server", svid)
    assert t["host"] == "10.60.0.3" and t["port"] == 22

    assert webshell.resolve_target(temp_db, "server", 999999) is None


def test_server_ssh_port_prefers_2222_when_22_closed(temp_db):
    sid = db.save_server(temp_db, "ALT", "10.60.1.1")
    db.update_server(temp_db, sid, open_ports="80,2222,8080")
    assert webshell.resolve_target(temp_db, "server", sid)["port"] == 2222
    db.update_server(temp_db, sid, open_ports="22,2222")
    assert webshell.resolve_target(temp_db, "server", sid)["port"] == 22


def test_session_credentials_not_shared_across_kinds(temp_db, monkeypatch):
    """세션 자격증명 저장소는 스위치 id로만 키가 잡힌다.

    같은 숫자 id의 서버가 스위치 계정으로 접속되면 안 된다.
    """
    from core import credentials
    credentials.save_credential(7, "switch-user", "switch-pw")
    try:
        assert webshell._resolve_credentials(temp_db, "switch", 7, "", "") == \
            ("switch-user", "switch-pw")
        assert webshell._resolve_credentials(temp_db, "server", 7, "", "") == (None, None)
        assert webshell._resolve_credentials(temp_db, "firewall", 7, "", "") == (None, None)
    finally:
        credentials.clear_session_switch(7)


def test_explicit_credentials_take_priority(temp_db):
    assert webshell._resolve_credentials(temp_db, "server", 1, "u", "p") == ("u", "p")


# ── 백엔드: 진단 엔드포인트 ───────────────────────────────────────
def test_server_diagnose_returns_fields(dev_client, monkeypatch):
    from core import server_collector
    monkeypatch.setattr(server_collector, "scan_ports",
                        lambda ip, ports=None, timeout=1.0: [22, 443])
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: "web01.local")
    monkeypatch.setattr(server_collector, "netbios_name", lambda ip, timeout=2: "")

    sid = dev_client.post("/api/servers",
                          json={"name": "D1", "ip": "10.61.0.1"}).get_json()["id"]
    r = dev_client.post("/api/servers/%d/diagnose" % sid)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    d = r.get_json()["diag"]
    assert d["reachable"] is True
    assert d["open_ports"] == "22,443"
    assert d["ssh_port"] == 22
    assert d["hostname"] == "web01.local"
    assert d["has_cred"] is False


def test_server_diagnose_unknown_id_is_404(dev_client):
    assert dev_client.post("/api/servers/999999/diagnose").status_code == 404
    assert dev_client.post("/api/servers/99999999999999999999/diagnose").status_code == 404


def test_firewall_diagnose_returns_fields(dev_client, monkeypatch):
    from core import connectivity
    monkeypatch.setattr(connectivity, "test_tcp",
                        lambda host, port, timeout=3, source_ip=None: int(port) == 443)
    monkeypatch.setattr(connectivity, "test_firewall",
                        lambda *a, **k: {"ok": True, "stage": "reachable",
                                         "detail": "TCP 443 연결 가능 (인증 미검증)"})
    r = dev_client.post("/api/firewalls",
                        json={"name": "FW-D", "vendor": "fortigate", "host": "10.61.1.1",
                              "port": 443})
    assert r.status_code in (200, 201), r.get_data(as_text=True)[:300]
    fid = r.get_json()["firewall_id"]
    res = dev_client.post("/api/firewalls/%d/diagnose" % fid)
    assert res.status_code == 200, res.get_data(as_text=True)[:300]
    d = res.get_json()["diag"]
    assert d["mgmt_port"] == 443
    assert d["tcp_mgmt"] is True and d["tcp_ssh"] is False
    assert d["has_token"] is False and d["has_login"] is False
    assert d["auth_ok"] is False          # 자격증명이 없으니 인증은 미검증


def test_firewall_diagnose_unknown_id_is_404(dev_client):
    assert dev_client.post("/api/firewalls/999999/diagnose").status_code == 404


def test_diagnose_endpoints_are_registered():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '"/api/servers/<int:server_id>/diagnose"' in src
    assert '"/api/firewalls/<int:fid>/diagnose"' in src
    assert '"/ws/shell/<kind>/<int:target_id>"' in src
    assert '"/ws/shell/<int:switch_id>"' in src, "기존 스위치 터미널 경로가 사라졌다"
