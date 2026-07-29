# -*- coding: utf-8 -*-
"""MINOR 백로그 일괄 처리 (B-12·B-15~B-17·B-20~B-28) 회귀 테스트.

각 테스트는 "고치기 전에는 실패한다"가 성립하도록 동작/배선을 직접 확인한다.
DOM이 없는 환경이라 프론트 항목은 소스 배선을 검사하되, 문자열 존재가 아니라
'예전 코드가 남아 있으면 실패'하는 형태로 쓴다.
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, topology, server_collector

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
WALLJS = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
WALLHTML = (ROOT / "web" / "templates" / "wall.html").read_text(encoding="utf-8")


# ── B-12: 서버 개별 수집 후 상태 감시 ────────────────────────────
def test_server_collect_watches_until_done():
    """6초 뒤 1회 갱신이 아니라 '수집중'이 사라질 때까지 감시해야 한다."""
    assert "_watchServerCollecting" in APPJS
    assert "setTimeout(loadServers, 6000)" not in APPJS
    i = APPJS.index("function _watchServerCollecting")
    body = APPJS[i:i + 700]
    assert 'status === "collecting"' in body, "완료 판정 없이 시간만 재면 같은 결함"


# ── B-15: 서버실 전체 진단 ───────────────────────────────────────
def test_room_diagnose_does_not_proxy_switch_button():
    """서버실 '전체 진단'이 스위치 탭 버튼을 대리 클릭하면 안 된다."""
    i = APPJS.index('getElementById("btn-room-diagnose")')
    body = APPJS[i:i + 2200]
    assert 'getElementById("btn-diagnose-all")' not in body, \
        "스위치 탭 버튼 대리 클릭 = 서버실 밖 스위치까지 진단"
    assert "/api/servers/diagnose-all" in body and "/api/firewalls/diagnose-all" in body
    assert '"room-progress"' in body, "진행바가 서버실 화면에 그려져야 한다"
    assert "room_rack" in body, "서버실 소속 장비만 대상이어야 한다"


def test_diagnose_all_endpoints_accept_ids(client, temp_db):
    """대상 한정(ids)을 받지 않으면 '서버실만 진단'을 만들 수 없다."""
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    i = src.index('@app.route("/api/servers/diagnose-all"')
    assert 'data.get("ids")' in src[i:i + 1400]
    j = src.index('@app.route("/api/firewalls/diagnose-all"')
    assert 'data.get("ids")' in src[j:j + 1400]
    # 방화벽 러너가 ids로 실제 필터링하는지
    assert "ids=None" in inspect.getsource(app_mod._run_diagnose_all_firewalls)
    assert "_want" in inspect.getsource(app_mod._run_diagnose_all_firewalls)


def test_collect_all_servers_supports_ids_with_no_cred():
    sig = server_collector.collect_all_servers.__code__.co_varnames
    assert "ids" in sig and "no_cred" in sig


# ── B-16: 서버실 정보 수집 진행률 덮어쓰기 ───────────────────────
def test_room_collect_runs_pollers_sequentially():
    """방화벽·서버 폴러가 동시에 같은 #room-progress에 쓰면 진행률이 덮인다."""
    i = APPJS.index('getElementById("btn-room-collect")')
    body = APPJS[i:i + 2000]
    assert "_roomServers" in body, "방화벽 완료 후 서버를 시작하는 순차 실행이어야 한다"
    # collect-all/status 폴러가 두 개 다 '즉시' 시작되지 않는지: 서버 수집은
    # 방화벽 pollProgress의 onDone 안에서만 호출돼야 한다.
    fw_at = body.index("/api/firewalls/collect-all/status")
    sv_call = body.index("_roomServers();")
    assert sv_call > fw_at, "서버 수집이 방화벽 완료 콜백 뒤에 있어야 한다"


# ── B-17: 메모리 구성 표기(화면 vs CSV) ──────────────────────────
def test_js_and_python_module_summary_agree_on_placeholders():
    """'Unknown' 규격을 화면은 쓰고 CSV는 거르면 표기가 갈린다."""
    mods = [{"size_mb": 16384, "type": "Unknown"}, {"size_mb": 16384, "type": "Unknown"}]
    assert "Unknown" not in server_collector.summarize_modules(mods)
    # JS 쪽에 같은 목록이 있어야 한다
    assert "_HW_PLACEHOLDERS" in APPJS and "_hwPlaceholder" in APPJS
    i = APPJS.index("var _HW_PLACEHOLDERS")
    js_list = set(re.findall(r'"([^"]+)"', APPJS[i:APPJS.index("];", i)]))
    import inspect
    py_src = inspect.getsource(server_collector._unknown_to_blank)
    py_body = py_src[py_src.index("in ("):py_src.index("):", py_src.index("in ("))]
    py_list = set(re.findall(r'"([^"]+)"', py_body))
    assert js_list == py_list, "화면과 CSV의 무의미값 목록이 달라지면 표기가 갈린다"
    # 요약에서 실제로 걸러지는지(문자열 검사가 아니라 배선 검사)
    i2 = APPJS.index("function summarizeModules")
    assert "_hwPlaceholder(m.type)" in APPJS[i2:i2 + 900]


# ── B-20: 저장 계정 관리 로드 실패 ───────────────────────────────
def test_creds_load_failure_resets_all_three_tables():
    i = APPJS.index("function loadCreds()")
    body = APPJS[i:APPJS.index("\n}\n", i)]
    tail = body[body.index(".catch("):]
    for var in ("sw.innerHTML", "fw.innerHTML", "pf.innerHTML"):
        assert var in tail, "%s 가 '불러오는 중...'에서 멈춘다" % var
    assert "creds-retry" in tail, "재시도 경로가 없으면 모달을 닫았다 열어야 한다"
    assert "creds-retry" in APPJS[APPJS.index("modal-creds\").addEventListener"):
                                  APPJS.index("modal-creds\").addEventListener") + 400]
    assert "if (!r.ok) throw" in body, "HTTP 오류를 json()으로 흘리면 catch가 안 걸린다"


# ── B-21: SMTP 인증정보 삭제 ─────────────────────────────────────
def test_smtp_clear_auth_control_exists():
    assert 'id="btn-em-clear-auth"' in HTML
    assert "clear_auth: true" in APPJS
    i = APPJS.index("btn-em-clear-auth")
    assert "has_auth" in APPJS[:i], "저장돼 있을 때만 노출해야 한다"


def test_clear_auth_backend_path_exists():
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    i = src.index('"/api/settings/email"')
    assert 'data.get("clear_auth")' in src[i:i + 4000]


# ── B-22: 관제 방화벽 장애 ───────────────────────────────────────
def test_wall_shows_firewall_failures(client, temp_db):
    from core import db
    db.save_firewall(temp_db, "FW-1", "10.99.0.1", "fortinet")
    r = client.get("/api/wall")
    assert r.status_code == 200
    d = r.get_json()
    assert "firewalls_down" in d, "방화벽 장애 카운터가 없다"
    keys = [c["key"] for c in d["categories"]]
    assert "firewall" in keys, "관제 화면에 방화벽 카테고리가 없다"


def test_wall_translates_firewall_event_kind():
    assert "firewall_unreachable" in WALLJS and "방화벽 연결 실패" in WALLJS
    assert 't-fwdown' in WALLHTML and 't-fwdown' in WALLJS


# ── B-23: 중지 버튼 응답 확인 ────────────────────────────────────
def test_stop_button_restores_on_failure():
    i = APPJS.index(".np-stop-btn")
    body = APPJS[i:i + 1400]
    assert "res.ok" in body and "b.disabled = false" in body, \
        "응답을 안 보면 400/{ok:false}에서 '중지 중…'으로 굳는다"


# ── B-24: 새로고침 복구 ──────────────────────────────────────────
def test_progress_resumes_after_reload():
    assert "새로고침 복구" in APPJS
    i = APPJS.index("var JOBS = [")
    body = APPJS[i:i + 900]
    for url in ("/api/servers/collect-all/status",
                "/api/firewalls/collect-all/status",
                "/api/switches/bulk-collect/status"):
        assert url in body, url
    assert "st.running" in body
    # 스위치 전체 진단도 복구돼야 한다(마지막 상태 조회 = 시작 시 복구 블록)
    j = APPJS.rindex('fetch("/api/switches/diagnose-all/status")')
    tail = APPJS[j:j + 400]
    assert "s.running" in tail and "setInterval(_pollDiagnoseAll" in tail


# ── B-25: 편집기 장비 종류 판정 일치 ─────────────────────────────
def test_lookup_device_returns_canonical_topo_kind(temp_db):
    from core import db
    sid = db.save_switch(temp_db, "CORE-1", "10.97.0.1", "cisco_ios")
    db.update_switch_device_type(temp_db, sid, "L4 Switch") \
        if hasattr(db, "update_switch_device_type") else None
    d = topology.lookup_device(temp_db, "10.97.0.1")
    assert d and "topo_kind" in d, "서버가 정답 종류를 안 주면 프론트가 다시 해석한다"


def test_frontend_uses_server_topo_kind():
    i = APPJS.index("// 구분 자동 매핑")
    body = APPJS[i:i + 700]
    assert "d.topo_kind" in body
    assert 'dt.indexOf("backbone")' not in body, \
        "device_type을 프론트가 다시 해석하면 판정 우선순위가 서버와 갈린다"


def test_switch_kind_prefers_l4_over_l3_class():
    """서버 판정 규칙 자체의 회귀 방지 — L4는 config가 L3여도 L4."""
    cfg = "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
    assert topology._switch_kind(cfg, "L4 Switch") == "l4"
    assert topology._switch_kind(cfg, "Backbone") == "backbone"
    # 프론트의 옛 규칙은 L3(l3_class/dt)를 L4보다 먼저 봤다 → 같은 장비가 갈림
    assert topology._switch_kind("", "L3 Switch") == "l3"
    assert topology._switch_kind("", "") == "l2"


# ── B-26: 원격 접속 토큰 ─────────────────────────────────────────
def test_page_shell_injects_api_token():
    assert "window._API_TOKEN" in HTML and "window._API_TOKEN" in WALLHTML
    assert "api_token" in HTML and "api_token" in WALLHTML


def test_fetch_wrapper_attaches_token():
    for src, name in ((APPJS, "app.js"), (WALLJS, "wall.js")):
        assert "X-API-Token" in src, name
        i = src.index("X-API-Token")
        assert "_API_TOKEN" in src[max(0, i - 700):i], name


def test_remote_page_requires_token(tmp_path, monkeypatch):
    """0.0.0.0 바인드에서 토큰 없는 원격 요청은 페이지도 못 받는다."""
    import app as app_mod
    from config import reset_config
    reset_config()
    token = "Abcdefgh1234567890Abcdefgh1234567890"   # 프로덕션 강도 요건(32자+)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "app:\n  host: 0.0.0.0\n  port: 8099\n  demo_mode: false\n"
        "  data_dir: %s\napi_token: %s\n" % (str(tmp_path).replace("\\", "/"), token),
        encoding="utf-8")
    monkeypatch.setenv("NETDASH_CONFIG", str(cfg_file))
    monkeypatch.delenv("API_TOKEN", raising=False)
    reset_config()
    application = app_mod.create_app()
    application.config["TESTING"] = True
    c = application.test_client()
    r = c.get("/", environ_overrides={"REMOTE_ADDR": "192.168.0.50"})
    assert r.status_code == 401, "토큰 없이 셸이 열리면 그 안의 fetch는 전부 401이 된다"
    # 토큰은 POST로 제출한다(쿼리스트링은 접근 로그에 평문으로 남는다 — C-2)
    r2 = c.post("/session", data={"token": token, "next": "/"},
                environ_overrides={"REMOTE_ADDR": "192.168.0.50"})
    assert r2.status_code == 302
    assert "netdash_token" in r2.headers.get("Set-Cookie", "")
    r3 = c.get("/", environ_overrides={"REMOTE_ADDR": "192.168.0.50"})
    assert r3.status_code == 200
    assert token.encode() in r3.data, "토큰이 페이지에 안 실리면 fetch가 401"
    reset_config()


# ── B-27: 죽은 코드 정리 ─────────────────────────────────────────
def _code_lines(src):
    """줄 주석(//)을 뺀 코드만 — 설명 주석의 식별자 언급을 오탐하지 않도록."""
    out = []
    for ln in src.splitlines():
        s = ln.strip()
        if s.startswith("//"):
            continue
        out.append(ln.split("//")[0] if "://" not in ln else ln)
    return "\n".join(out)


APPJS_CODE = _code_lines(APPJS)


def test_dead_reconcile_ui_removed():
    for token in ("loadReconcile", "renderReconcile", "reconcile-summary",
                  "reconcile-table-body", "btn-reconcile-refresh"):
        assert token not in APPJS_CODE, token


def test_dead_topo_toolbar_bindings_removed():
    """모드/존/L2 툴바 배선은 HTML에 요소가 없어 죽은 코드였다.

    v6.4.1에서 그 코드를 품고 있던 자동 렌더 뷰 자체가 제거됐으므로,
    파일 전체에서 사라졌는지로 확인한다.
    """
    for token in ("topo-zone-select", "btn-topo-l2", 'querySelectorAll(".topo-mode")'):
        assert token not in APPJS_CODE, token


# ── B-28: 로그 살균 ──────────────────────────────────────────────
@pytest.mark.parametrize("raw,gone", [
    (r"cannot open C:\NetDash\data\netdash.db", r"C:\NetDash"),
    (r"denied \\fileserver\share\netdash\db", r"\\fileserver"),
])
def test_sanitizer_strips_absolute_paths(raw, gone):
    out = collector._sanitize_error_msg(raw)
    assert gone not in out
    assert "<path>" in out


def test_periodic_loops_sanitize_exceptions():
    import inspect
    from core import reachability, facility
    assert "_sanitize_error_msg" in inspect.getsource(reachability._loop)
    for fn in ("_sanitize_error_msg",):
        src = (ROOT / "core" / "facility.py").read_text(encoding="utf-8")
        for evt in ("facility_reconcile_skip", "facility_monitor_save_skip"):
            k = src.index(evt)
            assert fn in src[k:k + 200], evt
    assert facility is not None
