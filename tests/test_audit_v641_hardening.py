# -*- coding: utf-8 -*-
"""전체 버그 검증 후속(v6.4.1) — 남겨뒀던 하드닝 항목 회귀 테스트."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, exporter  # noqa: E402

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


# ── CSV 수식 인젝션 ──────────────────────────────────────────────
def test_csv_neutralizes_formula_prefixes(temp_db):
    """스위치 이름·설명은 장비 config에서 오고, 이 파일은 Excel로 열린다."""
    for i, name in enumerate(["=cmd|'/c calc'!A1", "+1+1", "@SUM(1+1)", "-2+3"]):
        db.save_switch(temp_db, name, "10.0.0.%d" % (9 + i), "cisco_ios")
    text = exporter.to_csv(exporter.SWITCH_COLS,
                           exporter.switches_rows(temp_db)).decode("utf-8-sig")
    for line in text.splitlines()[1:]:
        first = line.split(",")[0].lstrip('"')
        assert first[:1] not in ("=", "+", "@", "-"), "수식으로 실행되는 셀: %s" % first


def test_csv_keeps_value_readable():
    """무력화가 값 자체를 훼손하면 안 된다(앞 따옴표만 붙는다)."""
    assert exporter._s("=1+1") == "'=1+1"
    assert exporter._s("정상값") == "정상값"
    assert exporter._s("10.0.0.1") == "10.0.0.1"
    assert exporter._s(None) == ""


# ── 경로 id 범위 ─────────────────────────────────────────────────
def _big(path):
    return path.replace("<id>", "99999999999999999999")


def test_oversized_path_ids_return_404(client):
    """SQLite 상한을 넘는 id는 없는 id다 — 500(+DB 오류 배너 오염)이 아니라 404."""
    cases = [("GET", "/api/switches/<id>/detail"), ("PUT", "/api/switches/<id>"),
             ("DELETE", "/api/switches/<id>"), ("POST", "/api/switches/<id>/collect"),
             ("POST", "/api/switches/<id>/diagnose"), ("GET", "/api/firewalls/<id>"),
             ("PUT", "/api/firewalls/<id>"), ("DELETE", "/api/firewalls/<id>"),
             ("POST", "/api/firewalls/<id>/collect"), ("GET", "/api/switches/<id>/events")]
    for method, path in cases:
        r = client.open(_big(path), method=method, json={})
        assert r.status_code == 404, "%s %s -> %s" % (method, path, r.status_code)


def test_zero_and_negative_ids_return_404(client):
    assert client.get("/api/switches/0/detail").status_code == 404


def test_normal_ids_still_work(client):
    """가드가 정상 요청까지 막으면 안 된다."""
    assert client.get("/api/state").status_code == 200
    assert client.get("/api/switches/1/detail").status_code in (200, 404)


# ── 업로드 CSRF ──────────────────────────────────────────────────
def _xlsx():
    import io
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["name", "ip", "hostname", "vendor", "location"])
    ws.append(["CSRF-PWN", "10.88.9.9", "x", "cisco_ios", ""])
    b = io.BytesIO()
    wb.save(b)
    b.seek(0)
    return b


def test_cross_origin_upload_is_rejected(client):
    """multipart는 CORS 프리플라이트가 없어 크로스 오리진 폼 전송이 그대로 실행됐다."""
    r = client.post("/api/switches/import",
                    data={"file": (_xlsx(), "a.xlsx")},
                    content_type="multipart/form-data",
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_same_origin_upload_still_works(client):
    r = client.post("/api/switches/import",
                    data={"file": (_xlsx(), "a.xlsx")},
                    content_type="multipart/form-data",
                    headers={"Origin": "http://localhost"})
    assert r.status_code in (200, 201)


def test_cross_origin_json_write_is_rejected(client):
    r = client.post("/api/switches/manual", json={"name": "X", "ip": "10.1.1.1"},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_no_origin_request_is_allowed(client):
    """브라우저가 아닌 클라이언트(스크립트)는 토큰 검증에 맡긴다."""
    r = client.post("/api/switches/import",
                    data={"file": (_xlsx(), "a.xlsx")},
                    content_type="multipart/form-data")
    assert r.status_code in (200, 201)


# ── /session 레이트리밋 ──────────────────────────────────────────
def test_session_route_is_rate_limited():
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    i = src.index('@app.route("/session"')
    assert "@rate_limit(" in src[i:i + 200], "토큰을 검증하는 유일한 라우트에 제한이 없다"


# ── 업로드 크기 설정 ─────────────────────────────────────────────
def test_upload_limit_follows_config(tmp_path, monkeypatch):
    from config import reset_config
    import app as app_mod
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "app:\n  host: 127.0.0.1\n  port: 8099\n  demo_mode: true\n"
        "  data_dir: %s\nupload_max_mb: 3\n" % str(tmp_path).replace("\\", "/"),
        encoding="utf-8")
    monkeypatch.setenv("NETDASH_CONFIG", str(cfg))
    reset_config()
    a = app_mod.create_app(demo_mode=True)
    assert a.config["MAX_CONTENT_LENGTH"] == 3 * 1024 * 1024, "설정이 무시되고 16MB 고정이었다"
    reset_config()


# ── DB ACL ───────────────────────────────────────────────────────
def test_acl_skips_shared_location(monkeypatch):
    """공유 폴더를 호스팅하는 PC에서는 경로가 로컬이라 가드를 통과했었다."""
    import subprocess as sp
    calls = []
    monkeypatch.setattr(sp, "run", lambda *a, **k: calls.append(a) or None)
    shared = r"C:\NetDashShare\netdash_acl_probe.db"
    db._acl_applied.discard(shared)
    db._restrict_db_permissions(shared)
    assert calls == [], "SYSTEM·Administrators·다른 PC 계정까지 차단된다"


def test_acl_helper_recognizes_profile_paths():
    home = os.path.expanduser("~")
    assert db._is_under_user_profile(os.path.join(home, "x", "netdash.db")) is True
    assert db._is_under_user_profile(r"C:\NetDashShare\netdash.db") is False


# ── 기동 로그 ────────────────────────────────────────────────────
def test_file_logger_attached_for_readonly_instances():
    """2번째 PC가 '왜 읽기 전용인지'가 공유 로그에 남아야 진단이 가능하다."""
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    i = src.index("db_path = config.get_db_path()")
    assert "_attach_file_logger" in src[i:i + 800], \
        "주 서버 초기화 안에만 있으면 읽기 전용 인스턴스는 로그를 남기지 않는다"


# ── 죽은 코드 정리 ───────────────────────────────────────────────
def test_unreachable_topology_renderer_removed():
    for name in ("function renderTopology", "function _renderCoreMap",
                 "function _renderZoneMap", "function _renderTpsMap",
                 "function _layoutLayered", "function _topoKindOf"):
        assert name not in APPJS, name


def test_topo_kind_declared_once():
    """같은 이름 var 중복 선언은 뒤엣것이 앞엣것을 가려 조용한 오동작을 만든다."""
    assert APPJS.count("var _TOPO_KIND") == 1


def test_editor_helpers_survived():
    """실제 쓰이는 편집기 헬퍼까지 지우면 구성도 탭이 통째로 깨진다."""
    for name in ("function _deviceSymbol", "function _topoBindTips",
                 "function _topoWinOn", "function _topoWinClear",
                 "function _renderEditor"):
        assert name in APPJS, name
