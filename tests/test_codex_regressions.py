# -*- coding: utf-8 -*-
"""Codex 지적 5개 항목(T-05/T-16/T-22/T-20/T-23) named 회귀 게이트.

ACCEPTANCE.md(2절 매핑표, 게이트 A5)가 이 파일의 named 테스트 존재+PASS를
완료 판정 근거로 지정한다. 원본 파일은 저장소가 외부 SSOT를 쓰던 시절 산물이라
이 git 저장소엔 커밋된 적이 없었다(2026-08-22 재작성). 각 테스트는 추측이 아니라
**현행 코드의 실제 동작**을 고정한다 — core/config_loader.load_config,
app.create_app, web/templates/index.html·web/static/style.css의 실제 마크업 기준.

실서버 포트 바인딩 없이 Flask test client로만 실행. 유효 토큰은 conftest.py가
모듈 로드 시 세팅하는 API_TOKEN 환경변수 값이며, load_config가 config 파일보다
환경변수를 우선한다(CWE-306 수정).
"""
import textwrap
from pathlib import Path

import pytest

from core.config_loader import Config, load_config
from app import create_app

ROOT = Path(__file__).resolve().parent.parent

# conftest.py가 모듈 로드 시 세팅하는 값과 동일 — 실제 유효 토큰(env가 config보다 우선).
VALID_TOKEN = "test_token_32_chars_long_secure_value_12345"
# config 파일에 넣는 강한 토큰(강도 요건: 32자 이상 + 대/소/숫자/특수 혼합).
# env가 우선하므로 실제 인증엔 VALID_TOKEN이 쓰이지만, external bind에서
# '토큰 필수' 조건을 만족시켜 ValueError를 피한다.
STRONG_TOKEN = "Cfg_Strong_Token_32chars_ABCD1234xyz!"


def _prod_config(tmp_path, host="127.0.0.1", with_token=True):
    body = textwrap.dedent("""\
        db_path: netdash.db
        flap_threshold: 3
        upload_max_mb: 16
        app:
          host: %s
    """) % host
    if with_token:
        body += "api_token: %s\n" % STRONG_TOKEN
    cfg = tmp_path / "config.yaml"
    cfg.write_text(body, encoding="utf-8")
    return cfg


def _boot_prod(tmp_path, monkeypatch, host="127.0.0.1", with_token=True):
    """배포와 동형(프로덕션·api_token 포함) config로 실제 앱을 기동한다."""
    monkeypatch.chdir(tmp_path)
    cfg = _prod_config(tmp_path, host=host, with_token=with_token)
    monkeypatch.setenv("NETDASH_CONFIG", str(cfg))
    app = create_app(demo_mode=False)
    app.config["TESTING"] = True
    return app


# ── T-05: config 로딩 — 모드별 미존재 파일 처리 ───────────────────
class TestT05ConfigDefaults:
    def test_t05_missing_file_demo_returns_defaults(self):
        cfg = load_config("nonexistent_path_t05.yaml", demo_mode=True)
        assert isinstance(cfg, Config)
        assert cfg.flap_threshold == 3
        assert cfg.db_path == "netdash.db"
        assert cfg.switches == []

    def test_t05_missing_file_production_raises_runtimeerror(self):
        # 현행 설계: 프로덕션은 config 파일이 필수 — 조용한 기본값 대신 명시적 조기 실패.
        with pytest.raises(RuntimeError, match="not found. Required for production mode"):
            load_config("nonexistent_path_t05.yaml", demo_mode=False)

    def test_t05_production_loopback_no_token_autogenerates(self, tmp_path, monkeypatch, no_api_token_env):
        # 프로덕션 + loopback bind + 토큰 없음 → 강한 토큰 자동 생성(크래시 아님).
        monkeypatch.chdir(tmp_path)
        cfg = _prod_config(tmp_path, host="127.0.0.1", with_token=False)
        c = load_config(str(cfg), demo_mode=False)
        assert c.api_token is not None
        assert len(c.api_token) >= 32

    def test_t05_production_external_bind_requires_token(self, tmp_path, no_api_token_env):
        # 프로덕션 + 외부 도달 가능 bind(0.0.0.0) + 토큰 없음 → 명시적 ValueError(CWE-306).
        cfg = _prod_config(tmp_path, host="0.0.0.0", with_token=False)
        with pytest.raises(ValueError, match="api_token is required in production mode"):
            load_config(str(cfg), demo_mode=False)

    def test_t05_create_app_boots_in_production_with_config(self, tmp_path, monkeypatch):
        app = _boot_prod(tmp_path, monkeypatch)
        assert app is not None
        with app.test_client() as cl:
            assert cl.get("/").status_code == 200


# ── T-16: 배포 config로 프로덕션 기동 + 인증 ──────────────────────
class TestT16ProductionBoot:
    def test_t16_shipped_config_has_api_token_slot(self):
        # 배포 config(저장소 루트 config.yaml)는 api_token 슬롯을 갖는다.
        # 값은 env 주입 설계로 null 가능하나, 기동 실패 방지를 위한 키는 존재해야 한다.
        root_cfg = ROOT / "config.yaml"
        assert root_cfg.exists()
        assert "api_token" in root_cfg.read_text(encoding="utf-8")

    def test_t16_app_boots_and_index_200(self, tmp_path, monkeypatch):
        app = _boot_prod(tmp_path, monkeypatch)
        with app.test_client() as cl:
            assert cl.get("/").status_code == 200

    def test_t16_api_state_200_with_valid_token(self, tmp_path, monkeypatch):
        # external bind → loopback 면제 없음 → 유효 토큰으로 200.
        app = _boot_prod(tmp_path, monkeypatch, host="0.0.0.0")
        with app.test_client() as cl:
            r = cl.get("/api/state", headers={"X-API-Token": VALID_TOKEN})
            assert r.status_code == 200

    def test_t16_api_state_401_without_token(self, tmp_path, monkeypatch):
        # external bind + 토큰 헤더 없음 → 401 unauthorized(CWE-306).
        app = _boot_prod(tmp_path, monkeypatch, host="0.0.0.0")
        with app.test_client() as cl:
            r = cl.get("/api/state")
            assert r.status_code == 401
            assert r.get_json()["error"] == "unauthorized"

    def test_t16_loopback_local_request_exempt(self, tmp_path, monkeypatch):
        # loopback bind + 로컬 요청 → 토큰 없이 200(폐쇄망 단일 호스트 UX, 의도된 동작).
        app = _boot_prod(tmp_path, monkeypatch, host="127.0.0.1")
        with app.test_client() as cl:
            assert cl.get("/api/state").status_code == 200


# ── T-22: 프로덕션 모드 /api/state ────────────────────────────────
class TestT22ProductionApiState:
    def test_t22_production_api_state_switches_empty(self, tmp_path, monkeypatch):
        # 프로덕션 신규 DB: {"switches": [], "demo": false}.
        app = _boot_prod(tmp_path, monkeypatch, host="127.0.0.1")
        with app.test_client() as cl:
            r = cl.get("/api/state")
            assert r.status_code == 200
            data = r.get_json()
            assert data["switches"] == []
            assert data["demo"] is False

    def test_t22_production_api_state_requires_token(self, tmp_path, monkeypatch):
        app = _boot_prod(tmp_path, monkeypatch, host="0.0.0.0")
        with app.test_client() as cl:
            assert cl.get("/api/state").status_code == 401


# ── T-20: UI 렌더링(헤드리스) ─────────────────────────────────────
class TestT20BrowserRenderingHeadless:
    def test_t20_index_has_switch_render_targets(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b'id="switch-grid"' in r.data
        assert b'id="switch-table-body"' in r.data

    def test_t20_static_assets_served(self, client):
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/style.css").status_code == 200

    def test_t20_no_external_asset_references(self, client):
        # 폐쇄망: 모든 script/link는 /static 로컬 — 외부 http(s) 자산 로딩 0건.
        html = client.get("/").data
        assert b'src="http' not in html
        assert b'href="http' not in html

    def test_t20_demo_api_state_provides_three_switch_cards_data(self, client):
        data = client.get("/api/state").get_json()
        assert data["demo"] is True
        assert len(data["switches"]) == 3


# ── T-23: DEMO MODE 배지 렌더링 ───────────────────────────────────
class TestT23DemoBadge:
    def test_t23_demo_badge_element_rendered(self, client):
        r = client.get("/")
        assert b'badge badge--demo">DEMO' in r.data

    def test_t23_production_mode_has_no_demo_badge(self, tmp_path, monkeypatch):
        app = _boot_prod(tmp_path, monkeypatch)
        with app.test_client() as cl:
            assert b'badge--demo' not in cl.get("/").data

    def test_t23_badge_css_class_defined(self):
        css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
        assert "badge--demo" in css
