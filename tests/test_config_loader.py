import os
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from core import config_loader
from core.config_loader import Config, load_config


def test_load_config_defaults_when_file_missing():
    # Demo mode allows defaults when config file is missing
    cfg = load_config("nonexistent_path_xyz.yaml", demo_mode=True)
    assert isinstance(cfg, Config)
    assert cfg.flap_threshold == 3
    assert cfg.upload_max_mb == 16
    assert cfg.db_path == "netdash.db"
    assert cfg.switches == []


def test_load_config_parses_valid_yaml(tmp_path, no_api_token_env):
    yaml_file = tmp_path / "config.yaml"
    # HARDENING: Use a strong token (32+ chars with mixed case, digits, special chars)
    yaml_file.write_text(
        textwrap.dedent("""\
        db_path: test.db
        flap_threshold: 5
        upload_max_mb: 32
        api_token: test_token_32_chars_mixed_caseABCD123xyz
        switches:
          - name: SW-01
            ip: 10.0.0.1
            vendor: cisco
        """),
        encoding="utf-8",
    )
    cfg = load_config(str(yaml_file), demo_mode=False)
    assert cfg.db_path == "test.db"
    assert cfg.flap_threshold == 5
    assert cfg.upload_max_mb == 32
    assert cfg.api_token == "test_token_32_chars_mixed_caseABCD123xyz"
    assert len(cfg.switches) == 1
    assert cfg.switches[0]["ip"] == "10.0.0.1"


def test_load_config_partial_keys_uses_defaults(tmp_path, no_api_token_env):
    yaml_file = tmp_path / "partial.yaml"
    # HARDENING: Use a strong token (32+ chars with mixed case, digits, special chars)
    yaml_file.write_text("flap_threshold: 10\napi_token: test_token_32_chars_mixed_caseABCD123xyz\n", encoding="utf-8")
    cfg = load_config(str(yaml_file), demo_mode=False)
    assert cfg.flap_threshold == 10
    assert cfg.upload_max_mb == 16
    assert cfg.db_path == "netdash.db"
    assert cfg.api_token == "test_token_32_chars_mixed_caseABCD123xyz"


# Fix for WARNING: Missing Test for Production Mode Config Validation
def test_production_external_bind_requires_api_token(tmp_path, no_api_token_env):
    """Production + externally reachable bind (0.0.0.0) should still require api_token."""
    yaml_file = tmp_path / "config_no_token.yaml"
    # 외부 바인딩(0.0.0.0) + 토큰 없음 → 토큰 강제
    yaml_file.write_text(
        textwrap.dedent("""\
        db_path: test.db
        flap_threshold: 3
        upload_max_mb: 16
        app:
          host: 0.0.0.0
        """),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="api_token is required in production mode"):
        load_config(str(yaml_file), demo_mode=False)


def test_production_loopback_autogenerates_token(tmp_path, monkeypatch, no_api_token_env):
    """HOTFIX: Production + loopback bind + no token → 강한 토큰 자동 생성·영속화."""
    monkeypatch.chdir(tmp_path)  # netdash_token.txt가 tmp에 생성되도록 격리
    yaml_file = tmp_path / "config_no_token.yaml"
    yaml_file.write_text(
        textwrap.dedent("""\
        db_path: test.db
        flap_threshold: 3
        upload_max_mb: 16
        app:
          host: 127.0.0.1
        """),
        encoding="utf-8",
    )
    cfg = load_config(str(yaml_file), demo_mode=False)
    # 토큰이 자동 생성되어 강도 요건(>=32, 엔트로피) 충족
    assert cfg.api_token is not None
    assert len(cfg.api_token) >= 32
    # 파일로 영속화 + 재로딩 시 동일 토큰 재사용
    token_file = tmp_path / "netdash_token.txt"
    assert token_file.exists()
    assert token_file.read_text(encoding="utf-8").strip() == cfg.api_token
    cfg2 = load_config(str(yaml_file), demo_mode=False)
    assert cfg2.api_token == cfg.api_token


# ---------------------------------------------------------------------------
# exe(frozen)에서 DB 경로가 cwd가 아닌 exe 폴더에 고정되는지 검증
# (버그: 관리자 실행 시 cwd=System32 → 'unable to open database file')
# ---------------------------------------------------------------------------

@pytest.fixture
def _reset_data_dir_cache(monkeypatch):
    monkeypatch.setattr(config_loader, "_data_dir_cache", None)
    yield
    config_loader._data_dir_cache = None


def test_get_data_dir_dev_mode_is_cwd(tmp_path, monkeypatch, _reset_data_dir_cache):
    """비 frozen(개발/테스트) 모드: 기존 동작 유지 — cwd 기준."""
    monkeypatch.chdir(tmp_path)
    assert config_loader.get_data_dir() == Path.cwd()


def test_get_data_dir_frozen_uses_exe_dir(tmp_path, monkeypatch, _reset_data_dir_cache):
    """frozen exe: cwd가 아니라 exe가 있는 폴더를 사용."""
    exe_dir = tmp_path / "app_folder"
    exe_dir.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "netdash.exe"))
    # cwd를 다른 곳(System32 상황 모사)으로 바꿔도 exe 폴더가 선택되어야 함
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert config_loader.get_data_dir() == exe_dir.resolve()


def test_get_data_dir_frozen_fallback_when_exe_dir_unwritable(tmp_path, monkeypatch, _reset_data_dir_cache):
    """frozen exe + exe 폴더 쓰기 불가 → %LOCALAPPDATA%\\NetDash 폴백."""
    exe_dir = tmp_path / "readonly_program_files"
    exe_dir.mkdir()
    local_appdata = tmp_path / "LocalAppData"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "netdash.exe"))
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.setattr(config_loader, "_is_dir_writable", lambda d: False)
    result = config_loader.get_data_dir()
    assert result == local_appdata / "NetDash"
    assert result.is_dir()  # 폴백 디렉터리가 실제 생성됨


def test_get_db_path_relative_anchored_to_data_dir(tmp_path, monkeypatch, _reset_data_dir_cache):
    """상대 db_path는 데이터 디렉터리에 고정, 절대 경로는 그대로."""
    exe_dir = tmp_path / "app_folder"
    exe_dir.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "netdash.exe"))
    cfg = config_loader._get_default_config(demo_mode=True)  # db_path="netdash.db"
    assert cfg.get_db_path() == exe_dir.resolve() / "netdash.db"
    # 절대 경로는 손대지 않음
    abs_db = tmp_path / "explicit" / "custom.db"
    cfg_abs = Config(db_path=str(abs_db))
    assert cfg_abs.get_db_path() == abs_db


def test_local_token_created_in_data_dir_when_frozen(tmp_path, monkeypatch, _reset_data_dir_cache):
    """frozen exe: netdash_token.txt도 cwd가 아닌 데이터 디렉터리에 생성."""
    exe_dir = tmp_path / "app_folder"
    exe_dir.mkdir()
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "netdash.exe"))
    monkeypatch.chdir(other)
    token = config_loader._ensure_local_token()
    assert len(token) >= 32
    assert (exe_dir / "netdash_token.txt").exists()
    assert not (other / "netdash_token.txt").exists()


def test_production_mode_allows_missing_api_token_in_demo(tmp_path, no_api_token_env):
    """Demo mode should not require api_token"""
    yaml_file = tmp_path / "config_no_token.yaml"
    yaml_file.write_text(
        textwrap.dedent("""\
        db_path: test.db
        flap_threshold: 3
        upload_max_mb: 16
        """),
        encoding="utf-8",
    )
    # Should NOT raise error in demo mode
    cfg = load_config(str(yaml_file), demo_mode=True)
    assert cfg.api_token is None
    assert cfg.flap_threshold == 3
