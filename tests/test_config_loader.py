import os
import tempfile
import textwrap

import pytest

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
