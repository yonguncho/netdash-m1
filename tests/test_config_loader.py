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
def test_production_mode_requires_api_token(tmp_path, no_api_token_env):
    """Production mode should raise ValueError if api_token is missing and not in environment"""
    yaml_file = tmp_path / "config_no_token.yaml"
    # Write config WITHOUT api_token
    yaml_file.write_text(
        textwrap.dedent("""\
        db_path: test.db
        flap_threshold: 3
        upload_max_mb: 16
        """),
        encoding="utf-8",
    )
    # Should raise ValueError when loading in production mode without API_TOKEN env var
    with pytest.raises(ValueError, match="api_token is required in production mode"):
        load_config(str(yaml_file), demo_mode=False)


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
