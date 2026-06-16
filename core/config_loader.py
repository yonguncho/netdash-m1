import logging
import json
import os
import ipaddress
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

REQUIRED_KEYS = ["db_path", "flap_threshold", "upload_max_mb"]


@dataclass
class Config:
    switches: list[dict[str, Any]] = field(default_factory=list)
    flap_threshold: int = 3
    upload_max_mb: int = 16
    db_path: str = "netdash.db"
    api_token: str | None = None  # Optional API token for future auth


def _resolve_config_path(path: str = "config.yaml") -> str:
    """Resolve config path from env var, project root, or cwd."""
    # 1. Environment variable override
    if env_path := os.getenv("NETDASH_CONFIG"):
        return env_path
    # 2. Project root (parent of core/)
    project_root = Path(__file__).parent.parent
    project_config = project_root / path
    if project_config.exists():
        return str(project_config)
    # 3. Current working directory
    if Path(path).exists():
        return path
    # Return default (will log warning if not found)
    return path


def _validate_config_values(data: dict, demo_mode: bool = False) -> None:
    """Validate config field types and ranges. api_token is optional."""
    # Type validation for api_token if present
    if "api_token" in data and data["api_token"] is not None and not isinstance(data["api_token"], str):
        raise ValueError("api_token must be a string or None")
    if "flap_threshold" in data:
        if not isinstance(data["flap_threshold"], int) or data["flap_threshold"] < 0:
            raise ValueError("flap_threshold must be a non-negative integer")
    if "upload_max_mb" in data:
        if not isinstance(data["upload_max_mb"], int) or data["upload_max_mb"] <= 0 or data["upload_max_mb"] > 1000:
            raise ValueError("upload_max_mb must be a positive integer <= 1000")
    if "db_path" in data:
        if not isinstance(data["db_path"], str):
            raise ValueError("db_path must be a string")
        # Normalize to app data directory
        db_p = Path(data["db_path"])
        if db_p.is_absolute():
            logger.warning(json.dumps({"event": "config_warn", "msg": "db_path is absolute; ensure it's in a writable location"}))
    if "switches" in data and not isinstance(data["switches"], list):
        raise ValueError("switches must be a list")
    # Validate each switch
    for i, sw in enumerate(data.get("switches") or []):
        if not isinstance(sw, dict):
            raise ValueError(f"switches[{i}] must be a dict")
        # name is required
        if "name" not in sw or not isinstance(sw["name"], str) or not sw["name"].strip():
            raise ValueError(f"switches[{i}].name is required and must be a non-empty string")
        # ip is required
        if "ip" not in sw:
            raise ValueError(f"switches[{i}].ip is required")
        try:
            ipaddress.IPv4Address(sw["ip"])
        except ValueError:
            raise ValueError(f"switches[{i}].ip '{sw['ip']}' is not a valid IPv4 address")
        # status validation if present
        if "status" in sw:
            valid_statuses = ("pending", "collecting", "done", "failed", "unsupported")
            if sw["status"] not in valid_statuses:
                raise ValueError(f"switches[{i}].status '{sw['status']}' must be one of {valid_statuses}")
        # vendor validation if present
        if "vendor" in sw:
            if not isinstance(sw["vendor"], str):
                raise ValueError(f"switches[{i}].vendor must be a string")


def load_config(path: str = "config.yaml", demo_mode: bool = False) -> Config:
    resolved_path = _resolve_config_path(path)
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        if demo_mode:
            logger.warning(json.dumps({"event": "config_not_found", "path": resolved_path, "action": "using_defaults", "mode": "demo"}))
            return Config()
        else:
            logger.error(json.dumps({"event": "config_not_found", "path": resolved_path, "error": "Required in production mode"}))
            raise RuntimeError(f"Config file '{resolved_path}' not found. Required for production mode.")
    except yaml.YAMLError as e:
        if demo_mode:
            logger.warning(json.dumps({"event": "config_parse_error", "path": resolved_path, "error": str(e), "action": "using_defaults", "mode": "demo"}))
            return Config()
        else:
            logger.error(json.dumps({"event": "config_parse_error", "path": resolved_path, "error": str(e)}))
            raise RuntimeError(f"Failed to parse config file '{resolved_path}': {e}")

    # Validate values
    try:
        _validate_config_values(data, demo_mode=demo_mode)
    except ValueError as e:
        logger.error(json.dumps({"event": "config_validation_error", "error": str(e)}))
        raise

    for key in REQUIRED_KEYS:
        if key not in data:
            logger.warning(json.dumps({"event": "config_missing_key", "key": key, "action": "using_default"}))

    # Production mode requires an api_token for API authentication
    if not demo_mode and not data.get("api_token"):
        logger.error(json.dumps({"event": "config_validation_error", "error": "api_token is required in production mode"}))
        raise ValueError("api_token is required in production mode")

    logger.info(json.dumps({"event": "config_loaded", "path": resolved_path, "mode": "demo" if demo_mode else "production"}))
    return Config(
        switches=data.get("switches") or [],
        flap_threshold=data.get("flap_threshold", 3),
        upload_max_mb=data.get("upload_max_mb", 16),
        db_path=data.get("db_path", "netdash.db"),
        api_token=data.get("api_token"),
    )
