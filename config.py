import os
import logging
from pathlib import Path

from core.config_loader import load_config as _load_config
from core.config_loader import Config

logger = logging.getLogger(__name__)

_config_instance = None


def get_config(config_path: str = "config.yaml", demo_mode: bool = None) -> Config:
    """Get or create global config instance. Supports singleton pattern for Flask."""
    global _config_instance
    if _config_instance is None:
        # Determine demo_mode from parameter or environment
        if demo_mode is None:
            demo_env = os.getenv("DEMO_MODE", "").lower()
            demo_mode = demo_env == "true"
        _config_instance = _load_config(config_path, demo_mode=demo_mode)
    return _config_instance


def reset_config():
    """Reset config singleton (useful for testing)."""
    global _config_instance
    _config_instance = None
