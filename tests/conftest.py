import pytest
import tempfile
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from config import Config, reset_config

# HARDENING: Set a strong test API token for production mode tests
# Use autouse to ensure it's set before any test runs
os.environ["API_TOKEN"] = "test_token_32_chars_long_secure_value_12345"


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter state between tests to prevent test interference."""
    # Import app here to avoid circular imports
    import app
    app._rate_limit_tracker.clear()
    yield
    app._rate_limit_tracker.clear()


@pytest.fixture
def no_api_token_env():
    """Temporarily remove API_TOKEN environment variable for testing config validation."""
    old_token = os.environ.pop("API_TOKEN", None)
    yield
    if old_token:
        os.environ["API_TOKEN"] = old_token


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db.init_schema(db_path)
        yield db_path


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Demo mode Flask test client (shared across test modules)."""
    monkeypatch.chdir(tmp_path)
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def demo_config(temp_db):
    reset_config()
    config = Config(demo_mode=True)
    config.database = {"path": str(temp_db)}
    return config


@pytest.fixture
def demo_switches(temp_db):
    switches = [
        {"name": "CORE-SW01", "ip": "10.0.0.10", "vendor": "cisco_ios"},
        {"name": "CORE-SW02", "ip": "10.0.0.11", "vendor": "arista_eos"},
        {"name": "ACC-SW01", "ip": "10.0.0.20", "vendor": "extreme_exos"}
    ]
    for sw in switches:
        db.save_switch(temp_db, sw["name"], sw["ip"], sw["vendor"])
    return switches


@pytest.fixture
def demo_hosts():
    return [
        {"ip": "10.0.1.100", "mac": "00:11:22:33:44:aa"},
        {"ip": "10.0.1.101", "mac": "00:11:22:33:44:bb"},
        {"ip": "10.0.1.102", "mac": "00:11:22:33:44:cc"},
        {"ip": "10.0.1.103", "mac": "00:11:22:33:44:dd"},
        {"ip": "10.0.1.104", "mac": "00:11:22:33:44:ee"},
    ]
