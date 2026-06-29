import pytest
import sys
import os
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app


# NOTE: `client` fixture is now provided by conftest.py (shared across modules).


@pytest.fixture()
def client_with_token(tmp_path, monkeypatch):
    """Production mode client with valid API token for security tests"""
    monkeypatch.chdir(tmp_path)

    # Create config.yaml with api_token (required in production mode)
    # HARDENING: Use strong token (32+ chars with mixed case, digits, special chars)
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""flap_threshold: 3
upload_max_mb: 16
db_path: netdash.db
api_token: test_secret_token_xyz_32_chars_long_ABCD123
""")

    # Override NETDASH_CONFIG to ensure our config.yaml is used (not project root's)
    monkeypatch.setenv("NETDASH_CONFIG", str(config_file))

    app = create_app(demo_mode=False)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture()
def demo_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import shutil
    fixtures_src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
    fixtures_dst = tmp_path / "fixtures"
    shutil.copytree(fixtures_src, str(fixtures_dst))
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_returns_200(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"NetDash" in r.data


def test_api_rejects_missing_token_in_production(client_with_token):
    """Production mode API should reject requests without X-API-Token header"""
    r = client_with_token.get("/api/switches")
    assert r.status_code == 401
    data = r.get_json()
    assert data["error"] == "unauthorized"


def test_api_accepts_valid_token_in_production(client_with_token):
    """Production mode API should accept requests with valid X-API-Token header"""
    # Use the token from conftest.py API_TOKEN environment variable (takes precedence over config file)
    r = client_with_token.get("/api/switches", headers={"X-API-Token": "test_token_32_chars_long_secure_value_12345"})
    assert r.status_code == 200
    data = r.get_json()
    assert "switches" in data


def test_api_rejects_invalid_token_in_production(client_with_token):
    """Production mode API should reject requests with invalid X-API-Token header"""
    r = client_with_token.get("/api/switches", headers={"X-API-Token": "wrong-token"})
    assert r.status_code == 401
    data = r.get_json()
    assert data["error"] == "unauthorized"


def test_api_state_returns_200_with_switches_key(client):
    r = client.get("/api/state")
    assert r.status_code == 200
    data = r.get_json()
    assert "switches" in data
    assert isinstance(data["switches"], list)
    assert "demo" in data
    assert data["demo"] is True  # client is demo mode


def test_api_switches_returns_200(client):
    r = client.get("/api/switches")
    assert r.status_code == 200
    data = r.get_json()
    assert "switches" in data


def test_api_collect_returns_202(client):
    r = client.post("/api/switches/1/collect", json={})
    assert r.status_code == 202
    data = r.get_json()
    assert "status" in data
    assert data["status"] in ("queued", "error")


def test_404_no_stack_trace(client):
    r = client.get("/api/nonexistent_route_xyz")
    assert r.status_code == 404
    assert b"Traceback" not in r.data
    assert b"File \"" not in r.data


def test_demo_mode_api_state_has_demo_true(demo_client):
    r = demo_client.get("/api/state")
    assert r.status_code == 200
    data = r.get_json()
    assert data["demo"] is True


def test_demo_mode_has_three_switches(demo_client):
    r = demo_client.get("/api/state")
    data = r.get_json()
    assert len(data["switches"]) == 3


def test_demo_mode_index_contains_demo_badge(demo_client):
    r = demo_client.get("/")
    assert r.status_code == 200
    assert b'badge badge--demo">DEMO' in r.data


# Fix for WARNING: Missing Test Coverage for API Security Headers
def test_security_headers_present(client):
    """Verify security headers are present in all responses"""
    r = client.get("/api/state")
    assert r.status_code == 200
    # Check Content-Security-Policy header
    assert "Content-Security-Policy" in r.headers
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    # Check X-Content-Type-Options header
    assert "X-Content-Type-Options" in r.headers
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    # Check X-Frame-Options header
    assert "X-Frame-Options" in r.headers
    assert r.headers["X-Frame-Options"] == "DENY"
    # Check Referrer-Policy header
    assert "Referrer-Policy" in r.headers
    assert r.headers["Referrer-Policy"] == "no-referrer"
    # Check Cache-Control header (prevents stale data caching)
    assert "Cache-Control" in r.headers
    assert "no-store" in r.headers["Cache-Control"]


# Fix for WARNING: Missing Test for Production Mode Config Validation
def test_production_mode_requires_api_token(tmp_path, monkeypatch, no_api_token_env):
    """Production + externally reachable bind (0.0.0.0) must still require api_token.

    (Loopback binds auto-generate a token — covered in test_config_loader.)
    """
    monkeypatch.chdir(tmp_path)

    # Create config.yaml WITHOUT api_token, externally reachable bind
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""flap_threshold: 3
upload_max_mb: 16
db_path: netdash.db
app:
  host: 0.0.0.0
""")

    monkeypatch.setenv("NETDASH_CONFIG", str(config_file))

    # create_app in production mode should raise ValueError because api_token is missing
    # and the bind host is externally reachable (no_api_token_env removes API_TOKEN env var)
    with pytest.raises(ValueError, match="api_token is required in production mode"):
        create_app(demo_mode=False)


# FIX for WARNING: Sequential Request Stability Test
# WARNING FIX (test_app.py:180): Make 10 sequential requests to verify stability
# Note: Flask test_client is not thread-safe; actual concurrent DB safety is tested in test_db.py
def test_concurrent_api_requests(demo_client):
    """Verify API request handling stability across multiple sequential requests.

    Each request is made sequentially to test endpoint consistency without race conditions.
    Real concurrent database access is tested via test_db::test_concurrent_save_snapshot.
    """
    results = []
    for i in range(10):
        r = demo_client.get("/api/state")
        assert r.status_code == 200, f"Request {i+1} failed with status {r.status_code}"
        result = r.get_json()
        assert "switches" in result, f"Request {i+1} missing 'switches' key"
        assert "demo" in result, f"Request {i+1} missing 'demo' key"
        assert result["demo"] is True
        results.append(result)

    # All responses should have consistent data (no mutations between requests)
    assert len(results) == 10
    first_count = len(results[0]["switches"])
    for i, result in enumerate(results[1:], 1):
        assert len(result["switches"]) == first_count, f"Request {i+1} returned different switch count"
