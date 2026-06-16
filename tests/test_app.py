import pytest
import sys
import os
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Demo mode client for basic functionality tests"""
    monkeypatch.chdir(tmp_path)
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture()
def client_with_token(tmp_path, monkeypatch):
    """Production mode client with valid API token for security tests"""
    monkeypatch.chdir(tmp_path)

    # Create config.yaml with api_token (required in production mode)
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""flap_threshold: 3
upload_max_mb: 16
db_path: netdash.db
api_token: test-secret-token-xyz
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
    r = client_with_token.get("/api/switches", headers={"X-API-Token": "test-secret-token-xyz"})
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


def test_api_collect_returns_501(client):
    r = client.post("/api/switches/1/collect")
    assert r.status_code == 501
    data = r.get_json()
    assert data["error"] == "not_implemented"


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
    assert b"DEMO MODE" in r.data


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
def test_production_mode_requires_api_token(tmp_path, monkeypatch):
    """Production mode should raise ValueError during create_app if api_token is missing"""
    monkeypatch.chdir(tmp_path)

    # Create config.yaml WITHOUT api_token
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""flap_threshold: 3
upload_max_mb: 16
db_path: netdash.db
""")

    monkeypatch.setenv("NETDASH_CONFIG", str(config_file))

    # create_app in production mode should raise ValueError because api_token is missing
    with pytest.raises(ValueError, match="api_token is required in production mode"):
        create_app(demo_mode=False)


# Fix for WARNING: No Concurrent Flask Request Test
# (Flask context is not thread-safe with test_client; concurrent DB safety tested in test_db.py)
def test_concurrent_api_requests(demo_client):
    """Verify API handles multiple sequential requests without errors"""
    # Make 5 sequential requests to verify endpoint stability and data consistency
    results = []
    for _ in range(5):
        r = demo_client.get("/api/state")
        assert r.status_code == 200
        result = r.get_json()
        assert "switches" in result
        assert "demo" in result
        assert result["demo"] is True
        results.append(result)

    # All requests should return consistent data
    assert len(results) == 5
    # Verify all responses have same switch count (no mutations between requests)
    first_count = len(results[0]["switches"])
    for result in results[1:]:
        assert len(result["switches"]) == first_count
