import logging
import hmac
import os
from flask import Flask, jsonify, request, render_template_string
from pathlib import Path

from config import get_config, reset_config
from core import db, collector, correlator
from core.demo import run_demo
from core.utils import log_event
from core.collector import _sanitize_error_msg

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
)
logger = logging.getLogger(__name__)


def create_app(demo_mode=None):
    """Factory function to create and configure Flask app."""
    app = Flask(__name__)

    # Reset config singleton to allow fresh load in tests
    reset_config()
    config = get_config(demo_mode=demo_mode)

    db_path = config.get_db_path()
    db.init_schema(db_path)
    db.validate_schema(db_path)

    collector.init_collector()

    # Load demo data in demo mode
    if config.app.get("demo_mode"):
        run_demo(config)

    # API Token validation for production mode (CWE-306 fix: enforce authentication on all API routes)
    @app.before_request
    def validate_api_token():
        # Skip token validation only for "/" (home) route and health checks
        if request.path == "/" or request.path == "/health":
            return
        # In demo mode, skip validation only if explicitly enabled in config
        if config.app.get("demo_mode"):
            return
        # Enforce API authentication in production mode (all /api/* routes)
        if request.path.startswith("/api/"):
            token = request.headers.get("X-API-Token")
            expected_token = config.api_token
            # CWE-306 fix: Reject if token is missing or invalid; never accept empty token
            if not token:
                log_event("warning", "api_missing_token", path=request.path)
                return jsonify({"error": "unauthorized"}), 401
            if not expected_token:
                # Production mode requires api_token to be set in config
                log_event("error", "api_token_not_configured", path=request.path)
                return jsonify({"error": "server configuration error"}), 500
            if not hmac.compare_digest(token, expected_token):
                log_event("warning", "api_invalid_token", path=request.path)
                return jsonify({"error": "unauthorized"}), 401

    # Security headers for all responses
    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    @app.route("/", methods=["GET"])
    def index():
        demo_badge = "DEMO MODE" if config.app.get("demo_mode") else ""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NetDash</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .demo {{ background: #ffe6cc; padding: 10px; margin: 10px 0; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>NetDash</h1>
            {f'<div class="demo">⚠️ {demo_badge}</div>' if demo_badge else ''}
            <p>Network dashboard and monitoring system.</p>
            <p><a href="/api/state">API State</a></p>
        </body>
        </html>
        """
        return html, 200

    @app.route("/api/state", methods=["GET"])
    def get_state():
        log_event("info", "api_state")
        try:
            switches = db.get_switches(db_path)
            snapshots = db.get_snapshots(db_path)

            return jsonify({
                "switches": switches,
                "snapshots": snapshots,
                "demo": config.app.get("demo_mode", False)
            })
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "api_state_error", error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches", methods=["GET"])
    def get_switches():
        log_event("info", "api_switches")
        try:
            switches = db.get_switches(db_path)
            return jsonify({"switches": switches})
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "api_switches_error", error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>/collect", methods=["POST"])
    def collect_switch_endpoint(switch_id):
        log_event("info", "collect_requested", switch_id=switch_id)

        try:
            data = request.get_json() or {}
            username = data.get("username")
            password = data.get("password")

            # CWE-522 fix: Require credentials in production mode; sanitize log output
            if not config.app.get("demo_mode") and (not username or not password):
                return jsonify({"error": "username and password required"}), 400

            # Note: Credentials passed to collector are handled in-memory and logged with sanitization
            result = collector.collect_switch(db_path, switch_id, username, password)
            # Return 202 Accepted with queue information
            return jsonify(result), 202
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "collect_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>/detail", methods=["GET"])
    def get_switch_detail(switch_id):
        log_event("info", "detail_requested", switch_id=switch_id)

        try:
            switch = db.get_switch(db_path, switch_id)
            if not switch:
                return jsonify({"error": "Switch not found"}), 404

            ports = db.get_ports_by_switch(db_path, switch_id)
            macs = db.get_mac_entries_by_switch(db_path, switch_id)
            arps = db.get_arp_entries_by_switch(db_path, switch_id)
            hosts = db.get_hosts_by_switch(db_path, switch_id)

            return jsonify({
                "switch": switch,
                "ports": ports,
                "macs": macs,
                "arps": arps,
                "hosts": hosts
            })
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "detail_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
        sanitized_error = _sanitize_error_msg(str(e))
        log_event("error", "internal_error", error_type=type(e).__name__, error=sanitized_error)
        return jsonify({"error": "Internal server error"}), 500

    return app


if __name__ == "__main__":
    # CWE-306 fix: Production mode is default; demo_mode only if explicitly enabled via environment
    demo_mode = os.getenv("DEMO_MODE", "").lower() == "true"

    app = create_app(demo_mode=demo_mode)
    config = get_config()

    # CWE-306 fix: In production mode, API token MUST be configured
    if not demo_mode and not config.api_token:
        # Require API_TOKEN environment variable in production
        api_token_env = os.getenv("API_TOKEN", "")
        if not api_token_env:
            log_event("error", "app_start_failed", reason="API_TOKEN required in production mode")
            raise RuntimeError("API_TOKEN environment variable required in production mode")
        # Update config with API token from environment
        config.api_token = api_token_env

    host = config.app.get("host", "127.0.0.1")
    port = config.app.get("port", 8082)
    debug = config.app.get("debug", False)

    log_event("info", "app_start", host=host, port=port, debug=debug, demo_mode=config.app.get("demo_mode", False))

    app.run(host=host, port=port, debug=debug)
