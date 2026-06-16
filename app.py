import argparse
import hmac
import json
import logging
import socket
import sqlite3
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from core.config_loader import load_config
from core import db
from core.demo import run_demo

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":%(message)s}',
)
logging.getLogger("paramiko").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

_config = None


def _pick_port(preferred: int = 8082) -> int:
    for port in range(preferred, preferred + 10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                logger.info(json.dumps({"event": "port_selected", "port": port}))
                return port
            except OSError:
                logger.info(json.dumps({"event": "port_in_use", "port": port}))
    raise RuntimeError(f"No available port in range {preferred}–{preferred + 9}")


def _sanitize_switch(sw: dict) -> dict:
    """Remove sensitive fields (cred_blob, error) from switch record for API response."""
    return {
        k: v for k, v in sw.items()
        if k not in ("cred_blob", "error")
    }


def create_app(demo_mode: bool = False) -> Flask:
    global _config

    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )
    app.config["DEMO_MODE"] = demo_mode

    _config = load_config("config.yaml", demo_mode=demo_mode)
    db.init_db(_config.db_path)

    if demo_mode:
        logger.info(json.dumps({"event": "demo_mode_enabled"}))
        run_demo(_config)

    def _require_api_token():
        """Validate X-API-Token header when an api_token is configured (production mode).

        Demo mode has no token configured, so all requests are allowed. When a token
        is set, every /api/ request must present a matching X-API-Token header.
        """
        if app.config["DEMO_MODE"]:
            return None
        expected = getattr(_config, "api_token", None)
        if not expected:
            return None
        provided = request.headers.get("X-API-Token", "")
        if not provided or not hmac.compare_digest(str(provided), str(expected)):
            logger.warning(json.dumps({"event": "auth_rejected", "path": request.path}))
            return jsonify({"error": "unauthorized"}), 401
        return None

    @app.before_request
    def before_request():
        if request.path.startswith("/api/"):
            result = _require_api_token()
            if result:
                return result

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # Fix for WARNING: No Cache-Control headers (prevents stale data caching by proxies)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    @app.errorhandler(Exception)
    def handle_error(e):
        if isinstance(e, HTTPException):
            return jsonify({"error": e.name}), e.code
        logger.error(json.dumps({"event": "unhandled_exception", "error": str(e)}))
        return jsonify({"error": "internal_server_error"}), 500

    @app.route("/")
    def index():
        logger.info(json.dumps({"event": "request", "method": "GET", "path": "/"}))
        return render_template("index.html", demo_mode=app.config["DEMO_MODE"])

    @app.route("/api/state")
    def api_state():
        logger.info(json.dumps({"event": "request", "method": "GET", "path": "/api/state"}))
        try:
            # Fix for WARNING: N+1 Query Pattern - use single JOIN query instead of loop
            switches = db.get_switches_with_snapshot_info(_config.db_path)
            result = [
                {
                    "id": sw["id"],
                    "name": sw["name"],
                    "ip": sw["ip"],
                    "vendor": sw["vendor"],
                    "model": sw["model"],
                    "status": sw["status"],
                    "last_collected": sw["last_collected"],
                    "port_count": sw["port_count"],
                    "mac_count": sw["mac_count"],
                    "snapshot_id": sw["snapshot_id"],
                }
                for sw in switches
            ]
            payload = {
                "demo": app.config["DEMO_MODE"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "switches": result,
            }
            logger.info(json.dumps({"event": "response", "status": 200, "path": "/api/state", "count": len(result)}))
            return jsonify(payload), 200
        except sqlite3.Error as e:
            logger.error(json.dumps({"event": "db_error", "path": "/api/state", "error": str(e)}))
            return jsonify({"error": "database_error"}), 500

    @app.route("/api/switches")
    def api_switches():
        logger.info(json.dumps({"event": "request", "method": "GET", "path": "/api/switches"}))
        try:
            switches_raw = db.get_switches(_config.db_path)
            switches = [_sanitize_switch(sw) for sw in switches_raw]
            logger.info(json.dumps({"event": "response", "status": 200, "path": "/api/switches", "count": len(switches)}))
            return jsonify({"switches": switches}), 200
        except sqlite3.Error as e:
            logger.error(json.dumps({"event": "db_error", "path": "/api/switches", "error": str(e)}))
            return jsonify({"error": "database_error"}), 500

    @app.route("/api/switches/<int:switch_id>/collect", methods=["POST"])
    def api_collect(switch_id: int):
        logger.info(json.dumps({"event": "request", "method": "POST", "path": f"/api/switches/{switch_id}/collect"}))
        return jsonify({"error": "not_implemented", "milestone": "M2"}), 501

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetDash M1")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode (no real SSH)")
    args = parser.parse_args()

    app = create_app(demo_mode=args.demo)
    port = _pick_port(8082)
    print(f"[NetDash] Starting on http://127.0.0.1:{port}  demo={args.demo}")
    app.run(host="127.0.0.1", port=port, threaded=True)
