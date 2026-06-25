import logging
import hmac
import os
import re
import io
import argparse
from flask import Flask, jsonify, request, render_template_string, render_template
from pathlib import Path

from config import get_config, reset_config
from core import db, collector, correlator, credentials
from core.demo import run_demo
from core import flapping as flapping_mod
from core.utils import log_event
from core.collector import _sanitize_error_msg

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
)
logger = logging.getLogger(__name__)


def validate_credential(value, max_length=256):
    """CRITICAL FIX (CWE-20): Validate credential string length and printable ASCII only.

    Prevents DoS (oversized input), injection attacks (control chars).
    Allows printable ASCII characters except space (to prevent accidental whitespace in passwords).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("credentials must be string")
    if len(value) == 0:
        raise ValueError("credentials cannot be empty")
    if len(value) > max_length:
        raise ValueError(f"credentials max length {max_length}")
    # CWE-20: Accept printable ASCII only (ord 33-126); exclude space (ord 32) to prevent whitespace-only credentials
    if not all(33 <= ord(c) <= 126 for c in value):
        raise ValueError("credentials must contain only printable ASCII characters (no spaces, no control chars)")
    return value


def create_app(demo_mode=None):
    """Factory function to create and configure Flask app."""
    app = Flask(__name__,
                template_folder=str(Path(__file__).parent / "web" / "templates"),
                static_folder=str(Path(__file__).parent / "web" / "static"))

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
        demo_mode = config.app.get("demo_mode", False)
        return render_template("index.html", demo_mode=demo_mode)

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

    @app.route("/api/switches/manual", methods=["POST"])
    def add_switch_manual():
        """수동으로 스위치 1대 등록."""
        try:
            data = request.get_json() or {}
            name = data.get("name", "").strip()
            ip = data.get("ip", "").strip()
            hostname = data.get("hostname", "").strip()
            vendor = data.get("vendor", "unknown").strip()
            location = data.get("location", "").strip()

            if not ip:
                return jsonify({"error": "ip is required"}), 400
            if not name:
                name = hostname or ip

            rows = [{"name": name, "ip": ip, "hostname": hostname, "vendor": vendor, "location": location}]
            ids = db.import_switches_bulk(db_path, rows)
            return jsonify({"ok": True, "switch_id": ids[0]}), 201
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "add_switch_manual_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/import", methods=["POST"])
    def import_switches_excel():
        """엑셀 파일(xlsx)로 스위치 목록 일괄 등록.
        컬럼 순서: name, ip, hostname, vendor, location (헤더 행 필수)
        """
        try:
            import openpyxl
        except ImportError:
            return jsonify({"error": "openpyxl not installed"}), 500

        if "file" not in request.files:
            return jsonify({"error": "file field required"}), 400

        file = request.files["file"]
        if not file.filename.endswith((".xlsx", ".xls")):
            return jsonify({"error": "xlsx file required"}), 400

        try:
            wb = openpyxl.load_workbook(io.BytesIO(file.read()), read_only=True)
            ws = wb.active
            rows_iter = ws.iter_rows(values_only=True)
            header = [str(c).lower().strip() if c else "" for c in next(rows_iter)]

            parsed_rows = []
            for row in rows_iter:
                row_dict = dict(zip(header, row))
                ip = str(row_dict.get("ip", "") or "").strip()
                if not ip:
                    continue
                parsed_rows.append({
                    "name": str(row_dict.get("name", "") or "").strip() or ip,
                    "ip": ip,
                    "hostname": str(row_dict.get("hostname", "") or "").strip(),
                    "vendor": str(row_dict.get("vendor", "unknown") or "unknown").strip(),
                    "location": str(row_dict.get("location", "") or "").strip(),
                })

            if not parsed_rows:
                return jsonify({"error": "no valid rows found"}), 400

            ids = db.import_switches_bulk(db_path, parsed_rows)
            return jsonify({"ok": True, "imported": len(ids), "switch_ids": ids}), 201
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "import_excel_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/search", methods=["GET"])
    def search_ip():
        """IP로 호스트 위치(스위치+포트) 검색."""
        ip = request.args.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "ip parameter required"}), 400
        try:
            result = db.search_host_by_ip(db_path, ip)
            if result:
                return jsonify({"found": True, "result": result})
            return jsonify({"found": False, "result": None})
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "search_ip_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/vlans", methods=["GET"])
    def get_vlans():
        """전체 VLAN 현황 조회."""
        try:
            vlans = db.get_vlan_summary(db_path)
            return jsonify({"vlans": vlans})
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "get_vlans_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>/events", methods=["GET"])
    def get_switch_events(switch_id):
        """스위치의 포트 이벤트(flapping/looping) 조회."""
        try:
            events = db.get_port_events(db_path, switch_id)
            return jsonify({"switch_id": switch_id, "events": events})
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "get_events_error", switch_id=switch_id, error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>/collect", methods=["POST"])
    def collect_switch_endpoint(switch_id):
        log_event("info", "collect_requested", switch_id=switch_id)

        try:
            data = request.get_json() or {}

            # HIGH FIX (CWE-20): Validate credential string length, type, character set
            try:
                username = validate_credential(data.get("username"))
                password = validate_credential(data.get("password"))
            except ValueError as validation_error:
                log_event("warning", "collect_invalid_credentials", switch_id=switch_id, reason=str(validation_error))
                return jsonify({"error": str(validation_error)}), 400

            # CWE-522 fix: Require credentials in production mode; sanitize log output
            if not config.app.get("demo_mode") and (not username or not password):
                return jsonify({"error": "username and password required"}), 400

            # M3: Handle credential persistence (optional DPAPI encryption)
            persist = data.get("persist", False)
            cred_result = credentials.save_credential(switch_id, username, password, persist=persist)
            if persist and cred_result.get("encrypted"):
                # Store encrypted credential blob in DB for this switch
                cred_blob = cred_result.get("cred_blob")
                try:
                    db.update_cred_blob(db_path, switch_id, cred_blob)
                    log_event("info", "credential_persisted", switch_id=switch_id)
                except Exception as e:
                    sanitized = _sanitize_error_msg(str(e))
                    log_event("warning", "credential_persist_failed", switch_id=switch_id, error=sanitized)

            # Note: Credentials passed to collector are handled in-memory and logged with sanitization
            result = collector.collect_switch(db_path, switch_id, username, password)

            # M3: 수집 완료 후 flapping/looping 분석 (비동기 결과가 있는 경우에만)
            if result.get("status") == "done" and result.get("parsed"):
                try:
                    flapping_mod.run_analysis(db_path, switch_id, result["parsed"])
                except Exception:
                    pass

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
    parser = argparse.ArgumentParser(description="NetDash - Network switch current status dashboard")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode with sample data")
    args = parser.parse_args()

    # CLI --demo flag takes precedence over DEMO_MODE environment variable
    demo_mode = args.demo if args.demo else (os.getenv("DEMO_MODE", "").lower() == "true")

    # Create config with determined demo_mode
    reset_config()
    config = get_config(demo_mode=demo_mode)

    app = create_app(demo_mode=demo_mode)

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
    # CRITICAL FIX (CWE-489): In production mode, force debug=False to prevent credential/stack-trace exposure.
    # Do NOT allow debug override via environment variables in production (app.run() receives final value here).
    debug = config.app.get("debug", False) and demo_mode

    log_event("info", "app_start", host=host, port=port, debug=debug, demo_mode=demo_mode)

    app.run(host=host, port=port, debug=debug)
