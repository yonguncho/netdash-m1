import logging
from flask import Flask, jsonify, request
from pathlib import Path

from config import get_config, reset_config
from core import db, collector, correlator
from core.utils import log_event

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

    @app.route("/api/state", methods=["GET"])
    def get_state():
        log_event("info", "api_state")
        try:
            switches = db.get_switches(db_path)
            snapshots = db.get_snapshots(db_path)

            return jsonify({
                "switches": switches,
                "snapshots": snapshots
            })
        except Exception as e:
            log_event("error", "api_state_error", error=str(e))
            return jsonify({"error": str(e)}), 500

    @app.route("/api/switches/<int:switch_id>/collect", methods=["POST"])
    def collect_switch_endpoint(switch_id):
        log_event("info", "collect_requested", switch_id=switch_id)

        try:
            data = request.get_json() or {}
            username = data.get("username")
            password = data.get("password")

            if not config.app.get("demo_mode") and (not username or not password):
                return jsonify({"error": "username and password required"}), 400

            result = collector.collect_switch(db_path, switch_id, username, password)
            return jsonify(result)
        except Exception as e:
            log_event("error", "collect_error", switch_id=switch_id, error=str(e))
            return jsonify({"error": str(e)}), 500

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
            log_event("error", "detail_error", switch_id=switch_id, error=str(e))
            return jsonify({"error": str(e)}), 500

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        log_event("error", "internal_error", error=str(e))
        return jsonify({"error": "Internal server error"}), 500

    return app


# WSGI application instance for production servers
app = create_app()


if __name__ == "__main__":
    config = get_config()
    host = config.app.get("host", "127.0.0.1")
    port = config.app.get("port", 8082)
    debug = config.app.get("debug", False)

    log_event("info", "app_start", host=host, port=port, debug=debug, demo_mode=config.app.get("demo_mode", False))

    app.run(host=host, port=port, debug=debug)
