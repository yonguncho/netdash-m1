import json
import logging
import os
import sqlite3
from pathlib import Path

import yaml

from core.config_loader import Config
from core import db
from core.parsers import get_parser

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _read_fixture(filename: str) -> str:
    path = FIXTURES_DIR / filename
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning(json.dumps({"event": "fixture_not_found", "file": str(path)}))
        return ""
    except Exception as e:
        logger.warning(json.dumps({"event": "fixture_read_error", "file": str(path), "error": str(e)}))
        return ""


def run_demo(config: Config) -> None:
    logger.info(json.dumps({"event": "demo_start"}))

    yaml_path = FIXTURES_DIR / "demo_switches.yaml"
    try:
        demo_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        logger.error(json.dumps({"event": "demo_switches_yaml_not_found", "path": str(yaml_path)}))
        return
    except yaml.YAMLError as e:
        logger.error(json.dumps({"event": "demo_switches_yaml_error", "error": str(e)}))
        return

    switches = demo_data.get("switches") or []
    if not switches:
        logger.warning(json.dumps({"event": "demo_no_switches"}))
        return

    for sw in switches:
        try:
            switch_id = db.upsert_switch(config.db_path, {**sw, "status": "pending"})
        except (ValueError, sqlite3.Error) as e:
            # Catch only specific exceptions: validation errors and DB errors
            logger.warning(json.dumps({"event": "demo_upsert_switch_error", "ip": sw.get("ip"), "error": str(e)}))
            continue

        if switch_id is None:
            logger.warning(json.dumps({"event": "demo_switch_not_found_after_upsert", "ip": sw.get("ip")}))
            continue
        vendor = sw.get("vendor", "")
        parser = get_parser(vendor)

        outputs = {
            "status": _read_fixture("cisco_ios_status.txt"),
            "mac": _read_fixture("cisco_ios_mac.txt"),
            "arp": _read_fixture("cisco_ios_arp.txt"),
        }

        try:
            parsed = parser.parse(outputs)
            db.save_snapshot(config.db_path, switch_id, parsed)
            db.update_switch_status(config.db_path, switch_id, "done")
            logger.info(json.dumps({"event": "demo_switch_done", "ip": sw.get("ip"), "switch_id": switch_id}))
        except Exception as e:
            logger.warning(json.dumps({"event": "demo_snapshot_error", "switch_id": switch_id, "error": str(e)}))
            db.update_switch_status(config.db_path, switch_id, "failed", error=str(e))

    logger.info(json.dumps({"event": "demo_complete", "count": len(switches)}))
