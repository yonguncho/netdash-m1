import logging
import os
import sqlite3
from pathlib import Path

import yaml

from core.config_loader import Config
from core import db, fixtures
from core import utils
from core.parsers import get_parser

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def run_demo(config: Config) -> None:
    utils.log_event("info", "demo_start")

    db_path = config.get_db_path()

    # Check for demo_switches.yaml in multiple locations
    yaml_paths = [
        FIXTURES_DIR / "demo_switches.yaml",
        Path("fixtures") / "demo_switches.yaml",
        Path.cwd() / "fixtures" / "demo_switches.yaml"
    ]

    yaml_path = None
    for p in yaml_paths:
        if p.exists():
            yaml_path = p
            break

    if yaml_path is None:
        utils.log_event("error", "demo_switches_yaml_not_found", paths=str(yaml_paths))
        return

    try:
        demo_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        utils.log_event("error", "demo_switches_yaml_not_found", path=str(yaml_path))
        return
    except yaml.YAMLError as e:
        utils.log_event("error", "demo_switches_yaml_error", error=str(e))
        return

    switches = demo_data.get("switches") or []
    if not switches:
        utils.log_event("warning", "demo_no_switches")
        return

    for sw in switches:
        try:
            # Use save_switch with status="pending" (already supports status field via INSERT OR IGNORE)
            switch_id = db.save_switch(db_path, sw.get("name"), sw.get("ip"), sw.get("vendor", ""))
        except (ValueError, sqlite3.Error) as e:
            # Catch only specific exceptions: validation errors and DB errors
            utils.log_event("warning", "demo_save_switch_error", ip=sw.get("ip"), error=str(e))
            continue

        if switch_id is None:
            utils.log_event("warning", "demo_switch_not_found_after_save", ip=sw.get("ip"))
            continue
        vendor = sw.get("vendor", "")
        parser = get_parser(vendor)
        outputs = fixtures.get_demo_outputs_for_vendor(vendor)

        try:
            parsed = parser.parse(outputs, switch_id)
            # Save snapshot and decompose parsed data into individual tables
            snapshot_id = db.save_snapshot(db_path, switch_id, duration_seconds=None)
            db.save_ports(db_path, snapshot_id, switch_id, parsed.get("ports", []))
            db.save_mac_entries(db_path, snapshot_id, switch_id, parsed.get("macs", []))
            db.save_arp_entries(db_path, snapshot_id, switch_id, parsed.get("arps", []))
            db.set_switch_status(db_path, switch_id, "done")
            utils.log_event("info", "demo_switch_done", ip=sw.get("ip"), switch_id=switch_id)
        except Exception as e:
            utils.log_event("warning", "demo_snapshot_error", switch_id=switch_id, error=str(e))
            db.set_switch_status(db_path, switch_id, "failed")

    utils.log_event("info", "demo_complete", count=len(switches))
