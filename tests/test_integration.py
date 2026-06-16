import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, fixtures


class TestIntegration:
    def test_schema_creation(self, temp_db):
        db.init_schema(temp_db)
        db.validate_schema(temp_db)

    def test_demo_fixtures_exist(self):
        switches = fixtures.get_demo_switches()
        assert len(switches) == 3
        assert all(s["vendor"] in ["cisco_ios", "arista_eos", "extreme_exos"] for s in switches)

    def test_end_to_end_collection(self, temp_db, demo_switches):
        for switch in demo_switches:
            switch_id = db.save_switch(temp_db, switch["name"], switch["ip"], switch["vendor"])

            outputs = fixtures.get_demo_outputs_for_vendor(switch["vendor"])
            snapshot_id = db.save_snapshot(temp_db, switch_id)

            db.save_ports(temp_db, snapshot_id, switch_id, [{"name": "Gi1/0/1", "status": "up"}])
            db.save_mac_entries(temp_db, snapshot_id, switch_id, [])
            db.save_arp_entries(temp_db, snapshot_id, switch_id, [])

            db.set_switch_status(temp_db, switch_id, "done")

            retrieved = db.get_switch(temp_db, switch_id)
            assert retrieved["status"] == "done"
