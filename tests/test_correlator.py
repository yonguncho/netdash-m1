import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, correlator


class TestCorrelator:
    def test_correlate_basic(self, temp_db, demo_switches):
        switch = demo_switches[0]
        switch_id = db.save_switch(temp_db, switch["name"], switch["ip"], switch["vendor"])

        snapshot_id = db.save_snapshot(temp_db, switch_id)

        macs = [
            {"switch_id": switch_id, "vlan": 1, "mac": "00:11:22:33:44:aa", "port": "Gi1/0/1", "type": "dynamic"},
            {"switch_id": switch_id, "vlan": 1, "mac": "00:11:22:33:44:bb", "port": "Gi1/0/2", "type": "dynamic"},
        ]
        db.save_mac_entries(temp_db, snapshot_id, switch_id, macs)

        arps = [
            {"switch_id": switch_id, "ip": "10.0.1.100", "mac": "00:11:22:33:44:aa", "interface": "Vlan1"},
            {"switch_id": switch_id, "ip": "10.0.1.101", "mac": "00:11:22:33:44:bb", "interface": "Vlan1"},
        ]
        db.save_arp_entries(temp_db, snapshot_id, switch_id, arps)

        result = correlator.correlate(temp_db)

        assert "hosts" in result
        assert len(result["hosts"]) == 2
        assert result["hosts"]["10.0.1.100"]["located"] == True

    def test_uplink_port_filtering(self, temp_db, demo_switches):
        switch_id = db.save_switch(temp_db, demo_switches[0]["name"], demo_switches[0]["ip"], demo_switches[0]["vendor"])
        snapshot_id = db.save_snapshot(temp_db, switch_id)

        uplink_macs = [
            {"switch_id": switch_id, "vlan": 1, "mac": f"00:11:22:33:44:{i:02x}", "port": "Gi1/0/48", "type": "dynamic"}
            for i in range(5)
        ]
        db.save_mac_entries(temp_db, snapshot_id, switch_id, uplink_macs)

        result = correlator.correlate(temp_db)
        assert result["stats"]["located_ips"] == 0, "Uplink port should be filtered"
