import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import fixtures
from core.parsers import cisco_ios, arista_eos, extreme_exos


class TestCiscoIOSParser:
    def test_parse_cisco_ios(self):
        outputs = fixtures.get_cisco_ios_outputs()
        result = cisco_ios.parse(outputs, 1)

        assert "ports" in result
        assert "macs" in result
        assert "arps" in result

        assert len(result["ports"]) > 0
        assert len(result["macs"]) > 0
        assert len(result["arps"]) > 0

    def test_cisco_ports_have_required_fields(self):
        outputs = fixtures.get_cisco_ios_outputs()
        result = cisco_ios.parse(outputs, 1)

        for port in result["ports"]:
            assert "name" in port
            assert "status" in port
            assert port["switch_id"] == 1

    def test_cisco_macs_deduplicated(self):
        outputs = fixtures.get_cisco_ios_outputs()
        result = cisco_ios.parse(outputs, 1)

        macs = [m["mac"] for m in result["macs"]]
        assert len(macs) == len(set(macs)), "Duplicate MACs found"


class TestAristaEOSParser:
    def test_parse_arista_eos(self):
        outputs = fixtures.get_arista_eos_outputs()
        result = arista_eos.parse(outputs, 2)

        assert "ports" in result
        assert "macs" in result
        assert "arps" in result
        assert len(result["ports"]) > 0


class TestExtremeEXOSParser:
    def test_parse_extreme_exos(self):
        outputs = fixtures.get_extreme_exos_outputs()
        result = extreme_exos.parse(outputs, 3)

        assert "ports" in result
        assert "macs" in result
        assert "arps" in result
        assert len(result["ports"]) > 0

    def test_extreme_port_normalization(self):
        outputs = fixtures.get_extreme_exos_outputs()
        result = extreme_exos.parse(outputs, 3)

        assert len(result["ports"]) > 0
        for port in result["ports"]:
            name = port["name"]
            # M6: ExtremeXOS keeps native notation; no Cisco "Gi" prefix.
            assert name, "Empty port name"
            assert not name.startswith("Gi"), f"Port {name} has wrong Cisco 'Gi' prefix"
            # demo fixture uses slot:port notation
            assert ":" in name, f"Port {name} lost slot:port notation"
