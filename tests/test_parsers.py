from core.parsers.stub import parse, COMMANDS
from core.parsers import get_parser, PARSERS


def test_stub_parse_returns_correct_structure():
    result = parse({})
    assert "ports" in result
    assert "mac_entries" in result
    assert "arp_entries" in result


def test_stub_parse_ports_have_required_fields():
    result = parse({})
    for port in result["ports"]:
        assert "name" in port
        assert "link" in port
        assert "flap_count" in port


def test_stub_parse_non_empty_lists():
    result = parse({})
    assert len(result["ports"]) >= 2
    assert len(result["mac_entries"]) >= 2
    assert len(result["arp_entries"]) >= 2


def test_stub_commands_has_status_mac_arp():
    assert "status" in COMMANDS
    assert "mac" in COMMANDS
    assert "arp" in COMMANDS


def test_get_parser_unknown_vendor_returns_stub():
    import core.parsers.stub as stub_module
    result = get_parser("nonexistent_vendor_xyz")
    assert result is stub_module


def test_get_parser_cisco_returns_stub_in_m1():
    import core.parsers.stub as stub_module
    assert get_parser("cisco") is stub_module


def test_parsers_registry_empty_in_m1():
    assert PARSERS == {}
