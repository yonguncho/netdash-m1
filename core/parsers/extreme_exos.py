import re
import logging
from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "status": "show ports",
    "description": "show ports description",
    "mac": "show mac-address",
    "arp": "show arp"
}


def parse(outputs, switch_id):
    utils.log_event("info", "parse_extreme_exos", switch_id=switch_id)

    ports = _parse_ports(outputs.get("status", ""), outputs.get("description", ""), switch_id)
    macs = _parse_macs(outputs.get("mac", ""), switch_id)
    arps = _parse_arps(outputs.get("arp", ""), switch_id)

    return {
        "ports": ports,
        "macs": macs,
        "arps": arps
    }


def _parse_ports(status_output, desc_output, switch_id):
    ports = []

    # HIGH FIX (ReDoS prevention): Validate input size
    if len(status_output) > 1_000_000 or len(desc_output) > 1_000_000:
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return []

    descriptions = {}
    for line_idx, line in enumerate(desc_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        parts = line.split()
        if len(parts) >= 2:
            port_name = parts[0]
            desc = " ".join(parts[1:]) if len(parts) > 1 else ""
            descriptions[port_name] = desc.strip()[:256]

    for line_idx, line in enumerate(status_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        # M6: Token-based parse — robust to a variable-width Type column, leading
        # whitespace, and "Up"/"Down" substrings (e.g. "Up-Link") in other columns.
        tokens = line.split()
        if not tokens:
            continue
        port_tok = tokens[0]
        # First token must be a port: slot:port ("1:1") or standalone ("5").
        if not re.match(r"^(?:\d+:)?\d+$", port_tok):
            continue
        # Status is the EXACT "Up"/"Down" token, never a substring of another column.
        line_status = None
        for tok in tokens[1:]:
            if tok.lower() in ("up", "down"):
                line_status = tok
                break
        if line_status is None:
            continue

        status = utils.parse_interface_status(line_status)
        port_name = utils.normalize_port(port_tok, vendor="extreme_exos")

        if port_name:
            ports.append({
                "switch_id": switch_id,
                "name": port_name,
                "status": status,
                "vlan": 1,
                "speed": "unknown",
                "description": descriptions.get(port_name, "")
            })

    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_macs(mac_output, switch_id):
    macs = []

    # HIGH FIX (ReDoS prevention): Validate input size
    if len(mac_output) > 1_000_000:
        utils.log_event("warning", "parse_macs_input_too_large", switch_id=switch_id)
        return []

    for line_idx, line in enumerate(mac_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        # Regex supports both colon-separated (xx:xx:xx:xx:xx:xx) and no-colon (xxxxxxxxxxxx) MAC formats
        # M6: port column matches slot:port ("1:1") or standalone ("5")
        match = re.match(r"^\s*(\d+)\s+([\da-f:]{12,17})\s+(\w+)\s+((?:\d+:)?\d+)$", line, re.IGNORECASE)
        if match:
            vlan_str, mac_addr, mac_type, port_name = match.groups()

            vlan = utils.normalize_vlan(vlan_str)
            mac = utils.normalize_mac(mac_addr)
            port_name = utils.normalize_port(port_name, vendor="extreme_exos")

            if mac and vlan and port_name:
                macs.append({
                    "switch_id": switch_id,
                    "vlan": vlan,
                    "mac": mac,
                    "port": port_name,
                    "type": mac_type.lower()
                })

    return utils.deduplicate_list(macs, lambda m: (m["vlan"], m["mac"], m["port"]))


def _parse_arps(arp_output, switch_id):
    arps = []

    # HIGH FIX (ReDoS prevention): Validate input size
    if len(arp_output) > 1_000_000:
        utils.log_event("warning", "parse_arps_input_too_large", switch_id=switch_id)
        return []

    for line_idx, line in enumerate(arp_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        # Simplified regex with explicit IP/MAC format
        # M6: interface column matches slot:port ("1:1") or standalone ("5")
        match = re.match(r"^\s*([\d.]+)\s+([\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2}:[\da-f]{2})\s+(\d+)\s+((?:\d+:)?\d+)$", line, re.IGNORECASE)
        if match:
            ip, mac_addr, vlan_str, interface = match.groups()

            if utils.validate_ip(ip):
                mac = utils.normalize_mac(mac_addr)
                interface = utils.normalize_port(interface, vendor="extreme_exos")

                if mac and interface:
                    arps.append({
                        "switch_id": switch_id,
                        "ip": ip,
                        "mac": mac,
                        "interface": interface
                    })

    return utils.deduplicate_list(arps, lambda a: a["ip"])
