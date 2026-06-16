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

    descriptions = {}
    for line in desc_output.split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            port_name = parts[0]
            desc = " ".join(parts[1:]) if len(parts) > 1 else ""
            descriptions[port_name] = desc.strip()

    for line in status_output.split("\n"):
        match = re.match(r"(\d+:\d+)\s+\S+\s+\S+\s+(Up|Down)\s+", line, re.IGNORECASE)
        if match:
            port_name, line_status = match.groups()

            status = utils.parse_interface_status(line_status)
            port_name = utils.normalize_port(port_name, vendor="extreme_exos")

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

    for line in mac_output.split("\n"):
        match = re.match(r"\s*(\d+)\s+([\da-f:]+)\s+(\w+)\s+(\d+:\d+)", line, re.IGNORECASE)
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

    for line in arp_output.split("\n"):
        match = re.match(r"\s*([\d.]+)\s+([\da-f:]+)\s+(\d+)\s+(\d+:\d+)", line, re.IGNORECASE)
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
