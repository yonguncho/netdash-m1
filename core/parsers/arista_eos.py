import re
import logging
from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "status": "show interfaces",
    "description": "show interfaces description",
    "mac": "show mac address-table dynamic",
    "arp": "show ip arp"
}


def parse(outputs, switch_id):
    utils.log_event("info", "parse_arista_eos", switch_id=switch_id)

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
            desc = " ".join(parts[3:]) if len(parts) > 3 else ""
            descriptions[port_name] = desc.strip()

    for line in status_output.split("\n"):
        match = re.match(r"(\S+)\s+(up|down|notpresent|disabled)\s+(up|down|notpresent|disabled)", line, re.IGNORECASE)
        if match:
            port_name, line_status, proto_status = match.groups()

            status = utils.parse_interface_status(line_status)
            port_name = utils.normalize_port(port_name)

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
        match = re.match(r"\s*(\d+)\s+([\da-f:]+)\s+(\w+)\s+(\S+)", line, re.IGNORECASE)
        if match:
            vlan_str, mac_addr, mac_type, port_name = match.groups()

            vlan = utils.normalize_vlan(vlan_str)
            mac = utils.normalize_mac(mac_addr)
            port_name = utils.normalize_port(port_name)

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
        match = re.match(r"\s*([\d.]+)\s+\d+\s+([\da-f:]+)\s+(\S+)", line, re.IGNORECASE)
        if match:
            ip, mac_addr, interface = match.groups()

            if utils.validate_ip(ip):
                mac = utils.normalize_mac(mac_addr.replace(":", ""))
                interface = utils.normalize_port(interface)

                if mac and interface:
                    arps.append({
                        "switch_id": switch_id,
                        "ip": ip,
                        "mac": mac,
                        "interface": interface
                    })

    return utils.deduplicate_list(arps, lambda a: a["ip"])
