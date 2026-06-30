"""Cisco Nexus (NX-OS) 파서.

IOS와 명령/출력 형식이 다르다:
  status      : show interface brief   (Eth1/1 ... up/down ... speed)
  description : show interface description (Port Type Description)
  mac         : show mac address-table dynamic (* VLAN MAC Type age Secure NTFY Ports)
  arp         : show ip arp            (Address Age MAC Interface)
MAC은 dot 형식(0050.56a1.b2c3)을 쓴다.
"""
import re
import logging

from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "status": "show interface brief",
    "description": "show interface description",
    "mac": "show mac address-table dynamic",
    "arp": "show ip arp",
}

_IFACE = r"(Eth\S+|mgmt\d+|Po\d+|Vlan\d+|Lo\d+|Tunnel\d+)"


def parse(outputs, switch_id):
    utils.log_event("info", "parse_cisco_nxos", switch_id=switch_id)
    descriptions = _parse_descriptions(outputs.get("description", ""))
    ports = _parse_ports(outputs.get("status", ""), descriptions, switch_id)
    macs = _parse_macs(outputs.get("mac", ""), switch_id)
    arps = _parse_arps(outputs.get("arp", ""), switch_id)
    from . import cisco_ios  # show vlan brief 파싱은 IOS와 동일 형식
    vlans = cisco_ios.parse_vlans(outputs.get("vlan", ""), switch_id)
    return {"ports": ports, "macs": macs, "arps": arps, "vlans": vlans}


def _parse_descriptions(desc_output):
    """show interface description → {port: description}."""
    descriptions = {}
    if len(desc_output) > 1_000_000:
        return descriptions
    for i, line in enumerate(desc_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        m = re.match(r"^" + _IFACE + r"\s+\S+\s+(.+)$", line)
        if m:
            port, desc = m.groups()
            p = utils.normalize_port(port)
            if p:
                descriptions[p] = desc.strip()[:256]
    return descriptions


def _parse_ports(status_output, descriptions, switch_id):
    """show interface brief → 포트 상태."""
    ports = []
    if len(status_output) > 1_000_000:
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(status_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # 인터페이스명 + (행 어딘가의) 첫 up/down 상태
        m = re.match(r"^" + _IFACE + r"\s+.*?\b(up|down)\b", line, re.IGNORECASE)
        if m:
            port_name, status_word = m.groups()
            status = utils.parse_interface_status(status_word)
            port_name = utils.normalize_port(port_name)
            if port_name:
                ports.append({
                    "switch_id": switch_id,
                    "name": port_name,
                    "status": status,
                    "vlan": 1,
                    "speed": "unknown",
                    "description": descriptions.get(port_name, ""),
                })
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_macs(mac_output, switch_id):
    """show mac address-table dynamic → MAC-포트 매핑."""
    macs = []
    if len(mac_output) > 1_000_000:
        utils.log_event("warning", "parse_macs_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(mac_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # [*/+/G 등 플래그] VLAN MAC Type age Secure NTFY Ports
        m = re.match(
            r"^[\*\+GO\s]*?(\d+)\s+([0-9a-fA-F.:]{12,17})\s+(\w+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$",
            line)
        if m:
            vlan_str, mac_addr, mac_type, port_name = m.groups()
            vlan = utils.normalize_vlan(vlan_str)
            mac = utils.normalize_mac(mac_addr)
            port_name = utils.normalize_port(port_name)
            if mac and vlan and port_name:
                macs.append({
                    "switch_id": switch_id,
                    "vlan": vlan,
                    "mac": mac,
                    "port": port_name,
                    "type": mac_type.lower(),
                })
    return utils.deduplicate_list(macs, lambda m: (m["vlan"], m["mac"], m["port"]))


def _parse_arps(arp_output, switch_id):
    """show ip arp → IP-MAC 매핑."""
    arps = []
    if len(arp_output) > 1_000_000:
        utils.log_event("warning", "parse_arps_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(arp_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # Address  Age  MAC Address  Interface
        m = re.match(
            r"^([\d.]+)\s+\S+\s+([0-9a-fA-F.:]{12,17})\s+(\S+)", line)
        if m:
            ip, mac_addr, interface = m.groups()
            if utils.validate_ip(ip):
                mac = utils.normalize_mac(mac_addr)
                interface = utils.normalize_port(interface)
                if mac and interface:
                    arps.append({
                        "switch_id": switch_id,
                        "ip": ip,
                        "mac": mac,
                        "interface": interface,
                    })
    return utils.deduplicate_list(arps, lambda a: a["ip"])
