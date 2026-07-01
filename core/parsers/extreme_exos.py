import re
import logging
from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "status": "show ports no-refresh",
    "description": "show ports description",
    "mac": "show fdb",
    "arp": "show iparp",
    "logging": "show log messages memory-buffer",
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
        # EXOS 'show ports no-refresh' Link State: active(=up) / ready(=down) / disabled.
        # (구버전/타 출력의 up/down도 함께 인식). 정확 토큰 매칭.
        status = None
        for tok in tokens[1:]:
            tl = tok.lower()
            if tl in ("active", "up"):
                status = "up"; break
            if tl in ("ready", "down", "notpresent"):
                status = "down"; break
            if tl in ("disabled", "disable"):
                status = "disabled"; break
        if status is None:
            continue

        # 속도/듀플렉스 best-effort: 숫자 속도(10/100/1000/10000...) + FULL/HALF
        spd = ""
        for tok in tokens[1:]:
            if re.match(r"^\d{2,6}$", tok):
                spd = tok; break
        dup = ""
        for tok in tokens[1:]:
            if tok.upper() in ("FULL", "HALF"):
                dup = tok.upper(); break
        speed = " · ".join([x for x in (spd, dup) if x]) or "unknown"

        port_name = utils.normalize_port(port_tok, vendor="extreme_exos")

        if port_name:
            ports.append({
                "switch_id": switch_id,
                "name": port_name,
                "status": status,
                "vlan": 1,
                "speed": speed,
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
        # EXOS 'show fdb' 형식: MAC  VLAN이름(태그)  Age  Flags  Port
        #   00:04:96:52:e7:7e   Default(0001)   0000 d m   1:2
        # → MAC(맨앞), VLAN 태그는 (숫자), Port는 맨 끝 토큰(slot:port 또는 standalone)
        match = re.match(
            r"^\s*([\da-f:]{12,17})\s+\S*\((\d+)\).*?((?:\d+:)?\d+)\s*$", line, re.IGNORECASE)
        if match:
            mac_addr, vlan_str, port_name = match.groups()

            vlan = utils.normalize_vlan(vlan_str)
            mac = utils.normalize_mac(mac_addr)
            port_name = utils.normalize_port(port_name, vendor="extreme_exos")

            if mac and vlan and port_name:
                macs.append({
                    "switch_id": switch_id,
                    "vlan": vlan,
                    "mac": mac,
                    "port": port_name,
                    "type": "dynamic"
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
        # EXOS 'show iparp' 형식: VR  Destination(IP)  MAC  Age  Static  VLAN  VID  Port
        #   VR-Default  10.66.0.1  00:04:96:xx:xx:xx  0  NO  v10  10  1:15
        # → IP·MAC은 어디서든, Port는 맨 끝 토큰(slot:port 또는 standalone)
        match = re.search(
            r"((?:\d{1,3}\.){3}\d{1,3})\s+([\da-f:]{12,17}).*?((?:\d+:)?\d+)\s*$",
            line, re.IGNORECASE)
        if match:
            ip, mac_addr, interface = match.groups()

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
