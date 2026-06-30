"""Cisco IOS / IOS-XE / Catalyst 파서.

명령(IOS-XE·Catalyst·NX-OS 공통으로 통하는 세트):
  status      : show interface status      (Port Name Status Vlan Duplex Speed Type)
  description : show interface description  (Interface Status Protocol Description)
  mac         : show mac address-table      (Vlan MAC Type Ports) — dot 형식 MAC
  arp         : show ip arp                 (Internet Address Age MAC Type Interface)
"""
import re
import logging

from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "status": "show interface status",
    "description": "show interface description",
    "mac": "show mac address-table",
    "arp": "show ip arp",
}

# MAC: dot(0050.56a1.b2c3) / colon / hyphen 형식 모두 허용
_MAC = r"[0-9a-fA-F][0-9a-fA-F:.\-]{10,18}[0-9a-fA-F]"
# show interface status의 상태 키워드
_STATUS_RE = re.compile(
    r"\b(connected|notconnect|disabled|err-disabled|errdisable|inactive|"
    r"suspended|monitoring|sfpAbsent|xcvrAbsen|notpresent|up|down)\b", re.IGNORECASE)


def parse(outputs, switch_id):
    utils.log_event("info", "parse_cisco_ios", switch_id=switch_id)
    descriptions = _parse_descriptions(outputs.get("description", ""))
    ports = _parse_ports(outputs.get("status", ""), descriptions, switch_id)
    macs = _parse_macs(outputs.get("mac", ""), switch_id)
    arps = _parse_arps(outputs.get("arp", ""), switch_id)
    vlans = parse_vlans(outputs.get("vlan", ""), switch_id)
    return {"ports": ports, "macs": macs, "arps": arps, "vlans": vlans}


def parse_vlans(vlan_output, switch_id):
    """show vlan brief → [{vlan, name, status}]. IOS/IOS-XE/NX-OS 공통 형식."""
    vlans = []
    if not vlan_output or len(vlan_output) > 1_000_000:
        return vlans
    for i, line in enumerate(vlan_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # VLAN  Name  Status  Ports
        m = re.match(r"^(\d{1,4})\s+(\S+)\s+(\S+)", line)
        if m:
            vid, name, status = m.groups()
            try:
                vlan = int(vid)
            except ValueError:
                continue
            if 1 <= vlan <= 4094:
                vlans.append({"switch_id": switch_id, "vlan": vlan,
                              "name": name, "status": status})
    return utils.deduplicate_list(vlans, lambda v: v["vlan"])


def _parse_descriptions(desc_output):
    """show interface description → {port: description}.

    형식: Interface  Status  Protocol  Description
    """
    descriptions = {}
    if len(desc_output) > 1_000_000:
        return descriptions
    for i, line in enumerate(desc_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # Interface <status> <protocol> <description...>; status는 up/down/admin down
        m = re.match(r"^(\S+)\s+(?:admin\s+down|up|down)\s+(?:up|down)\s+(.*)$", line, re.IGNORECASE)
        if m:
            iface, desc = m.groups()
            p = utils.normalize_port(iface)
            if p and desc.strip():
                descriptions[p] = desc.strip()[:256]
    return descriptions


def _parse_ports(status_output, descriptions, switch_id):
    """show interface status → 포트 상태/VLAN/속도.

    형식: Port  Name(공백가능)  Status  Vlan  Duplex  Speed  Type
    상태 키워드를 기준으로 좌(포트)·우(vlan/speed)를 분리한다.
    """
    ports = []
    if len(status_output) > 1_000_000:
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(status_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        if line.strip().lower().startswith("port") or set(line.strip()) <= set("-"):
            continue  # 헤더/구분선
        sm = _STATUS_RE.search(line)
        if not sm:
            continue
        toks = line.split()
        if not toks:
            continue
        port = utils.normalize_port(toks[0])
        if not port:
            continue
        status_word = sm.group(1).lower()
        # show interface status 키워드 매핑: connected/up만 up, 나머지는 down
        if status_word in ("connected", "up"):
            status = "up"
        elif status_word in ("err-disabled", "errdisable", "disabled"):
            status = "error-disabled"
        else:  # notconnect, inactive, suspended, sfpAbsent, down, ...
            status = "down"
        # 상태 이후 토큰: Vlan Duplex Speed
        rest = line[sm.end():].split()
        vlan = 1
        if rest and rest[0].isdigit():
            v = utils.normalize_vlan(rest[0])
            vlan = v if v else 1
        speed = rest[2] if len(rest) > 2 else "unknown"
        ports.append({
            "switch_id": switch_id,
            "name": port,
            "status": status,
            "vlan": vlan,
            "speed": speed,
            "description": descriptions.get(port, ""),
        })
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_macs(mac_output, switch_id):
    """show mac address-table → MAC-포트 매핑 (dot 형식 MAC 포함)."""
    macs = []
    if len(mac_output) > 1_000_000:
        utils.log_event("warning", "parse_macs_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(mac_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # [*] VLAN MAC Type [age secure ntfy] Ports  — 선두 플래그/VLAN, dot MAC, 끝에 포트
        m = re.match(
            r"^[\*\+G\s]*?(\d+)\s+(" + _MAC + r")\s+(\w+)\s+.*?(\S+)\s*$", line)
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
    """show ip arp → IP-MAC 매핑. IOS 형식(Internet 행)."""
    arps = []
    if len(arp_output) > 1_000_000:
        utils.log_event("warning", "parse_arps_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(arp_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        # Internet  <ip>  <age>  <mac>  <type>  <interface>
        m = re.match(
            r"^Internet\s+([\d.]+)\s+\S+\s+(" + _MAC + r")\s+\S+\s+(\S+)", line, re.IGNORECASE)
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
