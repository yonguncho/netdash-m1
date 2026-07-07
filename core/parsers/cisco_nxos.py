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
    "status": "show interface status",       # vlan/speed 표(brief보다 정확)
    "brief": "show interface brief",          # up/down 폴백
    "description": "show interface description",
    "mac": "show mac address-table dynamic",
    "arp": "show ip arp",
    "port_channel": "show port-channel summary",
    "inventory": "show inventory",   # 모델명(PID) — show version에 없는 표기 변형 대응
    "errors": "show interface counters errors",   # CRC/IN/OUT 오류(표 형식)
}

_IFACE = r"(Eth\S+|mgmt\d+|Po\d+|Vlan\d+|Lo\d+|Tunnel\d+)"


def parse(outputs, switch_id):
    utils.log_event("info", "parse_cisco_nxos", switch_id=switch_id)
    descriptions = _parse_descriptions(outputs.get("description", ""))
    errors = _parse_counters_errors(outputs.get("errors", ""))
    # status(show interface status)에서 vlan/speed, 없으면 brief에서 up/down 폴백
    ports = _parse_ports(outputs.get("status", ""), descriptions, switch_id, errors)
    if not ports and outputs.get("brief"):
        ports = _parse_brief(outputs.get("brief", ""), descriptions, switch_id, errors)
    macs = _parse_macs(outputs.get("mac", ""), switch_id)
    arps = _parse_arps(outputs.get("arp", ""), switch_id)
    from . import cisco_ios  # show vlan brief 파싱은 IOS와 동일 형식
    vlans = cisco_ios.parse_vlans(outputs.get("vlan", ""), switch_id)
    port_channels = _parse_port_channels(outputs.get("port_channel", ""), switch_id)
    return {"ports": ports, "macs": macs, "arps": arps, "vlans": vlans,
            "port_channels": port_channels}


def _parse_port_channels(pc_output, switch_id):
    """show port-channel summary → 포트채널별 멤버 물리포트.

    형식(예):
      Group Port-Channel Type Protocol Member Ports
      ----- ------------ ---- -------- -------------------------------
      10    Po10         Eth  LACP     Eth1/1(P)   Eth1/2(P)
      1     Po1(SU)      Eth  NONE     Eth1/5(P)

    플래그 표기(Po10(SU))가 있든 없든(Po10) 모두 지원한다.
    포트채널 MAC이 어느 물리포트에 실제 연결됐는지 해석하는 데 쓴다.
    Returns: [{switch_id, port_channel, members:[...]}]
    """
    result = {}   # {po_name: [members]}
    cur = None
    if len(pc_output) > 1_000_000:
        return []
    for i, line in enumerate(pc_output.split("\n")):
        if i > 5000 or len(line) > 1000:
            continue
        # 그룹번호 + Po<N> (선택적 (플래그)). "Po10", "Po10(SU)" 모두 매칭.
        head = re.match(r"^\s*\d+\s+(Po\d+)\b", line)
        if head:
            cur = utils.normalize_port(head.group(1))
            members = re.findall(r"(Eth\d+(?:/\d+)+)", line)
            result[cur] = [utils.normalize_port(x) for x in members]
        elif cur and "Eth" in line and re.match(r"^\s", line):
            # 멤버가 다음 줄로 래핑된 경우(그룹 번호 없이 멤버만)
            result[cur].extend(utils.normalize_port(x) for x in re.findall(r"(Eth\d+(?:/\d+)+)", line))
    return [{"switch_id": switch_id, "port_channel": k,
             "members": [m for m in v if m]} for k, v in result.items()]


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


def _map_status(word):
    """show interface status 키워드 → 표준 상태(connected=up 등)."""
    w = (word or "").lower()
    if w.startswith("connect") or w == "up":
        return "up"
    if w.startswith("notconnec") or w in ("down", "sfpabsent", "xcvrabsen", "nooprmem", "noopermem"):
        return "down"
    if "disabled" in w:
        return "error-disabled"
    if "err" in w or "flap" in w:
        return "err-disabled"
    return "unknown"


def _parse_counters_errors(err_output):
    """show interface counters errors → {port: {in_errors, crc, out_errors}}.

    NX-OS 표 형식:
      Port          Align-Err    FCS-Err   Xmit-Err    Rcv-Err  UnderSize OutDiscards
      Eth1/1                0          0          0          0          0          0
    매핑: FCS-Err=CRC, Rcv-Err=input(수신) 오류, Xmit-Err=output(송신) 오류.
    """
    result = {}
    if not err_output or len(err_output) > 5_000_000:
        return result
    for i, line in enumerate(err_output.split("\n")):
        if i > 20000 or len(line) > 500:
            continue
        # 포트 + 정수 6개(Align FCS Xmit Rcv UnderSize OutDiscards)
        m = re.match(
            r"^\s*(Eth\S+|mgmt\d+|Po\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)",
            line)
        if m:
            port = utils.normalize_port(m.group(1))
            if port:
                result[port] = {
                    "crc": int(m.group(3)),        # FCS-Err
                    "out_errors": int(m.group(4)),  # Xmit-Err
                    "in_errors": int(m.group(5)),   # Rcv-Err
                }
    return result


def _parse_ports(status_output, descriptions, switch_id, errors=None):
    """show interface status → 포트 상태 + VLAN + 속도 + 오류.

    형식(NX-OS):
      Port          Name               Status    Vlan      Duplex  Speed   Type
      Eth1/1        uplink-to-core     connected trunk     full    10G     10Gbase-SR
      Eth1/2                           notconnec 200       auto    auto    --
    """
    errors = errors or {}
    ports = []
    if len(status_output) > 1_000_000:
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return []
    for i, line in enumerate(status_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        if re.match(r"^\s*Port\s+Name", line):     # 헤더 스킵
            continue
        m = re.match(r"^" + _IFACE + r"\s+(.*)$", line)
        if not m:
            continue
        port_name = utils.normalize_port(m.group(1))
        if not port_name:
            continue
        rest = m.group(2)
        # 상태 키워드(뒤쪽에서 vlan/duplex/speed 앞) — connected/notconnec/disabled/...
        sm = re.search(r"\b(connected|notconnec\w*|disabled|err-?disabled|"
                       r"noOperMem|sfpAbsent|linkFlapE|xcvrAbsen|up|down)\b", rest, re.IGNORECASE)
        status = _map_status(sm.group(1)) if sm else "unknown"
        # 상태 뒤 토큰: Vlan Duplex Speed Type
        tail = rest[sm.end():].split() if sm else rest.split()
        vlan = 1
        if tail:
            v = utils.normalize_vlan(tail[0])       # 'trunk'/'routed'는 None → 1 유지
            vlan = v if v else 1
        spd = ""
        if len(tail) >= 3:
            spd = tail[2]
        elif len(tail) >= 2:
            spd = tail[1]
        speed = spd if spd and spd not in ("--", "auto") else (spd or "unknown")
        err = errors.get(port_name, {})
        ports.append({
            "switch_id": switch_id, "name": port_name, "status": status,
            "vlan": vlan, "speed": speed or "unknown",
            "description": descriptions.get(port_name, ""),
            "crc_errors": err.get("crc", 0),
            "in_errors": err.get("in_errors", 0),
            "out_errors": err.get("out_errors", 0),
        })
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_brief(status_output, descriptions, switch_id, errors=None):
    """show interface brief → up/down 폴백(status 출력이 없을 때). VLAN/speed 일부."""
    errors = errors or {}
    ports = []
    if len(status_output) > 1_000_000:
        return []
    for i, line in enumerate(status_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        m = re.match(r"^" + _IFACE + r"\s+.*?\b(up|down)\b", line, re.IGNORECASE)
        if m:
            port_name, status_word = m.groups()
            port_name = utils.normalize_port(port_name)
            if not port_name:
                continue
            # brief: Eth1/1  VLAN  Type Mode Status Reason Speed Port
            mv = re.match(r"^" + _IFACE + r"\s+(\S+)\s", line)
            vlan = 1
            if mv:
                v = utils.normalize_vlan(mv.group(2))   # group1=iface, group2=vlan
                vlan = v if v else 1
            ms = re.search(r"\b(\d+G|\d+g|auto|10M|100M|1000M)\b", line)
            err = errors.get(port_name, {})
            ports.append({
                "switch_id": switch_id, "name": port_name,
                "status": utils.parse_interface_status(status_word),
                "vlan": vlan, "speed": ms.group(1) if ms else "unknown",
                "description": descriptions.get(port_name, ""),
                "crc_errors": err.get("crc", 0),
                "in_errors": err.get("in_errors", 0),
                "out_errors": err.get("out_errors", 0),
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
