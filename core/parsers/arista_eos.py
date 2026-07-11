import re
import logging
from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "status": "show interfaces",
    "description": "show interfaces description",
    "mac": "show mac address-table dynamic",
    "arp": "show ip arp",
    "lldp": "show lldp neighbors detail"
}


def parse(outputs, switch_id):
    utils.log_event("info", "parse_arista_eos", switch_id=switch_id)

    ports = _parse_ports(outputs.get("status", ""), outputs.get("description", ""), switch_id)
    macs = _parse_macs(outputs.get("mac", ""), switch_id)
    arps = _parse_arps(outputs.get("arp", ""), switch_id)

    # CRC/입출력 오류 병합 (show interfaces 상세 = Cisco와 동일 형식, 파서 재사용)
    from . import cisco_ios
    errors = cisco_ios.parse_interface_errors(outputs.get("errors", "") or outputs.get("status", ""))
    for p in ports:
        e = errors.get(cisco_ios._abbr(p["name"]), {})
        p["crc_errors"] = e.get("crc", 0)
        p["in_errors"] = e.get("in_errors", 0)
        p["out_errors"] = e.get("out_errors", 0)

    from . import neighbors as _nbr
    nbrs = _nbr.parse_lldp_detail(outputs.get("lldp", ""))
    return {
        "ports": ports,
        "macs": macs,
        "arps": arps,
        "neighbors": nbrs
    }


# 상세 형식 헤더: "Ethernet1 is up, line protocol is up (connected)"
#   괄호 상태(connected/notconnect/errdisabled/disabled)가 세분화의 원천.
_DETAIL_HDR = re.compile(
    r"^(\S+) is ([A-Za-z][A-Za-z\s-]*?), line protocol is \w+"
    r"(?:\s*\(([\w-]+)\))?", re.IGNORECASE)
_DUP_RE = re.compile(r"\b(full|half|auto)-duplex\b", re.IGNORECASE)
_SPD_RE = re.compile(r"\b(\d+(?:\.\d+)?\s*[MG]b(?:it)?/s(?:ec)?)\b", re.IGNORECASE)


def _parse_ports_detail(status_output, descriptions, switch_id):
    """'show interfaces' 상세 형식 → 포트 상태 세분화 + 속도/듀플렉스.

    상태 우선순위: 괄호 상태(connected→up, notconnect, errdisabled, disabled)
    → 'administratively down'=disabled → 관리 상태 up/down.
    """
    from . import cisco_ios
    ports = []
    cur = None
    for line_idx, line in enumerate(status_output.split("\n")):
        if line_idx > 100000:
            break
        if len(line) > 500:
            continue
        m = _DETAIL_HDR.match(line)
        if m:
            name, admin_st, paren = m.groups()
            port = utils.normalize_port(name)
            if not port:
                cur = None
                continue
            admin_l = admin_st.lower()
            if paren and paren.lower() in cisco_ios._STATUS_SET:
                status = cisco_ios._STATUS_MAP[paren.lower()]
            elif "administratively down" in admin_l:
                status = "disabled"
            elif admin_l.startswith("up"):
                status = "up"
            else:
                status = "down"
            cur = {"switch_id": switch_id, "name": port, "status": status,
                   "vlan": 1, "speed": "unknown", "duplex": "", "port_type": "",
                   "description": descriptions.get(port, "")
                                  or descriptions.get(cisco_ios._abbr(port), "")}
            ports.append(cur)
        elif cur:
            dm = _DUP_RE.search(line)
            sm = _SPD_RE.search(line)
            if dm and not cur["duplex"]:
                cur["duplex"] = dm.group(1).lower()
            if sm and cur["speed"] == "unknown":
                cur["speed"] = sm.group(1).replace(" ", "")
    for p in ports:  # cisco와 동일 표기: "1Gb/s · full"
        spd = p["speed"] if p["speed"] != "unknown" else ""
        p["speed"] = " · ".join(x for x in (spd, p["duplex"]) if x) or "unknown"
    return utils.deduplicate_list(ports, lambda p: p["name"])


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
            desc = " ".join(parts[3:]) if len(parts) > 3 else ""
            descriptions[port_name] = desc.strip()[:256]

    # ① 상세 형식(show interfaces) — 괄호 상태로 세분화(connected/notconnect/
    #    errdisabled/disabled) + Full-duplex, 1Gb/s 줄에서 속도/듀플렉스
    if "line protocol is" in status_output:
        detail = _parse_ports_detail(status_output, descriptions, switch_id)
        if detail:
            return detail
    else:
        # ② 상태표 형식(show interfaces status) — cisco와 동일 컬럼(토큰 파서 재사용)
        from . import cisco_ios
        tbl = cisco_ios._parse_ports(status_output, descriptions, switch_id)
        if tbl:
            return tbl

    # ③ legacy 2컬럼(status/protocol) 형식 폴백
    for line_idx, line in enumerate(status_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        # Match interface with explicit status keywords
        match = re.match(r"^([A-Za-z0-9/:._-]+)\s+(up|down|notpresent|disabled)\s+(up|down|notpresent|disabled)$", line, re.IGNORECASE)
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

    # HIGH FIX (ReDoS prevention): Validate input size
    if len(mac_output) > 1_000_000:
        utils.log_event("warning", "parse_macs_input_too_large", switch_id=switch_id)
        return []

    for line_idx, line in enumerate(mac_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        # MAC은 콜론/점/대시/무구분 모두 허용(Arista 표준은 dot: 0011.2233.44aa).
        # 이전엔 콜론-페어만 매칭해 Arista MAC 테이블이 전량 유실됐다.
        match = re.match(
            r"^\s*(\d+)\s+([0-9a-fA-F][0-9a-fA-F.:\-]{10,18}[0-9a-fA-F])\s+(\w+)\s+([A-Za-z0-9/:._-]+)$",
            line, re.IGNORECASE)
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

    # HIGH FIX (ReDoS prevention): Validate input size
    if len(arp_output) > 1_000_000:
        utils.log_event("warning", "parse_arps_input_too_large", switch_id=switch_id)
        return []

    for line_idx, line in enumerate(arp_output.split("\n")):
        if line_idx > 10000:  # Prevent billion-line attacks
            break
        if len(line) > 500:  # Reject oversized lines
            continue
        # MAC 형식 무관(dot/colon/dash) — 콜론-페어만 매칭하던 ARP 유실 수정
        match = re.match(
            r"^\s*([\d.]+)\s+\S+\s+([0-9a-fA-F][0-9a-fA-F.:\-]{10,18}[0-9a-fA-F])\s+([A-Za-z0-9/:._-]+)$",
            line, re.IGNORECASE)
        if match:
            ip, mac_addr, interface = match.groups()

            if utils.validate_ip(ip):
                mac = utils.normalize_mac(mac_addr)  # normalize_mac handles all separator formats
                interface = utils.normalize_port(interface)

                if mac and interface:
                    arps.append({
                        "switch_id": switch_id,
                        "ip": ip,
                        "mac": mac,
                        "interface": interface
                    })

    return utils.deduplicate_list(arps, lambda a: a["ip"])
