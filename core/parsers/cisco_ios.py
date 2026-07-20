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
    "neighbors": "show cdp neighbors detail",
    "lldp": "show lldp neighbors detail",
    # 시리얼/모델: Catalyst 일부(9300L 등)는 show version에 'System Serial Number'
    # 줄이 없고 하단 스위치 표(Serial No. 열)에만 있음 → show inventory의 SN이 가장 확실.
    "inventory": "show inventory",
    # 라우터/음성게이트웨이(VG3X0 등)는 'show interface status'(스위치 전용) 미지원.
    # status가 비면 이 출력으로 포트/상태를 도출한다.
    "port_brief": "show ip interface brief",
}

# 'show interface status' 미지원(라우터/VG) 판별 — IOS의 무효 명령 응답 패턴
_INVALID_CMD = re.compile(r"%\s*(invalid input|incomplete command|ambiguous)", re.I)

# MAC: dot(0050.56a1.b2c3) / colon / hyphen 형식 모두 허용
_MAC = r"[0-9a-fA-F][0-9a-fA-F:.\-]{10,18}[0-9a-fA-F]"
# show interface status 상태 키워드 → 표준 상태 매핑
# (FIX: 부분 정규식 search는 Name에 들어간 'up/down' 등을 오인식하므로
#  공백 분리 토큰의 '정확 일치'로만 상태를 판별한다.)
_STATUS_MAP = {
    "connected": "up", "up": "up",
    "notconnect": "notconnect", "notpresent": "notconnect",
    "sfpabsent": "notconnect", "xcvrabsen": "notconnect",
    "disabled": "disabled",
    "err-disabled": "err-disabled", "errdisable": "err-disabled",
    "errdisabled": "err-disabled",  # Arista 철자
    "inactive": "inactive", "suspended": "suspended", "monitoring": "up",
    "down": "down",
}
_STATUS_SET = frozenset(_STATUS_MAP.keys())
# show interfaces status의 Status 뒤 Vlan 컬럼 값(숫자 VLAN, trunk, routed, unassigned '--')
_VLAN_LIKE = re.compile(r"^(\d+|trunk|routed|monitoring|unassigned|--)$", re.IGNORECASE)


_ABBR = [
    ("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"), ("TenGigE", "Te"),
    ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"), ("FortyGigE", "Fo"),
    ("Port-channel", "Po"), ("Ethernet", "Et"),
]


def _abbr(port):
    """인터페이스 전체이름→표준 약어 통일(GigabitEthernet1/0/1 ↔ Gi1/0/1)."""
    if not port:
        return port
    for full, ab in _ABBR:
        if port.lower().startswith(full.lower()):
            return ab + port[len(full):]
    return port


def parse_interface_errors(output):
    """show interfaces(전체 상세) → {port: {in_errors, crc, out_errors}}.

    Cisco/Arista 공통: 'N input errors, M CRC' / 'K output errors' 라인.
    """
    result = {}
    cur = None
    if not output or len(output) > 5_000_000:
        return result
    for line in output.splitlines():
        m = re.match(r"^(\S+) is .*line protocol", line)
        if m:
            cur = _abbr(utils.normalize_port(m.group(1)))
            if cur:
                result[cur] = {"in_errors": 0, "crc": 0, "out_errors": 0}
            continue
        if not cur or cur not in result:
            continue
        mi = re.search(r"(\d+)\s+input errors(?:,\s*(\d+)\s+CRC)?", line)
        if mi:
            result[cur]["in_errors"] = int(mi.group(1))
            if mi.group(2):
                result[cur]["crc"] = int(mi.group(2))
        mc = re.search(r"(\d+)\s+CRC", line)
        if mc and result[cur]["crc"] == 0:
            result[cur]["crc"] = int(mc.group(1))
        mo = re.search(r"(\d+)\s+output errors", line)
        if mo:
            result[cur]["out_errors"] = int(mo.group(1))
    return result


def parse(outputs, switch_id):
    utils.log_event("info", "parse_cisco_ios", switch_id=switch_id)
    descriptions = _parse_descriptions(outputs.get("description", ""))
    errors = parse_interface_errors(outputs.get("errors", ""))
    ports = _parse_ports(outputs.get("status", ""), descriptions, switch_id, errors)
    # 라우터/음성게이트웨이(VG3X0 등): 'show interface status' 미지원 → 포트 0.
    # 'show ip interface brief'로 폴백 파싱(L3 인터페이스 상태·IP 도출).
    if not ports:
        ports = _parse_ports_brief(outputs.get("port_brief", ""), descriptions, switch_id)
        if ports:
            utils.log_event("info", "cisco_ios_brief_fallback",
                            switch_id=switch_id, ports=len(ports))
    macs = _parse_macs(outputs.get("mac", ""), switch_id)
    arps = _parse_arps(outputs.get("arp", ""), switch_id)
    vlans = parse_vlans(outputs.get("vlan", ""), switch_id)
    from . import neighbors as _nbr
    nbrs = _nbr.parse_cdp_detail(outputs.get("neighbors", ""))
    if not nbrs:
        nbrs = _nbr.parse_lldp_detail(outputs.get("lldp", ""))
    return {"ports": ports, "macs": macs, "arps": arps, "vlans": vlans, "neighbors": nbrs}


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


def _parse_ports(status_output, descriptions, switch_id, errors=None):
    """show interface status → 포트 상태/VLAN/속도 (+ errors 병합).

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
        toks = line.split()
        if len(toks) < 2:
            continue
        port = utils.normalize_port(toks[0])
        if not port:
            continue
        # FIX: 상태는 '정확 일치 토큰'으로 판별하되, Name 컬럼에 'down'/'up'이
        # 독립 토큰으로 들어간 경우(예: "link down bkp")의 오인식을 막기 위해
        # 'status 바로 뒤 토큰이 Vlan류(숫자/trunk/routed)'라는 제약을 우선 적용한다.
        # (show interfaces status 컬럼: Port Name Status Vlan Duplex Speed Type)
        status_idx = None
        for idx in range(1, len(toks)):
            if toks[idx].lower() in _STATUS_SET:
                nxt = toks[idx + 1] if idx + 1 < len(toks) else ""
                if _VLAN_LIKE.match(nxt):
                    status_idx = idx
                    break
        if status_idx is None:
            # 폴백(비표준 출력): Vlan 제약 없이 첫 status 토큰
            for idx in range(1, len(toks)):
                if toks[idx].lower() in _STATUS_SET:
                    status_idx = idx
                    break
        if status_idx is None:
            continue
        status = _STATUS_MAP.get(toks[status_idx].lower(), "down")
        # 상태 이후 토큰: Vlan  Duplex  Speed  Type...
        rest = toks[status_idx + 1:]
        vlan = 1
        if rest and rest[0].isdigit():
            v = utils.normalize_vlan(rest[0])
            vlan = v if v else 1
        duplex = rest[1] if len(rest) > 1 else ""
        spd = rest[2] if len(rest) > 2 else ""
        ptype = " ".join(rest[3:]) if len(rest) > 3 else ""
        # 속도/듀플렉스/타입을 함께 표기(auto-duplex/auto-speed/10/100/1000BaseTX)
        speed = " · ".join([x for x in (spd, duplex, ptype) if x]) or "unknown"
        err = (errors or {}).get(_abbr(port), {})
        ports.append({
            "switch_id": switch_id,
            "name": port,
            "status": status,
            "vlan": vlan,
            "speed": speed,
            "duplex": duplex,
            "port_type": ptype,
            "description": descriptions.get(port, ""),
            "crc_errors": err.get("crc", 0),
            "in_errors": err.get("in_errors", 0),
            "out_errors": err.get("out_errors", 0),
        })
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_ports_brief(brief_output, descriptions, switch_id):
    """show ip interface brief → 포트 상태/IP (라우터·음성게이트웨이 폴백).

    형식: Interface  IP-Address  OK?  Method  Status  Protocol
      GigabitEthernet0/0  10.92.1.5   YES  NVRAM  up                    up
      FastEthernet0/0     unassigned  YES  NVRAM  administratively down down
    Status가 'administratively down'(두 단어)일 수 있어 Protocol(마지막 토큰) 기준으로
    역파싱한다. IP는 speed 컬럼 대신 표기(라우터는 속도 개념이 포트 상태보다 덜 중요).
    """
    ports = []
    if not brief_output or _INVALID_CMD.search(brief_output):
        return ports
    if len(brief_output) > 1_000_000:
        return ports
    for i, line in enumerate(brief_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        toks = line.split()
        if len(toks) < 5:
            continue
        if toks[0].lower() == "interface":       # 헤더
            continue
        if toks[2].upper() not in ("YES", "NO"):   # OK? 컬럼 확인(데이터 행)
            continue
        port = _abbr(utils.normalize_port(toks[0]))  # 약어 통일(Gi0/0 — CDP/MAC과 일치)
        if not port:
            continue
        ip = toks[1]
        protocol = toks[-1].lower()              # 마지막 토큰 = Protocol
        # Status는 Method 뒤 ~ Protocol 앞(여러 단어 가능: 'administratively down')
        status_words = toks[4:-1]
        status_raw = " ".join(status_words).lower()
        if "administratively down" in status_raw or "admin" in status_raw:
            status = "disabled"
        elif protocol == "up" or "up" in status_raw:
            status = "up"
        else:
            status = "down"
        ip_disp = ip if ip.lower() not in ("unassigned", "") else ""
        ports.append({
            "switch_id": switch_id,
            "name": port,
            "status": status,
            "vlan": 1,
            "speed": ("IP " + ip_disp) if ip_disp else "routed",
            "duplex": "",
            "port_type": "routed",
            "description": descriptions.get(port, ""),
            "crc_errors": 0,
            "in_errors": 0,
            "out_errors": 0,
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
