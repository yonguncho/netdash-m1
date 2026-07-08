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
    "detail": "show interface",               # 실제 up/down·속도·CRC·in/out 오류(주 소스)
    "status": "show interface status",        # VLAN(액세스/트렁크)
    "brief": "show interface brief",           # up/down 폴백
    "description": "show interface description",
    "mac": "show mac address-table dynamic",
    "arp": "show ip arp",
    "port_channel": "show port-channel summary",
    "inventory": "show inventory",   # 모델명(PID) — show version에 없는 표기 변형 대응
}

_IFACE = r"(Eth\S+|mgmt\d+|Po\d+|Vlan\d+|Lo\d+|Tunnel\d+)"


def _abbr_nxos(port):
    """NX-OS 포트명을 MAC/description 파서와 동일한 축약형으로 정규화.

    'Ethernet1/9'→'Eth1/9', 'port-channel1'→'Po1'. 파서 간 이름 불일치 방지.
    """
    p = utils.normalize_port(port) or ""
    p = re.sub(r"^Ethernet", "Eth", p, flags=re.IGNORECASE)
    p = re.sub(r"^port-channel", "Po", p, flags=re.IGNORECASE)
    return p


def parse(outputs, switch_id):
    utils.log_event("info", "parse_cisco_nxos", switch_id=switch_id)
    descriptions = _parse_descriptions(outputs.get("description", ""))
    vlan_map = _vlan_map_from_status(outputs.get("status", ""))
    # 주 소스: show interface(전체) — 실제 up/down·속도·CRC·in/out 오류.
    ports = _parse_full(outputs.get("detail", ""), descriptions, vlan_map, switch_id)
    if not ports:
        # 폴백1: show interface status(vlan/speed) → 폴백2: brief(up/down)
        errors = {}
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


def _vlan_map_from_status(status_output):
    """show interface status → {port: vlan(int)}. 트렁크/routed는 제외(숫자만)."""
    vmap = {}
    if not status_output or len(status_output) > 1_000_000:
        return vmap
    for i, line in enumerate(status_output.split("\n")):
        if i > 10000 or len(line) > 500:
            continue
        m = re.match(r"^" + _IFACE + r"\s+(.*)$", line)
        if not m:
            continue
        port = _abbr_nxos(m.group(1))
        if not port:
            continue
        # status 다음이 vlan — 컬럼 기반(Name의 단어 오인식 방지)
        toks = m.group(2).split()
        _SW = ("connected", "notconnect", "notconnec", "disabled", "err-disabled",
               "errdisabled", "noOperMem", "sfpAbsent", "xcvrAbsen", "inactive")
        for j in range(len(toks) - 1):
            tl = toks[j].lower()
            if any(tl.startswith(s.lower()) for s in _SW) and re.match(r"^(\d+|trunk|routed|--)$", toks[j + 1], re.IGNORECASE):
                v = utils.normalize_vlan(toks[j + 1])
                if v:
                    vmap[port] = v
                break
    return vmap


def _parse_full(detail_output, descriptions, vlan_map, switch_id):
    """show interface(전체) → 포트별 실제 상태·속도·CRC·in/out 오류.

    NX-OS 형식:
      Ethernet1/1 is down (SFP not inserted)
        ...
        full-duplex, 10 Gb/s, media type is 10G
        RX
          0 runts 0 giants 12 CRC 0 no buffer
          7 input error 0 short frame 0 overrun ...
        TX
          3 output error 0 collision ...
    """
    vlan_map = vlan_map or {}
    if not detail_output or len(detail_output) > 8_000_000:
        return []
    blocks = {}   # {port: {...}}
    cur = None
    for line in detail_output.split("\n"):
        if len(line) > 800:
            continue
        # 인터페이스 헤더: "Ethernet1/1 is up" / "... is down (reason)"
        mh = re.match(r"^(" + _IFACE.strip("()") + r")\s+is\s+(up|down)\b(.*)$", line, re.IGNORECASE)
        if mh:
            port = _abbr_nxos(mh.group(1))       # Ethernet1/9 → Eth1/9 (파서 간 일치)
            if not port:
                cur = None
                continue
            cur = port
            state = mh.group(2).lower()
            reason = (mh.group(3) or "").strip()
            # 관리 다운 여부는 아래 admin state에서, 여기선 회선 상태
            blocks[cur] = {"status": "up" if state == "up" else "down",
                           "reason": reason, "speed": "unknown",
                           "crc": 0, "in_errors": 0, "out_errors": 0}
            continue
        if not cur or cur not in blocks:
            continue
        b = blocks[cur]
        # 속도: "..., 10 Gb/s, ..." 또는 "auto-speed"
        ms = re.search(r"([\d.]+)\s*Gb/s", line)
        if ms:
            b["speed"] = ms.group(1) + "G"
        else:
            ms2 = re.search(r"([\d.]+)\s*Mb/s", line)
            if ms2 and b["speed"] == "unknown":
                b["speed"] = ms2.group(1) + "M"
        # CRC: "... N CRC ..."
        mc = re.search(r"(\d+)\s+CRC\b", line)
        if mc:
            b["crc"] = int(mc.group(1))
        # 입력 오류: "N input error" (단수/복수)
        mi = re.search(r"(\d+)\s+input error", line)
        if mi:
            b["in_errors"] = int(mi.group(1))
        # 출력 오류: "N output error"
        mo = re.search(r"(\d+)\s+output error", line)
        if mo:
            b["out_errors"] = int(mo.group(1))
    ports = []
    for port, b in blocks.items():
        ports.append({
            "switch_id": switch_id, "name": port, "status": b["status"],
            "vlan": vlan_map.get(port, 1),
            "speed": b["speed"],
            "description": descriptions.get(port, ""),
            "crc_errors": b["crc"], "in_errors": b["in_errors"], "out_errors": b["out_errors"],
        })
    return utils.deduplicate_list(ports, lambda p: p["name"])


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
        # 컬럼 기반: status는 vlan 토큰(숫자/trunk/routed/--) 바로 '앞' 토큰이다.
        # (설명/Name 컬럼에 든 'down' 등 단어를 상태로 오인식하던 문제 수정)
        toks = rest.split()
        _STATUS_WORDS = ("connected", "notconnect", "notconnec", "disabled",
                         "err-disabled", "errdisabled", "noOperMem", "sfpAbsent",
                         "linkFlapE", "xcvrAbsen", "xcvrAbsent", "inactive", "suspended")
        _VLAN_LIKE = re.compile(r"^(\d+|trunk|routed|--|monitor|access)$", re.IGNORECASE)
        status = "unknown"
        vlan = 1
        spd = ""
        for j in range(len(toks) - 1):
            tl = toks[j].lower()
            if any(tl.startswith(sw.lower()) for sw in _STATUS_WORDS) and _VLAN_LIKE.match(toks[j + 1]):
                status = _map_status(toks[j])
                v = utils.normalize_vlan(toks[j + 1])
                vlan = v if v else 1
                # 상태 뒤: Vlan Duplex Speed Type → speed는 +3
                if j + 3 < len(toks):
                    spd = toks[j + 3]
                break
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
