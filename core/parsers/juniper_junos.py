# -*- coding: utf-8 -*-
"""Juniper JunOS(EX/QFX 시리즈) 파서.

수집 명령(config.yaml juniper_junos):
  status      : show interfaces terse        (Interface Admin Link Proto Local Remote)
  description : show interfaces descriptions (Interface Admin Link Description)
  mac         : show ethernet-switching table
  arp         : show arp no-resolve
  vlan        : show vlans
  lldp        : show lldp neighbors
  logging     : show log messages | last 100
  version     : show version

JunOS 표기 특성
  - 포트는 `ge-0/0/1`(물리) / `ge-0/0/1.0`(논리 유닛) / `ae0`(집합) 형태다.
    MAC 테이블은 논리 유닛(.0)으로 나오므로 **물리 이름으로 정규화**해 다른
    테이블(포트 상태·설명)과 키가 맞도록 한다. 이 정규화가 없으면 설비 현황의
    '연결 포트 설명'이 Juniper에서만 항상 비게 된다(Arista에서 겪은 것과 동일).
  - MAC 테이블은 구형(비ELS)과 ELS 두 형식이 섞여 있어 둘 다 처리한다.
"""
import re

from . import utils

COMMANDS = {
    "status": "show interfaces terse",
    "description": "show interfaces descriptions",
    "mac": "show ethernet-switching table",
    "arp": "show arp no-resolve",
    "vlan": "show vlans",
    "lldp": "show lldp neighbors",
    "logging": "show log messages | last 100",
    "version": "show version",
}

_MAX_BYTES = 1_000_000
_MAX_LINES = 20000

# ge-0/0/1 / xe-1/0/47 / et-0/0/2 / ae0 / irb.10 / vlan.20 / me0 / fxp0
_IFACE = r"([a-z]{2,4}-?\d+(?:/\d+){0,3}(?:\.\d+)?|ae\d+(?:\.\d+)?|irb\.\d+|vlan\.\d+|me\d+|fxp\d+)"


def parse(outputs, switch_id):
    utils.log_event("info", "parse_juniper_junos", switch_id=switch_id)
    descs = _parse_descriptions(outputs.get("description", ""))
    return {
        "ports": _parse_ports(outputs.get("status", ""), descs, switch_id),
        "macs": _parse_macs(outputs.get("mac", ""), switch_id),
        "arps": _parse_arps(outputs.get("arp", ""), switch_id),
        "vlans": _parse_vlans(outputs.get("vlan", "")),
    }


def phy_port(name):
    """논리 유닛(.0)·공백 제거 → 물리 포트 이름.

    'ge-0/0/1.0' → 'ge-0/0/1',  'ae0.0' → 'ae0',  'irb.10' → 'irb.10'(그대로).
    irb/vlan은 SVI라 유닛 번호가 식별자의 일부이므로 자르지 않는다.
    """
    p = (name or "").strip()
    if not p:
        return None
    if p.startswith(("irb.", "vlan.")):
        return p
    return p.split(".")[0]


def _too_big(text):
    return len(text or "") > _MAX_BYTES


def _parse_descriptions(desc_output):
    """show interfaces descriptions → {물리포트: 설명}.

    형식: Interface  Admin  Link  Description
          ge-0/0/0   up     up    uplink-to-core
    Admin/Link 두 컬럼을 건너뛴다(설명에 상태 단어가 섞이지 않도록).
    """
    out = {}
    if _too_big(desc_output):
        return out
    for i, line in enumerate((desc_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500:
            continue
        m = re.match(r"^\s*" + _IFACE + r"\s+(up|down)\s+(up|down)\s*(.*)$", line, re.I)
        if not m:
            continue
        port = phy_port(m.group(1))
        if not port:
            continue
        out[port] = (m.group(4) or "").strip()[:256]
    return out


def _parse_ports(status_output, descriptions, switch_id):
    """show interfaces terse → 포트 목록.

    형식: Interface     Admin Link Proto    Local              Remote
          ge-0/0/0      up    up
          ge-0/0/0.0    up    up   eth-switch
    물리 인터페이스 행만 취한다(논리 유닛 행은 같은 포트의 중복).
    """
    ports = []
    if _too_big(status_output):
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return ports
    for i, line in enumerate((status_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500:
            continue
        m = re.match(r"^\s*" + _IFACE + r"\s+(up|down)\s+(up|down)\b", line, re.I)
        if not m:
            continue
        raw, admin, link = m.group(1), m.group(2).lower(), m.group(3).lower()
        if "." in raw and not raw.startswith(("irb.", "vlan.")):
            continue                       # 논리 유닛 행은 건너뜀
        port = phy_port(raw)
        if not port:
            continue
        if admin == "down":
            status = "disabled"            # administratively down
        elif link == "up":
            status = "up"
        else:
            status = "down"
        ports.append({"switch_id": switch_id, "name": port, "status": status,
                      "vlan": 1, "speed": "unknown", "duplex": "", "port_type": "",
                      "description": descriptions.get(port, "")})
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_macs(mac_output, switch_id):
    """show ethernet-switching table → MAC/VLAN/포트.

    두 형식을 모두 지원한다.
      (구형)  VLAN10   00:1b:c0:11:22:33  D  -  ge-0/0/1.0  0  0
      (ELS)   v100     00:00:5e:00:01:01  D     ge-0/0/2.0
    VLAN 컬럼이 **이름**(숫자가 아님)이라 vlan id를 못 얻는 경우가 많다.
    그때는 이름에서 숫자를 뽑고(VLAN10→10, v100→100), 그래도 없으면 None으로 둔다
    (설비 대조는 MAC↔포트만 쓰므로 vlan 없이도 동작한다).
    """
    macs = []
    if _too_big(mac_output):
        return macs
    for i, line in enumerate((mac_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500:
            continue
        m = re.search(r"^\s*(\S+)\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+(.*)$", line, re.I)
        if not m:
            continue
        vlan_name, mac_raw, rest = m.group(1), m.group(2), m.group(3)
        mac = utils.normalize_mac(mac_raw)
        if not mac:
            continue
        pm = re.search(_IFACE, rest, re.I)
        port = phy_port(pm.group(1)) if pm else None
        if not port:
            continue
        macs.append({"switch_id": switch_id, "vlan": _vlan_from_name(vlan_name),
                     "mac": mac, "port": port, "type": "dynamic"})
    return utils.deduplicate_list(macs, lambda m: (m["mac"], m["port"]))


def _vlan_from_name(name):
    """VLAN 컬럼이 이름일 때 숫자를 뽑는다(VLAN10→10, v100→100). 없으면 None."""
    v = utils.normalize_vlan(name)
    if v:
        return v
    m = re.search(r"(\d{1,4})", str(name or ""))
    return utils.normalize_vlan(m.group(1)) if m else None


def _parse_arps(arp_output, switch_id):
    """show arp no-resolve → IP/MAC/인터페이스.

    형식: MAC Address        Address        Name          Interface        Flags
          00:1b:c0:11:22:33  10.1.1.1       10.1.1.1      irb.10 [ge-0/0/1.0]  none
    (MAC이 **앞**에 온다 — Cisco 계열과 순서가 반대다)
    """
    arps = []
    if _too_big(arp_output):
        return arps
    for i, line in enumerate((arp_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500:
            continue
        m = re.match(r"^\s*((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(.*)$",
                     line, re.I)
        if not m:
            continue
        mac = utils.normalize_mac(m.group(1))
        ip = m.group(2)
        if not mac or not utils.validate_ip(ip):
            continue
        rest = m.group(3)
        # 'irb.10 [ge-0/0/1.0]' 이면 대괄호 안의 물리 포트를 쓴다
        bm = re.search(r"\[([^\]]+)\]", rest)
        src = bm.group(1) if bm else rest
        im = re.search(_IFACE, src, re.I)
        iface = phy_port(im.group(1)) if im else ""
        arps.append({"switch_id": switch_id, "ip": ip, "mac": mac,
                     "interface": iface or ""})
    return utils.deduplicate_list(arps, lambda a: (a["ip"], a["mac"]))


def _parse_vlans(vlan_output):
    """show vlans → [{vlan, name, status}].

    형식: Routing instance   VLAN name   Tag   Interfaces
          default-switch     VLAN10      10    ge-0/0/1.0*
    Tag(숫자) 컬럼이 있는 행만 취한다.
    """
    out = []
    if _too_big(vlan_output):
        return out
    for i, line in enumerate((vlan_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        # 뒤에서부터 'VLAN이름 + 숫자태그' 조합을 찾는다(라우팅 인스턴스 컬럼 유무 흡수)
        for j in range(len(parts) - 1):
            tag = utils.normalize_vlan(parts[j + 1])
            name = parts[j]
            if tag and not name.isdigit() and re.match(r"^[\w.-]+$", name):
                out.append({"vlan": tag, "name": name[:64], "status": "active"})
                break
    return utils.deduplicate_list(out, lambda v: v["vlan"])
