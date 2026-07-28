# -*- coding: utf-8 -*-
"""ArubaOS-CX(6100·6300·8320·8360 등) 파서.

수집 명령(config.yaml aruba_os):
  status      : show interface brief
  mac         : show mac-address-table
  arp         : show arp
  vlan        : show vlan
  lldp        : show lldp neighbor-info
  logging     : show logging -n 100
  version     : show version

표기 특성
  - 포트는 `1/1/1`(멤버/슬롯/포트) 또는 `lag1`(집합) 형태다.
  - CLI가 Cisco와 비슷해 보이지만 컬럼 구성이 달라 별도 파서가 필요하다.
  - `show interface brief` 에 설명 컬럼이 없어 포트 설명은 상태 출력에서 얻지 못한다
    (필요하면 `show interface` 상세를 추가 수집해야 한다 — 현재는 미수집).
"""
import re

from . import utils

COMMANDS = {
    "status": "show interface brief",
    "mac": "show mac-address-table",
    "arp": "show arp",
    "vlan": "show vlan",
    "lldp": "show lldp neighbor-info",
    "logging": "show logging -n 100",
    "version": "show version",
}

_MAX_BYTES = 1_000_000
_MAX_LINES = 20000

# 1/1/1 / 1/1/49 / lag1 / vlan10
_PORT = r"(\d+/\d+/\d+|lag\d+|vlan\d+)"


def parse(outputs, switch_id):
    utils.log_event("info", "parse_aruba_cx", switch_id=switch_id)
    return {
        "ports": _parse_ports(outputs.get("status", ""), switch_id),
        "macs": _parse_macs(outputs.get("mac", ""), switch_id),
        "arps": _parse_arps(outputs.get("arp", ""), switch_id),
        "vlans": _parse_vlans(outputs.get("vlan", "")),
    }


def _too_big(t):
    return len(t or "") > _MAX_BYTES


def _skip(line):
    s = (line or "").strip()
    return (not s) or set(s) <= set("-=+ |")


def _parse_ports(status_output, switch_id):
    """show interface brief → 포트 목록.

      Port   Native  Mode    Type   Enabled Status  Reason                Speed
             VLAN                                                         (Mb/s)
      1/1/1  10      access  1GbT   yes     up      --                    1000
      1/1/2  1       access  1GbT   no      down    Administratively down --
    """
    ports = []
    if _too_big(status_output):
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return ports
    for i, line in enumerate((status_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*" + _PORT + r"\s+(\d{1,4})?\s*(\S+)?\s+(\S+)?\s+(yes|no)\s+(up|down)\b(.*)$",
                     line, re.I)
        if not m:
            continue
        port = m.group(1)
        vlan = utils.normalize_vlan(m.group(2)) or 1
        enabled = (m.group(5) or "").lower()
        link = (m.group(6) or "").lower()
        rest = m.group(7) or ""
        if enabled == "no":
            status = "disabled"
        elif link == "up":
            status = "up"
        else:
            status = "down"
        sm = re.search(r"(\d{2,6})\s*$", rest.strip())
        ports.append({"switch_id": switch_id, "name": port, "status": status,
                      "vlan": vlan, "speed": sm.group(1) if sm else "unknown",
                      "duplex": "", "port_type": (m.group(4) or ""),
                      "description": ""})
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_macs(mac_output, switch_id):
    """show mac-address-table → MAC/VLAN/포트.

      MAC Address         VLAN   Type      Port
      ----------------------------------------------
      00:1b:c0:11:22:33   10     dynamic   1/1/1
      00:50:56:aa:bb:cc   20     dynamic   lag1
    """
    macs = []
    if _too_big(mac_output):
        return macs
    for i, line in enumerate((mac_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+(\d{1,4})\s+(\S+)\s+" + _PORT,
                     line, re.I)
        if not m:
            continue
        mac = utils.normalize_mac(m.group(1))
        if not mac:
            continue
        macs.append({"switch_id": switch_id, "vlan": utils.normalize_vlan(m.group(2)),
                     "mac": mac, "port": m.group(4),
                     "type": (m.group(3) or "dynamic").lower()})
    return utils.deduplicate_list(macs, lambda m: (m["mac"], m["port"]))


def _parse_arps(arp_output, switch_id):
    """show arp → IP/MAC/포트.

      IPv4 Address   MAC                Port     Physical Port   State
      ----------------------------------------------------------------
      10.1.1.1       00:1b:c0:11:22:33  vlan10   1/1/1           reachable

    Physical Port(실제 물리 포트)가 있으면 그것을 쓴다 — 설비 대조 정확도가 높다.
    """
    arps = []
    if _too_big(arp_output):
        return arps
    for i, line in enumerate((arp_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s*(.*)$",
                     line, re.I)
        if not m:
            continue
        ip, mac = m.group(1), utils.normalize_mac(m.group(2))
        if not mac or not utils.validate_ip(ip):
            continue
        rest = m.group(3) or ""
        phys = re.findall(r"\d+/\d+/\d+|lag\d+", rest)
        iface = phys[0] if phys else (rest.split()[0] if rest.split() else "")
        arps.append({"switch_id": switch_id, "ip": ip, "mac": mac, "interface": iface})
    return utils.deduplicate_list(arps, lambda a: (a["ip"], a["mac"]))


def _parse_vlans(vlan_output):
    """show vlan → [{vlan, name, status}].

      VLAN  Name       Status   Reason        Type     Interfaces
      ----------------------------------------------------------
      10    OFFICE     up       ok            static   1/1/1,1/1/2
    """
    out = []
    if _too_big(vlan_output):
        return out
    for i, line in enumerate((vlan_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*(\d{1,4})\s+(\S+)\s+(\S+)", line)
        if not m:
            continue
        vid = utils.normalize_vlan(m.group(1))
        if not vid:
            continue
        st = (m.group(3) or "").lower()
        out.append({"vlan": vid, "name": m.group(2)[:64],
                    "status": "active" if st in ("up", "active") else "suspended"})
    return utils.deduplicate_list(out, lambda v: v["vlan"])
