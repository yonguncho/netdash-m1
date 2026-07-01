# -*- coding: utf-8 -*-
"""Radware/Nortel Alteon Application Switch (메뉴형 CLI) 파서.

Alteon은 '/info/...' 메뉴 명령을 쓴다(netmiko 미지원 → 전용 paramiko 수집).
표준 Alteon OS 출력 형식 기반. 컬럼 폭이 버전마다 다를 수 있어 유연 매칭.

수집 명령:
  version : /info/sys/general
  mac     : /info/l2/fdb/dump        (MAC  VLAN  Port  Trunk  State)
  arp     : /info/l3/arp/dump        (Destination  Flags  MAC  VLAN  Age  Port)
  status  : /info/link               (Port  Speed  Duplex  FlowCtl  Link)
"""
import re
import logging

from . import utils

logger = logging.getLogger(__name__)

COMMANDS = {
    "version": "/info/sys/general",
    "mac": "/info/l2/fdb/dump",
    "arp": "/info/l3/arp/dump",
    "status": "/info/link",
}


def parse(outputs, switch_id):
    utils.log_event("info", "parse_alteon", switch_id=switch_id)
    return {
        "ports": _parse_ports(outputs.get("status", ""), switch_id),
        "macs": _parse_macs(outputs.get("mac", ""), switch_id),
        "arps": _parse_arps(outputs.get("arp", ""), switch_id),
    }


def _parse_macs(mac_output, switch_id):
    """/info/l2/fdb/dump → MAC/VLAN/Port.

    형식: MAC address  VLAN  Port  Trunk  State
      00:04:96:12:34:56    1     5           FWD
    """
    macs = []
    if len(mac_output) > 1_000_000:
        return []
    for i, line in enumerate(mac_output.split("\n")):
        if i > 20000 or len(line) > 500:
            continue
        # MAC(맨앞) + VLAN(숫자) + Port(숫자)
        m = re.match(r"^\s*([0-9a-f:]{17})\s+(\d+)\s+(\d+)\b", line, re.IGNORECASE)
        if not m:
            continue
        mac = utils.normalize_mac(m.group(1))
        vlan = utils.normalize_vlan(m.group(2))
        port = utils.normalize_port(m.group(3))
        if mac and vlan and port:
            macs.append({"switch_id": switch_id, "vlan": vlan, "mac": mac,
                         "port": port, "type": "dynamic"})
    return utils.deduplicate_list(macs, lambda m: (m["vlan"], m["mac"], m["port"]))


def _parse_arps(arp_output, switch_id):
    """/info/l3/arp/dump → IP/MAC/Port.

    형식: Destination  Flags  MAC address  VLAN  Age  Port
      10.0.0.1              00:04:96:12:34:56    1  10    5
    IP·MAC은 어디서든, Port는 맨 끝 숫자.
    """
    arps = []
    if len(arp_output) > 1_000_000:
        return []
    for i, line in enumerate(arp_output.split("\n")):
        if i > 20000 or len(line) > 500:
            continue
        m = re.search(
            r"((?:\d{1,3}\.){3}\d{1,3})\s+.*?([0-9a-f:]{17}).*?(\d+)\s*$",
            line, re.IGNORECASE)
        if not m:
            continue
        ip, mac_addr, port = m.groups()
        if not utils.validate_ip(ip):
            continue
        mac = utils.normalize_mac(mac_addr)
        interface = utils.normalize_port(port)
        if mac and interface:
            arps.append({"switch_id": switch_id, "ip": ip, "mac": mac,
                         "interface": interface})
    return utils.deduplicate_list(arps, lambda a: a["ip"])


def _parse_ports(status_output, switch_id):
    """/info/link → 포트/링크 상태.

    형식: Port  Speed  Duplex  Flow Ctl  Link
       1   1000   full    yes/yes   up
       2    any    any    yes/yes   down
    """
    ports = []
    if len(status_output) > 1_000_000:
        return []
    for i, line in enumerate(status_output.split("\n")):
        if i > 20000 or len(line) > 500:
            continue
        tokens = line.split()
        if not tokens or not re.match(r"^\d+$", tokens[0]):
            continue
        status = None
        for tok in tokens[1:]:
            tl = tok.lower()
            if tl == "up":
                status = "up"; break
            if tl in ("down", "disabled"):
                status = "down" if tl == "down" else "disabled"; break
        if status is None:
            continue
        # 속도/듀플렉스 best-effort
        spd = ""
        for tok in tokens[1:]:
            if re.match(r"^\d{2,6}$", tok):
                spd = tok; break
        dup = ""
        for tok in tokens[1:]:
            if tok.lower() in ("full", "half"):
                dup = tok.upper(); break
        speed = " · ".join([x for x in (spd, dup) if x]) or "unknown"
        port = utils.normalize_port(tokens[0])
        if port:
            ports.append({"switch_id": switch_id, "name": port, "status": status,
                          "vlan": 1, "speed": speed, "description": ""})
    return utils.deduplicate_list(ports, lambda p: p["name"])
