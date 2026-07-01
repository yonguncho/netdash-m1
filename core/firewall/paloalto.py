# -*- coding: utf-8 -*-
"""M10: Palo Alto Networks PAN-OS 방화벽 클라이언트 (SSH CLI).

프로덕션본 paloalto_panos 파서 이식. netmiko로 SSH 접속 후:
  show arp all        → ARP (ip, mac, interface)
  show interface all  → 인터페이스 (name)
"""
import logging
import re

logger = logging.getLogger(__name__)

# show arp all: address hw_address port status ttl
_RE_ARP_LINE = re.compile(
    r"^((?:\d{1,3}\.){3}\d{1,3})\s+([0-9A-Fa-f:]{17})\s+(\S+)\s+(\S+)\s+(\d+)\s*$",
    re.IGNORECASE,
)
# show interface all: name id speed/duplex/state mac
_RE_PORT_HEADER = re.compile(r"^name\s+id\s+speed/duplex/state", re.IGNORECASE)
_RE_PORT_SEP = re.compile(r"^[-\s]+$")
_RE_PORT_LINE = re.compile(
    r"^(\S+)\s+(\d+)\s+(\S+)/(\S+)/(\S+)\s+([0-9A-Fa-f:]{17})\s*$", re.IGNORECASE)
# show interface logical: name id vsys zone forwarding tag address(=IP/prefix or N/A)
_RE_LOGICAL_HEADER = re.compile(r"^name\s+id\s+vsys\s+zone", re.IGNORECASE)
_RE_LOGICAL_LINE = re.compile(
    r"^(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s*$")


def parse_arp(output):
    """show arp all 출력 → [{"ip","mac","interface"}] (ip 기준 dedup)."""
    entries, seen = [], set()
    for line in (output or "").split("\n")[:20000]:
        s = line.strip()
        if not s or len(s) > 500:
            continue
        m = _RE_ARP_LINE.match(s)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2).upper()
        if mac == "00:00:00:00:00:00" or ip in seen:
            continue
        seen.add(ip)
        entries.append({"ip": ip, "mac": mac, "interface": m.group(3)})
    return entries


def parse_interfaces(output):
    """show interface all 출력 → [{"name","ip","mask","vdom_zone"}] (name 기준 dedup).

    PAN-OS 'show interface all'에는 IP가 없으므로 name 위주(ip는 빈 값).
    """
    ifaces, seen, in_table = [], set(), False
    for line in (output or "").split("\n")[:20000]:
        s = line.strip()
        if not s or len(s) > 500:
            continue
        if _RE_PORT_HEADER.match(s):
            in_table = True
            continue
        if not in_table or _RE_PORT_SEP.match(s):
            continue
        m = _RE_PORT_LINE.match(s)
        if not m:
            continue
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        ifaces.append({"name": name, "ip": "", "mask": "", "vdom_zone": ""})
    return ifaces


def parse_logical_interfaces(output):
    """show interface logical → [{"name","ip","mask","vdom_zone"}].

    논리 인터페이스 테이블의 address 컬럼에서 실제 IP/prefix를 추출한다.
    address가 'N/A'면 IP 없음.
    """
    ifaces, seen, in_table = [], set(), False
    for line in (output or "").split("\n")[:20000]:
        s = line.strip()
        if not s or len(s) > 500:
            continue
        if _RE_LOGICAL_HEADER.match(s):
            in_table = True
            continue
        if not in_table or _RE_PORT_SEP.match(s):
            continue
        m = _RE_LOGICAL_LINE.match(s)
        if not m:
            continue
        name, _id, _vsys, zone, _fwd, _tag, addr = m.groups()
        if name in seen:
            continue
        ip, mask = "", ""
        if addr and addr.upper() != "N/A":
            if "/" in addr:
                ip, mask = addr.split("/", 1)
            else:
                ip = addr
        seen.add(name)
        ifaces.append({"name": name, "ip": ip, "mask": mask, "vdom_zone": zone})
    return ifaces


def collect(host, username, password, port=22, timeout=30, source_ip=None):
    """netmiko SSH로 PAN-OS 방화벽 인터페이스/ARP 수집 (source_ip로 출발지 바인딩).

    Returns: {"interfaces": [...], "arp": [...]}
    """
    from netmiko import ConnectHandler
    device = {
        "device_type": "paloalto_panos",
        "ip": host, "username": username, "password": password,
        "port": port, "conn_timeout": timeout, "fast_cli": False,
    }
    if source_ip:
        from .. import netbind
        device["sock"] = netbind.bind_socket(host, port, source_ip, timeout)
    with ConnectHandler(**device) as conn:
        arp_out = conn.send_command("show arp all")
        if_out = conn.send_command("show interface all")
        logical_out = conn.send_command("show interface logical")
    # 논리 인터페이스(IP 보유)를 우선 사용, 없으면 하드웨어 인터페이스(IP 없음)
    logical = parse_logical_interfaces(logical_out)
    interfaces = logical if logical else parse_interfaces(if_out)
    result = {"interfaces": interfaces, "arp": parse_arp(arp_out)}
    logger.info("paloalto host=%s interfaces=%d arp=%d",
                host, len(result["interfaces"]), len(result["arp"]))
    return result
