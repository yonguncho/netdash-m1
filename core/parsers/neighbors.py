# -*- coding: utf-8 -*-
"""CDP/LLDP neighbor 파서 — 물리 연결(로컬포트↔원격장비/포트)을 직접 수집.

MAC 추론보다 정확: 이웃 장비의 이름/IP/포트를 프로토콜이 직접 알려준다.
반환 형식(공통): [{local_port, remote_name, remote_port, remote_ip, platform}]
"""
import re

from . import utils


def _norm(p):
    return utils.normalize_port(p) or (p or "").strip()


def parse_cdp_detail(output):
    """Cisco 'show cdp neighbors detail' 파싱(IOS/IOS-XE/NX-OS 공통 형식).

    블록 구분: 'Device ID:' ... 'Interface: <local>,  Port ID (outgoing port): <remote>'
    """
    neighbors = []
    if not output or len(output) > 5_000_000:
        return neighbors
    # 장비 블록을 'Device ID'로 분할
    blocks = re.split(r"(?:^|\n)-{3,}\s*\n|(?=Device ID:)", output)
    for blk in blocks:
        if "Device ID" not in blk and "Interface:" not in blk:
            continue
        dev = re.search(r"Device ID:\s*(\S+)", blk)
        ip = re.search(r"IP(?:v4)? address:\s*([\d.]+)", blk) or \
            re.search(r"IP address:\s*([\d.]+)", blk)
        plat = re.search(r"Platform:\s*([^,\n]+)", blk)
        local = re.search(r"Interface:\s*([^,\n]+?)\s*,", blk)
        remote = re.search(r"Port ID \(outgoing port\):\s*([^\n,]+)", blk)
        if not (dev and local):
            continue
        name = dev.group(1).split(".")[0]        # FQDN → 호스트명
        neighbors.append({
            "local_port": _norm(local.group(1)),
            "remote_name": name,
            "remote_port": _norm(remote.group(1)) if remote else "",
            "remote_ip": ip.group(1) if ip else "",
            "platform": plat.group(1).strip() if plat else "",
        })
    return _dedup(neighbors)


def parse_lldp_detail(output):
    """LLDP 'show lldp neighbors detail'(Arista/EXOS/일반) 파싱.

    벤더별 라벨 차이를 흡수: System Name / Port ID / Management Address / 로컬 인터페이스.
    """
    neighbors = []
    if not output or len(output) > 5_000_000:
        return neighbors
    # 로컬 인터페이스 헤더로 블록 분할
    #  Arista: "Interface Ethernet1 detected 1 LLDP neighbors:"
    #  EXOS:   "LLDP Port 1 detected 1 neighbor" / "Port: 1"
    parts = re.split(r"(?=Interface\s+\S+\s+detected|LLDP Port\s+\S+|^Local Port\s*:|\nPort\s+\d)", output)
    for blk in parts:
        lm = (re.search(r"Interface\s+(\S+)\s+detected", blk) or
              re.search(r"LLDP Port\s+(\S+)", blk) or
              re.search(r"Local Port\s*:\s*(\S+)", blk) or
              re.search(r"(?:^|\n)Port\s+(\d[\w/]*)", blk))
        if not lm:
            continue
        local = _norm(lm.group(1))
        name = re.search(r'System Name\s*[:=]?\s*"?([^"\n]+?)"?\s*$', blk, re.MULTILINE) or \
            re.search(r'SysName\s*[:=]\s*(\S+)', blk)
        rport = re.search(r'Port ID\s*[:=]?\s*(?:.*?)"?([\w/.:-]+)"?\s*$', blk, re.MULTILINE) or \
            re.search(r'Port ID\s*[:=]\s*(\S+)', blk)
        ip = re.search(r"Management Address(?:es)?\s*[:=]?\s*([\d.]+)", blk)
        plat = re.search(r"System Description\s*[:=]?\s*([^\n]+)", blk)
        if not name:
            continue
        neighbors.append({
            "local_port": local,
            "remote_name": name.group(1).strip().split(".")[0],
            "remote_port": _norm(rport.group(1)) if rport else "",
            "remote_ip": ip.group(1) if ip else "",
            "platform": (plat.group(1).strip()[:80]) if plat else "",
        })
    return _dedup(neighbors)


def _dedup(neighbors):
    seen, out = set(), []
    for n in neighbors:
        key = (n["local_port"].lower(), (n["remote_name"] or "").lower(), (n["remote_port"] or "").lower())
        if key in seen or not n["local_port"]:
            continue
        seen.add(key)
        out.append(n)
    return out
