# -*- coding: utf-8 -*-
"""CDP/LLDP neighbor 파서 — 물리 연결(로컬포트↔원격장비/포트)을 직접 수집.

MAC 추론보다 정확: 이웃 장비의 이름/IP/포트를 프로토콜이 직접 알려준다.
반환 형식(공통): [{local_port, remote_name, remote_port, remote_ip, platform}]
"""
import re

from . import utils


def _norm(p):
    return utils.normalize_port(p) or (p or "").strip()


def neighbor_source_status(cdp_out, lldp_out, n_cdp, n_lldp):
    """이웃 수집 결과를 진단 문자열로. (실제 링크 vs 비활성 vs 미지원 구분)

    반환: (source, note)
      source: 'cdp' | 'lldp' | 'disabled' | 'none'
      note  : 사람이 읽는 사유(비활성 등). 정상이면 "".
    """
    def _disabled(txt):
        t = (txt or "").lower()
        return ("not enabled" in t or "disabled globally" in t or
                "invalid command" in t or "% invalid" in t or
                ("feature" in t and "lldp" in t))
    if n_cdp:
        return "cdp", ""
    if n_lldp:
        return "lldp", ""
    cdp_off = _disabled(cdp_out)
    lldp_off = _disabled(lldp_out)
    if cdp_off or lldp_off:
        parts = []
        if cdp_off:
            parts.append("CDP 비활성")
        if lldp_off:
            parts.append("LLDP 비활성")
        return "disabled", " · ".join(parts) + " — MAC 추론 링크 사용(정확도↓). 장비에서 CDP/LLDP 활성화 권장"
    return "none", ""


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
    #  IOS:    "Local Intf: Gi1/0/1"
    #  NX-OS:  "Local Port id: Eth1/1"
    parts = re.split(
        r"(?=Interface\s+\S+\s+detected|LLDP Port\s+\S+|"
        r"^Local Port\s*:|Local Intf\s*:|Local Port id\s*:|\nPort\s+\d)",
        output, flags=re.IGNORECASE | re.MULTILINE)
    for blk in parts:
        lm = (re.search(r"Interface\s+(\S+)\s+detected", blk) or
              re.search(r"LLDP Port\s+(\S+)", blk) or
              re.search(r"Local Intf\s*:\s*(\S+)", blk, re.IGNORECASE) or
              re.search(r"Local Port id\s*:\s*(\S+)", blk, re.IGNORECASE) or
              re.search(r"Local Port\s*:\s*(\S+)", blk, re.IGNORECASE) or
              re.search(r"(?:^|\n)Port\s+(\d[\w/]*)", blk))
        if not lm:
            continue
        local = _norm(lm.group(1))
        # IOS/NX-OS는 소문자 'Port id:'/'System Name:'도 씀 → IGNORECASE
        name = re.search(r'System Name\s*[:=]?\s*"?([^"\n]+?)"?\s*$', blk, re.MULTILINE | re.IGNORECASE) or \
            re.search(r'SysName\s*[:=]\s*(\S+)', blk, re.IGNORECASE)
        # 줄 시작 앵커: NX-OS 'Local Port id:'(local)의 'Port id'를 remote로
        # 오인하지 않도록 — remote는 들여쓰기 후 'Port ID'로 시작하는 줄만.
        rport = re.search(r'^\s*Port ID\s*[:=]?\s*(?:.*?)"?([\w/.:-]+)"?\s*$', blk, re.MULTILINE | re.IGNORECASE) or \
            re.search(r'^\s*Port ID\s*[:=]\s*(\S+)', blk, re.MULTILINE | re.IGNORECASE)
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
