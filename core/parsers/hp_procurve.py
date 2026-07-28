# -*- coding: utf-8 -*-
"""HP ProCurve / ArubaOS-Switch(2530·2930·3810·5400 등) 파서.

수집 명령(config.yaml hp_procurve / aruba_osswitch):
  status      : show interfaces brief
  description : show name
  mac         : show mac-address
  arp         : show arp
  vlan        : show vlans
  lldp        : show lldp info remote-device
  logging     : show logging -r
  version     : show version

표기 특성
  - MAC 표기가 `001bc0-112233`(하이픈 1개, 6+6) 형태다 → normalize_mac이 그대로 처리.
  - 포트는 `1`, `A5`, `Trk1`(트렁크) 처럼 짧다. 숫자만 있는 포트도 유효하다.
  - 출력이 페이지 구분선(`----`)과 제목 블록을 포함하므로 헤더/구분선을 건너뛴다.
"""
import re

from . import utils

COMMANDS = {
    "status": "show interfaces brief",
    "description": "show name",
    "mac": "show mac-address",
    "arp": "show arp",
    "vlan": "show vlans",
    "lldp": "show lldp info remote-device",
    "logging": "show logging -r",
    "version": "show version",
}

_MAX_BYTES = 1_000_000
_MAX_LINES = 20000

# 1 / 24 / A5 / B12 / Trk1 / Trk10
_PORT = r"([A-Za-z]{0,3}\d{1,4}|Trk\d{1,3})"
_HP_MAC = r"([0-9a-f]{6}-[0-9a-f]{6}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})"


def parse(outputs, switch_id):
    utils.log_event("info", "parse_hp_procurve", switch_id=switch_id)
    descs = _parse_descriptions(outputs.get("description", ""))
    return {
        "ports": _parse_ports(outputs.get("status", ""), descs, switch_id),
        "macs": _parse_macs(outputs.get("mac", ""), switch_id),
        "arps": _parse_arps(outputs.get("arp", ""), switch_id),
        "vlans": _parse_vlans(outputs.get("vlan", "")),
    }


def _too_big(t):
    return len(t or "") > _MAX_BYTES


def _skip(line):
    """헤더·구분선·빈 줄인가."""
    s = (line or "").strip()
    if not s:
        return True
    if set(s) <= set("-=+ |"):
        return True
    return False


def _parse_descriptions(desc_output):
    """show name → {포트: 이름}.

      Port  Name
      ----- ------------------------
      1     uplink-to-core
      2     CCTV-front

    일부 펌웨어는 'Port Name : uplink' 형태로도 낸다(둘 다 처리).
    """
    out = {}
    if _too_big(desc_output):
        return out
    for i, line in enumerate((desc_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*" + _PORT + r"\s*:\s*(.*)$", line)
        if not m:
            m = re.match(r"^\s*" + _PORT + r"\s{2,}(.*)$", line)
        if not m:
            continue
        port, name = m.group(1), (m.group(2) or "").strip()
        if port.lower() in ("port", "name"):
            continue
        out[port] = name[:256]
    return out


def _parse_ports(status_output, descriptions, switch_id):
    """show interfaces brief → 포트 목록.

      Port  Type       | Intrusion Alert  Enabled  Status  Mode      MDI  Flow  Bcast
      1     100/1000T  | No               Yes      Up      1000FDx   MDIX off   0
      2     100/1000T  | No               Yes      Down    1000FDx   Auto off   0

    Enabled=No 는 관리자 차단(disabled)으로 본다.
    """
    ports = []
    if _too_big(status_output):
        utils.log_event("warning", "parse_ports_input_too_large", switch_id=switch_id)
        return ports
    for i, line in enumerate((status_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*" + _PORT + r"\s+(\S+)\s*\|?\s+(.*)$", line)
        if not m:
            continue
        port, rest = m.group(1), m.group(3)
        if port.lower() in ("port", "name", "status"):
            continue
        toks = rest.split()
        # 컬럼 순서: | Alert  Enabled  Status  Mode ...
        # Alert도 Yes/No라 '첫 Yes/No'를 Enabled로 보면 침입경보 값을 읽는다
        # (Alert=No인 정상 포트가 전부 '관리자 차단'으로 표시됐다).
        # Status(Up/Down) **바로 앞** 토큰이 Enabled다.
        st_idx = next((k for k, t in enumerate(toks) if t.lower() in ("up", "down")), None)
        if st_idx is None:
            continue                       # 포트 행이 아님(제목 블록 등)
        st_tok = toks[st_idx]
        enabled = toks[st_idx - 1] if st_idx > 0 and toks[st_idx - 1].lower() in ("yes", "no") else None
        if enabled and enabled.lower() == "no":
            status = "disabled"
        elif st_tok and st_tok.lower() == "up":
            status = "up"
        else:
            status = "down"
        speed = next((t for t in toks if re.match(r"^\d+[FH]Dx$", t, re.I)), "")
        ports.append({"switch_id": switch_id, "name": port, "status": status,
                      "vlan": 1, "speed": speed or "unknown",
                      "duplex": "full" if speed.lower().endswith("fdx") else "",
                      "port_type": m.group(2),
                      "description": descriptions.get(port, "")})
    return utils.deduplicate_list(ports, lambda p: p["name"])


def _parse_macs(mac_output, switch_id):
    """show mac-address → MAC/포트/VLAN.

      MAC Address    Port   VLAN
      -------------- ------ ----
      001bc0-112233  1      10
      005056-aabbcc  Trk1   20

    VLAN 컬럼이 없는 펌웨어도 있어(포트만) vlan은 선택으로 둔다.
    """
    macs = []
    if _too_big(mac_output):
        return macs
    for i, line in enumerate((mac_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*" + _HP_MAC + r"\s+" + _PORT + r"(?:\s+(\d{1,4}))?\s*$", line, re.I)
        if not m:
            continue
        mac = utils.normalize_mac(m.group(1))
        if not mac:
            continue
        macs.append({"switch_id": switch_id, "vlan": utils.normalize_vlan(m.group(3)),
                     "mac": mac, "port": m.group(2), "type": "dynamic"})
    return utils.deduplicate_list(macs, lambda m: (m["mac"], m["port"]))


def _parse_arps(arp_output, switch_id):
    """show arp → IP/MAC/포트.

      IP Address    MAC Address      Type     Port
      ------------- ---------------- -------- ----
      10.1.1.1      001bc0-112233    dynamic  1
    """
    arps = []
    if _too_big(arp_output):
        return arps
    for i, line in enumerate((arp_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+" + _HP_MAC + r"\s*(.*)$", line, re.I)
        if not m:
            continue
        ip, mac = m.group(1), utils.normalize_mac(m.group(2))
        if not mac or not utils.validate_ip(ip):
            continue
        rest = (m.group(3) or "").split()
        iface = rest[-1] if rest else ""
        arps.append({"switch_id": switch_id, "ip": ip, "mac": mac, "interface": iface})
    return utils.deduplicate_list(arps, lambda a: (a["ip"], a["mac"]))


def _parse_vlans(vlan_output):
    """show vlans → [{vlan, name, status}].

      VLAN ID  Name          Status      Voice  Jumbo
      -------- ------------- ----------- ------ -----
      10       OFFICE        Port-based  No     No
    """
    out = []
    if _too_big(vlan_output):
        return out
    for i, line in enumerate((vlan_output or "").split("\n")):
        if i > _MAX_LINES or len(line) > 500 or _skip(line):
            continue
        m = re.match(r"^\s*(\d{1,4})\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        vid = utils.normalize_vlan(m.group(1))
        if not vid:
            continue
        out.append({"vlan": vid, "name": m.group(2)[:64], "status": "active"})
    return utils.deduplicate_list(out, lambda v: v["vlan"])
