# -*- coding: utf-8 -*-
"""네트워크 토폴로지 추론 — 수집 데이터만으로 스위치 간 연결 관계를 그린다.

원리(추가 장비 접근 없음, 수집된 것 재활용):
  1) 각 스위치의 관리 IP ↔ MAC: 아무 스위치의 ARP 테이블에서 다른 스위치 IP의 MAC을 찾음
  2) 스위치 A의 MAC 테이블에서 스위치 B의 관리 MAC이 보이는 포트 = A에서 B로 가는 방향
  3) 양방향(A→B, B→A)이 모두 잡히면 상호 확인된 링크(신뢰도 높음)
  4) 루트(백본) = 링크가 가장 많은 노드 → BFS 계층 배치용 depth 부여
"""
import logging
import ipaddress
import re

from . import db

logger = logging.getLogger(__name__)


def _arp_ip_macs(db_path):
    """최신 스냅샷 ARP 전체에서 {ip: mac(lower)} — 스위치/방화벽 IP의 MAC 탐색용."""
    out = {}
    with db.get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT a.ip, a.mac FROM arp_entries a
                   WHERE a.snapshot_id IN (SELECT MAX(id) FROM snapshots GROUP BY switch_id)""")
            for r in cur.fetchall():
                if r["ip"] and r["mac"]:
                    out.setdefault(r["ip"], r["mac"].lower())
        except Exception:
            pass
    return out


def _switch_mgmt_macs(db_path, switches, ip_macs=None):
    """{switch_id: mgmt_mac(lower)} — 전체 ARP에서 각 스위치 IP의 MAC을 찾음."""
    ip_macs = ip_macs if ip_macs is not None else _arp_ip_macs(db_path)
    return {s["id"]: ip_macs[s["ip"]]
            for s in switches if s.get("ip") and s["ip"] in ip_macs}


def _iface_ips_from_config(cfg):
    """running-config/show ip interface 텍스트에서 인터페이스 host IP 목록 추출.

    "ip address 10.92.10.1 255.255.255.0"(secondary 포함) + "Internet address is 10.92.10.1/24".
    관리 IP 외 데이터/SVI 인터페이스 IP까지 모아 그 장비의 '모든 MAC'을 ARP로 역추적한다.
    """
    import re as _re
    ips = []
    for line in (cfg or "").splitlines():
        m = _re.search(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\.\d+\.\d+\.\d+", line)
        if m:
            ips.append(m.group(1))
            continue
        m2 = _re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+)/\d{1,2}", line)
        if m2:
            ips.append(m2.group(1))
    return ips


def _device_macs(db_path, switches, ip_macs=None):
    """{switch_id: set(mac)} — 각 장비가 소유한 '모든' MAC.

    관리 IP MAC(기존) + 저장된 running-config의 모든 인터페이스 IP를 ARP에서 역추적한 MAC.
    관리 MAC이 MAC 테이블에 없어도 데이터 인터페이스 MAC으로 물리 연결(포트)을 찾을 수 있다.
    (CDP/LLDP 비활성 장비의 링크/포트 커버리지 향상)
    """
    ip_macs = ip_macs if ip_macs is not None else _arp_ip_macs(db_path)
    out = {}
    for s in switches:
        if s.get("ip") and s["ip"] in ip_macs:
            out.setdefault(s["id"], set()).add(ip_macs[s["ip"]])
    try:
        with db.get_db(db_path) as conn:
            cur = conn.cursor()
            for s in switches:
                try:
                    cur.execute("SELECT content FROM config_backups WHERE switch_id=? "
                                "ORDER BY id DESC LIMIT 1", (s["id"],))
                    row = cur.fetchone()
                    if not row or not row["content"]:
                        continue
                    for ip in _iface_ips_from_config(row["content"]):
                        mac = ip_macs.get(ip)
                        if mac:
                            out.setdefault(s["id"], set()).add(mac)
                except Exception:
                    continue
    except Exception:
        pass
    return out


def infer_role(name, hostname=""):
    """hostname/이름 패턴으로 장비 계층(구분) 추론 — device_type 미지정 시 사용.

    반환: Firewall / BackBone / L3 Switch / L4 Switch / L2 Switch / "" (불명).
    순서 중요: 백본(BB)·L4를 일반 SW보다 먼저 판별(FABB=백본, FASW=액세스).
    """
    import re as _re
    # 언더스코어는 단어문자라 \b가 안 먹으므로 부분 문자열로 매칭(순서=우선순위)
    t = ((name or "") + " " + (hostname or "")).upper()
    if _re.search(r"FIREWALL|_FW|-FW|FW_|FW-|ASA|PALO|FORTI|UTM", t):
        return "Firewall"
    if _re.search(r"L4|SLB|ADC|ALTEON|OASVR", t):
        return "L4 Switch"
    if _re.search(r"BACKBONE|CORE|BB", t):
        return "BackBone"
    if _re.search(r"L3|DSW|DIST|AGGR|AGG", t):
        return "L3 Switch"
    if _re.search(r"FASW|ASW|ACCESS|ACC|EDGE|L2|SW", t):
        return "L2 Switch"
    return ""


import re as _re_zone
# 존(구성도 그룹) 추론 규칙 — hostname/이름 토큰 기반. 명시적 zone이 없을 때 기본값으로
# 사용해 토폴로지가 '미지정'으로 뭉치지 않게 한다(사용자가 존 지정 시 그 값이 우선).
_ZONE_RULES = [
    (_re_zone.compile(r"DMZ", _re_zone.I), "DMZ"),
    (_re_zone.compile(r"SERVER[\s_-]?FARM|SVR|SERVER", _re_zone.I), "SERVERFARM"),
    (_re_zone.compile(r"ECO[\s_-]?LAB", _re_zone.I), "ECO-LAB"),
    (_re_zone.compile(r"ECO[\s_-]?HUB", _re_zone.I), "ECO-HUB"),
]
_ZONE_FLOOR_RE = _re_zone.compile(r"(?<![A-Za-z0-9])(B?\d{1,2}F)(?![A-Za-z0-9])",
                                  _re_zone.I)


# 명명규칙 파싱용 — 장비타입 토큰(SW/ASW/FASW 등, 2글자 접두까지 허용)
_ZONE_DEVTYPE_RE = _re_zone.compile(
    r"^([A-Z]{0,2}SW|SWITCH|RTR|ROUTER|FW|FIREWALL|AP|L[234])$", _re_zone.I)
# 층 토큰: F1, 4F, B1, B1F 형태
_ZONE_FLOOR_TOKEN_RE = _re_zone.compile(r"^(B?\d{1,2}F?|F\d{1,2})$", _re_zone.I)
# 모델명으로 보이는 토큰(5420M, X590 등) — 존 이름에서 제외
_ZONE_MODEL_RE = _re_zone.compile(r"^[A-Z]{0,2}\d{3,}[A-Z]{0,2}$", _re_zone.I)


def _parse_zone_tokens(host):
    """언더스코어 명명규칙(사이트_층_존..._장비타입_번호)에서 존 토큰 추출.

    예: SKBA_F1_DMZ_SW_1 → "DMZ" / SKBA_F1_VDI_NASSW_1 → "VDI NAS".
    마지막 의미 토큰이 장비타입(SW 계열)일 때만 이 규칙을 적용해
    임의 문자열(random_host 등)을 존으로 오인하지 않는다.
    """
    tokens = [t for t in _re_zone.split(r"[_\-]+", (host or "").strip().upper()) if t]
    if len(tokens) < 3:
        return ""
    while tokens and tokens[-1].isdigit():   # 뒤 번호(인덱스) 제거
        tokens.pop()
    if not tokens:
        return ""
    last = tokens[-1]
    if _ZONE_DEVTYPE_RE.match(last):
        tokens.pop()                          # 순수 장비타입(SW/FASW...) 제거
    elif len(last) > 4 and last.endswith("SW"):
        tokens[-1] = last[:-2]                # 결합형(NASSW → NAS)은 SW만 분리
    else:
        return ""                             # 명명규칙 형태 아님 — 기존 규칙으로
    core = [t for t in tokens
            if not _ZONE_FLOOR_TOKEN_RE.match(t)      # 층 제거
            and not _ZONE_MODEL_RE.match(t)           # 모델명 제거
            and not t.isdigit()]
    if len(core) >= 2:
        core = core[1:]                       # 첫 토큰 = 사이트 코드로 간주
    return " ".join(core) if core else ""


def infer_zone(name, hostname=""):
    """hostname/이름 토큰으로 존 자동 분류.

    우선순위: 의미토큰(DMZ/SERVERFARM/ECO-*) → 명명규칙 파싱(사이트_층_존_SW_번호,
    예: SKBA_F1_VDI_NASSW_1 → "VDI NAS") → 층(4F/B1F).
    아무것도 못 찾으면 "" 반환(→ 프론트에서 '미지정')."""
    t = "%s %s" % (name or "", hostname or "")
    for rx, z in _ZONE_RULES:
        if rx.search(t):
            return z
    for cand in (hostname, name):
        z = _parse_zone_tokens(cand)
        if z:
            return z
    m = _ZONE_FLOOR_RE.search(name or hostname or "")
    if m:
        return m.group(1).upper()   # 예: 4F, 7F, B1F
    return ""


def _connected_subnets_by_switch(db_path, switch_ids):
    """{switch_id: [대역, ...]} — 각 스위치 최신 config 백업의 'ip address' 줄에서 도출.

    추가 장비 접근 없이 이미 저장된 running-config를 재활용. 백본/L3 노드에
    '이 스위치가 라우팅하는 대역'을 태그로 보여주기 위함.
    """
    from . import facility
    out = {}
    with db.get_db(db_path) as conn:
        cur = conn.cursor()
        for sid in switch_ids:
            try:
                cur.execute("SELECT content FROM config_backups WHERE switch_id=? "
                            "ORDER BY id DESC LIMIT 1", (sid,))
                row = cur.fetchone()
                if not row or not row["content"]:
                    continue
                subs = facility._parse_connected_subnets("", "", row["content"])
                if subs:
                    out[sid] = subs[:12]         # 노드 태그 과밀 방지
            except Exception:
                continue
    return out


def build_topology(db_path):
    """토폴로지 그래프 계산.

    Returns: {
      nodes: [{id, name, ip, vendor, status, alert, group, depth}],
      links: [{a, b, a_port, b_port, mutual}],   # a<b (정렬)
    }
    """
    switches = db.get_switches(db_path)
    if not switches:
        return {"nodes": [], "links": []}

    ip_macs = _arp_ip_macs(db_path)                      # {ip: mac}
    dev_macs = _device_macs(db_path, switches, ip_macs)  # {sid: set(mac)} 관리+인터페이스 MAC
    mac_map = db.get_mac_to_switchport(db_path)          # {mac: [(sid, name, port)]}
    pc_map = db.get_port_channel_members(db_path)        # {(sid, po): [members]}
    port_counts = db.get_port_mac_counts(db_path)        # {(sid, port_lower): MAC수}

    def _resolve_port(sid, port):
        """Po면 멤버 물리포트 표기로 해석."""
        members = pc_map.get((sid, (port or "").lower()))
        if members:
            return "%s (%s)" % (", ".join(members), port)
        return port

    # 방향 관측: directed[(A,B)] = A에서 B의 MAC이 보인 '직결' 포트.
    # B의 관리 MAC이 A의 여러 포트에 보이면(루프/이중화), 어느 게 실제 직결인지
    # 고른다: 물리 포트 우선 + 그 포트의 학습 MAC 수가 가장 적은 것(=액세스/직결 성향).
    # 이렇게 하면 이미 수집된 MAC 테이블만으로 추론 장비의 연결도 정확히 완성된다.
    directed = {}
    cand = {}   # (a,b) -> [ports]
    for b_sid, b_macs in dev_macs.items():
        for b_mac in b_macs:
            for (a_sid, _a_name, a_port) in mac_map.get(b_mac, []):
                if a_sid == b_sid:
                    continue
                cand.setdefault((a_sid, b_sid), []).append(a_port)
    for (a_sid, b_sid), ports in cand.items():
        def _score(p):
            pl = (p or "").lower()
            is_logical = pl.startswith(("po", "vl", "port-channel"))
            cnt = port_counts.get((a_sid, pl), 9999)
            return (1 if is_logical else 0, cnt)   # 물리 우선, MAC 수 적은 순
        directed[(a_sid, b_sid)] = sorted(ports, key=_score)[0]

    # 링크 병합(양방향 확인 여부 포함). MAC 추론 링크는 source='mac'.
    links = {}
    for (a, b), a_port in directed.items():
        key = (min(a, b), max(a, b))
        entry = links.setdefault(key, {"a": key[0], "b": key[1], "a_port": None,
                                       "b_port": None, "mutual": False, "source": "mac"})
        if a == key[0]:
            entry["a_port"] = _resolve_port(a, a_port)
        else:
            entry["b_port"] = _resolve_port(a, a_port)
        if entry["a_port"] and entry["b_port"]:
            entry["mutual"] = True

    # CDP/LLDP 이웃 = 정확한 물리 링크(양쪽 포트 확정). MAC 추론 링크 위에 덮어씀.
    name_to_sid = {(s.get("name") or "").lower(): s["id"] for s in switches}
    host_to_sid = {(s.get("hostname") or "").lower(): s["id"] for s in switches if s.get("hostname")}
    ip_to_sid = {s.get("ip"): s["id"] for s in switches if s.get("ip")}
    try:
        nbrs = db.get_all_neighbors(db_path)
    except Exception:
        nbrs = []
    for nb in nbrs:
        a_sid = nb.get("switch_id")
        rname = (nb.get("remote_name") or "").lower()
        b_sid = (name_to_sid.get(rname) or host_to_sid.get(rname)
                 or ip_to_sid.get(nb.get("remote_ip")))
        if not b_sid or b_sid == a_sid:
            continue
        key = (min(a_sid, b_sid), max(a_sid, b_sid))
        entry = links.setdefault(key, {"a": key[0], "b": key[1],
                                       "a_port": None, "b_port": None, "mutual": False})
        lp = _resolve_port(a_sid, nb.get("local_port"))
        rp = nb.get("remote_port")
        if a_sid == key[0]:
            entry["a_port"] = lp; entry["b_port"] = entry["b_port"] or rp
        else:
            entry["b_port"] = lp; entry["a_port"] = entry["a_port"] or rp
        entry["mutual"] = True
        entry["source"] = "cdp/lldp"      # 프로토콜 확정 링크 표시

    link_list = list(links.values())

    # BFS 계층(depth): 링크 수가 가장 많은 노드 = 루트(백본)
    adj = {}
    for l in link_list:
        adj.setdefault(l["a"], set()).add(l["b"])
        adj.setdefault(l["b"], set()).add(l["a"])
    depth = {}
    if adj:
        root = max(adj, key=lambda k: len(adj[k]))
        depth[root] = 0
        queue = [root]
        while queue:
            cur = queue.pop(0)
            for nxt in adj.get(cur, ()):  # noqa: B905
                if nxt not in depth:
                    depth[nxt] = depth[cur] + 1
                    queue.append(nxt)

    # 스위치별 최신 config 백업에서 directly-connected 대역 도출(추가 명령 없음)
    subnet_map = _connected_subnets_by_switch(db_path, [s["id"] for s in switches])

    nodes = []
    for s in switches:
        # 존 우선순위: 사용자 지정(zone) > TPS hostname 위치 > 토큰 추론 > location
        zone_explicit = (s.get("zone") or "").strip()
        try:
            from . import tps_location
            info = tps_location.parse(s.get("hostname"))
            tps_group = ("%d공장 %s %d층" % (info["phase"], info["building_name"], info["floor"])) if info else ""
        except Exception:
            tps_group = ""
        group = (zone_explicit or tps_group
                 or infer_zone(s.get("name"), s.get("hostname"))
                 or (s.get("location") or ""))
        # 구분(device_type) 미지정이면 hostname/이름 패턴으로 계층 자동 추론
        dtype = s.get("device_type") or infer_role(s.get("name"), s.get("hostname"))
        nodes.append({
            "id": s["id"], "kind": "sw", "name": s.get("name"), "ip": s.get("ip"),
            "vendor": s.get("vendor"), "status": s.get("status"),
            "alert": s.get("alert") or "none",
            "device_type": dtype,
            "inferred": not s.get("device_type") and bool(dtype),
            "subnets": subnet_map.get(s["id"], []),
            "group": group,
            "zone_explicit": bool(zone_explicit),
            "depth": depth.get(s["id"], None),
        })

    # 방화벽 노드 + 직결 링크: 스위치 ARP에서 방화벽 IP의 MAC을 찾아
    # 그 MAC이 보이는 '물리 포트'(가장 구체적 관측)를 직결로 판단
    try:
        firewalls = db.list_firewalls(db_path)
    except Exception:
        firewalls = []
    for fw in firewalls:
        fw_id = "f%d" % fw["id"]
        # 방화벽 인터페이스 IP 요약(서버실 구성도 노드 태그용)
        fw_ifaces = []
        try:
            for it in db.get_firewall_interfaces(db_path, fw["id"]):
                if it.get("ip"):
                    pfx = ("/" + str(it["mask"])) if it.get("mask") else ""
                    fw_ifaces.append("%s %s%s" % (it.get("name") or "", it["ip"], pfx))
        except Exception:
            pass
        # HA 구성(수집된 hbdev 포트) — 이중화 연결선 라벨용
        ha = None
        try:
            import json as _json
            if fw.get("ha_info"):
                ha = _json.loads(fw["ha_info"])
        except Exception:
            ha = None
        nodes.append({
            "id": fw_id, "kind": "fw", "name": fw.get("name"),
            "ip": fw.get("host"), "vendor": fw.get("vendor"),
            "status": fw.get("status"), "alert": "none",
            "device_type": "Firewall", "interfaces": fw_ifaces[:12],
            "ha": ha,
            "group": ((fw.get("zone") or "").strip() or infer_zone(fw.get("name"))
                      or (fw.get("location") or "")),
            "depth": None,
        })
        linked_switches = set()
        mac = ip_macs.get(fw.get("host"))
        cands = mac_map.get(mac, []) if mac else []
        # 물리 포트 관측(Po/Vl 논리포트는 업링크 경유) — 스위치별 1개로 다중 연결
        phys = [c for c in cands
                if not (c[2] or "").lower().startswith(("po", "vl", "port-channel"))]
        for sid, _name, port in (phys or cands):
            if sid in linked_switches:
                continue
            linked_switches.add(sid)
            link_list.append({"a": sid, "b": fw_id,
                              "a_port": _resolve_port(sid, port),
                              "b_port": None, "mutual": True})   # 관측된 직결 = 실선
        # L3 인접 폴백: MAC으로 못 잡은 스위치 중, 그 스위치가 라우팅하는 대역에
        # 방화벽 IP가 포함되면(= 방화벽이 그 스위치에 L3로 붙음) 링크 추가.
        # FABB(백본)↔방화벽처럼 L2 MAC이 안 보이는 직결을 그려준다.
        try:
            fw_ip = ipaddress.IPv4Address(fw.get("host"))
            for sid, subs in subnet_map.items():
                if sid in linked_switches:
                    continue
                for net_str in subs:
                    try:
                        if fw_ip in ipaddress.IPv4Network(net_str, strict=False):
                            linked_switches.add(sid)
                            link_list.append({"a": sid, "b": fw_id, "a_port": None,
                                              "b_port": None, "mutual": True,
                                              "l3": True})    # L3 인접(대역 기반)
                            break
                    except (ipaddress.AddressValueError, ValueError):
                        continue
        except (ipaddress.AddressValueError, ValueError):
            pass

    return {"nodes": nodes, "links": link_list}


# ─── 서버실 트리 구성도 (v4.2) ──────────────────────────────────────
def _latest_configs(db_path, sids):
    """{switch_id: running-config 텍스트} — 최신 백업."""
    out = {}
    with db.get_db(db_path) as conn:
        cur = conn.cursor()
        for sid in sids:
            try:
                cur.execute("SELECT content FROM config_backups WHERE switch_id=? "
                            "ORDER BY id DESC LIMIT 1", (sid,))
                row = cur.fetchone()
                if row and row["content"]:
                    out[sid] = row["content"]
            except Exception:
                continue
    return out


def parse_svi_subnets(cfg):
    """running-config에서 L3 인터페이스의 (VLAN, 대역) 추출.

    interface Vlan10 / ip address 10.0.10.1 255.255.255.0 → {vlan:10, cidr:10.0.10.0/24}.
    라우티드 물리 인터페이스(Vlan 아님)는 vlan=None. 중복 대역 제거.
    """
    import ipaddress as _ip
    out, seen = [], set()
    cur_vlan = "__none__"
    in_iface = False
    for line in (cfg or "").splitlines():
        m = re.match(r"^\s*interface\s+(\S+)", line, re.I)
        if m:
            in_iface = True
            name = m.group(1)
            vm = re.match(r"Vl(?:an)?0*(\d+)", name, re.I)
            cur_vlan = int(vm.group(1)) if vm else None
            continue
        if in_iface:
            m2 = re.search(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                           line, re.I)
            if m2:
                try:
                    net = str(_ip.IPv4Network("%s/%s" % (m2.group(1), m2.group(2)),
                                              strict=False))
                except (ValueError, _ip.AddressValueError):
                    continue
                if net.startswith(("127.", "169.254.")) or net in seen:
                    continue
                seen.add(net)
                out.append({"vlan": cur_vlan, "cidr": net})
    return out


def classify_l3(cfg):
    """running-config로 L3/L2 판정. 없으면 None(미수집).

    L3: 'ip routing' 있음 / SVI(대역) 2개 이상 / 기본경로 외 정적 라우트 존재.
    L2: 관리 SVI 1개 이하 + default gateway/route만.
    """
    if not cfg:
        return None
    if re.search(r"^\s*ip routing\b", cfg, re.M):
        return "L3"
    if len(parse_svi_subnets(cfg)) >= 2:
        return "L3"
    routes = re.findall(r"^\s*ip route\s+(\S+)\s+\S+", cfg, re.M)
    if any(r != "0.0.0.0" for r in routes):
        return "L3"
    return "L2"


_INTERNET_FW_RE = _re_zone.compile(
    r"internet|외부|ext|perimeter|edge|외부망|인터넷", _re_zone.I)


def _fw_tree_role(fw):
    """방화벽 역할: internet_fw(외부/인터넷 경계) or firewall(구간)."""
    blob = " ".join(str(fw.get(k) or "") for k in ("name", "zone", "location"))
    return "internet_fw" if _INTERNET_FW_RE.search(blob) else "firewall"


def build_serverroom_tree(db_path):
    """서버실(랙 위치 지정) 방화벽·L3/백본 스위치 트리 구성도.

    - 포함: location이 랙형식(A09U27)인 방화벽 + config상 L3/백본 스위치. L2 숨김.
    - 링크: build_topology의 직결(CDP/LLDP/ARP-MAC/L3인접) 중 포함 노드 간만.
    - L3/백본 노드에 SVI 대역(VLAN 병기) 부착 → 프론트에서 세로 박스로 표시.
    - 역할 tier: internet(가상)→internet_fw→backbone→(l3/l4/firewall).
    Returns: {nodes, links, roots} — roots=최상위(백본/인터넷FW) id 목록.
    """
    from . import serverroom
    base = build_topology(db_path)
    switches = {s["id"]: s for s in db.get_switches(db_path)}
    try:
        fws = {"f%d" % f["id"]: f for f in db.list_firewalls(db_path)}
    except Exception:
        fws = {}
    cfgs = _latest_configs(db_path, list(switches.keys()))

    keep = {}
    for n in base["nodes"]:
        nid = n["id"]
        if n["kind"] == "sw":
            sw = switches.get(nid)
            if not sw or not serverroom.parse_rack(sw.get("location")):
                continue                       # 서버실 아님
            cfg = cfgs.get(nid, "")
            cls = classify_l3(cfg)
            dt = (n.get("device_type") or "").lower()
            is_backbone = "backbone" in dt or "core" in dt
            is_l4 = "l4" in dt
            if not is_backbone and not is_l4 and cls == "L2":
                continue                       # L2 노드 숨김(대역은 상위 L3가 대표)
            n["role"] = ("backbone" if is_backbone else "l4" if is_l4 else "l3")
            n["subnets_vlan"] = parse_svi_subnets(cfg)
            n["l3_class"] = cls
            keep[nid] = n
        else:
            fw = fws.get(nid)
            if not fw or not serverroom.parse_rack(fw.get("location")):
                continue
            n["role"] = _fw_tree_role(fw)
            keep[nid] = n

    links = [l for l in base["links"] if l["a"] in keep and l["b"] in keep]

    # tier 계층(위→아래): internet_fw=1, backbone=2, l3/l4/firewall=3
    tier = {"internet_fw": 1, "backbone": 2, "l3": 3, "l4": 3, "firewall": 3}
    for nid, n in keep.items():
        n["tier"] = tier.get(n.get("role"), 3)

    roots = [nid for nid, n in keep.items()
             if n["role"] in ("internet_fw", "backbone")]
    return {"nodes": list(keep.values()), "links": links, "roots": roots}
