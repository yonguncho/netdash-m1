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
    mgmt = _switch_mgmt_macs(db_path, switches, ip_macs)  # {sid: mac}
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
    for b_sid, b_mac in mgmt.items():
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
        try:
            from . import tps_location
            info = tps_location.parse(s.get("hostname"))
            group = ("%d공장 %s %d층" % (info["phase"], info["building_name"], info["floor"])) if info else ""
        except Exception:
            group = ""
        # 구분(device_type) 미지정이면 hostname/이름 패턴으로 계층 자동 추론
        dtype = s.get("device_type") or infer_role(s.get("name"), s.get("hostname"))
        nodes.append({
            "id": s["id"], "kind": "sw", "name": s.get("name"), "ip": s.get("ip"),
            "vendor": s.get("vendor"), "status": s.get("status"),
            "alert": s.get("alert") or "none",
            "device_type": dtype,
            "inferred": not s.get("device_type") and bool(dtype),
            "subnets": subnet_map.get(s["id"], []),
            "group": group or (s.get("location") or ""),
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
        nodes.append({
            "id": fw_id, "kind": "fw", "name": fw.get("name"),
            "ip": fw.get("host"), "vendor": fw.get("vendor"),
            "status": fw.get("status"), "alert": "none",
            "device_type": "Firewall", "interfaces": fw_ifaces[:12],
            "group": fw.get("location") or "", "depth": None,
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
