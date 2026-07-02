# -*- coding: utf-8 -*-
"""네트워크 토폴로지 추론 — 수집 데이터만으로 스위치 간 연결 관계를 그린다.

원리(추가 장비 접근 없음, 수집된 것 재활용):
  1) 각 스위치의 관리 IP ↔ MAC: 아무 스위치의 ARP 테이블에서 다른 스위치 IP의 MAC을 찾음
  2) 스위치 A의 MAC 테이블에서 스위치 B의 관리 MAC이 보이는 포트 = A에서 B로 가는 방향
  3) 양방향(A→B, B→A)이 모두 잡히면 상호 확인된 링크(신뢰도 높음)
  4) 루트(백본) = 링크가 가장 많은 노드 → BFS 계층 배치용 depth 부여
"""
import logging

from . import db

logger = logging.getLogger(__name__)


def _switch_mgmt_macs(db_path, switches):
    """{switch_id: mgmt_mac(lower)} — 전체 ARP에서 각 스위치 IP의 MAC을 찾음."""
    ip_to_sid = {s["ip"]: s["id"] for s in switches if s.get("ip")}
    macs = {}
    with db.get_db(db_path) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """SELECT a.ip, a.mac FROM arp_entries a
                   WHERE a.snapshot_id IN (SELECT MAX(id) FROM snapshots GROUP BY switch_id)""")
            for r in cur.fetchall():
                sid = ip_to_sid.get(r["ip"])
                if sid and r["mac"]:
                    macs[sid] = r["mac"].lower()
        except Exception:
            pass
    return macs


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

    mgmt = _switch_mgmt_macs(db_path, switches)          # {sid: mac}
    mac_map = db.get_mac_to_switchport(db_path)          # {mac: [(sid, name, port)]}
    pc_map = db.get_port_channel_members(db_path)        # {(sid, po): [members]}

    def _resolve_port(sid, port):
        """Po면 멤버 물리포트 표기로 해석."""
        members = pc_map.get((sid, (port or "").lower()))
        if members:
            return "%s (%s)" % (", ".join(members), port)
        return port

    # 방향 관측: directed[(A,B)] = A에서 B의 MAC이 보인 포트
    directed = {}
    for b_sid, b_mac in mgmt.items():
        for (a_sid, _a_name, a_port) in mac_map.get(b_mac, []):
            if a_sid == b_sid:
                continue
            # 같은 (A,B)에 여러 포트가 보이면 첫 관측 유지
            directed.setdefault((a_sid, b_sid), a_port)

    # 링크 병합(양방향 확인 여부 포함)
    links = {}
    for (a, b), a_port in directed.items():
        key = (min(a, b), max(a, b))
        entry = links.setdefault(key, {"a": key[0], "b": key[1],
                                       "a_port": None, "b_port": None, "mutual": False})
        if a == key[0]:
            entry["a_port"] = _resolve_port(a, a_port)
        else:
            entry["b_port"] = _resolve_port(a, a_port)
        if entry["a_port"] and entry["b_port"]:
            entry["mutual"] = True
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

    nodes = []
    for s in switches:
        try:
            from . import tps_location
            info = tps_location.parse(s.get("hostname"))
            group = ("%d공장 %s %d층" % (info["phase"], info["building_name"], info["floor"])) if info else ""
        except Exception:
            group = ""
        nodes.append({
            "id": s["id"], "name": s.get("name"), "ip": s.get("ip"),
            "vendor": s.get("vendor"), "status": s.get("status"),
            "alert": s.get("alert") or "none", "group": group,
            "depth": depth.get(s["id"], None),
        })
    return {"nodes": nodes, "links": link_list}
