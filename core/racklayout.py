# -*- coding: utf-8 -*-
"""서버실 랙 배치 저장/복원.

문제: 랙뷰는 스위치·방화벽·서버의 location에서 **파생**된다. 장비를 삭제하거나
재등록하면(엑셀 재등록·잘못 삭제 후 다시 추가) 그 장비의 랙 위치가 같이 사라진다
— 사용자에게는 "서버실 현황이 자동 업데이트되며 삭제됐다"로 보인다.

해결: 배치를 스냅샷으로 **보관**한다.
  - 저장: 지금 랙에 배치된 장비들의 (종류, IP, 이름, 위치)를 통째로 저장.
  - 복원(업데이트): 현황에서 장비를 다시 읽어, 위치가 비어 있는데 보관본에
    위치가 있는 장비(IP로 대조 — 재등록해도 IP는 대개 유지)에 위치를 되살린다.
    **이미 위치가 있는 장비는 건드리지 않는다** — 사용자가 그 사이 옮겼을 수 있다.
  - 유령(ghost): 보관본에는 있는데 현황 어디에도 없는 장비는 랙뷰에 흐리게
    표시한다. 조용히 사라지는 것보다 "여기 있었는데 지금 현황에 없다"가 낫다.
"""
from . import db, serverroom, utils


def _live_devices(db_path):
    """현황 3종의 (kind, obj) 목록 — 랙 배치 후보 전부."""
    out = []
    try:
        for s in db.get_switches(db_path):
            out.append(("sw", s))
    except Exception:
        pass
    try:
        for f in db.list_firewalls(db_path):
            # 방화벽은 ip 컬럼이 host다 — 아래에서 공통 키로 쓰기 위해 맞춘다.
            f = dict(f)
            f.setdefault("ip", f.get("host"))
            out.append(("fw", f))
    except Exception:
        pass
    try:
        for v in db.list_servers(db_path):
            out.append(("srv", v))
    except Exception:
        pass
    return out


def _racked(kind_obj):
    """랙 형식 위치(A09U27 등)가 있는 장비만 [(kind, ip, name, location)]로."""
    rows = []
    for kind, o in kind_obj:
        loc = (o.get("location") or "").strip()
        if not loc:
            continue
        if not serverroom.parse_rack(loc):
            continue                      # 랙 형식이 아닌 위치(사무실 등)는 보관 대상 아님
        ip = (o.get("ip") or o.get("host") or "").strip()
        if not ip:
            continue
        rows.append({"kind": kind, "ip": ip, "name": o.get("name") or "",
                     "location": loc})
    return rows


def save_snapshot(db_path):
    """현재 랙 배치를 통째로 보관. 반환: 저장 건수.

    빈 배치(0건)도 그대로 저장한다 — 사용자가 의도적으로 비웠을 수 있고,
    '0건이면 저장 안 함'은 옛 보관본이 몰래 남는 경로가 된다.
    """
    rows = _racked(_live_devices(db_path))
    with db._db_lock:
        with db.get_db(db_path) as conn:
            conn.execute("DELETE FROM rack_layout")
            for r in rows:
                conn.execute(
                    "INSERT OR REPLACE INTO rack_layout (kind, ip, name, location, updated) "
                    "VALUES (?,?,?,?, datetime('now','localtime'))",
                    (r["kind"], r["ip"], r["name"], r["location"]))
    utils.log_event("info", "rack_layout_saved", count=len(rows))
    return len(rows)


def get_layout(db_path):
    """보관본 전체 [{kind, ip, name, location, updated}]."""
    with db.get_db(db_path) as conn:
        try:
            cur = conn.execute("SELECT kind, ip, name, location, updated FROM rack_layout")
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def restore(db_path):
    """보관본의 위치를 '위치가 빈' 현황 장비에 되살린다(IP 대조).

    반환: {"applied": [{kind, ip, name, location}], "ghosts": [...],
           "kept": n(이미 위치가 있어 건드리지 않은 수)}
    """
    layout = get_layout(db_path)
    if not layout:
        return {"applied": [], "ghosts": [], "kept": 0}
    live = _live_devices(db_path)
    by_key = {}
    for kind, o in live:
        ip = (o.get("ip") or o.get("host") or "").strip()
        if ip:
            by_key[(kind, ip)] = o

    applied, ghosts, kept = [], [], 0
    for ent in layout:
        o = by_key.get((ent["kind"], ent["ip"]))
        if o is None:
            ghosts.append(ent)            # 현황에 없음 — 랙뷰에 유령으로 표시
            continue
        cur_loc = (o.get("location") or "").strip()
        if cur_loc and serverroom.parse_rack(cur_loc):
            kept += 1                     # 이미 배치돼 있음 — 사용자가 옮겼을 수 있다
            continue
        try:
            if ent["kind"] == "sw":
                db.update_switch(db_path, o["id"], location=ent["location"])
            elif ent["kind"] == "fw":
                db.update_firewall(db_path, o["id"], location=ent["location"])
            else:
                db.update_server(db_path, o["id"], location=ent["location"])
            applied.append(ent)
        except Exception as e:
            utils.log_event("warning", "rack_layout_restore_skip",
                            kind=ent["kind"], ip=ent["ip"], error=str(e)[:120])
    utils.log_event("info", "rack_layout_restored",
                    applied=len(applied), ghosts=len(ghosts), kept=kept)
    return {"applied": applied, "ghosts": ghosts, "kept": kept}


def ghosts(db_path):
    """보관본에는 있는데 현황 어디에도 없는 장비 — 랙뷰 유령 표시용."""
    layout = get_layout(db_path)
    if not layout:
        return []
    live_keys = set()
    for kind, o in _live_devices(db_path):
        ip = (o.get("ip") or o.get("host") or "").strip()
        if ip:
            live_keys.add((kind, ip))
    return [e for e in layout if (e["kind"], e["ip"]) not in live_keys]
