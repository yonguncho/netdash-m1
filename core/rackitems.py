# -*- coding: utf-8 -*-
"""랙에 직접 적어 넣는 항목 — 현황에 등록하지 않는 장비와 '비워둘 자리'.

배경: 랙뷰는 스위치·방화벽·서버의 location에서 파생되므로, 현황에 없는 것은
랙에 그릴 방법이 없었다. 그런데 실제 랙에는 KVM·콘솔·PDU·테이프처럼 관리
대상이 아닌 장비도 실장되고, "증설 예정이라 비워둘 자리"도 표시해 둬야 한다.

현황 3종에 억지로 등록하면 수집·도달성 감시 대상이 돼 없는 장비로 알람이
난다. 그래서 별도 테이블에 두고 랙뷰에서만 그린다.

  item_type 'etc'      — 기타 장비(KVM·PDU 등)
  item_type 'reserved' — 예약·사용 금지(비워둘 자리)

자리 겹침은 저장 시점에 막는다. 화면에서만 막으면 두 창을 띄워 각각 저장할 때
뚫리고, 그러면 랙뷰에서 한쪽이 조용히 사라진다(현황 장비에서 이미 겪은 문제).
"""
from . import db, racklayout, serverroom, utils

TYPES = ("etc", "reserved")
MAX_NAME = 40
MAX_NOTE = 120


def _norm(rack, unit, height):
    """입력 정규화. 잘못된 값은 (None, 사유)."""
    rack = (rack or "").strip().upper()
    if not rack:
        return None, "랙 이름이 필요합니다"
    if len(rack) > 12:
        return None, "랙 이름이 너무 깁니다"
    try:
        unit = int(unit)
        height = int(height or 1)
    except (TypeError, ValueError):
        return None, "U 번호가 올바르지 않습니다"
    if unit < 1 or unit > serverroom.MAX_HEIGHT:
        return None, "U 번호는 1~%d 사이여야 합니다" % serverroom.MAX_HEIGHT
    if height < 1:
        height = 1
    if unit + height - 1 > serverroom.MAX_HEIGHT:
        return None, "랙 높이(%dU)를 넘어갑니다" % serverroom.MAX_HEIGHT
    return {"rack": rack, "unit": unit, "height": height}, None


def occupied_units(db_path, rack, exclude_id=None):
    """그 랙에서 이미 찬 U → {u: 무엇이 쓰는지}.

    현황 장비(location 파생)와 직접 입력 항목을 **둘 다** 본다. 한쪽만 보면
    같은 자리에 둘이 겹쳐 그려진다.
    """
    taken = {}
    rack = (rack or "").strip().upper()
    for kind, o in racklayout._live_devices(db_path):
        info = serverroom.parse_rack(o.get("location"))
        if not info or info["rack"] != rack:
            continue
        who = o.get("name") or o.get("ip") or o.get("host") or "등록 장비"
        for u in range(info["unit"], info["unit_end"] + 1):
            taken[u] = who
    for it in list_items(db_path, rack=rack):
        if exclude_id is not None and it["id"] == exclude_id:
            continue
        who = it.get("name") or ("예약" if it["item_type"] == "reserved" else "기타")
        for u in range(it["unit"], it["unit"] + it["height"]):
            taken[u] = who
    return taken


def list_items(db_path, rack=None):
    """직접 입력 항목 목록. rack을 주면 그 랙만."""
    with db.get_db(db_path) as conn:
        try:
            if rack:
                cur = conn.execute(
                    "SELECT id, rack, unit, height, name, item_type, note, updated "
                    "FROM rack_items WHERE rack=? ORDER BY rack, unit",
                    ((rack or "").strip().upper(),))
            else:
                cur = conn.execute(
                    "SELECT id, rack, unit, height, name, item_type, note, updated "
                    "FROM rack_items ORDER BY rack, unit")
            return [dict(r) for r in cur.fetchall()]
        except Exception:
            return []


def save_item(db_path, rack, unit, height=1, name="", item_type="etc",
              note="", item_id=None):
    """추가 또는 수정. 반환 {ok, id} 또는 {ok: False, error, conflicts}."""
    norm, err = _norm(rack, unit, height)
    if err:
        return {"ok": False, "error": err}
    item_type = (item_type or "etc").strip().lower()
    if item_type not in TYPES:
        item_type = "etc"
    name = (name or "").strip()[:MAX_NAME]
    note = (note or "").strip()[:MAX_NOTE]
    if not name:
        name = "예약(비움)" if item_type == "reserved" else "기타 장비"

    taken = occupied_units(db_path, norm["rack"], exclude_id=item_id)
    hit = [u for u in range(norm["unit"], norm["unit"] + norm["height"])
           if u in taken]
    if hit:
        # 어디가 왜 막혔는지 그대로 돌려준다 — "저장 실패"만 뜨면 사용자가
        # 어느 칸을 비워야 하는지 알 수 없다.
        return {"ok": False,
                "error": "U%s 자리에 이미 %s 이(가) 있습니다"
                         % ("·U".join(str(u) for u in hit), taken[hit[0]]),
                "conflicts": hit}

    with db._db_lock:
        with db.get_db(db_path) as conn:
            if item_id:
                conn.execute(
                    "UPDATE rack_items SET rack=?, unit=?, height=?, name=?, "
                    "item_type=?, note=?, updated=datetime('now','localtime') "
                    "WHERE id=?",
                    (norm["rack"], norm["unit"], norm["height"], name,
                     item_type, note, int(item_id)))
                new_id = int(item_id)
            else:
                cur = conn.execute(
                    "INSERT INTO rack_items (rack, unit, height, name, item_type, "
                    "note, updated) VALUES (?,?,?,?,?,?, datetime('now','localtime'))",
                    (norm["rack"], norm["unit"], norm["height"], name,
                     item_type, note))
                new_id = cur.lastrowid
    utils.log_event("info", "rack_item_saved", rack=norm["rack"],
                    unit=norm["unit"], height=norm["height"],
                    item_type=item_type, item_id=new_id)
    return {"ok": True, "id": new_id}


def delete_item(db_path, item_id):
    with db._db_lock:
        with db.get_db(db_path) as conn:
            cur = conn.execute("DELETE FROM rack_items WHERE id=?", (int(item_id),))
            n = cur.rowcount
    if n:
        utils.log_event("info", "rack_item_deleted", item_id=int(item_id))
    return {"ok": bool(n), "deleted": n}
