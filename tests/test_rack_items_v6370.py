# -*- coding: utf-8 -*-
"""v6.37.0 — 랙에 직접 입력하는 항목(기타 장비·예약 자리).

사용자 요청: 현황에 등록하지 않는 장비도 랙을 채워야 하고, 비워둬야 하는
자리도 표시해 두고 싶다. 랙뷰에서 U를 클릭해 직접 입력.
"""
import os
import tempfile

import pytest

from core import db, rackitems


@pytest.fixture()
def dbf():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def _sw(path, name, ip, location):
    db.save_switch(path, name, ip, "cisco_ios")
    sw = [s for s in db.get_switches(path) if s["ip"] == ip][0]
    db.update_switch(path, sw["id"], location=location)


# ── 저장·수정·삭제 ────────────────────────────────────────────────

def test_save_and_list(dbf):
    r = rackitems.save_item(dbf, "A09", 10, 2, "KVM 스위치", "etc", "콘솔용")
    assert r["ok"] and r["id"]
    items = rackitems.list_items(dbf)
    assert len(items) == 1
    it = items[0]
    assert (it["rack"], it["unit"], it["height"]) == ("A09", 10, 2)
    assert it["name"] == "KVM 스위치" and it["item_type"] == "etc"
    assert it["note"] == "콘솔용"


def test_rack_name_is_uppercased(dbf):
    """랙 이름은 대문자로 통일 — a09와 A09가 다른 랙이 되면 자리 검사가 뚫린다."""
    rackitems.save_item(dbf, "a09", 5, 1, "x")
    assert rackitems.list_items(dbf)[0]["rack"] == "A09"
    r = rackitems.save_item(dbf, "A09", 5, 1, "y")
    assert not r["ok"]                       # 같은 자리로 인식돼야 한다


def test_default_names_by_type(dbf):
    """이름을 비워도 무엇인지 보여야 한다 — 빈 칸은 '고장'처럼 보인다."""
    rackitems.save_item(dbf, "A01", 1, 1, "", "reserved")
    rackitems.save_item(dbf, "A01", 2, 1, "", "etc")
    by_u = {i["unit"]: i for i in rackitems.list_items(dbf)}
    assert by_u[1]["name"] == "예약(비움)"
    assert by_u[2]["name"] == "기타 장비"


def test_unknown_type_falls_back_to_etc(dbf):
    rackitems.save_item(dbf, "A01", 1, 1, "x", "무엇인가")
    assert rackitems.list_items(dbf)[0]["item_type"] == "etc"


def test_edit_moves_item(dbf):
    iid = rackitems.save_item(dbf, "A09", 10, 1, "KVM")["id"]
    r = rackitems.save_item(dbf, "A09", 30, 2, "KVM", "etc", "", item_id=iid)
    assert r["ok"]
    items = rackitems.list_items(dbf)
    assert len(items) == 1 and items[0]["unit"] == 30 and items[0]["height"] == 2


def test_edit_can_keep_its_own_slot(dbf):
    """자기 자리를 자기가 막으면 이름조차 못 고친다(exclude_id 누락 회귀)."""
    iid = rackitems.save_item(dbf, "A09", 10, 2, "KVM")["id"]
    r = rackitems.save_item(dbf, "A09", 10, 2, "KVM 2호기", "etc", "", item_id=iid)
    assert r["ok"], r.get("error")


def test_delete(dbf):
    iid = rackitems.save_item(dbf, "A09", 10, 1, "KVM")["id"]
    assert rackitems.delete_item(dbf, iid)["ok"]
    assert rackitems.list_items(dbf) == []
    assert not rackitems.delete_item(dbf, iid)["ok"]      # 없는 것 삭제는 실패


# ── 자리 겹침 ─────────────────────────────────────────────────────

def test_overlap_with_other_item_is_rejected(dbf):
    rackitems.save_item(dbf, "A09", 10, 2, "KVM")         # U10-U11
    r = rackitems.save_item(dbf, "A09", 11, 1, "PDU")
    assert not r["ok"] and r["conflicts"] == [11]
    assert "KVM" in r["error"]                            # 무엇이 막는지 알려준다


def test_overlap_with_registered_device_is_rejected(dbf):
    """현황 장비 자리도 막아야 한다 — 직접 입력끼리만 보면 겹쳐 그려진다."""
    _sw(dbf, "SW-CORE", "10.0.0.1", "A09U20")
    r = rackitems.save_item(dbf, "A09", 20, 1, "PDU")
    assert not r["ok"] and "SW-CORE" in r["error"]


def test_multi_u_device_blocks_all_its_units(dbf):
    _sw(dbf, "SRV-BIG", "10.0.0.2", "A09U13-U15")
    assert not rackitems.save_item(dbf, "A09", 14, 1, "x")["ok"]
    assert not rackitems.save_item(dbf, "A09", 15, 1, "x")["ok"]
    assert rackitems.save_item(dbf, "A09", 16, 1, "x")["ok"]


def test_other_rack_is_not_blocked(dbf):
    rackitems.save_item(dbf, "A09", 10, 1, "KVM")
    assert rackitems.save_item(dbf, "B12", 10, 1, "KVM")["ok"]


def test_occupied_units_merges_both_sources(dbf):
    _sw(dbf, "SW1", "10.0.0.1", "A09U40")
    rackitems.save_item(dbf, "A09", 10, 2, "KVM")
    taken = rackitems.occupied_units(dbf, "A09")
    assert set(taken) == {40, 10, 11}


# ── 입력 검증 ─────────────────────────────────────────────────────

def test_unit_out_of_range(dbf):
    assert not rackitems.save_item(dbf, "A09", 0, 1, "x")["ok"]
    assert not rackitems.save_item(dbf, "A09", 43, 1, "x")["ok"]


def test_height_overflow_rejected(dbf):
    """U41에 5U를 넣으면 랙 밖으로 나간다 — 화면에서 잘려 사라진다."""
    assert not rackitems.save_item(dbf, "A09", 41, 5, "x")["ok"]


def test_missing_rack_rejected(dbf):
    assert not rackitems.save_item(dbf, "", 1, 1, "x")["ok"]


def test_long_text_is_truncated_not_rejected(dbf):
    rackitems.save_item(dbf, "A09", 1, 1, "가" * 200, "etc", "나" * 400)
    it = rackitems.list_items(dbf)[0]
    assert len(it["name"]) == rackitems.MAX_NAME
    assert len(it["note"]) == rackitems.MAX_NOTE


# ── 화면 배선 ─────────────────────────────────────────────────────

def _read(*parts):
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), *parts)
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_app_js_wires_rack_item_flow():
    js = _read("web", "static", "app.js")
    assert "function openRackItemModal(" in js
    assert "add-rack-item" in js and "edit-rack-item" in js
    assert "/api/room/rack-items" in js
    # 빈 칸이 클릭 가능해야 입력을 시작할 수 있다
    assert "data-action='add-rack-item'" in js


def test_app_js_renders_items_in_rack():
    js = _read("web", "static", "app.js")
    assert "_roomRackItems" in js
    assert '_put({ k: "item"' in js
    # 직접 입력 항목에는 높이 드래그 손잡이를 달지 않는다(수정 창에서 바꾼다)
    assert "isItem ?" in js


def test_index_html_has_rack_item_modal():
    html = _read("web", "templates", "index.html")
    for el in ("rack-item-modal", "rack-item-type", "rack-item-name",
               "rack-item-height", "rack-item-note", "btn-rack-item-save",
               "btn-rack-item-delete"):
        assert el in html, el


def test_reserved_slot_has_distinct_style():
    """예약 자리가 일반 장비처럼 보이면 '비었다'는 뜻이 전달되지 않는다."""
    css = _read("web", "static", "style.css")
    assert ".ru--item-reserved" in css
    assert "repeating-linear-gradient" in css[css.index(".ru--item-reserved"):]
