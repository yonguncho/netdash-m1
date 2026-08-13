# -*- coding: utf-8 -*-
"""v6.36.0 — 관제 설비 탭 '대역별 IP 사용 현황'.

사용자 요청: 설비 대역별로 IP를 몇 개 쓰는지, 대역별로 리스트업.
예전 by_subnet은 LIMIT 12로 잘려 13번째 대역이 조용히 사라졌다.
"""
import json
import os
import sqlite3
import tempfile

import pytest

from core import db, wallstats


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


def _add(path, subnet, ip, online=1, sw="SW1", port="Gi1/0/1", direct=1):
    with db.get_db(path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO facility_hosts "
            "(subnet, ip, mac, switch_id, switch_name, port, online, direct, via, updated) "
            "VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))",
            (subnet, ip, "00:11:22:33:44:55", None, sw, port, online, direct, ""))
        conn.commit()


# ── 대역 용량 계산 ────────────────────────────────────────────────

def test_capacity_ipv4_prefixes():
    assert wallstats.subnet_capacity("10.92.140.0/24") == 254
    assert wallstats.subnet_capacity("10.92.140.0/22") == 1022
    assert wallstats.subnet_capacity("192.168.0.0/16") == 65534


def test_capacity_edge_prefixes():
    # /31은 RFC 3021 링크(2개 다 호스트), /32는 단일 호스트 — 2를 빼면 0/음수가 된다
    assert wallstats.subnet_capacity("10.0.0.0/31") == 2
    assert wallstats.subnet_capacity("10.0.0.1/32") == 1


def test_capacity_unknown_returns_none():
    """모르면 None. 0을 돌려주면 사용률 계산이 ZeroDivision으로 죽는다."""
    assert wallstats.subnet_capacity("미지정") is None
    assert wallstats.subnet_capacity("") is None
    assert wallstats.subnet_capacity(None) is None
    assert wallstats.subnet_capacity("10.0.0.0/xx") is None
    assert wallstats.subnet_capacity("10.0.0.0/99") is None


# ── 집계 ──────────────────────────────────────────────────────────

def test_by_subnet_counts_and_usage(dbf):
    for i in range(1, 11):
        _add(dbf, "10.92.140.0/24", "10.92.140.%d" % i, online=1 if i <= 7 else 0)
    stats = wallstats.build(dbf)["facility"]
    row = [x for x in stats["by_subnet"] if x["name"] == "10.92.140.0/24"][0]
    assert row["count"] == 10
    assert row["online"] == 7
    assert row["offline"] == 3
    assert row["capacity"] == 254
    assert row["usage_pct"] == pytest.approx(3.9, abs=0.1)   # 10/254


def test_by_subnet_not_truncated_at_12(dbf):
    """예전 LIMIT 12 회귀 — 대역 15개면 15개가 다 와야 한다."""
    for n in range(15):
        _add(dbf, "10.%d.0.0/24" % n, "10.%d.0.5" % n)
    stats = wallstats.build(dbf)["facility"]
    assert len(stats["by_subnet"]) == 15


def test_by_subnet_unknown_subnet_has_no_usage(dbf):
    """대역 표기가 없으면 사용률은 None — 0%로 보내면 텅 빈 대역으로 오독된다."""
    _add(dbf, "", "10.1.1.1")
    stats = wallstats.build(dbf)["facility"]
    row = [x for x in stats["by_subnet"] if x["name"] == "미지정"][0]
    assert row["usage_pct"] is None
    assert row["capacity"] is None


def test_by_subnet_direct_counts_only_confirmed(dbf):
    _add(dbf, "10.5.0.0/24", "10.5.0.1", direct=1, sw="SW-A")
    _add(dbf, "10.5.0.0/24", "10.5.0.2", direct=0, sw="SW-A")
    _add(dbf, "10.5.0.0/24", "10.5.0.3", direct=1, sw="")     # 이름 없으면 미확인
    stats = wallstats.build(dbf)["facility"]
    row = [x for x in stats["by_subnet"] if x["name"] == "10.5.0.0/24"][0]
    assert row["count"] == 3
    assert row["direct"] == 1


# ── 대역별 IP 리스트업 ────────────────────────────────────────────

def test_subnet_hosts_sorted_numerically(dbf):
    for ip in ("10.9.0.10", "10.9.0.2", "10.9.0.100", "10.9.0.1"):
        _add(dbf, "10.9.0.0/24", ip)
    out = wallstats.facility_subnet_hosts(dbf, "10.9.0.0/24")
    got = [h["ip"] for h in out["hosts"]]
    # 문자열 정렬이면 .10 이 .2 보다 앞에 온다 — 옥텟 숫자 정렬이어야 한다
    assert got == ["10.9.0.1", "10.9.0.2", "10.9.0.10", "10.9.0.100"]


def test_subnet_hosts_fields_and_summary(dbf):
    _add(dbf, "10.9.0.0/24", "10.9.0.1", online=1, sw="TPS-1", port="Gi1/0/25")
    _add(dbf, "10.9.0.0/24", "10.9.0.2", online=0, sw="", direct=0)
    out = wallstats.facility_subnet_hosts(dbf, "10.9.0.0/24")
    assert out["count"] == 2 and out["online"] == 1 and out["offline"] == 1
    assert out["capacity"] == 254
    h = out["hosts"][0]
    assert h["ip"] == "10.9.0.1" and h["online"] is True
    assert h["switch_name"] == "TPS-1" and h["port"] == "Gi1/0/25"


def test_subnet_hosts_excludes_other_subnets(dbf):
    _add(dbf, "10.9.0.0/24", "10.9.0.1")
    _add(dbf, "10.8.0.0/24", "10.8.0.1")
    out = wallstats.facility_subnet_hosts(dbf, "10.9.0.0/24")
    assert [h["ip"] for h in out["hosts"]] == ["10.9.0.1"]


def test_subnet_hosts_truncation_is_flagged(dbf):
    for i in range(1, 8):
        _add(dbf, "10.7.0.0/24", "10.7.0.%d" % i)
    out = wallstats.facility_subnet_hosts(dbf, "10.7.0.0/24", limit=5)
    assert out["truncated"] is True and len(out["hosts"]) == 5
    assert out["total"] == 7                       # 잘려도 전체 수는 알려준다
    # 잘릴 때도 IP 순서의 '앞'이 와야 한다 — SQL LIMIT으로 자르면 임의 5개가 온다
    assert [h["ip"] for h in out["hosts"]] == ["10.7.0.%d" % i for i in range(1, 6)]
    full = wallstats.facility_subnet_hosts(dbf, "10.7.0.0/24")
    assert full["truncated"] is False and len(full["hosts"]) == 7


def test_subnet_hosts_empty_subnet_is_not_error(dbf):
    out = wallstats.facility_subnet_hosts(dbf, "10.255.0.0/24")
    assert out["hosts"] == [] and out["count"] == 0


# ── 화면(wall.js) ─────────────────────────────────────────────────

def _wall_js():
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "web", "static", "wall.js")
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_wall_js_has_subnet_card_and_modal():
    js = _wall_js()
    assert "function subnetCard(" in js
    assert "function openSubnetModal(" in js
    assert "대역별 IP 사용 현황" in js
    assert "/api/wall/facility-subnet?subnet=" in js


def test_wall_js_subnet_click_handler_wired():
    """카드만 그리고 클릭 핸들러를 안 붙이면 '클릭해도 아무 일 없음'이 된다."""
    js = _wall_js()
    assert "[data-subnet]" in js
    assert "data-subnet='" in js


def test_modal_box_is_height_capped_and_scrolls():
    """팝업에 높이 제한이 없으면 IP가 100개 넘을 때 헤더의 ×가 화면 밖으로
    밀려 닫을 수 없다(selfcheck가 클릭 타임아웃으로 잡아낸 실제 결함)."""
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "web", "static", "wall.css")
    with open(p, encoding="utf-8") as f:
        css = f.read()
    box = css[css.index(".wswm__box {"):css.index(".wswm__hd {")]
    assert "max-height" in box
    assert "flex-direction:column" in box
    bd = css[css.index(".wswm__bd {"):]
    assert "overflow-y:auto" in bd.split("}")[0]


def test_wall_js_subnet_uses_esc_not_escHtml():
    """wall.js의 이스케이프 함수는 esc — escHtml은 app.js 것이라 여기선 죽는다."""
    js = _wall_js()
    start = js.index("function subnetTable(")
    block = js[start:js.index("function openSubnetModal(")]
    assert "escHtml(" not in block
    assert "esc(x.name)" in block
