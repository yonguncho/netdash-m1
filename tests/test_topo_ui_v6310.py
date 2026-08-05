# -*- coding: utf-8 -*-
"""v6.31.0 — 토폴로지 도구 아이콘 SVG화 + 선 양끝 인터페이스 도트.

사용자 요청 ① 토폴로지 도구도 이모지 말고 세련되게 ② 선 호버 합본 툴팁 대신
양끝 도트에 각 장비의 포트를 따로 표시(어느 포트에 각각 연결됐는지 구분).
"""
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _topo_block():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r'<div id="tab-topology".*?<!-- 계정 입력 모달 -->', html, re.S)
    assert m, "토폴로지 탭 블록"
    return m.group(0)


def test_topology_toolbar_no_emoji_uses_svg():
    block = _topo_block()
    for e in ("✏", "\U0001F3E2", "\U0001F500", "⤢", "\U0001F4CA", "\U0001F4BE",
              "↩", "\U0001F5D1", "\U0001F517"):   # ✏🏢🔀⤢📊💾↩🗑🔗
        assert e not in block, "토폴로지 툴바에 이모지 잔재: %r" % e
    assert block.count('class="ticon"') >= 8, "도구 버튼마다 SVG 아이콘"


def test_appjs_topology_no_emoji():
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    for e in ("✏", "\U0001F517", "↩"):
        assert e not in js, "app.js에 토폴로지 이모지 잔재: %r" % e
    assert "_TICO" in js, "JS 갱신 라벨용 아이콘 맵"
    css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert ".ticon" in css


def test_edge_port_dots():
    """선 양끝 도트 — 각 도트에 그 장비의 포트만 툴팁. 미확인이면 회색."""
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "tport-dot" in js
    assert "인터페이스: " in js and "미확인" in js
    # 꺾은선은 끝 구간 방향이 달라 끝별 안쪽 벡터를 따로 계산해야 한다
    assert "aIn" in js and "bIn" in js
    css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert ".tport-dot" in css
