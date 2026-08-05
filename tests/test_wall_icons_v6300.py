# -*- coding: utf-8 -*-
"""v6.30.0 — 관제 UI 벤더 톤 개편(사용자: "이런 아이콘 말고 세련되게").

이모지는 OS·폰트마다 다르게 그려져 관제 화면 톤을 깬다 → 라인 SVG 아이콘
(1em·currentColor)으로 전면 교체. 이모지가 다시 스며들면 여기서 잡는다.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent

_EMOJI = ("\U0001F6E0", "\U0001F4FA", "\U0001F50C", "⟳", "◱",
          "⚙", "\U0001F947", "\U0001F4CA")   # 🛠 📺 🔌 ⟳ ◱ ⚙ 🥇 📊


def test_wall_js_no_emoji_uses_svg_icons():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    for e in _EMOJI:
        assert e not in js, "wall.js에 이모지 잔재: %r" % e
    assert "function ico(" in js and "_ICO" in js
    for name in ("sliders", "monitor", "refresh", "expand", "eyeoff", "port"):
        assert "%s:" % name in js, "아이콘 누락: " + name


def test_wall_html_header_and_css():
    html = (ROOT / "web" / "templates" / "wall.html").read_text(encoding="utf-8")
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    for e in _EMOJI:
        assert e not in html
    assert "wall-logo__mark" in html, "SVG 로고 마크"
    assert "wall-live" in html, "LIVE 인디케이터"
    assert ".ico {" in css and "1em" in css
    # 탭 언더라인 방식(벤더 공통 문법) — 활성 탭은 아래 액센트 선
    assert "border-bottom-color:#22d3ee" in css
