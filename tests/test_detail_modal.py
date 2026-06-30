"""상세 정보 — 넓은 중앙 모달 + 요약 통계 UI 테스트."""
from pathlib import Path

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
CSS = ROOT / "web" / "static" / "style.css"
HTML = ROOT / "web" / "templates" / "index.html"


def test_summary_element_exists():
    assert 'id="detail-summary"' in HTML.read_text(encoding="utf-8")


def test_summary_render_function():
    src = APP_JS.read_text(encoding="utf-8")
    assert "function renderDetailSummary" in src
    # 요약 항목들
    for label in ("전체 포트", "Up", "Down", "MAC", "ARP", "VLAN"):
        assert label in src


def test_detail_panel_centered_modal_css():
    css = CSS.read_text(encoding="utf-8")
    # 중앙 정렬 모달(translate)로 전환됐는지
    assert "translate(-50%, -50%)" in css
    assert ".detail-summary" in css
