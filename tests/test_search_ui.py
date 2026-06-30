"""상세/방화벽 테이블 검색 + 카드 클릭 버그 가드 (UI) 테스트."""
from pathlib import Path

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"


def test_table_search_delegation():
    src = APP_JS.read_text(encoding="utf-8")
    assert "tbl-search" in src
    assert "_searchBox" in src
    # 입력 위임으로 행 필터
    assert 'addEventListener("input"' in src


def test_detail_tabs_have_search():
    src = APP_JS.read_text(encoding="utf-8")
    # 포트/MAC/ARP + 방화벽 ARP tbody에 검색 연결
    for tid in ("ports-tbody", "macs-tbody", "arps-tbody", "fw-arp-tbody"):
        assert tid in src


def test_card_click_ignores_action_buttons():
    """상세보기 버튼 클릭이 카드 클릭(수집 모달)을 트리거하지 않아야."""
    src = APP_JS.read_text(encoding="utf-8")
    assert 'closest("[data-action]")' in src
