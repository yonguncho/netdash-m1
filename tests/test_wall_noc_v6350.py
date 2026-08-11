# -*- coding: utf-8 -*-
"""v6.35.0 — 설비 상태/결과 정리 + 진단 팝업 확대 + 스위치 온도 컬럼 제거 +
관제 NOC 정돈(벤더 사례 조사 반영: Grafana BP·SolarWinds NOC·FortiAnalyzer)."""
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_facility_three_state_badge():
    """직접 연결 미확인 + 응답 있음 = '연결됨'이 아니라 '확인 필요'(사용자 지적)."""
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function facStateBadge" in js and "확인 필요" in js
    fn = js[js.index("function facStateBadge"):js.index("function _renderFacilityRows")]
    assert "_facIsDirect" in fn and "reachBadge" in fn


def test_facility_result_column_button_only():
    """결과 컬럼은 [진단 결과] 버튼만 — 요약 단어는 상태 배지가 담당."""
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    rows_fn = js[js.index("function _renderFacilityRows"):]
    rows_fn = rows_fn[:rows_fn.index("\nfunction ")]
    assert "resWord" not in rows_fn
    assert ">진단 결과</button>" in rows_fn


def test_diagnose_modal_bigger():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "max-width:940px" in html, "진단 팝업 확대(사용자: 글씨가 작다)"
    assert "font-size:14px" in html.split('id="diag-result"')[1][:220]


def test_wall_noc_cleanup_markers():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    # 설명 텍스트 → ⓘ 툴팁(패널당 질문 하나)
    assert "function tidyHints" in js and ".winfo" in css
    # 수집 전 카드 숨김 + 요약 한 줄
    assert "wempty-note" in js and ".wempty-note" in css
    # 긴 목록 표준 높이(행 정렬)
    assert "wcard--tall" in js and ".wcard--tall" in css
    # 상단 타일 슬림 스탯 바
    assert ".wall-tiles { display:flex" in css
