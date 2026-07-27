# -*- coding: utf-8 -*-
"""대량 선택 시 일괄 수집 팝업이 조작 불가가 되던 문제 + 팝업/버튼 정돈.

증상: 스위치 전체 선택 후 '정보 수집'을 누르면 선택된 스위치 이름이 전부
      나열돼 팝업이 화면 밖으로 자라고, 계정 입력칸과 '수집 시작' 버튼을
      누를 수 없었다.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")


def _rule(selector):
    """CSS에서 '정확히 그 선택자'의 기본 규칙 본문을 꺼낸다(파생 규칙 제외)."""
    m = re.search(r"\n" + re.escape(selector) + r"\s*\{([^}]*)\}", CSS)
    assert m, "CSS 규칙을 찾지 못함: " + selector
    return m.group(1)


# ── 팝업이 화면을 넘어가지 않는 구조 ──────────────────────────────
def test_modal_box_is_height_bounded_column():
    box = _rule(".modal__box")
    assert "max-height" in box, "팝업 높이 제한이 없어 내용이 길면 화면 밖으로 자란다"
    assert "flex-direction: column" in box


def test_modal_body_scrolls_not_the_box():
    body = _rule(".modal__body")
    assert "overflow-y: auto" in body, "본문이 스크롤되지 않으면 푸터가 밀려난다"
    assert "min-height: 0" in body, "flex 자식은 min-height:0 이 없으면 축소되지 않는다"
    assert "flex: 1 1 auto" in body


def test_modal_header_and_footer_stay_visible():
    for sel in (".modal__header", ".modal__footer"):
        assert "flex: 0 0 auto" in _rule(sel), sel + " 가 축소되면 버튼이 사라진다"


def test_target_list_box_is_bounded():
    info = _rule(".switch-info-box")
    assert "max-height" in info and "overflow-y: auto" in info


# ── 선택 목록 요약 ────────────────────────────────────────────────
def test_bulk_target_info_is_shared_and_capped():
    assert "function _bulkTargetInfo(" in APPJS
    assert "var _BULK_PREVIEW" in APPJS
    # 두 진입점(현황판·스위치 현황) 모두 공용 요약을 쓴다
    assert APPJS.count("_bulkTargetInfo(ids)") >= 2, \
        "한쪽만 고치면 다른 화면에서 같은 문제가 남는다"


def test_no_raw_name_dump_left():
    """선택된 이름을 통째로 innerHTML에 붓는 코드가 남아 있으면 안 된다."""
    assert 'names.map(escHtml).join(", ") + "</span>"' not in APPJS


def test_full_list_is_collapsed_by_default():
    block = APPJS[APPJS.index("function _bulkTargetInfo("):APPJS.index("function _updateBulkCollectBtn(")]
    assert "<details class='target-list'" in block
    assert "open>" not in block, "기본으로 펼쳐지면 입력칸이 다시 밀려난다"
    assert "target-list__items" in block


def test_bulk_modal_still_has_all_controls():
    """요약으로 바뀌어도 계정 입력·옵션·시작 버튼은 그대로여야 한다."""
    box = HTML[HTML.index('id="modal-bulk-collect"'):HTML.index('id="modal-diagnose"')]
    for el in ("bulk-cred-info", "bulk-username", "bulk-password", "bulk-enable",
               "bulk-persist", "bulk-remember", "btn-bulk-start"):
        assert 'id="%s"' % el in box, el


# ── 버튼 정돈(고급화) ─────────────────────────────────────────────
def test_buttons_have_press_and_focus_feedback():
    base = _rule(".btn")
    assert "user-select: none" in base
    assert "white-space: nowrap" in base, "버튼 라벨이 줄바꿈되면 툴바가 흐트러진다"
    assert ".btn:active:not(:disabled)" in CSS, "클릭 반응이 없으면 먹었는지 알 수 없다"
    assert ".btn:focus-visible" in CSS


def test_modal_inputs_have_focus_ring():
    m = re.search(r"\.modal__body input:focus[^{]*\{([^}]*)\}", CSS)
    assert m and "box-shadow" in m.group(1), "입력 포커스가 보이지 않으면 어디를 치는지 모른다"


def test_checkbox_uses_brand_color():
    m = re.search(r'\.modal__body input\[type="checkbox"\]\s*\{([^}]*)\}', CSS)
    assert m and "accent-color" in m.group(1)


def test_reduced_motion_respected():
    assert "prefers-reduced-motion" in CSS, "애니메이션을 끌 수 없으면 접근성 문제가 된다"
