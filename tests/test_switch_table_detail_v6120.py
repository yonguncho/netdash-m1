"""스위치 현황 표에도 '상세보기' 버튼 (v6.12.0).

지금까지 상세보기는 현황판(대시보드) 카드와 랙뷰에만 있었다. 스위치 현황
페이지는 등록 장비 전체를 보는 곳인데, 여기서 포트/MAC/ARP를 보려면 현황판으로
돌아가야 했다. 클릭 핸들러(detail-switch)는 페이지 공용이므로 버튼만 추가하면 된다.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
HTML = ROOT / "web" / "templates" / "index.html"


def _fn_body(src, name):
    """최상위 function <name>( ... ) 본문을 다음 최상위 function 직전까지 잘라낸다."""
    start = src.index("function " + name + "(")
    nxt = src.find("\nfunction ", start + 1)
    return src[start:nxt if nxt != -1 else len(src)]


def test_switch_table_row_has_detail_button():
    body = _fn_body(APP_JS.read_text(encoding="utf-8"), "renderSwitchTable")
    assert "data-action='detail-switch'" in body
    assert "상세보기" in body


def test_switch_table_detail_button_passes_full_switch_payload():
    """openDetailPanel은 sw.id/name/ip/hostname을 읽으므로 id만 넘기면 제목이 빈다."""
    body = _fn_body(APP_JS.read_text(encoding="utf-8"), "renderSwitchTable")
    idx = body.index("data-action='detail-switch'")
    tail = body[idx:idx + 200]
    assert "payloadAttr" in tail, "detail-switch에 payload가 아니라 data-id만 넘기고 있다"


def test_switch_table_keeps_existing_actions():
    """상세보기를 끼워 넣으면서 기존 작업 버튼을 떨어뜨리지 않았는지."""
    body = _fn_body(APP_JS.read_text(encoding="utf-8"), "renderSwitchTable")
    for action in ("collect-switch", "edit-switch", "diagnose-switch",
                   "terminal-switch", "delete-switch"):
        assert "data-action='" + action + "'" in body, action


def test_detail_switch_action_still_routed():
    """공용 위임 핸들러가 살아 있어야 새 버튼이 동작한다."""
    src = APP_JS.read_text(encoding="utf-8")
    idx = src.index('case "detail-switch"')
    assert "openDetailPanel" in src[idx:idx + 160]


def test_actions_column_tooltip_lists_detail():
    html = HTML.read_text(encoding="utf-8")
    idx = html.index('id="sw-check-all"')
    head = html[idx:idx + 800]  # 스위치 표 헤더 행
    assert "상세보기" in head
