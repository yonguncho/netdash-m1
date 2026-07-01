# -*- coding: utf-8 -*-
"""현황판 랙뷰 위치 폴백 + 방화벽 통합 + 탭 이름/제거 UI 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_switch_tab_renamed():
    html = HTML.read_text(encoding="utf-8")
    assert "스위치 리스트" in html
    # 탭 버튼 텍스트가 '스위치 현황'이 아니어야
    assert '>스위치 현황</button>' not in html


def test_reconcile_tab_removed():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-tab="reconcile"' not in html
    assert 'id="tab-reconcile"' not in html


def test_dashboard_unifies_firewall_card():
    js = APP_JS.read_text(encoding="utf-8")
    # 통합 방화벽 카드 함수
    assert "function _fwCardHTML" in js
    # 현황판 카드/랙뷰가 방화벽 포함
    assert "_fwCardHTML" in js
    assert "function _deviceRackKeys" in js
    # 위치 폴백: room_rack / location
    assert "room_rack" in js and "위치 미상(미지정)" in js


def test_room_uses_same_card():
    js = APP_JS.read_text(encoding="utf-8")
    # 서버실/현황판 모두 동일한 통합 방화벽 카드 사용 → 스위치와 통일
    assert "firewalls.map(_fwCardHTML)" in js
    assert "fws.map(_fwCardHTML)" in js  # 현황판 카드뷰
