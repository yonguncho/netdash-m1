# -*- coding: utf-8 -*-
"""현황판 랙뷰 위치 폴백 + 방화벽 통합 + 탭 이름/제거 UI 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_switch_tab_renamed():
    """탭 이름: '스위치 현황' (v3.26.1에서 '스위치 리스트'→'스위치 현황' 재변경)."""
    html = HTML.read_text(encoding="utf-8")
    # v5.2: 사이드바 네비로 이동하며 라벨이 <span class="nav-label">로 감싸짐
    assert 'data-tab="switch"' in html
    assert '<span class="nav-label">스위치 현황</span>' in html
    assert "스위치 리스트" not in html


def test_reconcile_tab_removed():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-tab="reconcile"' not in html
    assert 'id="tab-reconcile"' not in html


def test_dashboard_unifies_firewall_card():
    js = APP_JS.read_text(encoding="utf-8")
    # 통합 방화벽 카드 함수(서버실 카드뷰에서 사용)
    assert "function _fwCardHTML" in js
    assert "_fwCardHTML" in js
    assert "function _deviceRackKeys" in js
    # 위치 폴백: room_rack / location
    assert "room_rack" in js and "위치 미상(미지정)" in js


def test_room_uses_same_card():
    js = APP_JS.read_text(encoding="utf-8")
    # 서버실 카드뷰는 통합 방화벽 카드 사용(스위치와 동일 골격)
    assert "firewalls.map(_fwCardHTML)" in js  # 서버실 카드뷰(현황판과 동일 평면 그리드)


def test_dashboard_shows_tps_switches_only():
    """현황판 = 현장 TPS 스위치 전용. 서버실 소속/서버/방화벽은 전용 탭에만."""
    js = APP_JS.read_text(encoding="utf-8")
    # 필터 헬퍼 존재 + 세 가지 제외 조건
    assert "function _isDashSwitch" in js
    assert "sw.room_rack) return false" in js            # 서버실 위치 제외
    assert '"Server" || dt === "Firewall") return false' in js  # 서버/방화벽 구분 제외
    # 현황판 카드뷰가 필터를 적용
    assert "switches = _dashSwitches(switches)" in js
    # 현황판 카드뷰는 방화벽 카드를 더 이상 붙이지 않음
    assert "fws.map(_fwCardHTML)" not in js
