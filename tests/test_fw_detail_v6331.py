# -*- coding: utf-8 -*-
"""v6.33.1 — 방화벽 상세 빈 화면 회귀(사용자 신고).

원인: fwStatusHtml 초기 가드가 부하 지표(CPU/세션/VPN/정책/센서)만 보고 조기
반환 → SSH get sys status로 모델·버전만 수집된 방화벽은 모델·펌웨어·수명주기
정보가 있는데도 '수집된 상태 정보가 없습니다'만 나와 상세가 비어 보였다.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _js():
    return (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


def test_no_early_return_before_model_facts():
    js = _js()
    fn = js[js.index("function fwStatusHtml"):js.index("function _fmtBytes")]
    # 조기 반환 가드 제거 — hasLoad 변수 방식(모델만 있어도 상세를 그린다)
    assert "if (!m.cpu_pct && !m.sessions" not in fn
    assert "hasLoad" in fn
    # 모델 fact + 펌웨어는 목록 값(fw_version) 폴백
    assert 'facts.push(["모델", fw.fw_model])' in fn
    assert "m.version || fw.fw_version" in fn
    # 정말 아무것도 없을 때만 안내문
    assert "수집된 상태 정보가 없습니다" in fn
    # 부하만 없을 땐 사유 한 줄 + 수집된 정보 표시
    assert "부하·세션 지표는 아직 수집 전" in fn


def test_detail_scrolls_into_view():
    """표가 길면 상세가 화면 밖(하단)에 그려져 '안 나온다'로 보인다 — 스크롤 필수."""
    js = _js()
    fn = js[js.index("function showFirewallDetail"):js.index("function fwStatusHtml")]
    assert "scrollIntoView" in fn
