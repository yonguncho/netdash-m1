# -*- coding: utf-8 -*-
"""v3.41: 접근로그 IP·마지막 수집·방화벽 도달성·UI 식별 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_last_collected_set_on_done(temp_db):
    """FIX: 수집 성공 시 last_collected 갱신(이전엔 항상 비어 있었음)."""
    sid = db.save_switch(temp_db, "SW-LC", "10.0.0.8", "cisco_ios")
    assert not db.get_switch(temp_db, sid)["last_collected"]
    db.set_switch_status(temp_db, sid, "done")
    assert db.get_switch(temp_db, sid)["last_collected"]  # 타임스탬프 기록됨
    # 실패 시엔 last_collected 유지(마지막 '성공' 시각 의미 보존)
    ts = db.get_switch(temp_db, sid)["last_collected"]
    db.set_switch_status(temp_db, sid, "failed", error="x")
    assert db.get_switch(temp_db, sid)["last_collected"] == ts


def test_client_ip_ignores_forwarded_headers_by_default(client, monkeypatch):
    """포워딩 헤더는 **설정에 명시한 프록시**에서 온 요청일 때만 채택한다.

    보안: 이 제품은 폐쇄망 전용이라 정상 클라이언트가 전부 사설 IP다. 예전처럼
    "remote_addr가 사설이면 신뢰"하면 그 조건이 공격자 집단과 정확히 일치해,
    누구나 X-Forwarded-For를 붙여 감사 로그의 행위자를 위조하고(감사 추적의 유일한
    근거) 레이트리밋 키까지 바꿔 제한을 우회할 수 있었다.
    """
    import app as _app
    ctx_app = client.application
    # 기본(신뢰 프록시 미설정) → 헤더 무시, 소켓 주소 기록
    with ctx_app.test_request_context(
            headers={"X-Forwarded-For": "10.92.170.55, 10.0.0.1"},
            environ_base={"REMOTE_ADDR": "10.0.0.9"}):
        assert _app._client_ip() == "10.0.0.9"
    with ctx_app.test_request_context(
            headers={"X-Real-IP": "10.92.170.66"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        assert _app._client_ip() == "10.0.0.1"
    # 공인 직접 접속도 동일하게 위조 무시
    with ctx_app.test_request_context(
            headers={"X-Forwarded-For": "1.2.3.4"},
            environ_base={"REMOTE_ADDR": "8.8.8.8"}):
        assert _app._client_ip() == "8.8.8.8"
    with ctx_app.test_request_context(environ_base={"REMOTE_ADDR": "10.0.0.5"}):
        assert _app._client_ip()  # remote_addr 폴백


def test_client_ip_honors_configured_trusted_proxy(client, monkeypatch):
    """리버스 프록시를 쓰는 배포는 app.trusted_proxies로 명시하면 동작한다."""
    import app as _app
    monkeypatch.setattr(_app, "_trusted_proxies", lambda: {"10.0.0.1"})
    ctx_app = client.application
    with ctx_app.test_request_context(
            headers={"X-Forwarded-For": "10.92.170.55, 10.0.0.1"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        assert _app._client_ip() == "10.92.170.55"
    # 목록에 없는 주소에서 온 헤더는 여전히 무시
    with ctx_app.test_request_context(
            headers={"X-Forwarded-For": "10.92.170.55"},
            environ_base={"REMOTE_ADDR": "10.0.0.2"}):
        assert _app._client_ip() == "10.0.0.2"


def test_reachability_covers_firewalls(temp_db, monkeypatch):
    """도달성 감시가 방화벽(관리 포트)도 확인 → get_fw_state 반영 + 전이 이벤트."""
    from core import reachability as r
    db.save_switch(temp_db, "SW-R", "10.0.0.9", "cisco_ios")
    fid = db.save_firewall(temp_db, "FW-R", "fortigate", "10.0.0.99", port=443)

    monkeypatch.setattr(r, "_check_tcp", lambda ip, port=22, timeout=3: True)
    r._sweep(temp_db)                      # 첫 관측: 기준 설정
    assert r.get_fw_state().get(fid) is True

    monkeypatch.setattr(r, "_check_tcp", lambda ip, port=22, timeout=3: False)
    r._sweep(temp_db)                      # 도달→불가 전이
    assert r.get_fw_state().get(fid) is False
    events = db.list_device_events(temp_db, limit=20)
    assert any(e["kind"] == "firewall_unreachable" for e in events)


def test_fw_table_and_cards_show_reachability():
    html = HTML.read_text(encoding="utf-8")
    assert "<th>연결 상태</th>" in html
    assert "<th>인터페이스</th><th>ARP</th>" not in html   # 컬럼 제거
    js = APP_JS.read_text(encoding="utf-8")
    assert "🟢 연결됨" in js and "🔴 끊김" in js            # 방화벽 표
    # 카드 배지: 빨간 원(reach-dot)이 반짝이는 마크업 + 텍스트
    assert "reach-dot" in js and "reach-down" in js
    assert "연결 끊김</span>" in js                         # 방화벽 카드 배지
    assert "도달불가</span>" in js                          # 스위치 카드 배지


def test_topology_hover_highlight():
    js = APP_JS.read_text(encoding="utf-8")
    assert "drop-shadow(0 0 4px #38bdf8)" in js   # 직결 라인 글로우
    assert '"0.12"' in js                         # 무관 링크 페이드
    assert 'nn.style.opacity = nb[nid]' in js     # 무관 노드 페이드
    assert "data-basestroke" in js                # 종류색 복구
