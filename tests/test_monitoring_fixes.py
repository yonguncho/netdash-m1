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


def test_client_ip_prefers_forwarded(client):
    """접근 로그 IP: 신뢰(로컬/사설) 프록시 경유 시에만 XFF/X-Real-IP 채택.

    보안(L): 외부 직접 접속에서 클라이언트가 헤더를 위조해 감사 로그를 오염시키지
    않도록 remote_addr가 사설/루프백일 때만 포워딩 헤더를 신뢰한다.
    """
    import app as _app
    ctx_app = client.application
    # 신뢰 프록시(사설 remote_addr) → XFF 실사용자 IP 기록
    with ctx_app.test_request_context(
            headers={"X-Forwarded-For": "10.92.170.55, 10.0.0.1"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert _app._client_ip() == "10.92.170.55"
    with ctx_app.test_request_context(
            headers={"X-Real-IP": "10.92.170.66"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        assert _app._client_ip() == "10.92.170.66"
    # 외부(공인) 직접 접속 → XFF 위조 무시하고 remote_addr 기록
    # (8.8.8.8은 실제 공인 = is_private False; 203.0.113.x 문서대역은 파이썬이
    #  is_private True로 취급하므로 부적합)
    with ctx_app.test_request_context(
            headers={"X-Forwarded-For": "1.2.3.4"},
            environ_base={"REMOTE_ADDR": "8.8.8.8"}):
        assert _app._client_ip() == "8.8.8.8"
    with ctx_app.test_request_context(environ_base={"REMOTE_ADDR": "10.0.0.5"}):
        assert _app._client_ip()  # remote_addr 폴백


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
    assert "🔴 연결 끊김" in js                             # 방화벽 카드 배지
    assert "🔴 도달불가" in js                              # 스위치 카드 배지(기존)


def test_topology_hover_highlight():
    js = APP_JS.read_text(encoding="utf-8")
    assert "drop-shadow(0 0 4px #38bdf8)" in js   # 직결 라인 글로우
    assert '"0.12"' in js                         # 무관 링크 페이드
    assert 'nn.style.opacity = nb[nid]' in js     # 무관 노드 페이드
    assert "data-basestroke" in js                # 종류색 복구
