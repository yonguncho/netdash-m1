# -*- coding: utf-8 -*-
"""공통 계정 일괄 정보 수집 — 엔드포인트 + UI 요소 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def _reg(client, ip, name):
    return client.post("/api/switches/manual",
                       json={"ip": ip, "name": name, "vendor": "cisco"}).get_json()["switch_id"]


def test_bulk_collect_queues_all(client, monkeypatch):
    from core import collector
    calls = []

    def fake(db_path, sid, u, p, enable_secret=None):
        calls.append((sid, u, p))
        return {"status": "queued", "switch_id": sid}

    monkeypatch.setattr(collector, "collect_switch", fake)
    id1 = _reg(client, "10.9.9.1", "A")
    id2 = _reg(client, "10.9.9.2", "B")
    r = client.post("/api/switches/bulk-collect",
                    json={"ids": [id1, id2], "username": "admin", "password": "secret123"})
    assert r.status_code == 202
    b = r.get_json()
    assert b["ok"] and b["queued_count"] == 2 and b["skipped_count"] == 0
    assert {c[0] for c in calls} == {id1, id2}
    # 공통 계정이 각 호출에 동일 전달
    assert all(c[1] == "admin" and c[2] == "secret123" for c in calls)


def test_bulk_collect_skips_unknown_id(client, monkeypatch):
    from core import collector
    monkeypatch.setattr(collector, "collect_switch",
                        lambda db_path, sid, u, p, enable_secret=None: {"status": "queued", "switch_id": sid})
    id1 = _reg(client, "10.9.9.5", "A")
    r = client.post("/api/switches/bulk-collect",
                    json={"ids": [id1, 999999], "username": "admin", "password": "secret123"})
    b = r.get_json()
    assert b["queued_count"] == 1 and b["skipped_count"] == 1


def test_bulk_collect_requires_ids(client):
    r = client.post("/api/switches/bulk-collect",
                    json={"ids": [], "username": "a", "password": "b"})
    assert r.status_code == 400


def test_bulk_collect_rejects_invalid_credentials(client, monkeypatch):
    """잘못된(과도하게 긴/부적합) 자격증명은 400 (데모 모드와 무관하게 검증)."""
    from core import collector
    monkeypatch.setattr(collector, "collect_switch",
                        lambda db_path, sid, u, p, enable_secret=None: {"status": "queued", "switch_id": sid})
    id1 = _reg(client, "10.9.9.7", "C")
    r = client.post("/api/switches/bulk-collect",
                    json={"ids": [id1], "username": "a" * 5000, "password": "b"})
    assert r.status_code == 400


def test_dash_status_filter_tabs():
    """현황판 상태 필터 탭(전체/정상/오류/미수집) — 필터된 리스트만 선택·재수집."""
    html = HTML.read_text(encoding="utf-8")
    assert 'data-sfilter="failed"' in html and 'data-sfilter="new"' in html
    assert 'id="sf-cnt-failed"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "_swStatusBucket" in js and "_applyStatusFilter" in js
    assert "_dashStatusFilter" in js
    # 필터 전환 시 이전 선택 해제(다른 리스트 오수집 방지)
    assert js.index("_bulkSel = {};  // 필터 전환") > 0


def test_rack_group_select_ui():
    """랙 뷰 구역별 일괄 선택 버튼 — 그 구역만 '정보 수집(N)'로 재수집."""
    js = APP_JS.read_text(encoding="utf-8")
    assert "rack-group-sel" in js
    assert "구역 전체 선택" in js and "구역 선택 해제" in js
    # 선택된 유닛 하이라이트 + 수집 버튼 카운트 갱신
    assert "outline:2px solid #38bdf8" in js
    assert js.count("_updateBulkCollectBtn") >= 3


def test_dash_header_credentials_ui():
    """상단 공통 계정 입력(팝업 없이 즉시 일괄 수집) UI + 로직."""
    html = HTML.read_text(encoding="utf-8")
    assert 'id="dash-cred-user"' in html and 'id="dash-cred-pass"' in html
    assert 'id="dash-cred-persist"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "_runBulkCollect" in js
    assert "dash-cred-user" in js  # 상단 계정 있으면 팝업 생략 경로


def test_dash_bulk_delete_ui_present():
    """현황판 선택 삭제 버튼(수집 선택 체크박스 공용) + 핸들러."""
    html = HTML.read_text(encoding="utf-8")
    assert 'id="btn-dash-bulk-delete"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "btn-dash-bulk-delete" in js
    # 선택 삭제도 bulk-delete API 재사용
    assert js.count("/api/switches/bulk-delete") >= 2


def test_bulk_collect_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="btn-bulk-collect"' in html
    assert 'id="modal-bulk-collect"' in html
    assert 'id="btn-bulk-start"' in html
    assert 'id="dash-check-all"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "/api/switches/bulk-collect" in js
    assert "sw-collect-check" in js
    assert "_bulkSel" in js
