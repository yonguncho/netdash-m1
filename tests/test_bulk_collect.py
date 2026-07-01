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

    def fake(db_path, sid, u, p):
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
                        lambda db_path, sid, u, p: {"status": "queued", "switch_id": sid})
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
                        lambda db_path, sid, u, p: {"status": "queued", "switch_id": sid})
    id1 = _reg(client, "10.9.9.7", "C")
    r = client.post("/api/switches/bulk-collect",
                    json={"ids": [id1], "username": "a" * 5000, "password": "b"})
    assert r.status_code == 400


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
