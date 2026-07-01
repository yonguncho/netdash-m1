"""M8: 장부 대조(Reconcile) UI 패널 테스트.

기존 UI 테스트 방식(HTML/정적파일 문자열 검증 + 엔드포인트 통합)을 따른다.
별도 JS 런타임은 없다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"
STYLE_CSS = Path(__file__).parent.parent / "web" / "static" / "style.css"


# ── HTML/정적 파일 검증 ────────────────────────────────────────────

# 1. 장부 대조 탭 UI 제거됨(사용자 요청으로 기능 숨김)
def test_index_reconcile_tab_removed(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b'data-tab="reconcile"' not in r.data
    assert 'id="tab-reconcile"' not in r.data.decode("utf-8")


# 2. 탭 전환 핸들러에서 reconcile 분기 제거됨
def test_appjs_reconcile_tab_unwired():
    src = APP_JS.read_text(encoding="utf-8")
    assert 'btn.dataset.tab === "reconcile"' not in src


# ── API 통합 (백엔드는 유지 — UI만 제거) ────────────────────────────

# 7. /api/reconcile 응답 구조
def test_api_reconcile_endpoint_shape(client):
    r = client.get("/api/reconcile")
    assert r.status_code == 200
    data = r.get_json()
    assert "hosts" in data
    assert "summary" in data
    assert isinstance(data["hosts"], list)
    assert isinstance(data["summary"], dict)


# 8. 장부+실측 적재 후 판정이 응답에 반영
def test_api_reconcile_reflects_data(client):
    from config import get_config
    config = get_config(demo_mode=True)
    db_path = config.get_db_path()

    sid = db.save_switch(db_path, "ACC-SW01", "10.0.0.20", "cisco_ios")
    db.save_ledger_hosts(db_path, [{"ip": "10.0.77.10", "hostname": "WEB-77",
                                    "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"}])
    db.save_hosts(db_path, {"10.0.77.10": {"mac": "aa", "switch_id": sid,
                                           "port": "Gi1/0/5", "located": True}})

    r = client.get("/api/reconcile")
    data = r.get_json()
    match_host = [h for h in data["hosts"] if h["ip"] == "10.0.77.10"]
    assert len(match_host) == 1
    assert match_host[0]["verdict"] == "match"
    assert data["summary"].get("match", 0) >= 1
