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

# 1. 인덱스에 reconcile 탭 버튼
def test_index_has_reconcile_tab(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b'data-tab="reconcile"' in r.data
    assert "장부 대조".encode("utf-8") in r.data


# 2. reconcile tab-pane 및 컨테이너 요소
def test_index_has_reconcile_pane(client):
    r = client.get("/")
    body = r.data.decode("utf-8")
    assert 'id="tab-reconcile"' in body
    assert 'id="reconcile-summary"' in body
    assert 'id="reconcile-table-body"' in body


# 3. app.js에 reconcile 함수 정의
def test_appjs_has_loadReconcile():
    src = APP_JS.read_text(encoding="utf-8")
    assert "function loadReconcile" in src
    assert "function renderReconcile" in src
    assert "function verdictBadgeClass" in src


# 4. renderReconcile이 escHtml로 XSS 방지
def test_appjs_reconcile_uses_eschtml():
    src = APP_JS.read_text(encoding="utf-8")
    start = src.index("function renderReconcile")
    end = src.index("function ", start + 1)
    body = src[start:end]
    assert "escHtml(" in body


# 5. 탭 전환 핸들러가 reconcile 분기 호출
def test_appjs_tab_wires_reconcile():
    src = APP_JS.read_text(encoding="utf-8")
    assert 'btn.dataset.tab === "reconcile"' in src
    assert "loadReconcile()" in src


# 6. style.css에 info 배지
def test_css_has_info_badge():
    src = STYLE_CSS.read_text(encoding="utf-8")
    assert ".status-badge--info" in src


# ── API 통합 ───────────────────────────────────────────────────────

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
