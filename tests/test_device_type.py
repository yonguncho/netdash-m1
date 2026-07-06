# -*- coding: utf-8 -*-
"""장비 구분(device_type) — 저장/수정/일괄 변경 + UI 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_device_type_roundtrip(temp_db):
    sid = db.save_switch(temp_db, "SW-T", "10.0.0.5", "cisco_ios")
    db.update_switch(temp_db, sid, device_type="L2 Switch")
    assert db.get_switch(temp_db, sid)["device_type"] == "L2 Switch"
    db.update_switch(temp_db, sid, device_type="")   # 비우기 허용
    assert db.get_switch(temp_db, sid)["device_type"] == ""


def test_manual_add_with_device_type(client):
    r = client.post("/api/switches/manual",
                    json={"ip": "10.66.0.1", "name": "BB-01", "vendor": "nexus",
                          "device_type": "BackBone"})
    sid = r.get_json()["switch_id"]
    switches = client.get("/api/state").get_json()["switches"]
    sw = [s for s in switches if s["id"] == sid][0]
    assert sw["device_type"] == "BackBone"


def test_put_update_device_type(client):
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.66.0.2", "name": "T2", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.put("/api/switches/%d" % sid, json={"device_type": "L3 Switch"})
    assert r.get_json()["ok"]
    switches = client.get("/api/state").get_json()["switches"]
    assert [s for s in switches if s["id"] == sid][0]["device_type"] == "L3 Switch"


def test_bulk_set_type(client):
    a = client.post("/api/switches/manual",
                    json={"ip": "10.66.0.3", "name": "T3", "vendor": "cisco"}).get_json()["switch_id"]
    b = client.post("/api/switches/manual",
                    json={"ip": "10.66.0.4", "name": "T4", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.post("/api/switches/bulk-set-type",
                    json={"ids": [a, b], "device_type": "L2 Switch"})
    assert r.get_json()["updated"] == 2
    # 화이트리스트 밖 값 거부
    r2 = client.post("/api/switches/bulk-set-type",
                     json={"ids": [a], "device_type": "<script>"})
    assert r2.status_code == 400


def test_edit_rate_limits_allow_continuous_editing():
    """구분 인라인 변경(PUT) 연속 편집이 rate limit에 걸리지 않도록 한도 상향."""
    import inspect
    import app as _app
    src = inspect.getsource(_app.create_app)
    assert '"update_switch", max_requests=240' in src   # 대당 1회 PUT — 240대/분
    assert '"delete_switch", max_requests=60' in src
    assert '"bulk_set_type", max_requests=60' in src


def test_switch_column_filters_removed():
    """v3.36.2: 컬럼 필터 행 전체 제거(드롭다운·초기화 포함) — 검색은 상단 통합 검색창 하나."""
    html = HTML.read_text(encoding="utf-8")
    assert 'id="sw-filter-row"' not in html
    assert 'sw-colf' not in html
    assert 'id="btn-sw-filter-clear"' not in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "_applyColFilters" not in js and "sw-colf" not in js
    assert "_applySwSearch" in js               # 상단 검색창 = 전 컬럼 통합 검색


def test_device_type_ui():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="sw-bulk-type"' in html and 'id="btn-sw-apply-type"' in html
    assert 'id="add-devtype"' in html
    assert "BackBone" in html and "L4 Switch" in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "sw-type-sel" in js and "_DEVICE_TYPES" in js
    assert "/api/switches/bulk-set-type" in js
