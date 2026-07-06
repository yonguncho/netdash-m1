# -*- coding: utf-8 -*-
"""벤더 표준화(별칭→표준 값) + 버전 백필 + UI 통일 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, collector

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_canonical_vendor():
    c = collector.canonical_vendor
    assert c("cisco") == "cisco_ios"
    assert c("extreme") == "extreme_exos"
    assert c("nexus") == "cisco_nxos"
    assert c("extreme_exos") == "extreme_exos"   # 이미 표준이면 그대로
    assert c("unknown") == "unknown"             # unknown은 유지(자동 학습 대상)
    assert c("") == "unknown"


def test_normalize_vendor_values(temp_db):
    a = db.save_switch(temp_db, "A", "10.0.0.1", "cisco")
    b = db.save_switch(temp_db, "B", "10.0.0.2", "extreme")
    csw = db.save_switch(temp_db, "C", "10.0.0.3", "extreme_exos")
    u = db.save_switch(temp_db, "U", "10.0.0.4", "unknown")
    n = db.normalize_vendor_values(temp_db)
    assert n == 2   # cisco, extreme만 변경
    assert db.get_switch(temp_db, a)["vendor"] == "cisco_ios"
    assert db.get_switch(temp_db, b)["vendor"] == "extreme_exos"
    assert db.get_switch(temp_db, csw)["vendor"] == "extreme_exos"
    assert db.get_switch(temp_db, u)["vendor"] == "unknown"


def test_manual_add_stores_canonical(client):
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.77.0.1", "name": "V1", "vendor": "extreme"}).get_json()["switch_id"]
    switches = client.get("/api/state").get_json()["switches"]
    assert [s for s in switches if s["id"] == sid][0]["vendor"] == "extreme_exos"


def test_backfill_version_from_config(temp_db):
    sid = db.save_switch(temp_db, "BF", "10.0.0.9", "cisco_ios")
    db.save_config_backup(temp_db, sid, "hostname BF\nversion 15.2(7)E3\ninterface Gi1/0/1")
    assert db.backfill_versions_from_config(temp_db) == 1
    assert db.get_switch(temp_db, sid)["os_version"] == "IOS 15.2(7)E3"
    # 이미 값 있으면 건드리지 않음
    assert db.backfill_versions_from_config(temp_db) == 0


def test_vendor_ui_unified():
    html = HTML.read_text(encoding="utf-8")
    # 수정/추가 모달의 옵션 값이 표준 값
    assert 'value="cisco_ios"' in html and 'value="extreme_exos"' in html
    assert 'value="cisco"' not in html and 'value="extreme"' not in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "_canonVendor" in js and "_vendorLabel" in js
    # 현황판 검색이 IP 포함
    assert "s.ip, s.host, s.name" in js
