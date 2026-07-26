# -*- coding: utf-8 -*-
"""현황 페이지 CSV/TXT 내보내기 + IP 정렬·컬럼 리사이즈 UI 가드."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, exporter

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
CSS = ROOT / "web" / "static" / "style.css"
HTML = ROOT / "web" / "templates" / "index.html"


def _seed(dbp):
    sid = db.save_switch(dbp, "SW-1", "10.1.0.2", "cisco_ios")
    db.update_switch(dbp, sid, hostname="SKBA_RC_4F_SW1", location="A09U27",
                     model="C9300", os_version="17.6", serial="FOC123")
    db.save_firewall(dbp, "FW-1", "fortigate", "10.1.0.1", 443, location="A09U10")
    srv = db.save_server(dbp, "SRV-1", "10.1.0.9", os_type="linux", location="A09U05")
    db.update_server(dbp, srv, hostname="srv1", mac="00:11:22:33:44:55",
                     open_ports="22,443", switch_name="SW-1", switch_port="Gi1/0/1")
    db.save_facility_hosts(dbp, [
        {"subnet": "10.2.0.0/24", "ip": "10.2.0.5", "mac": "AA:BB:CC:00:00:05",
         "switch_name": "SW-1", "port": "Gi1/0/5", "direct": 1, "online": 1},
        {"subnet": "10.2.0.0/24", "ip": "10.2.0.6", "mac": "AA:BB:CC:00:00:06",
         "switch_name": "", "port": "", "online": 0}])


def test_all_datasets_csv_txt(temp_db):
    _seed(temp_db)
    for kind in ("switches", "servers", "firewalls", "serverroom", "facility"):
        for fmt in ("csv", "txt"):
            data, mime, fname = exporter.export(temp_db, kind, fmt)
            text = data.decode("utf-8-sig")
            assert text.strip(), "%s/%s 비어 있음" % (kind, fmt)
            assert fname.endswith("." + fmt)
            assert ("csv" in mime) if fmt == "csv" else ("plain" in mime)
            # 헤더 행이 컬럼 정의와 일치
            cols = exporter.DATASETS[kind][0]
            first = text.splitlines()[0]
            sep = "," if fmt == "csv" else "\t"
            assert first.split(sep)[0].strip('"') == cols[0]


def test_csv_has_bom_for_excel(temp_db):
    _seed(temp_db)
    data, _, _ = exporter.export(temp_db, "switches", "csv")
    assert data.startswith("﻿".encode("utf-8"))   # Excel 한글 깨짐 방지


def test_switch_export_excludes_servers(temp_db):
    _seed(temp_db)
    sid = db.save_switch(temp_db, "AS-SERVER", "10.1.0.77", "unknown")
    db.update_switch(temp_db, sid, device_type="Server")
    rows = exporter.switches_rows(temp_db)
    assert all(r["IP"] != "10.1.0.77" for r in rows)   # 화면과 동일하게 제외


def test_serverroom_export_contains_all_kinds(temp_db):
    _seed(temp_db)
    rows = exporter.serverroom_rows(temp_db)
    kinds = {r["종류"] for r in rows}
    assert {"스위치", "방화벽", "서버"} <= kinds
    assert all(r["랙"] for r in rows)


def test_facility_export_remarks(temp_db):
    _seed(temp_db)
    rows = {r["IP"]: r for r in exporter.facility_rows(temp_db)}
    assert rows["10.2.0.5"]["상태"] == "온라인"
    assert rows["10.2.0.6"]["상태"] == "연결 실패"
    assert "미수집" in rows["10.2.0.6"]["비고"] or "오프라인" in rows["10.2.0.6"]["비고"]


def test_export_endpoint(client):
    r = client.get("/api/export/switches?format=csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["Content-Type"]
    assert "switches.csv" in r.headers["Content-Disposition"]
    r2 = client.get("/api/export/facility?format=txt")
    assert r2.status_code == 200 and "facility.txt" in r2.headers["Content-Disposition"]
    assert client.get("/api/export/nope").status_code == 404


def test_export_buttons_present():
    html = HTML.read_text(encoding="utf-8")
    for kind in ("serverroom", "servers", "firewalls", "switches", "facility"):
        assert 'data-export="%s"' % kind in html
    assert html.count('class="btn btn--secondary nd-export"') >= 5
    js = APP_JS.read_text(encoding="utf-8")
    assert "nd-export" in js and "/api/export/" in js


def test_column_resize_and_ip_sort_ui():
    js = APP_JS.read_text(encoding="utf-8")
    assert "col-resizer" in js and "nd_colw:" in js      # 컬럼 폭 조절·저장
    assert "ip-sort-arrow" in js and "ipToInt" in js     # IP 정렬
    css = CSS.read_text(encoding="utf-8")
    assert ".col-resizer" in css and ".data-table.col-sized" in css
