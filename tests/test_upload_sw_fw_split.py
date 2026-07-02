# -*- coding: utf-8 -*-
"""엑셀 업로드 시 hostname의 SW/FW로 스위치·방화벽 구분 + 방화벽 일괄등록."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


def test_import_firewalls_bulk(temp_db):
    rows = [{"ip": "10.0.0.1", "name": "CORE-FW-01", "hostname": "core-fw-01", "location": "A09U27"}]
    ids = db.import_firewalls_bulk(temp_db, rows)
    assert len(ids) == 1
    fws = db.list_firewalls(temp_db)
    assert fws[0]["host"] == "10.0.0.1" and fws[0]["vendor"] == "unknown"
    assert fws[0]["location"] == "A09U27"


def _make_xlsx(tmp_path, rows):
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active
    for r in rows:
        ws.append(r)
    p = tmp_path / "inv.xlsx"
    wb.save(str(p))
    return str(p)


def test_upload_fw_word_boundary(client, tmp_path):
    """회귀(Opus): 'fw' 부분일치 오분류 방지 — GBFW-SW01은 스위치, FW01은 방화벽."""
    path = _make_xlsx(tmp_path, [
        ["hostname", "ip"],
        ["GBFW-SW01", "10.11.0.1"],      # 'fw' 포함이지만 토큰 경계 아님 + SW 명시 → 스위치
        ["SWFW-CORE", "10.11.0.2"],      # fw가 경계 없이 붙음 → 스위치
        ["FW01", "10.11.0.3"],           # fw+숫자 → 방화벽
        ["DMZ-FW-01", "10.11.0.4"],      # -fw- → 방화벽
    ])
    with open(path, "rb") as f:
        r = client.post("/api/upload", data={"file": (f, "inv.xlsx")},
                        content_type="multipart/form-data")
    assert r.status_code == 201
    b = r.get_json()
    assert len(b["imported_switch_ids"]) == 2
    assert len(b["imported_firewall_ids"]) == 2


def test_upload_splits_sw_and_fw(client, tmp_path):
    # name 열은 없고 hostname으로만 구분 → SW/FW
    path = _make_xlsx(tmp_path, [
        ["hostname", "ip", "location"],
        ["TPS-F1B02_1F01_SW1", "10.10.0.1", "A01U10"],
        ["DMZ-FW-01", "10.10.0.2", "A01U11"],
        ["EDGE-FW-02", "10.10.0.3", ""],
    ])
    with open(path, "rb") as f:
        r = client.post("/api/upload", data={"file": (f, "inv.xlsx")},
                        content_type="multipart/form-data")
    assert r.status_code == 201, r.get_data(as_text=True)
    b = r.get_json()
    assert len(b["imported_switch_ids"]) == 1   # SW1
    assert len(b["imported_firewall_ids"]) == 2  # 2 FW
    assert b["diagnostics"]["imported_firewalls"] == 2
