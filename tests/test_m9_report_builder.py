"""M9: 엑셀 현황 보고서 빌더 테스트."""
import io
import sys
from pathlib import Path

import pytest
import openpyxl

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, report_builder


def _load(data):
    return openpyxl.load_workbook(io.BytesIO(data))


def _seed(db_path):
    """스위치 + 스냅샷(포트/맥) + 이벤트 + 장부/실측 호스트 시드."""
    sid = db.save_switch(db_path, "ACC-SW01", "10.0.0.20", "cisco_ios")
    snap = db.save_snapshot(db_path, sid)
    db.save_ports(db_path, snap, sid, [
        {"name": "Gi1/0/1", "status": "up", "vlan": 10, "speed": "1G", "description": "uplink"},
        {"name": "Gi1/0/2", "status": "down", "vlan": 20, "speed": "1G", "description": ""},
    ])
    db.save_mac_entries(db_path, snap, sid, [
        {"vlan": 10, "mac": "00:11:22:33:44:55", "port": "Gi1/0/1", "type": "dynamic"},
    ])
    # 장부 + 실측 호스트 (match 판정)
    db.save_ledger_hosts(db_path, [{"ip": "10.0.1.10", "hostname": "WEB-01",
                                    "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/1"}])
    db.save_hosts(db_path, {"10.0.1.10": {"mac": "00:11:22:33:44:55", "switch_id": sid,
                                          "port": "Gi1/0/1", "located": True}})
    return sid


# 1. bytes 반환 + 재로딩 가능
def test_build_report_returns_bytes(temp_db):
    _seed(temp_db)
    data = report_builder.build_report(temp_db)
    assert isinstance(data, bytes)
    assert len(data) > 0
    wb = _load(data)
    assert wb is not None


# 2. 4시트 이름
def test_report_has_four_sheets(temp_db):
    _seed(temp_db)
    wb = _load(report_builder.build_report(temp_db))
    assert wb.sheetnames == ["스위치 현황", "포트 현황", "이벤트 로그", "호스트 대장"]


# 3. 스위치 시트 헤더 + 데이터
def test_switch_sheet_headers_and_rows(temp_db):
    _seed(temp_db)
    wb = _load(report_builder.build_report(temp_db))
    ws = wb["스위치 현황"]
    headers = [c.value for c in ws[1]]
    assert headers == ["id", "name", "ip", "vendor", "status",
                       "port_count", "mac_count", "last_collected"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    assert any(r[1] == "ACC-SW01" for r in rows)
    sw_row = [r for r in rows if r[1] == "ACC-SW01"][0]
    assert sw_row[5] == 2  # port_count
    assert sw_row[6] == 1  # mac_count


# 4. 포트 시트에 수집 포트 반영
def test_port_sheet_reflects_ports(temp_db):
    _seed(temp_db)
    wb = _load(report_builder.build_report(temp_db))
    ws = wb["포트 현황"]
    names = [r[1] for r in ws.iter_rows(min_row=2, values_only=True)]
    assert "Gi1/0/1" in names
    assert "Gi1/0/2" in names


# 5. 이벤트 시트에 port_events 반영
def test_event_sheet_reflects_events(temp_db):
    sid = _seed(temp_db)
    # port_events 기록 (flapping)
    db.upsert_port_event(temp_db, sid, "Gi1/0/2", "flapping")
    wb = _load(report_builder.build_report(temp_db))
    ws = wb["이벤트 로그"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    assert any(r[1] == "Gi1/0/2" and r[2] == "flapping" for r in rows)


# 6. 호스트 시트에 reconcile verdict 포함
def test_host_sheet_includes_verdict(temp_db):
    _seed(temp_db)
    wb = _load(report_builder.build_report(temp_db))
    ws = wb["호스트 대장"]
    headers = [c.value for c in ws[1]]
    assert "verdict" in headers
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    host_row = [r for r in rows if r[0] == "10.0.1.10"][0]
    assert host_row[-1] == "match"  # verdict 마지막 컬럼


# 7. 빈 DB → 헤더만, 예외 없음
def test_build_report_empty_db(temp_db):
    data = report_builder.build_report(temp_db)
    wb = _load(data)
    assert wb.sheetnames == ["스위치 현황", "포트 현황", "이벤트 로그", "호스트 대장"]
    # 각 시트 헤더 행만 존재
    assert wb["스위치 현황"].max_row == 1


# 8. GET /api/report → 200 + xlsx content-type + 첨부 헤더
def test_api_report_endpoint(client):
    r = client.get("/api/report")
    assert r.status_code == 200
    assert "spreadsheetml.sheet" in r.headers.get("Content-Type", "")
    assert "attachment" in r.headers.get("Content-Disposition", "")
    assert "netdash_report.xlsx" in r.headers.get("Content-Disposition", "")
    # 실제 xlsx로 파싱 가능
    wb = _load(r.data)
    assert len(wb.sheetnames) == 4
