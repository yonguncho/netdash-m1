# -*- coding: utf-8 -*-
"""사양 정보 엑셀 일괄 반영 — IP로 기존 서버에만 매칭 (v6.8.2).

사용자 요청: "사양 정보를 엑셀로 받아서 등록하면, IP 기반으로 매칭되는
서버에 사양 정보가 등록되도록 해야해."

실측 수집(SSH·WMI·SNMP)이 막힌 서버가 있어, 이미 파악해 둔 사양(CPU·메모리·
디스크)을 엑셀로 한 번에 채우기 위한 경로다. **새 서버를 만들지 않는다** —
IP가 일치하는 서버가 없으면 그 행은 건너뛴다. 엉뚱한 IP로 유령 서버가
생기면 서버실 랙뷰 등에서 조용히 어긋난다.
"""
import io
import sys
from pathlib import Path

import pytest
from openpyxl import Workbook

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, excel_loader  # noqa: E402

ROOT = Path(__file__).parent.parent


def _xlsx(rows):
    wb = Workbook()
    ws = wb.active
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── 파서: 컬럼 매핑·단위 환산 ────────────────────────────────────
def test_parses_basic_spec_columns():
    x = _xlsx([
        ["IP", "CPU", "코어수", "메모리", "디스크", "사용디스크"],
        ["10.0.0.1", "Intel Xeon Gold 6248", "16", "64", "500", "220"],
    ])
    rows = excel_loader.parse_server_specs(x)
    assert len(rows) == 1
    r = rows[0]
    assert r["ip"] == "10.0.0.1"
    assert r["cpu_model"] == "Intel Xeon Gold 6248"
    assert r["cpu_cores"] == 16
    assert r["mem_total_mb"] == 65536, "메모리(GB) 칸이 MB로 환산되지 않았다"
    assert r["disk_total_gb"] == 500.0
    assert r["disk_used_gb"] == 220.0


def test_mem_mb_column_used_directly_when_present():
    x = _xlsx([
        ["IP", "메모리MB"],
        ["10.0.0.2", "32768"],
    ])
    rows = excel_loader.parse_server_specs(x)
    assert rows[0]["mem_total_mb"] == 32768


def test_numbers_with_units_and_commas_are_parsed():
    """'32 GB', '1,024' 처럼 사람이 적기 쉬운 형태도 받아야 한다."""
    x = _xlsx([
        ["IP", "메모리", "디스크"],
        ["10.0.0.3", "32 GB", "1,024"],
    ])
    rows = excel_loader.parse_server_specs(x)
    assert rows[0]["mem_total_mb"] == 32768
    assert rows[0]["disk_total_gb"] == 1024.0


def test_rows_without_any_spec_are_dropped():
    """IP만 있고 사양 칸이 전부 비면 반영할 게 없다."""
    x = _xlsx([
        ["IP", "CPU"],
        ["10.0.0.4", ""],
    ])
    assert excel_loader.parse_server_specs(x) == []


def test_partial_spec_only_fills_given_fields():
    """한 칸만 채워도 되고, 나머지 필드는 아예 안 실린다(=안 건드림 신호)."""
    x = _xlsx([
        ["IP", "코어수"],
        ["10.0.0.5", "8"],
    ])
    r = excel_loader.parse_server_specs(x)[0]
    assert r == {"ip": "10.0.0.5", "cpu_cores": 8}


def test_invalid_ip_rows_are_skipped():
    x = _xlsx([
        ["IP", "코어수"],
        ["not-an-ip", "8"],
        ["10.0.0.6", "8"],
    ])
    rows = excel_loader.parse_server_specs(x)
    assert [r["ip"] for r in rows] == ["10.0.0.6"]


def test_duplicate_ip_keeps_first_row():
    x = _xlsx([
        ["IP", "코어수"],
        ["10.0.0.7", "4"],
        ["10.0.0.7", "99"],
    ])
    rows = excel_loader.parse_server_specs(x)
    assert len(rows) == 1 and rows[0]["cpu_cores"] == 4


def test_zero_cores_or_negative_disk_is_ignored():
    """0이나 음수는 파싱 오류(예: 빈 셀이 0으로 읽힘) 가능성이 높다."""
    x = _xlsx([
        ["IP", "코어수", "디스크"],
        ["10.0.0.8", "0", "-5"],
    ])
    assert excel_loader.parse_server_specs(x) == []


# ── DB 반영: IP 매칭, 미매칭 건너뜀 ──────────────────────────────
def test_update_only_touches_provided_fields(temp_db):
    sid = db.save_server(temp_db, "SRV1", "10.1.1.1", location="A09U10")
    db.update_server(temp_db, sid, cpu_model="OldCPU")
    db.update_server(temp_db, sid, cpu_cores=8, mem_total_mb=16000)
    row = db.get_server(temp_db, sid)
    assert row["location"] == "A09U10", "사양만 갱신했는데 위치가 지워지면 안 된다"
    assert row["cpu_model"] == "OldCPU"
    assert row["cpu_cores"] == 8 and row["mem_total_mb"] == 16000


def test_get_server_by_ip_used_for_matching(temp_db):
    sid = db.save_server(temp_db, "SRV2", "10.1.1.2")
    found = db.get_server_by_ip(temp_db, "10.1.1.2")
    assert found and found["id"] == sid
    assert db.get_server_by_ip(temp_db, "10.1.1.99") is None


# ── 라우트: 기존 서버만 갱신, 새 서버 생성 금지 ─────────────────
def test_import_specs_endpoint_matches_and_updates(cli):
    p = Path.cwd() / "netdash.db"
    sid = db.save_server(p, "SRV-A", "10.2.2.1")
    x = _xlsx([
        ["IP", "CPU", "코어수", "메모리", "디스크"],
        ["10.2.2.1", "Xeon Gold", "32", "128", "2000"],
    ])
    r = cli.post("/api/servers/import-specs",
                data={"file": (x, "specs.xlsx")},
                content_type="multipart/form-data")
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True and body["matched"] == 1 and body["unmatched"] == 0
    row = db.get_server(p, sid)
    assert row["cpu_cores"] == 32 and row["mem_total_mb"] == 131072
    assert row["disk_total_gb"] == 2000.0


def test_import_specs_endpoint_does_not_create_new_server(cli):
    """등록 안 된 IP는 새 서버를 만들지 않는다 — 등록은 이 라우트의 일이 아니다."""
    p = Path.cwd() / "netdash.db"
    before = len(db.list_servers(p))
    x = _xlsx([
        ["IP", "코어수"],
        ["10.2.2.99", "16"],
    ])
    r = cli.post("/api/servers/import-specs",
                data={"file": (x, "specs.xlsx")},
                content_type="multipart/form-data")
    body = r.get_json()
    assert body["ok"] is True
    assert body["unmatched"] == 1 and body["matched"] == 0
    assert len(db.list_servers(p)) == before, "매칭 안 된 IP로 서버가 생성됐다"
    assert db.get_server_by_ip(p, "10.2.2.99") is None


def test_import_specs_preserves_existing_fields_not_in_sheet(cli):
    """엑셀에 없는 필드(위치·이름 등)를 지우면 다른 화면에서 데이터가 사라진다."""
    p = Path.cwd() / "netdash.db"
    sid = db.save_server(p, "KEEP-ME", "10.2.2.2", location="B12U05")
    x = _xlsx([
        ["IP", "코어수"],
        ["10.2.2.2", "4"],
    ])
    cli.post("/api/servers/import-specs",
            data={"file": (x, "specs.xlsx")}, content_type="multipart/form-data")
    row = db.get_server(p, sid)
    assert row["name"] == "KEEP-ME" and row["location"] == "B12U05"
    assert row["cpu_cores"] == 4


def test_import_specs_rejects_ssrf_ip(cli):
    """도달 불가/위험 대역 IP를 엑셀에 적어 넣는 경로도 검증을 거쳐야 한다."""
    x = _xlsx([
        ["IP", "코어수"],
        ["127.0.0.1", "4"],
    ])
    r = cli.post("/api/servers/import-specs",
                data={"file": (x, "specs.xlsx")}, content_type="multipart/form-data")
    body = r.get_json()
    assert body["ok"] is True and body["skipped"] == 1 and body["matched"] == 0


def test_import_specs_endpoint_requires_file(cli):
    r = cli.post("/api/servers/import-specs")
    assert r.status_code == 400


# ── 화면 배선 ────────────────────────────────────────────────────
def test_ui_has_specs_import_button():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="btn-server-import-specs"' in html
    assert 'id="server-import-specs-file"' in html


def test_ui_binds_specs_import_and_reports_unmatched():
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "/api/servers/import-specs" in js
    assert "res.unmatched" in js, "등록 안 된 IP가 있었다는 사실을 안내하지 않는다"
