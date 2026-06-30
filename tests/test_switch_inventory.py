"""IP/SUBNET/HOSTNAME 인벤토리 엑셀 → 스위치 일괄 등록 테스트."""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from openpyxl import Workbook

from core import db, excel_loader


def _make_xlsx(rows, headers):
    wb = Workbook()
    ws = wb.active
    ws.append(headers)
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


def test_parse_inventory_basic():
    buf = _make_xlsx(
        [["10.0.0.1", "255.255.255.0", "TPS-F1B02_1F01_FA_SW1"],
         ["10.0.0.2", "255.255.255.0", "TPS-F1B02_1F01_FA_SW2"]],
        ["IP", "IP SUBNET", "HOSTNAME"])
    rows = excel_loader.parse_switch_inventory(buf)
    assert len(rows) == 2
    assert rows[0]["ip"] == "10.0.0.1"
    assert rows[0]["hostname"] == "TPS-F1B02_1F01_FA_SW1"
    assert rows[0]["subnet"] == "255.255.255.0"
    assert rows[0]["vendor"] == "unknown"
    assert rows[0]["name"]  # name=hostname or ip


def test_parse_inventory_skips_non_ip():
    buf = _make_xlsx(
        [["설명행", "", ""], ["10.0.0.5", "/24", "SW-A"], ["", "", ""]],
        ["IP", "SUBNET", "HOSTNAME"])
    rows = excel_loader.parse_switch_inventory(buf)
    assert len(rows) == 1
    assert rows[0]["ip"] == "10.0.0.5"


def test_parse_inventory_dedup():
    buf = _make_xlsx(
        [["10.0.0.9", "/24", "A"], ["10.0.0.9", "/24", "A-dup"]],
        ["IP", "SUBNET", "HOSTNAME"])
    rows = excel_loader.parse_switch_inventory(buf)
    assert len(rows) == 1


def test_import_inventory_endpoint(client):
    buf = _make_xlsx(
        [["10.0.1.10", "255.255.255.0", "TPS-F1B02_1F01_FA_SW1"],
         ["8.8.8.8", "255.255.255.0", "PUBLIC"]],   # 공인 IP는 SSRF로 제외
        ["IP", "IP SUBNET", "HOSTNAME"])
    r = client.post("/api/switches/import-inventory",
                    data={"file": (buf, "inv.xlsx")},
                    content_type="multipart/form-data")
    body = r.get_json()
    assert body["ok"] is True
    assert body["imported"] == 1   # 사설만
    assert body["skipped"] == 1    # 공인 제외
