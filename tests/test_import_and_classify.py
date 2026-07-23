# -*- coding: utf-8 -*-
"""스위치 구분 자동분류 + 서버 OS 스캔추정 + 서버/방화벽 엑셀 일괄등록."""
import io
import sys
from pathlib import Path

import pytest
from openpyxl import Workbook

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import topology, server_collector, excel_loader, db


def _xlsx(rows):
    """rows(리스트의 리스트) → xlsx 바이트."""
    wb = Workbook()
    ws = wb.active
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ── 구분 자동 분류 ──────────────────────────────────────────────
def test_classify_switch_kind():
    assert topology.classify_switch_kind("ip routing\n", "cisco_ios") == "L3 Switch"
    two_svi = ("interface Vlan10\n ip address 10.0.10.1 255.255.255.0\n"
               "interface Vlan20\n ip address 10.0.20.1 255.255.255.0\n")
    assert topology.classify_switch_kind(two_svi, "cisco_ios") == "L3 Switch"
    l2 = ("hostname SW\ninterface Vlan1\n ip address 10.0.0.2 255.255.255.0\n"
          "ip default-gateway 10.0.0.1\n")
    assert topology.classify_switch_kind(l2, "cisco_ios") == "L2 Switch"
    # 로드밸런서 벤더 → 설정 없이도 L4
    assert topology.classify_switch_kind(None, "alteon") == "L4 Switch"
    assert topology.classify_switch_kind("", "radware") == "L4 Switch"
    # config 미수집 → None(프론트에서 'SWITCH')
    assert topology.classify_switch_kind(None, "cisco_ios") is None


def test_get_latest_configs(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.save_config_backup(temp_db, sid, "ip routing\nhostname SW1\n")
    db.save_config_backup(temp_db, sid, "ip routing\nhostname SW1-new\n")  # 최신
    cfgs = db.get_latest_configs(temp_db)
    assert sid in cfgs and "SW1-new" in cfgs[sid]


# ── 서버 OS 스캔 추정 ───────────────────────────────────────────
def test_infer_os_from_scan():
    assert server_collector.infer_os_from_scan([3389, 80]) == "windows"
    assert server_collector.infer_os_from_scan([445]) == "windows"
    assert server_collector.infer_os_from_scan([80], netbios_hit=True) == "windows"
    assert server_collector.infer_os_from_scan([22, 80]) == "linux"
    assert server_collector.infer_os_from_scan([80, 443]) is None
    assert server_collector.infer_os_from_scan([]) is None


def test_pick_ssh_port():
    # 22 우선, 없으면 2222, 둘 다 없으면 None(22 고정 안 함)
    assert server_collector.pick_ssh_port([22, 80, 443]) == 22
    assert server_collector.pick_ssh_port([80, 2222]) == 2222
    assert server_collector.pick_ssh_port([80, 443, 3389]) is None
    # 스캔 대상에 2222/WinRM 포트가 포함됨
    assert 2222 in server_collector.COMMON_PORTS
    assert 5985 in server_collector.COMMON_PORTS


# ── 엑셀 파서 ───────────────────────────────────────────────────
def test_parse_server_inventory():
    src = _xlsx([["이름", "IP", "위치"],
                 ["WEB-01", "10.92.10.5", "A09U27"],
                 ["DB-01", "10.92.10.6", ""],
                 ["", "not-an-ip", ""]])       # IP 무효 → 제외
    rows = excel_loader.parse_server_inventory(src)
    assert len(rows) == 2
    assert rows[0]["name"] == "WEB-01" and rows[0]["ip"] == "10.92.10.5"
    assert rows[0]["location"] == "A09U27"
    assert rows[0]["os_type"] == "auto"


def test_parse_firewall_inventory():
    src = _xlsx([["이름", "벤더", "IP", "포트"],
                 ["FW-A", "fortigate", "10.0.0.1", "443"],
                 ["FW-B", "Palo Alto", "10.0.0.2", "22"]])
    rows = excel_loader.parse_firewall_inventory(src)
    assert len(rows) == 2
    assert rows[0]["vendor"] == "fortigate" and rows[0]["port"] == 443
    assert rows[1]["vendor"] == "paloalto" and rows[1]["host"] == "10.0.0.2"


# ── 엔드포인트(데모 모드) ───────────────────────────────────────
def test_import_servers_endpoint(client):
    src = _xlsx([["name", "ip"], ["S1", "10.50.0.5"], ["S2", "10.50.0.6"]])
    r = client.post("/api/servers/import",
                    data={"file": (src, "servers.xlsx")},
                    content_type="multipart/form-data")
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j["imported"] == 2
    names = {s["name"] for s in client.get("/api/servers").get_json()["servers"]}
    assert {"S1", "S2"} <= names


def test_import_firewalls_endpoint(client):
    src = _xlsx([["name", "vendor", "ip", "port"],
                 ["FW1", "fortigate", "10.60.0.1", "443"]])
    r = client.post("/api/firewalls/import",
                    data={"file": (src, "fw.xlsx")},
                    content_type="multipart/form-data")
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j["imported"] == 1
    hosts = {f["host"] for f in client.get("/api/firewalls").get_json()["firewalls"]}
    assert "10.60.0.1" in hosts
