# -*- coding: utf-8 -*-
"""서버(리눅스/윈도우) 현황 — 등록/수집/서버실 포함 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector


@pytest.fixture
def temp_db(tmp_path):
    p = tmp_path / "test.db"
    db.init_schema(p)
    return p


# ── DB CRUD ──────────────────────────────────────────────
def test_server_crud(temp_db):
    sid = db.save_server(temp_db, "WEB-01", "10.0.0.5", os_type="linux",
                         location="A09U27")
    sv = db.get_server(temp_db, sid)
    assert sv["name"] == "WEB-01" and sv["os_type"] == "linux"
    # upsert(같은 IP) → 갱신
    sid2 = db.save_server(temp_db, "WEB-01b", "10.0.0.5")
    assert sid2 == sid
    db.update_server(temp_db, sid, hostname="web01.local", open_ports="22,80,443")
    sv = db.get_server(temp_db, sid)
    assert sv["hostname"] == "web01.local" and sv["open_ports"] == "22,80,443"
    # 목록은 blob 비노출 + has_cred
    rows = db.list_servers(temp_db)
    assert rows[0]["has_cred"] is False and "cred_blob" not in rows[0]
    assert db.delete_server(temp_db, sid) == 1
    assert db.get_server(temp_db, sid) is None


def test_update_server_none_skips(temp_db):
    """None 필드는 기존값 보존."""
    sid = db.save_server(temp_db, "S", "10.0.0.6")
    db.update_server(temp_db, sid, hostname="h1")
    db.update_server(temp_db, sid, hostname=None, open_ports="22")
    sv = db.get_server(temp_db, sid)
    assert sv["hostname"] == "h1" and sv["open_ports"] == "22"


# ── VM 판정(MAC OUI) ─────────────────────────────────────
def test_vm_detection_from_mac():
    assert server_collector.guess_vm_from_mac("00:50:56:aa:bb:cc")[0] is True   # VMware
    assert server_collector.guess_vm_from_mac("00-15-5D-01-02-03")[0] is True   # Hyper-V
    assert server_collector.guess_vm_from_mac("52:54:00:12:34:56")[0] is True   # KVM
    assert server_collector.guess_vm_from_mac("A4:BB:6D:11:22:33")[0] is False  # 물리(Dell 등)


# ── MAC/위치 대조(스위치 수집 데이터 재활용) ─────────────
def test_find_mac_location_from_facility(temp_db):
    db.save_facility_hosts(temp_db, [{
        "subnet": "10.0.0.0/24", "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF",
        "switch_name": "CORE-SW", "port": "Gi1/0/5", "online": 1}])
    loc = db.find_mac_location(temp_db, "10.0.0.5")
    assert loc["mac"] == "AA:BB:CC:DD:EE:FF"
    assert loc["switch_name"] == "CORE-SW" and loc["port"] == "Gi1/0/5"


# ── API + 서버실 포함 ────────────────────────────────────
def test_server_api_and_room_inclusion(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    client = application.test_client()

    # 물리 서버(랙 위치) + VM(위치 있어도 서버실 제외)
    r = client.post("/api/servers", json={"name": "PHY-01", "ip": "10.0.0.10",
                                          "location": "A03U10", "is_vm": False})
    assert r.status_code == 201
    client.post("/api/servers", json={"name": "VM-01", "ip": "10.0.0.11",
                                      "location": "A03U11", "is_vm": True})

    data = client.get("/api/servers").get_json()["servers"]
    phy = [s for s in data if s["name"] == "PHY-01"][0]
    vm = [s for s in data if s["name"] == "VM-01"][0]
    # 물리 서버만 room_* 주입(서버실 현황 포함 대상)
    assert phy.get("room_rack") == "A03" and phy.get("room_unit") == 10
    assert "room_rack" not in vm      # VM은 서버실 제외


def test_collect_server_no_cred_still_scans(temp_db, monkeypatch):
    """계정 없이도 무자격 수집(포트/역DNS/ARP 대조) 수행 → done."""
    sid = db.save_server(temp_db, "S", "127.0.0.1")
    monkeypatch.setattr(server_collector, "scan_ports", lambda ip, **k: [22, 80])
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: "myhost")
    res = server_collector.collect_server(temp_db, sid)  # username/password 없음
    assert res["status"] == "done"
    sv = db.get_server(temp_db, sid)
    assert sv["open_ports"] == "22,80" and sv["hostname"] == "myhost"


def test_status_uses_open_ports_not_port22(temp_db, monkeypatch):
    """상태 판정은 열린 포트 존재 기준(22 유무 아님). 포트 없고 정보도 없으면 failed."""
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(server_collector, "netbios_name", lambda ip, **k: "")
    monkeypatch.setattr(db, "find_mac_location", lambda dbp, ip: {})
    # 22 없이 다른 포트만 열림 → 도달(up)
    sid = db.save_server(temp_db, "S1", "10.0.0.21")
    monkeypatch.setattr(server_collector, "scan_ports", lambda ip, **k: [3389, 445])
    assert server_collector.collect_server(temp_db, sid)["status"] == "done"
    # 열린 포트 전무 + 정보 없음 → failed(도달 불가)
    sid2 = db.save_server(temp_db, "S2", "10.0.0.22")
    monkeypatch.setattr(server_collector, "scan_ports", lambda ip, **k: [])
    r = server_collector.collect_server(temp_db, sid2)
    assert r["status"] == "failed" and "도달 불가" in db.get_server(temp_db, sid2)["last_error"]


def test_hostname_netbios_fallback(temp_db, monkeypatch):
    """역DNS 실패 시 NetBIOS 이름으로 hostname 폴백."""
    sid = db.save_server(temp_db, "S", "10.0.0.30")
    monkeypatch.setattr(server_collector, "scan_ports", lambda ip, **k: [445])
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(server_collector, "netbios_name", lambda ip, **k: "WINSRV01")
    monkeypatch.setattr(db, "find_mac_location", lambda dbp, ip: {})
    server_collector.collect_server(temp_db, sid)
    assert db.get_server(temp_db, sid)["hostname"] == "WINSRV01"


def test_os_auto_detect(temp_db, monkeypatch):
    """os_type='auto'면 접속해서 OS 판별 후 확정."""
    sid = db.save_server(temp_db, "S", "10.0.0.40", os_type="auto")
    monkeypatch.setattr(server_collector, "scan_ports", lambda ip, **k: [22])
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(server_collector, "netbios_name", lambda ip, **k: "")
    monkeypatch.setattr(db, "find_mac_location", lambda dbp, ip: {})
    monkeypatch.setattr(server_collector, "detect_os", lambda ip, u, p, **k: "linux")
    monkeypatch.setattr(server_collector, "_ssh_detail_linux",
                        lambda ip, u, p, **k: {"os_info": "Linux 5.15"})
    server_collector.collect_server(temp_db, sid, "admin", "pw123")
    sv = db.get_server(temp_db, sid)
    assert sv["os_type"] == "linux" and sv["os_info"] == "Linux 5.15"


def test_find_mac_location_prefers_physical_port(temp_db):
    """같은 MAC이 Po10과 물리포트에 보이면 물리포트를 택한다(케이블 실제 위치)."""
    import sqlite3
    sid = db.import_switches_bulk(
        temp_db, [{"name": "SW", "ip": "10.0.0.99", "vendor": "cisco_ios"}])[0]
    snap = db.save_snapshot(temp_db, sid, 1)
    conn = sqlite3.connect(str(temp_db))
    conn.execute("INSERT INTO arp_entries (snapshot_id, switch_id, ip, mac) VALUES (?,?,?,?)",
                 (snap, sid, "10.0.0.50", "AA:BB:CC:00:11:22"))
    for port in ("Po10", "Gi1/0/5"):
        conn.execute("INSERT INTO mac_entries (snapshot_id, switch_id, vlan, mac, port) "
                     "VALUES (?,?,?,?,?)", (snap, sid, 10, "AA:BB:CC:00:11:22", port))
    conn.commit(); conn.close()
    loc = db.find_mac_location(temp_db, "10.0.0.50")
    assert loc["port"] == "Gi1/0/5"          # Po가 아니라 물리포트
    assert loc["switch_id"] == sid


def test_collect_all_common_cred_persist(temp_db, monkeypatch):
    """전체 수집 공통 계정 + persist → 각 서버에 계정 저장."""
    s1 = db.save_server(temp_db, "A", "10.0.0.61")
    s2 = db.save_server(temp_db, "B", "10.0.0.62")
    monkeypatch.setattr(server_collector, "collect_server",
                        lambda dbp, sid, u, p: {"status": "done"})
    server_collector.collect_all_servers(temp_db, common_user="root",
                                         common_pass="pw12345", persist=True)
    assert db.get_server_credential(temp_db, s1)
    assert db.get_server_credential(temp_db, s2)
