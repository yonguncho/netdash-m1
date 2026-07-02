import concurrent.futures
import os
import tempfile

import pytest

from core import db


@pytest.fixture()
def tmp_db(tmp_path):
    path = str(tmp_path / "test.db")
    db.init_db(path)
    return path


def test_init_db_creates_core_tables(tmp_path):
    path = str(tmp_path / "new.db")
    db.init_db(path)
    import sqlite3
    conn = sqlite3.connect(path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()}
    conn.close()
    expected = {
        "switches", "snapshots", "ports", "mac_entries", "arp_entries",
        "hosts", "events", "port_events",
        # M10: 방화벽
        "firewalls", "firewall_interfaces", "firewall_arp",
        # M12: 앱 설정
        "app_settings",
        # VLAN 이름(show vlan brief)
        "vlan_names",
        # 시스템 로그(show logging)
        "switch_logs",
        # 설비 현황
        "facility_hosts",
        # NX-OS 포트채널 멤버
        "port_channels",
        # 장비 변경/알람 이벤트
        "device_events",
        # 설정(running-config) 백업
        "config_backups",
        # 툴 접근(감사) 로그
        "audit_log",
    }
    assert expected == tables


def test_get_switches_empty_db(tmp_db):
    result = db.get_switches(tmp_db)
    assert result == []


def test_upsert_switch_insert_and_update(tmp_db):
    row = {"name": "SW-01", "ip": "10.0.0.1", "vendor": "cisco", "model": "C2960"}
    db.upsert_switch(tmp_db, row)
    switches = db.get_switches(tmp_db)
    assert len(switches) == 1
    assert switches[0]["ip"] == "10.0.0.1"

    db.upsert_switch(tmp_db, {**row, "model": "C2960X"})
    switches = db.get_switches(tmp_db)
    assert len(switches) == 1
    assert switches[0]["model"] == "C2960X"


def test_upsert_switch_raises_on_missing_ip(tmp_db):
    with pytest.raises((ValueError, Exception)):
        db.upsert_switch(tmp_db, {"name": "SW-BAD"})


def test_save_snapshot_and_latest_snapshot_id(tmp_db):
    db.upsert_switch(tmp_db, {"name": "SW-01", "ip": "10.0.0.1"})
    switches = db.get_switches(tmp_db)
    sw_id = switches[0]["id"]

    assert db.latest_snapshot_id(tmp_db, sw_id) is None

    parsed = {
        "ports": [{"name": "Gi0/1", "link": "connected", "vlan": "10", "speed": "1G", "descr": "TEST", "flap_count": 0}],
        "mac_entries": [{"vlan": "10", "mac": "aabb.cc00.0001", "port": "Gi0/1"}],
        "arp_entries": [{"ip": "10.0.0.10", "mac": "aabb.cc00.0001", "interface": "Vlan10"}],
    }
    sid1 = db.save_snapshot(tmp_db, sw_id, parsed)
    assert db.latest_snapshot_id(tmp_db, sw_id) == sid1

    sid2 = db.save_snapshot(tmp_db, sw_id, parsed)
    assert db.latest_snapshot_id(tmp_db, sw_id) == sid2
    assert sid2 > sid1


def test_get_ports_and_mac_count(tmp_db):
    db.upsert_switch(tmp_db, {"name": "SW-01", "ip": "10.0.0.1"})
    sw_id = db.get_switches(tmp_db)[0]["id"]
    parsed = {
        "ports": [
            {"name": "Gi0/1", "link": "connected", "vlan": "10", "speed": "1G", "descr": "", "flap_count": 0},
            {"name": "Gi0/2", "link": "notconnect", "vlan": "20", "speed": "auto", "descr": "", "flap_count": 1},
        ],
        "mac_entries": [
            {"vlan": "10", "mac": "aa:bb:cc:00:00:01", "port": "Gi0/1"},
            {"vlan": "10", "mac": "aa:bb:cc:00:00:02", "port": "Gi0/1"},
            {"vlan": "20", "mac": "aa:bb:cc:00:00:03", "port": "Gi0/2"},
        ],
        "arp_entries": [],
    }
    sid = db.save_snapshot(tmp_db, sw_id, parsed)
    ports = db.get_ports(tmp_db, sid)
    assert len(ports) == 2
    assert db.get_mac_count(tmp_db, sid) == 3


def test_update_switch_status(tmp_db):
    db.upsert_switch(tmp_db, {"name": "SW-01", "ip": "10.0.0.1"})
    sw_id = db.get_switches(tmp_db)[0]["id"]
    db.update_switch_status(tmp_db, sw_id, "done")
    switches = db.get_switches(tmp_db)
    assert switches[0]["status"] == "done"
    assert switches[0]["last_collected"] is not None


def test_concurrent_save_snapshot(tmp_db):
    db.upsert_switch(tmp_db, {"name": "SW-01", "ip": "10.0.0.1"})
    sw_id = db.get_switches(tmp_db)[0]["id"]
    parsed = {
        "ports": [{"name": "Gi0/1", "link": "connected", "vlan": "1", "speed": "1G", "descr": "", "flap_count": 0}],
        "mac_entries": [],
        "arp_entries": [],
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(db.save_snapshot, tmp_db, sw_id, parsed) for _ in range(3)]
        results = [f.result() for f in futs]

    assert len(results) == 3
    assert len(set(results)) == 3


def test_save_snapshot_raises_on_none_parsed(tmp_db):
    db.upsert_switch(tmp_db, {"name": "SW-01", "ip": "10.0.0.1"})
    sw_id = db.get_switches(tmp_db)[0]["id"]
    with pytest.raises(ValueError):
        db.save_snapshot(tmp_db, sw_id, None)


def test_latest_snapshot_id_returns_none_for_unknown_switch(tmp_db):
    assert db.latest_snapshot_id(tmp_db, 99999) is None
