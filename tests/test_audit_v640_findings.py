# -*- coding: utf-8 -*-
"""전체 버그 검증(v6.4.0)에서 재현된 결함들의 회귀 테스트.

전부 "고치기 전에는 실패한다"가 성립하도록 동작으로 검사한다.
"""
import logging
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, db, exporter, facility, server_collector  # noqa: E402
from core.parsers import arista_eos as ar, cisco_nxos as nx          # noqa: E402

ROOT = Path(__file__).parent.parent


# ── 데이터 파괴 ──────────────────────────────────────────────────
def test_delete_switch_reports_failure_instead_of_faking_success(temp_db):
    """events FK 때문에 삭제가 막히면 True를 돌려주면 안 된다."""
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    s1 = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, s1, sid,
                        [{"vlan": 1, "mac": "aa:bb:cc:dd:ee:01", "port": "Gi1/0/1"},
                         {"vlan": 1, "mac": "aa:bb:cc:dd:ee:02", "port": "Gi1/0/2"}])
    db._detect_disconnected(temp_db, sid, s1, [(1, "aa:bb:cc:dd:ee:01", "Gi1/0/1")])
    with db.get_db(temp_db) as c:
        assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0, "전제: events 존재"
    assert db.delete_switch(temp_db, sid) is True
    with db.get_db(temp_db) as c:
        left = c.execute("SELECT COUNT(*) FROM switches").fetchone()[0]
    assert left == 0, "'삭제 완료'라고 했는데 스위치가 그대로 남아 있다"


def test_events_is_in_switch_child_tables():
    assert "events" in db._SWITCH_CHILD_TABLES


def test_deleting_switch_keeps_facility_inventory(temp_db):
    """설비는 스캔 결과(인벤토리)다 — 스위치를 지웠다고 행째로 사라지면 안 된다."""
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.20.0.0/24", "ip": "10.20.0.5", "mac": "aa:bb:cc:00:00:05",
         "switch_id": sid, "switch_name": "SW1", "port": "Gi1/0/5",
         "online": 1, "direct": 1}])
    db.delete_switch(temp_db, sid)
    rows = db.get_facility_hosts(temp_db)
    assert [h["ip"] for h in rows] == ["10.20.0.5"], "설비 IP·MAC·대역이 통째로 사라졌다"
    assert rows[0]["switch_id"] is None, "연결 위치만 무효화돼야 한다"


def test_facility_subnet_replace_is_atomic(temp_db):
    """저장이 실패하면 기존 행이 남아 있어야 한다(삭제만 되고 끝나면 안 됨)."""
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.%d" % i, "mac": "aa:bb:cc:00:00:%02x" % i,
         "switch_id": None, "switch_name": None, "port": None, "online": 1,
         "direct": 0} for i in range(5)])
    assert len(db.get_facility_hosts(temp_db)) == 5
    bad = [{"subnet": "10.1.0.0/24", "ip": "10.1.0.9", "mac": {"unhashable": 1},
            "switch_id": None, "switch_name": None, "port": None,
            "online": 1, "direct": 0}]
    with pytest.raises(Exception):
        db.replace_facility_subnet(temp_db, "10.1.0.0/24", bad)
    assert len(db.get_facility_hosts(temp_db)) == 5, "실패했는데 대역이 비었다"


# ── 수집 엔진 ────────────────────────────────────────────────────
def test_worker_survives_exception_in_error_handler(temp_db, monkeypatch):
    """예외 처리기 안의 예외로 워커가 죽으면 수집 큐가 영구 정지한다."""
    import time
    sid = db.save_switch(temp_db, "SW1", "10.0.0.10", "cisco_ios")
    collector.init_collector()
    orig = db.set_switch_status

    def boom(dp, i, s, error=None):
        if s == "failed":
            raise RuntimeError("database is locked")
        return orig(dp, i, s, error)

    monkeypatch.setattr(collector.db, "set_switch_status", boom)
    for i in range(3):
        collector.collect_switch(temp_db, 90000 + i, "u", "p")
        time.sleep(0.4)
    assert sum(t.is_alive() for t in collector._worker_threads) == len(collector._worker_threads), \
        "워커가 죽으면 이후 모든 수집이 큐에 쌓이기만 한다"
    monkeypatch.setattr(collector.db, "set_switch_status", orig)
    assert collector.collect_switch(temp_db, sid, "u", "p").get("status") != "error"
    # 워커가 temp_db를 잡고 있으면 픽스처 정리가 실패한다 — 명시적으로 종료
    try:
        collector.shutdown_workers()
    except Exception:
        pass
    time.sleep(0.5)


def test_cancel_pending_keeps_previous_status(temp_db):
    """대기 중이던 스위치는 아직 수집을 시작하지 않았다 — 상태를 건드리면 안 된다."""
    import queue
    ids = [db.save_switch(temp_db, "SW%d" % i, "10.0.0.%d" % i, "cisco_ios")
           for i in range(1, 4)]
    db.set_switch_status(temp_db, ids[0], "done")
    db.set_switch_status(temp_db, ids[1], "failed")
    db.set_switch_status(temp_db, ids[2], "collecting")
    collector._worker_queue = queue.Queue()
    for i in ids:
        with collector._collector_lock:
            collector._collecting_switches.add(i)
        collector._worker_queue.put((temp_db, i))
    collector.cancel_pending()
    got = {s["id"]: s["status"] for s in db.get_switches(temp_db)}
    assert got[ids[0]] == "done", "수집 완료 장비가 '미수집'으로 바뀌었다"
    assert got[ids[1]] == "failed", "장애 장비가 관제 '수집 실패' 목록에서 사라진다"
    assert got[ids[2]] == "new", "실제 수집 중이던 것만 되돌려야 한다"


def test_zero_arp_scan_keeps_previous_state(temp_db, monkeypatch):
    """ARP 0건은 스캔 실패다 — 대역 전체를 끊김으로 만들면 안 된다."""
    class FakeConn:
        base_prompt = "SW#"

        def send_command(self, cmd, **kw):
            if cmd.startswith("ping"):
                return "!!!!!"
            if "arp" in cmd:
                return "Protocol  Address   Age (min)  Hardware Addr   Type   Interface\n"
            return ""

        def check_enable_mode(self):
            return True

        def enable(self):
            pass

        def disconnect(self):
            pass

    fake = types.ModuleType("netmiko")
    fake.ConnectHandler = lambda **kw: FakeConn()
    monkeypatch.setitem(sys.modules, "netmiko", fake)
    sid = db.save_switch(temp_db, "TPS-SW11", "10.0.1.11", "cisco_ios")
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.0.1.0/29", "ip": "10.0.1.%d" % (1 + i),
         "mac": "00:11:22:33:44:%02x" % i, "switch_id": sid, "switch_name": "TPS-SW11",
         "port": "Gi1/0/%d" % (i + 1), "online": 1, "direct": 1} for i in range(6)])
    res = facility.collect_band(temp_db, sid, "10.0.1.0/29", "u", "p")
    online = sum(h["online"] for h in db.get_facility_hosts(temp_db))
    assert online == 6, "ARP를 못 읽었는데 6대가 전부 '연결 끊김'이 됐다"
    assert res.get("zero_arp") is True
    kinds = [e["kind"] for e in db.list_device_events(temp_db, limit=50)]
    assert "device_offline" not in kinds, "허위 끊김 알람이 발송됐다"


def test_server_collect_failure_clears_collecting_status(temp_db, monkeypatch):
    """예외가 나가도 '수집중' 배지가 영구히 남으면 안 된다."""
    srv = db.save_server(temp_db, "SRV1", "10.9.9.9")
    monkeypatch.setattr(server_collector.db, "find_mac_location",
                        lambda p, i: (_ for _ in ()).throw(
                            sqlite3.OperationalError("database is locked")))
    with pytest.raises(Exception):
        server_collector.collect_server(temp_db, srv, None, None)
    assert db.get_server(temp_db, srv)["status"] != "collecting"


def test_empty_neighbor_list_keeps_topology_links(temp_db):
    """CDP/LLDP 출력이 비었다고 기존 연결선을 지우면 안 된다."""
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.save_neighbors(temp_db, sid, [{"local_port": "Gi1/0/1", "remote_name": "CORE",
                                      "remote_port": "Te1/1"}])
    src = (ROOT / "core" / "collector.py").read_text(encoding="utf-8")
    i = src.index('if "neighbors" in parsed_data:')
    body = src[i:i + 900]
    assert "if nbr_list:" in body, "빈 목록도 그대로 저장하면 연결선이 사라진다"
    assert "neighbors_empty_keeping_previous" in body


# ── 표기·집계 ────────────────────────────────────────────────────
def test_vlan_summary_counts_latest_snapshot_only(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.save_vlan_names(temp_db, sid, [{"vlan": 10, "name": "OFFICE", "status": "active"}])
    macs = [{"vlan": 10, "mac": "aa:bb:cc:00:00:%02x" % i, "port": "Gi1/0/%d" % i}
            for i in range(3)]
    for _ in range(4):
        s = db.save_snapshot(temp_db, sid)
        db.save_mac_entries(temp_db, s, sid, macs)
    got = db.get_vlan_summary(temp_db)[0]["mac_count"]
    assert got == 3, "보관 세대를 전부 합산하면 실제의 최대 50배로 표시된다 (got=%s)" % got


def test_firewall_export_uses_live_reachability(temp_db, monkeypatch):
    from core import reachability
    fid = db.save_firewall(temp_db, "FW-A", "fortinet", "10.1.1.1", 443)
    monkeypatch.setattr(reachability, "get_fw_state", lambda: {fid: False})
    row = exporter.firewalls_rows(temp_db)[0]
    assert row["연결 상태"] == "끊김", "화면은 아는 값을 엑셀만 '확인 중'으로 고정했다"


def test_search_and_mac_lookup_use_same_snapshot_generation(temp_db):
    """MAC 명령만 실패한 수집이 새 스냅샷을 만들어도 기준이 어긋나면 안 된다."""
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    s1 = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, s1, sid, [{"vlan": 10, "mac": "aa:bb:cc:00:00:01",
                                            "port": "Po10"}])
    db.save_port_channels(temp_db, s1, sid, [{"port_channel": "Po10",
                                              "members": ["Gi1/0/1", "Gi1/0/2"]}])
    s2 = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, s2, sid, [])
    assert db.get_mac_to_switchport(temp_db), "전제: 설비/관제는 이전 세대를 본다"
    assert db.get_port_channel_members(temp_db), "Po → 물리 멤버 해석이 통째로 실패한다"


def test_arista_port_description_lookup_matches_mac_table(temp_db):
    """ports는 'Ethernet1', MAC 테이블은 'Et1' — 조회 키가 어긋나면 설명이 항상 빈다."""
    sid = db.save_switch(temp_db, "AR-SW01", "10.0.0.2", "arista_eos")
    snap = db.save_snapshot(temp_db, sid)
    db.save_ports(temp_db, snap, sid, [{"switch_id": sid, "name": "Ethernet1",
                                        "status": "up", "vlan": 10, "speed": "1G",
                                        "duplex": "full", "port_type": "",
                                        "description": "CCTV-정문"}])
    descs = db.get_port_descriptions(temp_db)
    assert descs.get((sid, "et1")) == "CCTV-정문"


# ── 파서 ─────────────────────────────────────────────────────────
def test_nxos_description_drops_type_and_speed_columns():
    out = nx._parse_descriptions(
        "mgmt0         --          1000       mgmt-if\n"
        "Eth1/1        eth         10G        to-core-sw01\n"
        "Eth1/2        eth         10G        --\n"
        "Po10          uplink-bundle\n")
    assert out["Eth1/1"] == "to-core-sw01", "Speed 컬럼이 설명에 섞였다"
    assert out["Eth1/2"] == "", "'--'는 설명 없음이다"
    assert out.get("Po10") == "uplink-bundle", "2컬럼 형식이 통째로 유실됐다"
    assert out["mgmt0"] == "mgmt-if"


def test_arista_description_handles_admin_down():
    desc = ("Port       Status         Protocol           Description\n"
            "Et1            up             up                 core-uplink\n"
            "Et3            admin down     down               reserved-for-AP\n"
            "Et5            down           down\n")
    detail = ("Ethernet1 is up, line protocol is up (connected)\n"
              "Ethernet3 is administratively down, line protocol is down (disabled)\n"
              "Ethernet5 is down, line protocol is down (notconnect)\n")
    ports = {p["name"]: p.get("description")
             for p in ar.parse({"status": detail, "description": desc}, 1)["ports"]}
    assert ports.get("Ethernet3") == "reserved-for-AP", "'admin down'의 두 번째 단어가 설명에 섞였다"
    assert ports.get("Ethernet5") in ("", None), "설명 없는 포트에 'down'이 들어갔다"
    assert ports.get("Ethernet1") == "core-uplink"


# ── 로그 살균 ────────────────────────────────────────────────────
def test_sanitizer_keeps_normal_messages_readable():
    for raw in ("Connection to 10.0.0.1:22 timed out",
                "Authentication failed for user admin",
                "netmiko: Pattern not detected: '#' in output"):
        assert collector._sanitize_error_msg(raw) == raw
