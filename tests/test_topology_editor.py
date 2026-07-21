# -*- coding: utf-8 -*-
"""하이브리드 토폴로지 편집기 백엔드(v4.4) — 조회/대역제안/포트인식/저장."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, topology


_L3_CFG = """\
ip routing
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
interface Vlan20
 ip address 10.0.20.1 255.255.255.0
"""


def test_lookup_device_by_ip(temp_db):
    sid = db.import_switches_bulk(temp_db, [{"name": "SW1", "ip": "10.0.0.1",
        "vendor": "cisco_ios", "hostname": "sw1.local"}])[0]
    db.save_config_backup(temp_db, sid, _L3_CFG)
    dev = topology.lookup_device(temp_db, "10.0.0.1")
    assert dev["kind"] == "sw" and dev["hostname"] == "sw1.local"
    assert dev["l3_class"] == "L3"
    # 서버도 조회됨
    db.save_server(temp_db, "SRV", "10.0.0.9", os_type="linux")
    d2 = topology.lookup_device(temp_db, "10.0.0.9")
    assert d2["kind"] == "srv" and d2["name"] == "SRV"
    # 미등록 IP
    assert topology.lookup_device(temp_db, "10.0.0.250") is None


def test_subnet_suggest_l2_inherits_from_l3(temp_db):
    """L2가 나르는 VLAN을 상위 L3 SVI 대역으로 자동 제안."""
    l3 = db.import_switches_bulk(temp_db, [{"name": "L3", "ip": "10.0.0.1",
        "vendor": "cisco_ios"}])[0]
    l2 = db.import_switches_bulk(temp_db, [{"name": "L2", "ip": "10.0.0.2",
        "vendor": "cisco_ios"}])[0]
    db.save_config_backup(temp_db, l3, _L3_CFG)     # SVI Vlan10/20
    db.save_vlan_names(temp_db, l2, [{"vlan": 10, "name": "V10", "status": "active"},
                                     {"vlan": 20, "name": "V20", "status": "active"}])
    sug = topology.subnet_suggest(temp_db, "10.0.0.2")   # L2
    cidrs = {s["cidr"] for s in sug}
    assert "10.0.10.0/24" in cidrs and "10.0.20.0/24" in cidrs
    assert all(s["source"] == "vlan" for s in sug)   # 상속(SVI 아님)


def test_resolve_link_ports(temp_db):
    """A 스위치에서 B의 MAC이 보이는 물리 포트를 연결 포트로 인식."""
    a = db.import_switches_bulk(temp_db, [{"name": "A", "ip": "10.0.0.1",
        "vendor": "cisco_ios"}])[0]
    b = db.import_switches_bulk(temp_db, [{"name": "B", "ip": "10.0.0.2",
        "vendor": "cisco_ios"}])[0]
    snap = db.save_snapshot(temp_db, a, 1)
    conn = sqlite3.connect(str(temp_db))
    # B의 관리 MAC(BBBB..)이 A의 ARP에 + A의 Gi1/0/1 MAC 테이블에 보임
    conn.execute("INSERT INTO arp_entries (snapshot_id, switch_id, ip, mac) VALUES (?,?,?,?)",
                 (snap, a, "10.0.0.2", "BB:BB:BB:BB:BB:BB"))
    conn.execute("INSERT INTO mac_entries (snapshot_id, switch_id, vlan, mac, port) "
                 "VALUES (?,?,?,?,?)", (snap, a, 1, "BB:BB:BB:BB:BB:BB", "Gi1/0/1"))
    conn.commit(); conn.close()
    res = topology.resolve_link_ports(temp_db, "10.0.0.1", "10.0.0.2")
    assert res["a_port"] == "Gi1/0/1"     # A에서 B가 보이는 포트
    assert res["method"] == "mac"


def test_diagram_save_load(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    client = application.test_client()
    diagram = {"nodes": [{"id": "n1", "ip": "10.0.0.1", "x": 100, "y": 50,
                          "subnets": [{"cidr": "10.9.0.0/24", "source": "manual"}]}],
               "edges": [{"a": "n1", "b": "n2", "a_port": "Gi1/0/1"}]}
    r = client.post("/api/topology/diagram", json=diagram)
    assert r.status_code == 200 and r.get_json()["ok"]
    got = client.get("/api/topology/diagram").get_json()
    assert got["nodes"][0]["ip"] == "10.0.0.1"
    assert got["edges"][0]["a_port"] == "Gi1/0/1"
