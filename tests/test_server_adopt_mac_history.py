# -*- coding: utf-8 -*-
"""서버 편입(device_type=Server) + 과거 MAC 이력 조회 + 관제 과거위치 표기 + L3 라우팅신호."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, topology


# ── 과거 MAC 이력 ───────────────────────────────────────────────
def test_find_mac_history(temp_db):
    sid = db.save_switch(temp_db, "SW-HIST", "10.4.0.11", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid,
                        [{"mac": "AA:BB:CC:11:22:33", "port": "Gi1/0/24", "vlan": 10}])
    hist = db.find_mac_history(temp_db, "aabb.cc11.2233")   # 형식 무관
    assert hist and hist["switch_name"] == "SW-HIST" and hist["port"] == "Gi1/0/24"
    assert db.find_mac_history(temp_db, "00:00:00:00:00:00") is None


def test_wall_facility_shows_past_location(tmp_path, monkeypatch):
    """설비가 현재 끊겨 위치 미상이어도, 과거 스냅샷에 MAC이 있으면 '과거 확인' 표기."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()

    sid = db.save_switch(dbp, "SW-EDGE9", "10.4.0.9", "cisco_ios")
    snap = db.save_snapshot(dbp, sid)
    db.save_mac_entries(dbp, snap, sid,
                        [{"mac": "CC:CC:CC:00:00:77", "port": "Gi1/0/7", "vlan": 5}])
    # 현재 위치 미상(switch_name 비움)인 오프라인 설비 — MAC은 과거 스냅샷에 존재
    db.save_facility_hosts(dbp, [
        {"subnet": "10.4.0.0/24", "ip": "10.4.0.77", "mac": "CC:CC:CC:00:00:77",
         "switch_name": "", "port": "", "online": 0}])
    cats = application.test_client().get("/api/wall").get_json()["categories"]
    fac = [c for c in cats if c["key"] == "facility"][0]["items"]
    detail = {i["name"]: i["detail"] for i in fac}["10.4.0.77"]
    assert "과거 확인" in detail and "SW-EDGE9" in detail and "Gi1/0/7" in detail


# ── 서버 편입 ───────────────────────────────────────────────────
def test_adopt_server_switches(temp_db):
    sid = db.save_switch(temp_db, "SRV-01", "10.5.5.5", "unknown")
    db.update_switch(temp_db, sid, device_type="Server", hostname="srv01.local")
    n = db.adopt_server_switches(temp_db)
    assert n == 1
    # 서버 테이블에 나타나고, 스위치 목록에서는 사라짐
    servers = {s["ip"]: s for s in db.list_servers(temp_db)}
    assert "10.5.5.5" in servers
    # 스위치가 알던 hostname을 서버로 승계(편입 시 유실 방지)
    assert servers["10.5.5.5"]["hostname"] == "srv01.local"
    sw_ips = {s["ip"] for s in db.get_switches(temp_db)}
    assert "10.5.5.5" not in sw_ips
    # 멱등 — 다시 호출해도 0
    assert db.adopt_server_switches(temp_db) == 0


def test_servers_endpoint_adopts(client):
    """GET /api/servers 시 구분=Server 스위치가 서버로 편입되어 목록에 노출."""
    import app as app_module  # noqa
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SRV-X", "10.6.6.6", "unknown")
    db.update_switch(dbp, sid, device_type="Server")
    servers = client.get("/api/servers").get_json()["servers"]
    assert any(s["ip"] == "10.6.6.6" for s in servers)


# ── L3 분류 개선(라우팅 프로토콜) ───────────────────────────────
def test_classify_l3_routing_protocol():
    assert topology.classify_l3("hostname X\nrouter ospf 1\n network 10.0.0.0\n") == "L3"
    assert topology.classify_l3("feature bgp\nrouter bgp 65000\n") == "L3"
    # 순수 L2(관리 SVI 1개 + 기본 게이트웨이)는 여전히 L2
    l2 = "hostname SW\ninterface Vlan1\n ip address 10.0.0.2 255.255.255.0\nip default-gateway 10.0.0.1\n"
    assert topology.classify_l3(l2) == "L2"
