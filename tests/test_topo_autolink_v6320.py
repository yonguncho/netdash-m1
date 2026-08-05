# -*- coding: utf-8 -*-
"""v6.32.0 — 토폴로지 자동 연결·코어 초안·자동 정렬·검색.

사용자 방향: 전체 자동 배치는 장비가 너무 많아 폐기. 코어(방화벽·백본·L3)만
그리고, **캔버스에 올려진 장비끼리만** 수집 근거로 선을 자동으로 긋는다
("굳이 선을 하나하나 연결할 필요 없잖아").
"""
from pathlib import Path

from core import db, topology

ROOT = Path(__file__).parent.parent


def _sw(p, name, ip):
    return db.save_switch(p, name, ip, "cisco_ios")


def _links_by_pair(links):
    return {tuple(sorted((l["a_ip"], l["b_ip"]))): l for l in links}


def test_autolink_neighbor_by_ip_with_both_ports(temp_db):
    a = _sw(temp_db, "BB-01", "10.0.0.1")
    _sw(temp_db, "L3-01", "10.0.0.2")
    db.save_neighbors(temp_db, a, [
        {"local_port": "Eth1/1", "remote_name": "L3-01", "remote_port": "Te1/0/1",
         "remote_ip": "10.0.0.2"}])
    links = topology.autolink(temp_db, ["10.0.0.1", "10.0.0.2"])
    assert len(links) == 1
    l = links[0]
    assert {l["a_ip"], l["b_ip"]} == {"10.0.0.1", "10.0.0.2"}
    ports = {l["a_ip"]: l["a_port"], l["b_ip"]: l["b_port"]}
    assert ports["10.0.0.1"] == "Eth1/1" and ports["10.0.0.2"] == "Te1/0/1"
    assert l["basis"] == "neighbor"


def test_autolink_neighbor_by_name_matches_firewall(temp_db):
    """이웃 행에 IP가 없어도 정규화 이름으로 올려진 방화벽과 잇는다."""
    a = _sw(temp_db, "BB-01", "10.0.0.1")
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) "
                     "VALUES ('FW-CORE','fortigate','10.0.0.9')")
    db.save_neighbors(temp_db, a, [
        {"local_port": "Eth1/5", "remote_name": "FW-CORE.example.com",
         "remote_port": "port1", "remote_ip": ""}])
    links = topology.autolink(temp_db, ["10.0.0.1", "10.0.0.9"])
    assert len(links) == 1 and links[0]["basis"] == "neighbor"


def test_autolink_only_placed_pairs(temp_db):
    """올려진 쌍만 — 캔버스 밖 장비로는 선을 만들지 않는다(핵심 요구)."""
    a = _sw(temp_db, "BB-01", "10.0.0.1")
    _sw(temp_db, "L3-01", "10.0.0.2")
    _sw(temp_db, "ACC-77", "10.0.0.77")          # 캔버스에 없음
    db.save_neighbors(temp_db, a, [
        {"local_port": "Eth1/1", "remote_name": "L3-01", "remote_ip": "10.0.0.2"},
        {"local_port": "Eth1/7", "remote_name": "ACC-77", "remote_ip": "10.0.0.77"}])
    links = topology.autolink(temp_db, ["10.0.0.1", "10.0.0.2"])
    assert len(links) == 1
    assert "10.0.0.77" not in _links_by_pair(links).__str__()


def test_autolink_mac_learned_on_access_port(temp_db):
    """비스위치(서버)는 ARP로 MAC을 얻고 액세스 포트 학습 위치로 잇는다."""
    a = _sw(temp_db, "ACC-01", "10.0.0.2")
    snap = db.save_snapshot(temp_db, a)
    db.save_arp_entries(temp_db, snap, a, [
        {"ip": "10.0.0.50", "mac": "aa:bb:cc:dd:ee:01", "interface": "Vlan10"}])
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO mac_entries (snapshot_id, switch_id, mac, port, vlan) "
                     "VALUES (?,?,?,?,?)", (snap, a, "aabb.ccdd.ee01", "Gi1/0/10", "10"))
        conn.execute("INSERT INTO servers (name, ip) VALUES ('SRV-01','10.0.0.50')")
    db.invalidate_mac_last_cache(temp_db)
    links = topology.autolink(temp_db, ["10.0.0.2", "10.0.0.50"])
    assert len(links) == 1
    l = links[0]
    assert l["basis"] == "mac"
    ports = {l["a_ip"]: l["a_port"], l["b_ip"]: l["b_port"]}
    assert ports["10.0.0.2"] == "Gi1/0/10" and ports["10.0.0.50"] == ""


def test_autolink_uplink_observation_excluded(temp_db, monkeypatch):
    """업링크 관측(다른 스위치 너머)은 직결이 아니다 — 선을 긋지 않는다."""
    _sw(temp_db, "BB-01", "10.0.0.1")
    a = _sw(temp_db, "ACC-01", "10.0.0.2")
    snap = db.save_snapshot(temp_db, a)
    db.save_arp_entries(temp_db, snap, a, [
        {"ip": "10.0.0.50", "mac": "aa:bb:cc:dd:ee:02", "interface": "Vlan10"}])
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO servers (name, ip) VALUES ('SRV-02','10.0.0.50')")
    monkeypatch.setattr(db, "get_mac_last_seen",
                        lambda p, want_macs=None: {"aabbccddee02": {
                            "switch_name": "ACC-01", "port": "Po1",
                            "via_uplink": True}})
    assert topology.autolink(temp_db, ["10.0.0.2", "10.0.0.50"]) == []


def test_autolink_needs_two_ips(temp_db):
    assert topology.autolink(temp_db, ["10.0.0.1"]) == []
    assert topology.autolink(temp_db, []) == []
    assert topology.autolink(temp_db, None) == []


def test_autolink_endpoint(client):
    r = client.post("/api/topology/autolink", json={"ips": "notalist"})
    assert r.status_code == 400
    r = client.post("/api/topology/autolink", json={"ips": ["10.0.0.1", "10.0.0.2"]})
    assert r.status_code == 200 and "links" in r.get_json()


def test_topo_ui_markers_v6320():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    for m in ("btn-topo-core", "btn-topo-autolink", "btn-topo-arrange", "topo-search"):
        assert m in html, m
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function _tAutoLink" in js and "function _tAutoArrange" in js
    assert "/api/topology/autolink" in js
    # 코어 초안은 방화벽·백본·L3/L4만(사용자: 전체는 너무 많아 보기 어렵다)
    assert "CORE = { firewall: 1, backbone: 1, l3: 1, l4: 1 }" in js
