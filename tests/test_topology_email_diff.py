# -*- coding: utf-8 -*-
"""v3.29: 토폴로지 추론 + 이메일 알림 설정 + 설정 diff API 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, topology

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


# ─── 토폴로지 ─────────────────────────────
def _seed_link(db_path):
    """BACKBONE ↔ TPS11 상호 링크 시드: 서로의 관리 MAC을 상대 MAC 테이블에서 관측."""
    bb = db.save_switch(db_path, "BACKBONE", "10.0.0.1", "cisco_nxos")
    tps = db.save_switch(db_path, "TPS11", "10.0.0.11", "cisco_ios")
    mac_bb, mac_tps = "aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:11"
    s_bb = db.save_snapshot(db_path, bb)
    # BACKBONE의 ARP: 자기+TPS의 IP→MAC (관리 MAC 확보 경로)
    db.save_arp_entries(db_path, s_bb, bb, [
        {"ip": "10.0.0.1", "mac": mac_bb, "interface": "Vlan1"},
        {"ip": "10.0.0.11", "mac": mac_tps, "interface": "Vlan1"}])
    # BACKBONE MAC 테이블: TPS의 MAC이 Eth1/5에
    db.save_mac_entries(db_path, s_bb, bb, [
        {"vlan": 1, "mac": mac_tps, "port": "Eth1/5", "type": "dynamic"}])
    s_t = db.save_snapshot(db_path, tps)
    # TPS MAC 테이블: BACKBONE의 MAC이 Gi1/0/24에
    db.save_mac_entries(db_path, s_t, tps, [
        {"vlan": 1, "mac": mac_bb, "port": "Gi1/0/24", "type": "dynamic"}])
    return bb, tps


def test_topology_mutual_link(temp_db):
    bb, tps = _seed_link(temp_db)
    topo = topology.build_topology(temp_db)
    assert len(topo["nodes"]) == 2
    assert len(topo["links"]) == 1
    link = topo["links"][0]
    assert link["mutual"] is True
    ports = {link["a_port"], link["b_port"]}
    assert "Eth1/5" in ports and "Gi1/0/24" in ports
    # depth: 링크 수 동률이면 한쪽이 root(depth 0), 상대는 1
    depths = {n["id"]: n["depth"] for n in topo["nodes"]}
    assert sorted(depths.values()) == [0, 1]


def test_topology_empty(temp_db):
    topo = topology.build_topology(temp_db)
    assert topo == {"nodes": [], "links": []}


def test_topology_firewall_node_and_link(temp_db):
    """방화벽 노드 포함 + 스위치 ARP/MAC으로 직결 링크 추론(설비는 미포함)."""
    bb, tps = _seed_link(temp_db)
    fid = db.save_firewall(temp_db, "FW-1", "fortigate", "10.0.0.99", port=443)
    # BACKBONE ARP에 방화벽 IP→MAC, MAC 테이블에서 물리 포트 관측
    s2 = db.save_snapshot(temp_db, bb)
    db.save_arp_entries(temp_db, s2, bb, [
        {"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01", "interface": "Vlan1"},
        {"ip": "10.0.0.11", "mac": "bb:bb:bb:bb:bb:11", "interface": "Vlan1"},
        {"ip": "10.0.0.99", "mac": "cc:cc:cc:cc:cc:99", "interface": "Vlan1"}])
    db.save_mac_entries(temp_db, s2, bb, [
        {"vlan": 1, "mac": "bb:bb:bb:bb:bb:11", "port": "Eth1/5", "type": "dynamic"},
        {"vlan": 1, "mac": "cc:cc:cc:cc:cc:99", "port": "Eth1/7", "type": "dynamic"}])
    topo = topology.build_topology(temp_db)
    fw_nodes = [n for n in topo["nodes"] if n.get("kind") == "fw"]
    assert len(fw_nodes) == 1 and fw_nodes[0]["id"] == "f%d" % fid
    fw_links = [l for l in topo["links"] if str(l["b"]).startswith("f")]
    assert len(fw_links) == 1
    assert fw_links[0]["a"] == bb and fw_links[0]["a_port"] == "Eth1/7"
    # 스위치 노드에 kind 표기
    assert all(n.get("kind") in ("sw", "fw") for n in topo["nodes"])


def test_topology_zone_ui():
    """구역 집계 맵 ↔ 구역 상세 2단계 + 검색 UI."""
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "_renderZoneMap" in js and "_renderZoneDetail" in js
    assert "_topoZoneOf" in js and "🏢 백본" in js
    assert "topo-search" in js                  # 장비 검색
    assert "data-ghost" in js                   # 타 구역 직결(고스트) 노드
    assert "링크</text>" in js                  # 구역 간 링크 집계 라벨


def test_topology_api(client):
    r = client.get("/api/topology")
    b = r.get_json()
    assert "nodes" in b and "links" in b


# ─── 이메일 설정 ─────────────────────────────
def test_email_settings_roundtrip(client):
    r = client.post("/api/settings/email", json={
        "enabled": True, "smtp_host": "10.0.0.25", "smtp_port": "25",
        "smtp_from": "netdash@x.local", "email_to": "a@x.local,b@x.local",
        "min_sev": "info"})
    assert r.get_json()["ok"]
    g = client.get("/api/settings/email").get_json()
    assert g["enabled"] is True and g["smtp_host"] == "10.0.0.25"
    assert g["email_to"] == "a@x.local,b@x.local" and g["min_sev"] == "info"


def test_notifier_digest_format():
    from core import notifier
    body = notifier._format_digest([
        {"kind": "new_device", "severity": "warning", "ip": "10.0.0.5", "message": "새 설비 감지"},
        {"kind": "switch_unreachable", "severity": "warning", "label": "SW1"}])
    assert "새 설비" in body and "SW1" in body and "2건" in body


def test_notifier_severity_filter():
    from core import notifier
    assert notifier._severity_ok({"severity": "info"}, "warning") is False
    assert notifier._severity_ok({"severity": "warning"}, "warning") is True
    assert notifier._severity_ok({"severity": "info"}, "info") is True


# ─── 설정 diff ─────────────────────────────
def test_config_diff_api(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SW-D", "10.0.0.77", "cisco_ios")
    db.save_config_backup(dbp, sid, "hostname A\nline1")
    db.save_config_backup(dbp, sid, "hostname A\nline1-changed")
    backups = db.get_config_backups(dbp, sid)
    newest = backups[0]["id"]
    r = client.get("/api/configs/diff?a=%d" % newest)
    b = r.get_json()
    assert b["ok"] and not b["same"]
    joined = "\n".join(b["diff"])
    assert "-line1" in joined and "+line1-changed" in joined


# ─── UI ─────────────────────────────
def test_new_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-tab="topology"' in html and 'id="topology-canvas"' in html
    assert 'data-dtab="config"' in html and 'id="dtab-config"' in html
    assert 'id="em-enabled"' in html and 'id="btn-em-test"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "function loadTopology" in js and "function renderTopology" in js
    assert "function loadConfigTab" in js and "/api/configs/diff" in js


def test_topology_tree_ui_features():
    """v3.32: Meraki/UniFi식 트리 배치 + 호버 툴팁 + 줌/팬 + 미연결 분리."""
    js = APP_JS.read_text(encoding="utf-8")
    assert "assignX" in js                 # tidy tree(부모=자식 중앙)
    assert "topo-tip" in js                # 호버 툴팁
    assert "viewBox" in js and "wheel" in js  # 줌/팬
    assert "topo-orphan" in js             # 미연결 장비 하단 분리
    assert "topo-edge" in js               # 베지어 링크 + 노드 호버 강조
