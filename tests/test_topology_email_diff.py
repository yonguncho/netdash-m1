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
