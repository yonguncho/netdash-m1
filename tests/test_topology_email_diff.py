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
    assert link.get("source") == "mac"     # CDP/LLDP 없으면 MAC 추론 링크
    ports = {link["a_port"], link["b_port"]}
    assert "Eth1/5" in ports and "Gi1/0/24" in ports


def test_topology_mac_inference_picks_direct_port(temp_db):
    """추론 장비: 이웃 MAC이 여러 포트에 보여도 직결(MAC 수 적은 물리) 포트 선택."""
    a = db.save_switch(temp_db, "OABB", "10.0.0.1", "cisco_nxos")
    b = db.save_switch(temp_db, "FASW1", "10.0.0.2", "cisco_ios")
    mac_a, mac_b = "aa:aa:aa:00:00:01", "bb:bb:bb:00:00:02"
    sa = db.save_snapshot(temp_db, a)
    db.save_arp_entries(temp_db, sa, a, [
        {"ip": "10.0.0.1", "mac": mac_a, "interface": "Vlan1"},
        {"ip": "10.0.0.2", "mac": mac_b, "interface": "Vlan1"}])
    # OABB: FASW1의 MAC이 Eth1/1(트렁크, MAC 다수)과 Eth1/9(직결, MAC 1개) 둘 다 보임
    db.save_mac_entries(temp_db, sa, a, [
        {"vlan": 1, "mac": mac_b, "port": "Eth1/1", "type": "dynamic"},
        {"vlan": 1, "mac": "de:ad:be:ef:00:01", "port": "Eth1/1", "type": "dynamic"},
        {"vlan": 1, "mac": "de:ad:be:ef:00:02", "port": "Eth1/1", "type": "dynamic"},
        {"vlan": 1, "mac": mac_b, "port": "Eth1/9", "type": "dynamic"}])
    sb = db.save_snapshot(temp_db, b)
    db.save_mac_entries(temp_db, sb, b, [
        {"vlan": 1, "mac": mac_a, "port": "Gi1/0/48", "type": "dynamic"}])
    topo = topology.build_topology(temp_db)
    link = [l for l in topo["links"] if {l["a"], l["b"]} == {a, b}][0]
    ports = {link["a_port"], link["b_port"]}
    assert "Eth1/9" in ports          # 트렁크 Eth1/1이 아니라 직결 Eth1/9
    assert "Eth1/1" not in ports
    assert link.get("source") == "mac"
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


def test_topology_nodes_have_device_type_and_subnets(temp_db):
    """노드에 device_type + config 백업 기반 연결 대역(subnets) 포함."""
    bb, tps = _seed_link(temp_db)
    db.update_switch(temp_db, bb, device_type="BackBone")
    db.save_config_backup(temp_db, bb,
        "hostname BB\ninterface Vlan100\n ip address 10.92.174.1 255.255.254.0\n"
        "interface Vlan200\n ip address 10.92.176.1 255.255.255.0\n")
    topo = topology.build_topology(temp_db)
    bbn = [n for n in topo["nodes"] if n["id"] == bb][0]
    assert bbn["device_type"] == "BackBone"
    assert "10.92.174.0/23" in bbn["subnets"]
    assert "10.92.176.0/24" in bbn["subnets"]


def test_topology_firewall_interfaces_in_node(temp_db):
    """방화벽 노드에 인터페이스 IP 요약 포함(서버실 구성도 태그용)."""
    db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")   # switches 있어야 build 진행
    fid = db.save_firewall(temp_db, "FW-1", "fortigate", "10.0.0.99", port=443)
    db.save_firewall_interfaces(temp_db, fid, [
        {"name": "port1", "ip": "10.92.170.1", "mask": "23", "vdom_zone": "root"}])
    topo = topology.build_topology(temp_db)
    fwn = [n for n in topo["nodes"] if n.get("kind") == "fw"][0]
    assert fwn["device_type"] == "Firewall"
    assert any("10.92.170.1/23" in s for s in fwn["interfaces"])


def test_topology_firewall_l3_adjacency_link(temp_db):
    """FABB↔방화벽처럼 MAC이 안 잡혀도, 스위치 라우팅 대역에 방화벽 IP가
    포함되면 L3 인접 링크를 그린다(첨부 구성도 케이스)."""
    bb = db.save_switch(temp_db, "FABB", "10.92.0.1", "cisco_nxos")
    db.update_switch(temp_db, bb, device_type="BackBone")
    # FABB가 10.92.186.0/24를 라우팅(config)
    db.save_config_backup(temp_db, bb,
        "hostname FABB\ninterface Vlan186\n ip address 10.92.186.2 255.255.255.0\n")
    # 방화벽 IP가 그 대역 안(10.92.186.1) — MAC 관측은 없음
    fid = db.save_firewall(temp_db, "F1_FA_FW", "fortigate", "10.92.186.1", port=443)
    topo = topology.build_topology(temp_db)
    fw_links = [l for l in topo["links"] if str(l["b"]) == "f%d" % fid]
    assert len(fw_links) == 1
    assert fw_links[0]["a"] == bb and fw_links[0].get("l3") is True


def test_topology_firewall_multi_homed(temp_db):
    """방화벽이 여러 스위치에 물리 관측되면 각각 링크(다중 연결)."""
    a = db.save_switch(temp_db, "SW-A", "10.0.0.1", "cisco_ios")
    b = db.save_switch(temp_db, "SW-B", "10.0.0.2", "cisco_ios")
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.99", port=443)
    for sid in (a, b):
        snap = db.save_snapshot(temp_db, sid)
        db.save_arp_entries(temp_db, snap, sid, [
            {"ip": "10.0.0.99", "mac": "cc:cc:cc:00:00:99", "interface": "Vlan1"}])
        db.save_mac_entries(temp_db, snap, sid, [
            {"vlan": 1, "mac": "cc:cc:cc:00:00:99", "port": "Gi1/0/1", "type": "dynamic"}])
    topo = topology.build_topology(temp_db)
    fw_links = [l for l in topo["links"] if str(l["b"]) == "f%d" % fid]
    assert {l["a"] for l in fw_links} == {a, b}   # 두 스위치 모두 연결


def test_infer_role_from_hostname():
    """구분 미지정 시 hostname 패턴으로 계층 자동 추론."""
    assert topology.infer_role("SKBA_F1_FABB") == "BackBone"
    assert topology.infer_role("SKBA_F1_FASW1") == "L2 Switch"
    assert topology.infer_role("SKBA_F1_OASVR_L4_1") == "L4 Switch"
    assert topology.infer_role("SKBA_F1_FA_FW") == "Firewall"
    assert topology.infer_role("CORE_L3SW_01") == "BackBone"
    assert topology.infer_role("random-host") == ""


def test_topology_node_inferred_device_type(temp_db):
    """구분 미지정 스위치 노드에 추론된 device_type + inferred 플래그."""
    bb, tps = _seed_link(temp_db)   # BACKBONE, TPS11
    topo = topology.build_topology(temp_db)
    bbn = [n for n in topo["nodes"] if n["id"] == bb][0]
    assert bbn["device_type"] == "BackBone" and bbn["inferred"] is True


def test_topology_galaxy_view_removed():
    """성단 뷰 제거 확인 — 서버실/TPS 2탭만."""
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'data-mode="galaxy"' not in html
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "_renderGalaxy" not in js
    # 개선된 장비 심볼(라우터/스위치/방화벽) 존재
    assert "_deviceSymbol" in js


def test_topology_two_tab_ui():
    """토폴로지 2탭(서버실 구성도/TPS 구역도) + 중간 카드 + 종류 아이콘."""
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'data-mode="core"' in html and 'data-mode="tps"' in html
    assert 'id="topo-zone-select"' in html
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "_renderCoreMap" in js and "_renderTpsMap" in js
    assert "_isCoreDevice" in js and "_topoKindOf" in js
    assert "_drawNode" in js                     # 중간 카드
    assert "_deviceSymbol" in js                 # 실제 장비 심볼(SVG)
    assert "이중화 링크" in js                   # 이중화 쌍 인식
    assert "_RANK_SEG" in js                     # 세그먼트(구역) 컨테이너 박스
    assert "L3 대역 인접" in js                  # L3 링크 구분
    assert "코어 계층" in js and "분배 계층" in js and "액세스 계층" in js  # 3-Tier 라벨
    assert "_buildBands" in js and "_drawBand" in js  # L2 대역 뱃지(접기)
    assert "_topoExpandL2" in js                 # L2 펼치기/접기 토글


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
    """v3.45: 2탭 계층 배치 + 호버 툴팁 + 줌/팬 + 카드 노드."""
    js = APP_JS.read_text(encoding="utf-8")
    assert "_layoutLayered" in js          # 종류별 계층 배치
    assert "topo-tip" in js                # 호버 툴팁
    assert "viewBox" in js and "wheel" in js  # 줌/팬
    assert "topo-edge" in js               # 베지어 링크 + 노드 호버 강조
    assert "_drawNode" in js               # 중간 카드 노드


def test_topology_l2_band_ui():
    """L2 대역 뱃지: 토글 버튼 + 뱃지 렌더 + /24 그룹핑 + 드릴다운."""
    js = APP_JS.read_text(encoding="utf-8")
    html = HTML.read_text(encoding="utf-8")
    assert 'id="btn-topo-l2"' in html          # L2 펼치기/접기 토글 버튼
    assert "_ipBand" in js                      # /24 대역 산출
    assert "band-detail" in js                  # 드릴다운 패널
    assert 'kind === "band"' in js              # 대역 유사노드 처리


def test_serial_c9300l_formats():
    """C9300L: show inventory SN / 스위치 표(Serial No.) / System Serial 모두 파싱."""
    from core.collector import _parse_serial
    inv = 'PID: C9300L-48P-4G     , VID: V01  , SN: FOC2530L1AB'
    tbl = "*    1   57     C9300L-48P-4G      FOC2530L1AB"
    std = "System Serial Number            : FCW2140L0GH"
    assert _parse_serial("cisco_ios", inv) == "FOC2530L1AB"
    assert _parse_serial("cisco_ios", tbl) == "FOC2530L1AB"
    assert _parse_serial("cisco_ios", std) == "FCW2140L0GH"
    # cisco_xe도 동일 패턴 적용
    assert _parse_serial("cisco_xe", inv) == "FOC2530L1AB"


def test_cisco_ios_runs_inventory():
    """cisco_ios 수집 명령에 show inventory 포함(시리얼/모델 확실)."""
    from core.parsers import cisco_ios
    assert cisco_ios.COMMANDS.get("inventory") == "show inventory"
