# -*- coding: utf-8 -*-
"""서버실 트리 구성도(v4.2) — config 기반 L3 판정 + SVI 대역 + 트리 빌드."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, topology


_L3_CFG = """\
hostname L3-CORE
ip routing
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
interface Vlan20
 ip address 10.0.20.1 255.255.255.0
"""

_L2_CFG = """\
hostname L2-ACCESS
interface Vlan1
 ip address 10.0.99.5 255.255.255.0
ip default-gateway 10.0.99.1
"""


def test_classify_l3_vs_l2():
    assert topology.classify_l3(_L3_CFG) == "L3"
    assert topology.classify_l3(_L2_CFG) == "L2"
    assert topology.classify_l3("") is None
    # 정적 라우트(비 default)만 있어도 L3
    assert topology.classify_l3("ip route 10.1.0.0 255.255.0.0 10.0.0.2") == "L3"
    # default route만 → L2
    assert topology.classify_l3("ip route 0.0.0.0 0.0.0.0 10.0.0.1") == "L2"


def test_parse_svi_subnets():
    svis = topology.parse_svi_subnets(_L3_CFG)
    got = {(s["vlan"], s["cidr"]) for s in svis}
    assert (10, "10.0.10.0/24") in got
    assert (20, "10.0.20.0/24") in got


def test_serverroom_tree_hides_l2_and_boxes_subnets(temp_db):
    # L3(서버실) + L2(서버실) + 서버실 밖 스위치
    l3 = db.import_switches_bulk(temp_db, [{"name": "CORE", "ip": "10.0.0.1",
        "vendor": "cisco_ios", "location": "A01U40"}])[0]
    l2 = db.import_switches_bulk(temp_db, [{"name": "ACC", "ip": "10.0.0.2",
        "vendor": "cisco_ios", "location": "A01U10"}])[0]
    out = db.import_switches_bulk(temp_db, [{"name": "REMOTE", "ip": "10.0.0.3",
        "vendor": "cisco_ios", "location": "3층 사무실"}])[0]
    db.update_switch(temp_db, l3, device_type="BackBone")
    db.save_config_backup(temp_db, l3, _L3_CFG)
    db.save_config_backup(temp_db, l2, _L2_CFG)
    db.save_config_backup(temp_db, out, _L3_CFG)

    tree = topology.build_serverroom_tree(temp_db)
    names = {n["name"]: n for n in tree["nodes"]}
    assert "CORE" in names            # 서버실 L3/백본 포함
    assert "ACC" not in names         # 서버실 L2 → 숨김
    assert "REMOTE" not in names      # 서버실 밖 → 제외
    core = names["CORE"]
    assert core["role"] == "backbone"
    cidrs = {s["cidr"] for s in core["subnets_vlan"]}
    assert "10.0.10.0/24" in cidrs and "10.0.20.0/24" in cidrs
    assert l3 in tree["roots"]        # 백본은 루트


def test_serverroom_tree_includes_firewall_role(temp_db):
    # build_topology는 스위치가 있어야 노드를 만든다 → 서버실 L3 1대 추가
    l3 = db.import_switches_bulk(temp_db, [{"name": "CORE", "ip": "10.0.0.1",
        "vendor": "cisco_ios", "location": "A01U40"}])[0]
    db.save_config_backup(temp_db, l3, _L3_CFG)
    fid = db.save_firewall(temp_db, "INTERNET-FW", "paloalto", "10.0.0.254",
                           location="A01U42")
    tree = topology.build_serverroom_tree(temp_db)
    fw = [n for n in tree["nodes"] if n["kind"] == "fw"]
    assert fw and fw[0]["role"] == "internet_fw"   # 이름에 INTERNET → 경계 방화벽
