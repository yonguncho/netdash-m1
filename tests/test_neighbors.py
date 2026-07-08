# -*- coding: utf-8 -*-
"""CDP/LLDP 이웃 파서 + 저장 + 토폴로지 정확 링크 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, topology
from core.parsers import neighbors, cisco_nxos

CDP = """
----------------------------------------
Device ID: SKBA_F1_FASW1.corp.local
Entry address(es):
  IP address: 10.92.174.11
Platform: cisco N9K-C93180YC-EX,  Capabilities: Router Switch
Interface: Ethernet1/9,  Port ID (outgoing port): Ethernet1/48
Holdtime : 165 sec

----------------------------------------
Device ID: SKBA_F1_FW.corp.local
Entry address(es):
  IP address: 10.92.186.1
Platform: cisco ASA,  Capabilities: Host
Interface: Ethernet1/1,  Port ID (outgoing port): GigabitEthernet0/0
"""

LLDP = """
Interface Ethernet49 detected 1 LLDP neighbors:
  Neighbor 001c.7300.0001, age 12 seconds
  - System Name: "spine-1"
  - Port ID    : "Ethernet1"
  - Management Address : 10.0.0.1
  - System Description: Arista DCS-7050
"""


def test_parse_cdp_detail():
    n = neighbors.parse_cdp_detail(CDP)
    assert len(n) == 2
    a = next(x for x in n if x["remote_name"] == "SKBA_F1_FASW1")
    assert a["local_port"] in ("Eth1/9", "Ethernet1/9")
    assert a["remote_port"] in ("Eth1/48", "Ethernet1/48")
    assert a["remote_ip"] == "10.92.174.11"
    fw = next(x for x in n if x["remote_name"] == "SKBA_F1_FW")
    assert fw["remote_ip"] == "10.92.186.1"


def test_parse_lldp_detail():
    n = neighbors.parse_lldp_detail(LLDP)
    assert len(n) == 1
    assert n[0]["remote_name"] == "spine-1"
    assert n[0]["remote_ip"] == "10.0.0.1"


def test_nxos_parse_includes_neighbors():
    r = cisco_nxos.parse({"neighbors": CDP}, 1)
    assert len(r["neighbors"]) == 2


def test_neighbors_roundtrip_and_topology(temp_db):
    a = db.save_switch(temp_db, "SKBA_F1_FABB", "10.92.0.1", "cisco_nxos")
    b = db.save_switch(temp_db, "SKBA_F1_FASW1", "10.92.174.11", "cisco_nxos")
    db.save_neighbors(temp_db, a, [
        {"local_port": "Eth1/9", "remote_name": "SKBA_F1_FASW1",
         "remote_port": "Eth1/48", "remote_ip": "10.92.174.11", "platform": "N9K"}])
    got = db.get_all_neighbors(temp_db)
    assert len(got) == 1 and got[0]["remote_name"] == "SKBA_F1_FASW1"
    # 토폴로지: CDP 기반 정확 링크(양쪽 포트 + source=cdp/lldp)
    topo = topology.build_topology(temp_db)
    link = [l for l in topo["links"] if {l["a"], l["b"]} == {a, b}]
    assert len(link) == 1
    assert link[0]["mutual"] is True
    assert link[0].get("source") == "cdp/lldp"
    ports = {link[0]["a_port"], link[0]["b_port"]}
    assert "Eth1/9" in ports and "Eth1/48" in ports
