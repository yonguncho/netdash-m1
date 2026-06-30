"""Cisco Nexus(NX-OS) 파서 테스트 — IOS와 다른 명령/출력 형식."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector
from core.parsers import cisco_nxos, get_parser

# 실제 NX-OS 출력 샘플
SH_INT_BRIEF = """
--------------------------------------------------------------------------------
Port   VRF          Status IP Address                              Speed    MTU
--------------------------------------------------------------------------------
mgmt0  --           up     10.92.128.68                            1000     1500

--------------------------------------------------------------------------------
Ethernet      VLAN    Type Mode   Status  Reason                   Speed     Port
Interface                                                                    Ch #
--------------------------------------------------------------------------------
Eth1/1        100     eth  access up      none                       10G(D) --
Eth1/2        1       eth  trunk  down    Link not connected         auto    --
Eth1/3        --      eth  routed up      none                       10G(D) --
"""

SH_INT_DESC = """
-------------------------------------------------------------------------------
Port          Type      Description
-------------------------------------------------------------------------------
Eth1/1        eth       SERVER-WEB-01
Eth1/2        eth       UPLINK-CORE
mgmt0         --        --
"""

SH_MAC = """
Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
   VLAN     MAC Address      Type      age     Secure NTFY Ports
---------+-----------------+--------+---------+------+----+------------------
*  100      0050.56a1.b2c3   dynamic   0          F    F  Eth1/1
*  100      00ab.cdef.1234   dynamic   NA         F    F  Eth1/1
*  200      aabb.ccdd.eeff   dynamic   10         F    F  Po1
"""

SH_IP_ARP = """
Flags: * - Adjacencies learnt on non-active FHRP router

Address         Age       MAC Address     Interface       Flags
10.92.128.1     00:05:32  0050.56a1.0001  Ethernet1/1
10.92.128.50    00:12:01  0050.56a1.0002  Ethernet1/3
"""


def _outputs():
    return {"status": SH_INT_BRIEF, "description": SH_INT_DESC, "mac": SH_MAC, "arp": SH_IP_ARP}


def test_get_parser_nxos():
    assert get_parser("cisco_nxos") is cisco_nxos


def test_norm_vendor_nexus():
    assert collector._norm_vendor("nexus") == "cisco_nxos"


def test_nxos_parse_ports():
    r = cisco_nxos.parse(_outputs(), 1)
    names = {p["name"] for p in r["ports"]}
    # Eth1/1~3 인식, 설명 결합
    assert any("1/1" in n for n in names)
    by_name = {p["name"]: p for p in r["ports"]}
    eth11 = next(p for p in r["ports"] if "1/1" in p["name"])
    assert eth11["status"] == "up"
    assert "SERVER-WEB-01" in eth11["description"]


def test_nxos_parse_macs():
    r = cisco_nxos.parse(_outputs(), 1)
    assert len(r["macs"]) >= 3
    macs = {m["mac"] for m in r["macs"]}
    # dot 형식이 정규화돼야
    assert any("56" in m for m in macs)
    for m in r["macs"]:
        assert m["vlan"] in (100, 200)


def test_nxos_parse_arps():
    r = cisco_nxos.parse(_outputs(), 1)
    ips = {a["ip"] for a in r["arps"]}
    assert "10.92.128.1" in ips
    assert "10.92.128.50" in ips
    assert len(r["arps"]) == 2


def test_appjs_index_has_nexus_option():
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'value="nexus"' in html
