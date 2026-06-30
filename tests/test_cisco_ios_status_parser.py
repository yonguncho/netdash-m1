"""Cisco IOS/IOS-XE 파서 — show interface status + dot 형식 MAC 검증."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import cisco_ios

SH_INT_STATUS = """
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   SERVER-01          connected    100        a-full a-1000 10/100/1000BaseTX
Gi1/0/2                      notconnect   1            auto   auto 10/100/1000BaseTX
Te1/1/1   UPLINK-CORE        connected    trunk        full    10G SFP-10GBase-SR
"""

SH_INT_DESC = """
Interface                      Status         Protocol Description
Gi1/0/1                        up             up       SERVER-01
Gi1/0/2                        down           down
Te1/1/1                        up             up       UPLINK-CORE
"""

SH_MAC = """
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       ----        -----
 100    0050.56a1.b2c3    DYNAMIC     Gi1/0/1
 100    00ab.cdef.1234    DYNAMIC     Gi1/0/1
 200    aabb.ccdd.eeff    DYNAMIC     Te1/1/1
"""

SH_IP_ARP = """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.92.128.1            12   0050.56a1.0001  ARPA   GigabitEthernet1/0/1
Internet  10.92.128.50           -    0050.56a1.0002  ARPA   GigabitEthernet1/0/2
"""


def _out():
    return {"status": SH_INT_STATUS, "description": SH_INT_DESC, "mac": SH_MAC, "arp": SH_IP_ARP}


def test_ports_status_parsed():
    r = cisco_ios.parse(_out(), 1)
    by = {p["name"]: p for p in r["ports"]}
    g1 = next(p for p in r["ports"] if p["name"].endswith("1/0/1"))
    assert g1["status"] == "up"           # connected → up
    assert g1["vlan"] == 100
    assert "SERVER-01" in g1["description"]
    g2 = next(p for p in r["ports"] if p["name"].endswith("1/0/2"))
    assert g2["status"] == "down"         # notconnect → down


def test_dot_mac_parsed():
    """Cisco dot 형식 MAC(0050.56a1.b2c3)이 파싱돼야(과거 colon만 잡아 0건이던 버그)."""
    r = cisco_ios.parse(_out(), 1)
    assert len(r["macs"]) == 3
    macs = {m["mac"] for m in r["macs"]}
    assert "00:50:56:a1:b2:c3" in macs


def test_arp_parsed():
    r = cisco_ios.parse(_out(), 1)
    ips = {a["ip"] for a in r["arps"]}
    assert "10.92.128.1" in ips
    assert "10.92.128.50" in ips   # age "-" 케이스도 파싱
    assert len(r["arps"]) == 2
