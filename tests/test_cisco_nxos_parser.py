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


SH_INT_STATUS = """
--------------------------------------------------------------------------------
Port          Name               Status    Vlan      Duplex  Speed   Type
--------------------------------------------------------------------------------
Eth1/1        SERVER-WEB-01      connected trunk     full    10G     10Gbase-SR
Eth1/2                           notconnec 200       auto    auto    --
Eth1/3        routed-uplink      connected routed    full    40G     QSFP-40G
"""



def _outputs():
    return {"status": SH_INT_STATUS, "brief": SH_INT_BRIEF, "description": SH_INT_DESC,
            "mac": SH_MAC, "arp": SH_IP_ARP}


SH_INT_FULL = """
Ethernet1/1 is down (SFP not inserted)
admin state is up, Dedicated Interface
  Hardware: 100/1000/10000 Ethernet, address: 00de.fb12.3401
  Description: SERVER-WEB-01
  MTU 1500 bytes, BW 10000000 Kbit
  full-duplex, 10 Gb/s, media type is 10G
  Rx
    1000 unicast packets  50 multicast packets
    0 runts 0 giants 12 CRC 0 no buffer
    7 input error 0 short frame 0 overrun 0 underrun 0 ignored
  Tx
    2000 unicast packets
    3 output error 0 collision 0 deferred 0 late collision

Ethernet1/2 is up
admin state is up
  full-duplex, 40 Gb/s, media type is 40G
  Rx
    0 runts 0 giants 0 CRC 0 no buffer
    0 input error 0 short frame
  Tx
    0 output error 0 collision
"""


def test_nxos_full_interface_down_state_and_errors():
    """show interface(전체): GBIC 문제로 down인 포트가 실제 down + CRC/오류 수집."""
    r = cisco_nxos.parse({"detail": SH_INT_FULL, "status": SH_INT_STATUS,
                          "description": SH_INT_DESC}, 1)
    by = {p["name"]: p for p in r["ports"]}
    e11 = next(p for p in r["ports"] if "1/1" in p["name"])
    assert e11["status"] == "down"      # SFP 미삽입 → 실제 down (up 오표시 수정)
    assert e11["speed"] == "10G"
    assert e11["crc_errors"] == 12
    assert e11["in_errors"] == 7
    assert e11["out_errors"] == 3
    e12 = next(p for p in r["ports"] if "1/2" in p["name"])
    assert e12["status"] == "up" and e12["speed"] == "40G"


def test_nxos_full_abbreviates_name():
    """show interface 헤더 'Ethernet1/9'가 MAC/설명과 같은 'Eth1/9'로 축약."""
    r = cisco_nxos.parse({"detail": SH_INT_FULL}, 1)
    names = {p["name"] for p in r["ports"]}
    assert "Eth1/1" in names and "Ethernet1/1" not in names


def test_nxos_status_desc_with_down_word_not_misread():
    """폴백(status): Name/설명에 'down' 단어가 있어도 상태를 오인식하지 않음."""
    status = (
        "Port          Name               Status    Vlan   Duplex  Speed   Type\n"
        "Eth1/9        LINK-TO-DOWNSTREAM connected trunk  full    40G     40G\n"
    )
    r = cisco_nxos.parse({"status": status}, 1)   # detail 없음 → status 폴백
    e9 = next(p for p in r["ports"] if "1/9" in p["name"])
    assert e9["status"] == "up"        # 'DOWNSTREAM'의 down을 상태로 오인식하지 않음
    assert e9["vlan"] == 1             # trunk → 숫자 아님 → 1


def test_nxos_status_fallback_vlan_speed():
    """detail 없을 때 폴백: show interface status에서 VLAN·속도 파싱."""
    r = cisco_nxos.parse(_outputs(), 1)   # _outputs()엔 detail 없음 → status 폴백
    e11 = next(p for p in r["ports"] if "1/1" in p["name"])
    assert e11["speed"] == "10G"
    e2 = next(p for p in r["ports"] if "1/2" in p["name"])
    assert e2["vlan"] == 200            # 액세스 VLAN 숫자


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
    """v3.37: 벤더 옵션 값 표준화 — nexus 별칭 대신 cisco_nxos."""
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'value="cisco_nxos"' in html
