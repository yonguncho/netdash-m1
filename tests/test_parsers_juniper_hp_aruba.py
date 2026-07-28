# -*- coding: utf-8 -*-
"""신규 벤더 파서(Juniper JunOS · HP ProCurve/ArubaOS-Switch · ArubaOS-CX).

이전에는 이 장비들이 파서가 없어 **데이터 0건인데 status=done**('완료' 배지)이
됐다. 운영자는 초록 배지만 보고 실패를 알 수 없었다.
픽스처는 각 벤더의 실제 CLI 출력 형식을 따른다.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector                                  # noqa: E402
from core.parsers import get_parser, supported_vendors      # noqa: E402
from core.parsers import juniper_junos as jj                # noqa: E402
from core.parsers import hp_procurve as hp                  # noqa: E402
from core.parsers import aruba_cx as cx                     # noqa: E402


# ── 등록·명령 ────────────────────────────────────────────────────
def test_parsers_registered():
    for v in ("juniper_junos", "hp_procurve", "aruba_osswitch", "aruba_os"):
        assert v in supported_vendors()
        assert get_parser(v) is not None


def test_arubaos_switch_shares_procurve_parser():
    assert get_parser("aruba_osswitch") is get_parser("hp_procurve")


def test_default_commands_exist_for_new_vendors():
    """명령이 비면 접속에 성공해도 수집 결과가 0건이 된다."""
    from config import get_config, reset_config
    reset_config()
    cfg = get_config(demo_mode=True)
    for v in ("juniper_junos", "hp_procurve", "aruba_osswitch", "aruba_os"):
        cmds = cfg.get_commands(v)
        assert cmds, "%s 명령 정의 없음" % v
        for key in ("status", "mac", "arp"):
            assert cmds.get(key), "%s: %s 명령 없음" % (v, key)
    reset_config()


# ── 벤더 자동 판정 ───────────────────────────────────────────────
def test_vendor_detection():
    d = collector._detect_vendor_from_version
    assert d("JUNOS EX  Software Suite [18.4R3-S9.2]\nModel: ex4300-48t") == "juniper_junos"
    assert d("ArubaOS-CX\n(c) Copyright 2017-2021 Hewlett Packard Enterprise\n"
             "Version      : FL.10.08.1010") == "aruba_os"
    assert d("Image stamp:    /ws/swbuildm/rel_ukiah\n                WC.16.10.0009\n"
             "Boot Image:     Primary") == "hp_procurve"
    assert d("ProCurve J9147A 2910al-24G Switch") == "hp_procurve"
    # 기존 벤더 판정이 깨지지 않아야 한다
    assert d("Cisco Nexus Operating System (NX-OS) Software") == "cisco_nxos"
    assert d("Cisco IOS Software, C2960X Software") == "cisco_ios"


def test_vendor_alias_normalization():
    n = collector._norm_vendor
    assert n("juniper") == "juniper_junos"
    assert n("HP") == "hp_procurve"
    assert n("procurve") == "hp_procurve"
    assert n("aruba") == "aruba_os"
    assert n("aruba_cx") == "aruba_os"


def test_os_version_extraction():
    p = collector._parse_os_version
    assert p("juniper_junos", "Junos: 18.4R3-S9.2") == "JUNOS 18.4R3-S9.2"
    assert p("aruba_os", "Version      : FL.10.08.1010") == "AOS-CX FL.10.08.1010"
    assert p("hp_procurve", "Image stamp:\n   WC.16.10.0009\n") == "AOS-S WC.16.10.0009"
    assert p("aruba_osswitch", "Image stamp:\n   YA.16.11.0004\n") == "AOS-S YA.16.11.0004"


# ── Juniper JunOS ────────────────────────────────────────────────
JUNOS_TERSE = """Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   eth-switch
ge-0/0/1                up    down
ge-0/0/1.0              up    down eth-switch
ge-0/0/2                down  down
ae0                     up    up
ae0.0                   up    up   eth-switch
irb                     up    up
irb.10                  up    up   inet     10.1.1.1/24
"""

JUNOS_DESC = """Interface       Admin Link Description
ge-0/0/0        up    up   uplink-to-core
ge-0/0/1        up    down CCTV-정문
ge-0/0/2        down  down
ae0             up    up   LAG-to-backbone
"""

JUNOS_MAC = """MAC flags (S - static MAC, D - dynamic MAC, L - locally learned)

Ethernet switching table : 3 entries, 3 learned
Routing instance : default-switch
    Vlan                MAC                 MAC      Age    Logical
    name                address             flags           interface
    VLAN10              00:1b:c0:11:22:33   D          -   ge-0/0/1.0
    VLAN10              00:1b:c0:44:55:66   D          -   ae0.0
    VLAN20              00:50:56:aa:bb:cc   D          -   ge-0/0/12.0
"""

JUNOS_ARP = """MAC Address       Address         Name                      Interface        Flags
00:1b:c0:11:22:33 10.1.1.1        10.1.1.1                  irb.10 [ge-0/0/1.0] none
00:50:56:aa:bb:cc 10.1.1.50       10.1.1.50                 vlan.20          none
Total entries: 2
"""

JUNOS_VLAN = """Routing instance        VLAN name             Tag          Interfaces
default-switch          VLAN10                10
                                                           ge-0/0/1.0*
default-switch          VLAN20                20
                                                           ge-0/0/12.0
"""


def test_junos_ports_and_descriptions():
    out = jj.parse({"status": JUNOS_TERSE, "description": JUNOS_DESC}, 1)
    ports = {p["name"]: p for p in out["ports"]}
    # 논리 유닛(.0) 행은 중복이므로 물리 포트만 남아야 한다
    assert "ge-0/0/0.0" not in ports and "ae0.0" not in ports
    assert ports["ge-0/0/0"]["status"] == "up"
    assert ports["ge-0/0/1"]["status"] == "down"
    assert ports["ge-0/0/2"]["status"] == "disabled"      # admin down
    assert ports["ge-0/0/0"]["description"] == "uplink-to-core"
    assert ports["ge-0/0/1"]["description"] == "CCTV-정문"
    assert ports["ge-0/0/2"]["description"] == ""          # 설명 없음
    assert ports["ae0"]["description"] == "LAG-to-backbone"


def test_junos_mac_uses_physical_port_names():
    """MAC 테이블은 논리 유닛으로 나온다 — 포트 상태·설명과 키가 맞아야 한다."""
    macs = jj.parse({"mac": JUNOS_MAC}, 1)["macs"]
    by_mac = {m["mac"]: m for m in macs}
    assert len(macs) == 3
    assert by_mac["00:1b:c0:11:22:33"]["port"] == "ge-0/0/1"   # .0 제거
    assert by_mac["00:1b:c0:44:55:66"]["port"] == "ae0"
    assert by_mac["00:1b:c0:11:22:33"]["vlan"] == 10           # 'VLAN10' → 10
    assert by_mac["00:50:56:aa:bb:cc"]["vlan"] == 20


def test_junos_mac_els_format():
    """신형(ELS) 출력도 처리한다."""
    els = ("Vlan name   MAC address        MAC flags  Logical interface\n"
           "v100        00:00:5e:00:01:01  D          ge-0/0/2.0\n")
    macs = jj.parse({"mac": els}, 1)["macs"]
    assert len(macs) == 1
    assert macs[0]["port"] == "ge-0/0/2" and macs[0]["vlan"] == 100


def test_junos_arp_prefers_physical_port():
    arps = jj.parse({"arp": JUNOS_ARP}, 1)["arps"]
    by_ip = {a["ip"]: a for a in arps}
    assert len(arps) == 2
    assert by_ip["10.1.1.1"]["mac"] == "00:1b:c0:11:22:33"
    assert by_ip["10.1.1.1"]["interface"] == "ge-0/0/1"     # 대괄호 안 물리 포트
    assert by_ip["10.1.1.50"]["interface"] == "vlan.20"


def test_junos_vlans():
    vlans = {v["vlan"]: v["name"] for v in jj.parse({"vlan": JUNOS_VLAN}, 1)["vlans"]}
    assert vlans.get(10) == "VLAN10" and vlans.get(20) == "VLAN20"


# ── HP ProCurve / ArubaOS-Switch ─────────────────────────────────
HP_BRIEF = """ Status and Counters - Port Status

                            | Intrusion                           MDI   Flow  Bcast
  Port         Type         | Alert     Enabled Status Mode       Mode  Ctrl  Limit
  ------------ ------------ + --------- ------- ------ ---------- ----- ----- ------
  1            100/1000T    | No        Yes     Up     1000FDx    MDIX  off   0
  2            100/1000T    | No        Yes     Down   1000FDx    Auto  off   0
  3            100/1000T    | No        No      Down   1000FDx    Auto  off   0
  Trk1         100/1000T    | No        Yes     Up     1000FDx    MDIX  off   0
"""

HP_NAMES = """ Port Names

  Port  Name
  ----- --------------------------------
  1     uplink-to-core
  2     CCTV-정문
"""

HP_MAC = """ Status and Counters - Port Address Table

  MAC Address   Port                     VLAN
  ------------- ------------------------ ----
  001bc0-112233 1                        10
  005056-aabbcc Trk1                     20
"""

HP_ARP = """ IP ARP table

  IP Address       MAC Address       Type    Port
  ---------------  ----------------- ------- ----
  10.1.1.1         001bc0-112233     dynamic 1
  10.1.1.50        005056-aabbcc     dynamic Trk1
"""

HP_VLAN = """ Status and Counters - VLAN Information

  VLAN ID Name          | Status     Voice Jumbo
  ------- ------------- + ---------- ----- -----
  1       DEFAULT_VLAN  | Port-based No    No
  10      OFFICE        | Port-based No    No
"""


def test_hp_ports():
    out = hp.parse({"status": HP_BRIEF, "description": HP_NAMES}, 1)
    ports = {p["name"]: p for p in out["ports"]}
    assert ports["1"]["status"] == "up"
    assert ports["2"]["status"] == "down"
    assert ports["3"]["status"] == "disabled"      # Enabled=No
    assert ports["Trk1"]["status"] == "up"
    assert ports["1"]["description"] == "uplink-to-core"
    assert ports["2"]["description"] == "CCTV-정문"


def test_hp_mac_hyphen_format():
    """ProCurve MAC 표기(001bc0-112233)를 정규화해야 한다."""
    macs = hp.parse({"mac": HP_MAC}, 1)["macs"]
    by_mac = {m["mac"]: m for m in macs}
    assert len(macs) == 2
    assert by_mac["00:1b:c0:11:22:33"]["port"] == "1"
    assert by_mac["00:1b:c0:11:22:33"]["vlan"] == 10
    assert by_mac["00:50:56:aa:bb:cc"]["port"] == "Trk1"


def test_hp_arp():
    arps = hp.parse({"arp": HP_ARP}, 1)["arps"]
    by_ip = {a["ip"]: a for a in arps}
    assert len(arps) == 2
    assert by_ip["10.1.1.1"]["mac"] == "00:1b:c0:11:22:33"
    assert by_ip["10.1.1.1"]["interface"] == "1"


def test_hp_vlans():
    vlans = {v["vlan"]: v["name"] for v in hp.parse({"vlan": HP_VLAN}, 1)["vlans"]}
    assert vlans.get(10) == "OFFICE"


def test_hp_header_lines_are_not_parsed_as_ports():
    """제목·구분선을 포트로 오인하면 유령 포트가 생긴다."""
    names = {p["name"] for p in hp.parse({"status": HP_BRIEF}, 1)["ports"]}
    assert names == {"1", "2", "3", "Trk1"}


# ── ArubaOS-CX ───────────────────────────────────────────────────
CX_BRIEF = """
--------------------------------------------------------------------------------------
Port      Native  Mode    Type            Enabled Status  Reason                 Speed
          VLAN                                                                   (Mb/s)
--------------------------------------------------------------------------------------
1/1/1     10      access  1GbT            yes     up      --                     1000
1/1/2     1       access  1GbT            no      down    Administratively down  --
1/1/3     20      access  1GbT            yes     down    Waiting for link       --
lag1      1       trunk   --              yes     up      --                     2000
"""

CX_MAC = """MAC age-time            : 300 seconds
Number of MAC addresses : 3

MAC Address          VLAN     Type                      Port
--------------------------------------------------------------
00:1b:c0:11:22:33    10       dynamic                   1/1/1
00:50:56:aa:bb:cc    20       dynamic                   lag1
"""

CX_ARP = """ARP IPv4 Entries:

IPv4 Address     MAC                Port      Physical Port   State
------------------------------------------------------------------------
10.1.1.1         00:1b:c0:11:22:33  vlan10    1/1/1           reachable
10.1.1.50        00:50:56:aa:bb:cc  vlan20    lag1            reachable
"""

CX_VLAN = """
VLAN  Name           Status  Reason         Type     Interfaces
--------------------------------------------------------------
1     DEFAULT_VLAN   up      ok             default  1/1/2
10    OFFICE         up      ok             static   1/1/1
20    CCTV           down    admin_down     static   1/1/3
"""


def test_cx_ports():
    ports = {p["name"]: p for p in cx.parse({"status": CX_BRIEF}, 1)["ports"]}
    assert ports["1/1/1"]["status"] == "up"
    assert ports["1/1/2"]["status"] == "disabled"     # Enabled=no
    assert ports["1/1/3"]["status"] == "down"
    assert ports["lag1"]["status"] == "up"
    assert ports["1/1/1"]["vlan"] == 10


def test_cx_macs():
    macs = cx.parse({"mac": CX_MAC}, 1)["macs"]
    by_mac = {m["mac"]: m for m in macs}
    assert len(macs) == 2
    assert by_mac["00:1b:c0:11:22:33"]["port"] == "1/1/1"
    assert by_mac["00:1b:c0:11:22:33"]["vlan"] == 10
    assert by_mac["00:50:56:aa:bb:cc"]["port"] == "lag1"


def test_cx_arp_uses_physical_port():
    """vlan10(SVI)이 아니라 실제 물리 포트를 써야 설비 대조가 정확하다."""
    arps = {a["ip"]: a for a in cx.parse({"arp": CX_ARP}, 1)["arps"]}
    assert arps["10.1.1.1"]["interface"] == "1/1/1"
    assert arps["10.1.1.50"]["interface"] == "lag1"


def test_cx_vlans():
    vlans = {v["vlan"]: v for v in cx.parse({"vlan": CX_VLAN}, 1)["vlans"]}
    assert vlans[10]["name"] == "OFFICE" and vlans[10]["status"] == "active"
    assert vlans[20]["status"] == "suspended"


# ── 공통 강건성 ──────────────────────────────────────────────────
def test_all_new_parsers_survive_empty_and_garbage():
    for mod in (jj, hp, cx):
        for outputs in ({}, {"status": "", "mac": "", "arp": ""},
                        {"status": "% Invalid input detected", "mac": "\x00\x01",
                         "arp": "---\n---\n"}):
            out = mod.parse(outputs, 1)
            assert isinstance(out["ports"], list)
            assert out["macs"] == [] or isinstance(out["macs"], list)


def test_new_parsers_return_expected_keys():
    for mod in (jj, hp, cx):
        out = mod.parse({}, 1)
        for k in ("ports", "macs", "arps"):
            assert k in out, "%s: %s 키 없음" % (mod.__name__, k)


def test_collect_path_parses_new_vendors():
    """수집 경로(_parse_outputs)가 새 벤더에서 실제 데이터를 낸다."""
    cases = [
        ("juniper_junos", {"status": JUNOS_TERSE, "description": JUNOS_DESC,
                           "mac": JUNOS_MAC, "arp": JUNOS_ARP, "vlan": JUNOS_VLAN}),
        ("hp_procurve", {"status": HP_BRIEF, "description": HP_NAMES,
                         "mac": HP_MAC, "arp": HP_ARP, "vlan": HP_VLAN}),
        ("aruba_osswitch", {"status": HP_BRIEF, "mac": HP_MAC, "arp": HP_ARP}),
        ("aruba_os", {"status": CX_BRIEF, "mac": CX_MAC, "arp": CX_ARP, "vlan": CX_VLAN}),
    ]
    for vendor, outputs in cases:
        got = collector._parse_outputs(vendor, outputs, 1)
        assert got["ports"], "%s: 포트 0건" % vendor
        assert got["macs"], "%s: MAC 0건" % vendor
        assert got["arps"], "%s: ARP 0건" % vendor


def test_unsupported_vendor_raises_instead_of_silent_success():
    """파서 없는 벤더가 '완료'로 보이면 안 된다 — 이게 원래 문제였다."""
    import pytest
    with pytest.raises(collector.UnsupportedVendorError):
        collector._parse_outputs("hp_comware", {"status": "x"}, 1)


def test_demo_mode_falls_back_for_unknown_vendor():
    """데모는 화면을 보여주는 모드 — 픽스처가 없다고 '수집 실패'가 되면 안 된다."""
    from core import fixtures
    out = fixtures.get_demo_outputs_for_vendor("juniper_junos")
    assert isinstance(out, dict) and out, "데모 폴백 없음"
