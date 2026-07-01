# -*- coding: utf-8 -*-
"""ExtremeXOS 실제 명령/출력 형식(show fdb / show iparp / show ports no-refresh) 파싱."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import extreme_exos as e
from config import get_config


def test_exos_commands_config():
    """EXOS 명령이 실제 문법으로 설정됐는지(수집 실패 방지)."""
    cmds = get_config().get_commands("extreme_exos")
    assert cmds.get("status") == "show ports no-refresh"   # 자동갱신 방지
    assert cmds.get("mac") == "show fdb"
    assert cmds.get("arp") == "show iparp"
    assert "memory-buffer" in cmds.get("logging", "")
    # 파서 COMMANDS도 동일
    assert e.COMMANDS["mac"] == "show fdb"


def test_parse_fdb():
    fdb = (
        "MAC                     VLAN Name( Tag)      Age  Flags   Port\n"
        "----------------------------------------------------------------\n"
        "00:04:96:52:e7:7e       Default(0001)        0000 d m    1:2\n"
        "aa:bb:cc:dd:ee:ff       v100(0100)           0010 d      5\n")
    macs = e._parse_macs(fdb, 1)
    by = {m["mac"]: m for m in macs}
    assert by["00:04:96:52:e7:7e"]["vlan"] == 1
    assert by["00:04:96:52:e7:7e"]["port"] == "1:2"
    assert by["aa:bb:cc:dd:ee:ff"]["vlan"] == 100
    assert by["aa:bb:cc:dd:ee:ff"]["port"] == "5"


def test_parse_iparp():
    arp = (
        "VR          Destination     Mac                Age  Static VLAN     VID Port\n"
        "---------------------------------------------------------------------------\n"
        "VR-Default  10.66.0.1       00:04:96:aa:bb:cc  0    NO     v10      10  1:15\n"
        "VR-Default  10.66.0.2       00:04:96:aa:bb:dd  5    NO     Default  1   3\n")
    arps = e._parse_arps(arp, 1)
    by = {a["ip"]: a for a in arps}
    assert by["10.66.0.1"]["mac"] == "00:04:96:aa:bb:cc" and by["10.66.0.1"]["interface"] == "1:15"
    assert by["10.66.0.2"]["interface"] == "3"


def test_parse_ports_no_refresh_states():
    ports = (
        "Port      Link       Auto  Speed    Duplex Media\n"
        "          State      Neg   Actual   Actual\n"
        "================================================\n"
        "1         active     ON    1000     FULL   SR\n"
        "2         ready      ON\n"
        "1:15      disabled\n")
    ps = e._parse_ports(ports, "", 1)
    by = {p["name"]: p for p in ps}
    assert by["1"]["status"] == "up" and "1000" in by["1"]["speed"]
    assert by["2"]["status"] == "down"
    assert by["1:15"]["status"] == "disabled"
