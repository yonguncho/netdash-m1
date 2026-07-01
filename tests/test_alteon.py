# -*- coding: utf-8 -*-
"""Radware/Nortel Alteon(메뉴형 CLI) 파서 + 벤더 라우팅 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import alteon as a
from core import collector
from core.parsers import get_parser


def test_alteon_vendor_mapping():
    assert collector._norm_vendor("alteon") == "alteon"
    assert collector._norm_vendor("radware") == "alteon"
    assert collector._norm_vendor("nortel_alteon") == "alteon"


def test_alteon_parser_registered():
    assert get_parser("alteon") is a


def test_alteon_parse_fdb():
    fdb = (
        "    MAC address       VLAN  Port  Trunk  State\n"
        "    -----------------  ----  ----  -----  -----\n"
        "    00:04:96:12:34:56     1     5          FWD\n"
        "    00:04:96:12:34:57   100     6          FWD\n")
    macs = a._parse_macs(fdb, 1)
    by = {m["mac"]: m for m in macs}
    assert by["00:04:96:12:34:56"]["vlan"] == 1 and by["00:04:96:12:34:56"]["port"] == "5"
    assert by["00:04:96:12:34:57"]["vlan"] == 100 and by["00:04:96:12:34:57"]["port"] == "6"


def test_alteon_parse_arp():
    arp = (
        "        Destination      Flags    MAC address        VLAN Age Port\n"
        "    -------------------  -----  -----------------  ---- --- ----\n"
        "      10.0.0.1                  00:04:96:12:34:56     1  10    5\n"
        "      10.0.0.50          P      00:04:96:aa:bb:cc   100   5    6\n")
    arps = a._parse_arps(arp, 1)
    by = {x["ip"]: x for x in arps}
    assert by["10.0.0.1"]["mac"] == "00:04:96:12:34:56" and by["10.0.0.1"]["interface"] == "5"
    assert by["10.0.0.50"]["interface"] == "6"


def test_alteon_parse_link():
    link = (
        "Port  Speed  Duplex  Flow Ctl  Link\n"
        "----  -----  ------  --------  ----\n"
        "   1   1000   full    yes/yes   up\n"
        "   2    any    any    yes/yes   down\n")
    ps = a._parse_ports(link, 1)
    by = {p["name"]: p for p in ps}
    assert by["1"]["status"] == "up" and "1000" in by["1"]["speed"]
    assert by["2"]["status"] == "down"


def test_alteon_parse_full():
    out = {"status": "1  1000 full yes/yes up\n", "mac": "", "arp": ""}
    res = a.parse(out, 1)
    assert res["ports"] and res["ports"][0]["status"] == "up"
