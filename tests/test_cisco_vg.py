# -*- coding: utf-8 -*-
"""Cisco VG3X0(음성게이트웨이/라우터 IOS) 수집 — show interface status 미지원 폴백."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import cisco_ios
from core import collector


# 실제 VG3X0 계열 show ip interface brief 형식
_BRIEF = """\
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     10.92.1.5       YES NVRAM  up                    up
GigabitEthernet0/1     unassigned      YES NVRAM  administratively down down
FastEthernet0/0        10.92.2.10      YES NVRAM  up                    up
Voice0/0               unassigned      YES unset  down                  down
"""

_STATUS_INVALID = "               ^\n% Invalid input detected at '^' marker.\n"

_VERSION = """\
Cisco IOS Software, VG3X0-universalk9-M, Version 15.6(3)M5, RELEASE SOFTWARE (fc1)
cisco VG320 (revision 1.0) with 1024000K/24576K bytes of memory.
Processor board ID FTX1234ABCD
"""


def test_vg_brief_fallback_when_status_empty():
    """status가 비면(라우터/VG) show ip interface brief로 포트 도출."""
    out = {"status": "", "port_brief": _BRIEF, "arp": "", "description": ""}
    res = cisco_ios.parse(out, switch_id=1)
    ports = {p["name"]: p for p in res["ports"]}
    assert "Gi0/0" in ports and ports["Gi0/0"]["status"] == "up"
    assert ports["Gi0/0"]["speed"] == "IP 10.92.1.5"       # IP 표기
    assert ports["Gi0/1"]["status"] == "disabled"          # administratively down
    assert ports["Fa0/0"]["status"] == "up"
    assert ports["Voice0/0"]["status"] == "down"    # Voice 인터페이스(약어 없음)


def test_vg_status_invalid_cmd_falls_back():
    """status에 '% Invalid input'(명령 미지원)이 와도 brief 폴백."""
    out = {"status": _STATUS_INVALID, "port_brief": _BRIEF, "arp": "", "description": ""}
    res = cisco_ios.parse(out, switch_id=1)
    assert len(res["ports"]) == 4


def test_normal_switch_does_not_use_brief():
    """일반 스위치(status 정상)는 brief 폴백을 쓰지 않는다(L3 인터페이스만 나오는 오염 방지)."""
    status = ("Port      Name    Status       Vlan    Duplex  Speed Type\n"
              "Gi1/0/1           connected    10      a-full  a-1000 10/100/1000BaseTX\n")
    out = {"status": status, "port_brief": _BRIEF, "description": "", "arp": ""}
    res = cisco_ios.parse(out, switch_id=1)
    names = {p["name"] for p in res["ports"]}
    assert names == {"Gi1/0/1"}       # brief의 Gi0/0 등이 섞이지 않음


def test_vg_model_and_version_detection():
    assert collector._parse_model("cisco_ios", _VERSION) == "VG320"
    assert collector._parse_serial("cisco_ios", _VERSION) == "FTX1234ABCD"
    ver = collector._parse_os_version("cisco_ios", _VERSION)
    assert ver and "15.6(3)M5" in ver


def test_brief_ignores_invalid_only_output():
    """brief 자체가 무효 명령 응답이면 포트 0(오파싱 없음)."""
    out = {"status": "", "port_brief": _STATUS_INVALID, "description": "", "arp": ""}
    res = cisco_ios.parse(out, switch_id=1)
    assert res["ports"] == []
