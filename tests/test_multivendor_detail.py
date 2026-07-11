# -*- coding: utf-8 -*-
"""멀티벤더 포트상태 세분화·에러 카운터 확장 테스트 (Arista 상세/상태표, EXOS rx/txerrors)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import arista_eos, extreme_exos

ARISTA_DETAIL = """\
Ethernet1 is up, line protocol is up (connected)
  Hardware is Ethernet, address is 001c.7300.0001
  Full-duplex, 1Gb/s, auto negotiation: on, uni-link: n/a
     7 input errors, 3 CRC, 0 frame
     2 output errors, 0 collisions
Ethernet2 is down, line protocol is down (notconnect)
  Hardware is Ethernet
  Auto-duplex, auto speed
Ethernet3 is administratively down, line protocol is down (disabled)
  Hardware is Ethernet
Ethernet4 is down, line protocol is down (errdisabled)
  Hardware is Ethernet
"""

ARISTA_STATUS_TABLE = """\
Port       Name        Status       Vlan     Duplex Speed  Type
Et1                    connected    1        full   1G     1000BASE-T
Et2        uplink      notconnect   10       auto   auto   1000BASE-T
Et3                    disabled     1        auto   auto   1000BASE-T
Et4                    errdisabled  1        full   1G     1000BASE-T
"""

EXOS_RXERR = """\
Port Rx Error Monitor
Port      Link  Rx Crc     Rx Over    Rx Under   Rx Frag    Rx Jabber  Rx Align   Rx Lost
========= ===== ========== ========== ========== ========== ========== ========== ==========
1:1       A     5          0          0          1          0          0          2
1:2       R     0          0          0          0          0          0          0
========= ===== ========== ========== ========== ========== ========== ========== ==========
"""

EXOS_TXERR = """\
Port Tx Error Monitor
Port      Link  Tx Coll    Tx Late coll Tx Deferred Tx Errors  Tx Lost    Tx Parity
========= ===== ========== ============ =========== ========== ========== ==========
1:1       A     0          0            0           4          0          0
1:2       R     0          0            0           0          0          0
========= ===== ========== ============ =========== ========== ========== ==========
"""

EXOS_STATUS = """\
Port      Display String        VLAN Name    Port  Link  Speed  Duplex
                                             State State Actual Actual
========= ===================== ============ ===== ===== ====== ======
1:1                             Default      E     A     1000   FULL
1:2                             Default      E     R
"""


def test_arista_detail_status_granular():
    """상세 형식 괄호 상태 → connected/notconnect/disabled/err-disabled 세분화."""
    r = arista_eos.parse({"status": ARISTA_DETAIL, "description": "",
                          "mac": "", "arp": ""}, 1)
    by = {p["name"]: p for p in r["ports"]}
    assert by["Ethernet1"]["status"] == "up"
    assert by["Ethernet2"]["status"] == "notconnect"
    assert by["Ethernet3"]["status"] == "disabled"
    assert by["Ethernet4"]["status"] == "err-disabled"


def test_arista_detail_speed_duplex():
    """상세 형식에서 Full-duplex, 1Gb/s 추출."""
    r = arista_eos.parse({"status": ARISTA_DETAIL, "description": "",
                          "mac": "", "arp": ""}, 1)
    e1 = next(p for p in r["ports"] if p["name"] == "Ethernet1")
    assert e1["duplex"] == "full"
    assert "1Gb/s" in e1["speed"]


def test_arista_detail_errors_merge():
    """상세 형식 포트에도 CRC/in/out errors 병합."""
    r = arista_eos.parse({"status": ARISTA_DETAIL, "errors": ARISTA_DETAIL,
                          "description": "", "mac": "", "arp": ""}, 1)
    e1 = next(p for p in r["ports"] if p["name"] == "Ethernet1")
    assert e1["crc_errors"] == 3
    assert e1["in_errors"] == 7
    assert e1["out_errors"] == 2


def test_arista_status_table_reuses_cisco_parser():
    """상태표 형식(show interfaces status)도 세분화 파싱."""
    r = arista_eos.parse({"status": ARISTA_STATUS_TABLE, "description": "",
                          "mac": "", "arp": ""}, 1)
    by = {p["name"]: p for p in r["ports"]}
    assert by["Et1"]["status"] == "up"
    assert by["Et2"]["status"] == "notconnect"
    assert by["Et2"]["vlan"] == 10
    assert by["Et4"]["status"] == "err-disabled"


def test_exos_port_errors_parse():
    """EXOS rx/txerrors → crc/in/out 카운터."""
    errs = extreme_exos._parse_port_errors(EXOS_RXERR, EXOS_TXERR)
    assert errs["1:1"]["crc"] == 5
    # M11: Rx Lost(마지막, 버퍼 드롭)는 in_errors에서 제외 → 5+0+0+1+0+0=6
    assert errs["1:1"]["in_errors"] == 6
    assert errs["1:1"]["out_errors"] == 4  # Tx Errors=4 (Coll/Deferred 정상 제외)
    assert errs["1:2"]["crc"] == 0


def test_exos_errors_merged_into_ports():
    """EXOS parse()가 포트에 에러 카운터 병합."""
    r = extreme_exos.parse({"status": EXOS_STATUS, "description": "",
                            "mac": "", "arp": "",
                            "errors": EXOS_RXERR, "txerrors": EXOS_TXERR}, 1)
    p11 = next(p for p in r["ports"] if p["name"] == "1:1")
    assert p11["crc_errors"] == 5
    assert p11["in_errors"] == 6   # M11: Rx Lost 제외
    assert p11["out_errors"] == 4


def test_exos_commands_include_errors():
    """config.yaml EXOS에 errors/txerrors 명령 존재."""
    import yaml
    cfg = yaml.safe_load((Path(__file__).parent.parent / "config.yaml").read_text(encoding="utf-8"))
    cmds = cfg["collector"]["commands"]["extreme_exos"]
    assert "rxerrors" in cmds["errors"]
    assert "txerrors" in cmds["txerrors"]


def test_arista_legacy_two_column_fallback():
    """기존 2컬럼(up/down up/down) 형식 회귀 방지."""
    legacy = "Ethernet1 up up\nEthernet2 down down\n"
    r = arista_eos.parse({"status": legacy, "description": "", "mac": "", "arp": ""}, 1)
    by = {p["name"]: p for p in r["ports"]}
    assert by["Ethernet1"]["status"] == "up"
    assert by["Ethernet2"]["status"] == "down"
