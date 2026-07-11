# -*- coding: utf-8 -*-
"""2026-07-11 전체 감사에서 재현 확정된 버그 9건(B3~B11)의 회귀 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, db, log_analyzer
from core.parsers import arista_eos, cisco_nxos, neighbors, extreme_exos


# ── B1 (v3.71 회귀): log_analyzer 연말 경계 flap 억제 ──
def test_b1_flap_year_end_boundary():
    log = "\n".join([
        "Dec 31 23:55:01: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Dec 31 23:57:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
        "Jan  1 00:01:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Jan  1 00:03:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
    ])
    r = log_analyzer.analyze(log, flap_threshold=3, flap_window_min=10)
    assert [e for e in r["events"] if e["type"] == "flapping"], "연말 경계 flap 미탐"


def test_b1_still_suppresses_dispersed():
    """진짜 분산된 flap(1시간 간격)은 여전히 억제."""
    log = "\n".join([
        "Jul 11 09:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Jul 11 10:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
        "Jul 11 11:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
    ])
    r = log_analyzer.analyze(log, flap_threshold=3, flap_window_min=10)
    assert not [e for e in r["events"] if e["type"] == "flapping"]


# ── B2 (v3.71): extreme _parse_port_errors 유니코드 숫자 크래시 ──
def test_b2_exos_unicode_digit_no_crash():
    errs = extreme_exos._parse_port_errors("1:1  A  5  0  ²  1", "")  # ²
    assert errs["1:1"]["crc"] == 5  # 크래시 없이 ASCII 숫자만 처리


# ── B3: raw_outputs 경로 탈출 ──
def test_b3_path_traversal_sanitized():
    assert "/" not in collector._safe_dir_name("../etc/passwd", "fb")
    assert "\\" not in collector._safe_dir_name(r"C:\evil", "fb")
    assert ":" not in collector._safe_dir_name(r"C:\evil", "fb")
    assert collector._safe_dir_name("..", "fb") == "fb"  # 전부 점이면 폴백
    assert collector._safe_dir_name("SW-Core1", "fb") == "SW-Core1"  # 정상은 보존


# ── B4/M4: mac 실패 시 disconnect 오탐 / 파서 예외 오분류 ──
def test_b4_parse_outputs_propagates_parser_error():
    """파서 내부 예외는 parser_not_found로 둔갑하지 않고 전파."""
    import core.parsers as parsers

    class Boom:
        @staticmethod
        def parse(outputs, switch_id):
            raise ValueError("parser internal boom")

    orig = parsers.get_parser
    parsers.get_parser = lambda v: Boom
    try:
        raised = False
        try:
            collector._parse_outputs("cisco_ios", {}, 1)
        except ValueError:
            raised = True
        assert raised, "파서 내부 ValueError가 삼켜짐"
    finally:
        parsers.get_parser = orig


def test_b4_unknown_vendor_still_empty():
    """진짜 미지원 벤더는 빈 결과 폴백 유지."""
    r = collector._parse_outputs("no_such_vendor_xyz", {}, 1)
    assert r == {"ports": [], "macs": [], "arps": []}


# ── B5: Arista MAC 테이블 Moves/Last Move 컬럼 ──
def test_b5_arista_mac_with_moves_column():
    mac = ("Vlan Mac Address Type Ports Moves Last Move\n"
           "   1    001c.7301.9e01    DYNAMIC     Et1        1       0:01:13 ago\n"
           " 100    001c.7302.abcd    DYNAMIC     Et2        1       1:00:00 ago")
    r = arista_eos.parse({"status": "", "description": "", "mac": mac, "arp": ""}, 1)
    assert len(r["macs"]) == 2


# ── B6: Arista ARP 이중 인터페이스 ──
def test_b6_arista_arp_dual_interface():
    arp = ("Address Age Hardware Addr Interface\n"
           "10.0.0.2  0:00:12  001c.7301.9e01   Vlan100, Ethernet2\n"
           "10.0.0.3  0:00:05  001c.7302.abcd   Vlan100, Ethernet3")
    r = arista_eos.parse({"status": "", "description": "", "mac": "", "arp": arp}, 1)
    assert len(r["arps"]) == 2
    assert r["arps"][0]["interface"] == "Ethernet2"  # 물리 인터페이스 우선


# ── B7: NX-OS port-channel 포트 ──
def test_b7_nxos_port_channel_in_ports():
    detail = ("port-channel10 is up\n  full-duplex, 10 Gb/s\n"
              "Ethernet1/1 is up\n  full-duplex, 10 Gb/s")
    ports = cisco_nxos._parse_full(detail, {}, {}, 1)
    names = [p["name"] for p in ports]
    assert "Po10" in names
    assert "Eth1/1" in names


# ── B8: IOS/NX-OS LLDP detail ──
def test_b8_ios_lldp_detail():
    ios = ("Local Intf: Gi1/0/1\nChassis id: 001c.7301.9e01\n"
           "Port id: Gi0/1\nSystem Name: switch2\n")
    nb = neighbors.parse_lldp_detail(ios)
    assert len(nb) == 1
    assert nb[0]["local_port"] == "Gi1/0/1"
    assert nb[0]["remote_name"] == "switch2"


def test_b8_nxos_lldp_local_remote_distinct():
    """NX-OS 실제 순서(Chassis→Port id(remote)→Local Port id(local))에서
    remote/local이 정확히 분리되어야."""
    nxos = ("Chassis id: 001c.7302.abcd\nPort id: Eth1/5\n"
            "Local Port id: Eth1/1\nSystem Name: core-nx\n")
    nb = neighbors.parse_lldp_detail(nxos)
    assert len(nb) == 1
    assert nb[0]["local_port"] == "Eth1/1"
    assert nb[0]["remote_port"] == "Eth1/5"


def test_b8_nxos_lldp_two_neighbors_no_shift():
    """NX-OS 다중 이웃에서 remote_port가 한 칸씩 밀리지 않아야(v3.72 회귀 방지)."""
    nxos = ("Chassis id: 00c1.6401.0a01\nPort id: Ethernet1/10\n"
            "Local Port id: Eth1/1\nSystem Name: leaf-a\n"
            "Chassis id: 00c1.6402.0b01\nPort id: Ethernet2/20\n"
            "Local Port id: Eth1/2\nSystem Name: leaf-b\n")
    nb = neighbors.parse_lldp_detail(nxos)
    by = {n["local_port"]: n for n in nb}
    assert by["Eth1/1"]["remote_port"] == "Ethernet1/10"
    assert by["Eth1/1"]["remote_name"] == "leaf-a"
    assert by["Eth1/2"]["remote_port"] == "Ethernet2/20"
    assert by["Eth1/2"]["remote_name"] == "leaf-b"


def test_b8_arista_lldp_regression():
    """기존 Arista LLDP 형식 회귀 없음."""
    ar = ('Interface Ethernet1 detected 1 LLDP neighbors:\n'
          '  System Name: "arista2"\n  Port ID          : "Ethernet3"\n'
          '  Management Address : 10.0.0.5\n')
    nb = neighbors.parse_lldp_detail(ar)
    assert len(nb) == 1 and nb[0]["remote_port"] == "Ethernet3"


# ── B11: import_switches_bulk 데이터 보존 ──
def test_b11_reimport_preserves_metadata(temp_db):
    # 최초 등록 + 사용자가 note/location/vendor 채움
    db.import_switches_bulk(temp_db, [{"name": "SW1", "ip": "10.0.0.1",
                                       "vendor": "cisco_ios", "location": "Seoul",
                                       "note": "core switch"}])
    sid = db.import_switches_bulk(temp_db, [{"name": "SW1", "ip": "10.0.0.1"}])[0]
    sw = db.get_switch(temp_db, sid)
    # 엑셀 재업로드(vendor/location/note 없음)가 기존값을 지우지 않아야
    assert sw["vendor"] == "cisco_ios"
    assert sw["location"] == "Seoul"
    assert sw["note"] == "core switch"


def test_b11_reimport_updates_provided_fields(temp_db):
    """새로 제공된 값은 정상 갱신."""
    db.import_switches_bulk(temp_db, [{"name": "SW2", "ip": "10.0.0.2", "location": "Seoul"}])
    sid = db.import_switches_bulk(temp_db, [{"name": "SW2", "ip": "10.0.0.9", "location": "Busan"}])[0]
    sw = db.get_switch(temp_db, sid)
    assert sw["ip"] == "10.0.0.9"
    assert sw["location"] == "Busan"
