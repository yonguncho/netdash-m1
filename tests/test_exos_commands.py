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


def test_parse_ports_no_refresh_letter_states():
    """실장비 형식: Port State E/D + Link State A/R/NP 한 글자 코드."""
    ports = (
        "Port      Display             VLAN Name          Port  Link  Speed  Duplex\n"
        "#         String              (or # VLANs)       State State Actual Actual\n"
        "===========================================================================\n"
        "1                             Default             E     A     1000   FULL\n"
        "2                             Default             E     R\n"
        "3         UPLINK-49           (0002)              E     A     10G    FULL\n"
        "1:15                          Default             D     R\n"
        "1:16                          Default             D\n")
    ps = e._parse_ports(ports, "", 1)
    by = {p["name"]: p for p in ps}
    assert by["1"]["status"] == "up" and "1000" in by["1"]["speed"]
    assert by["2"]["status"] == "down"
    assert by["3"]["status"] == "up" and "10G" in by["3"]["speed"]
    assert by["1:15"]["status"] == "disabled"   # Port State D
    assert by["1:16"]["status"] == "disabled"   # 링크 상태 없이 D로 끝


def test_worker_skips_to_next_on_unreachable(temp_db, monkeypatch):
    """수집 실패(도달 불가) 시 즉시 실패 처리하고 다음 스위치 수집 진행."""
    from core import collector, credentials, db as _db

    import tempfile
    class _Cfg:
        app = {"demo_mode": False}
        def get_max_concurrent(self):
            return 1  # 워커 1개 → 순차 처리로 '다음 장비 진행' 검증
        def get_raw_outputs_path(self):
            return tempfile.mkdtemp(prefix="ndraw_")
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _Cfg())

    dead = _db.save_switch(temp_db, "DEAD-SW", "10.99.0.1", "cisco")
    alive = _db.save_switch(temp_db, "ALIVE-SW", "10.99.0.2", "cisco")
    credentials.save_credential(dead, "u", "p")
    credentials.save_credential(alive, "u", "p")

    # 첫 장비는 도달 불가, 둘째는 정상 + 가짜 SSH
    monkeypatch.setattr(collector, "_tcp_precheck",
                        lambda ip, port=22, timeout=4, source_ip=None: ip != "10.99.0.1")
    monkeypatch.setattr(collector, "_ssh_collect",
                        lambda *a, **k: ({"status": "", "mac": "", "arp": ""}, "cisco_ios"))

    collector.init_collector()
    collector.collect_switch(temp_db, dead, "u", "p")
    collector.collect_switch(temp_db, alive, "u", "p")

    import time
    for _ in range(100):
        s1 = _db.get_switch(temp_db, dead)["status"]
        s2 = _db.get_switch(temp_db, alive)["status"]
        if s1 == "failed" and s2 == "done":
            break
        time.sleep(0.1)
    assert _db.get_switch(temp_db, dead)["status"] == "failed"    # 즉시 실패
    assert _db.get_switch(temp_db, alive)["status"] == "done"      # 다음 장비 정상 진행
