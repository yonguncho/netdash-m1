# -*- coding: utf-8 -*-
"""서버 MAC·연결스위치·포트가 자주 비던 문제 (v6.7.4).

사용자 보고: "서버 현황에서 MAC이나 연결스위치, 포트 정보도 수집 안 된 게 많다."

원인 두 가지.
① **연결 위치를 한 번만, 그것도 너무 이른 시점에 찾았다.**
   `find_mac_location(ip)`는 스위치 ARP 테이블에 IP→MAC이 있어야 동작한다.
   그게 없으면 그대로 끝났는데, MAC은 그 뒤에 SSH·WMI·SNMP로 얻는 경우가 많다.
   → MAC은 채워졌는데 연결스위치·포트만 빈 서버가 대량 발생.
② **이 PC의 ARP 캐시를 안 봤다.**
   같은 서브넷 서버는 포트 스캔(TCP SYN)만으로 로컬 ARP 캐시가 채워진다
   (ARP가 TCP보다 먼저 일어나므로 접속이 거부돼도 남는다). 계정도 스위치 수집도
   필요 없는 공짜 경로인데 쓰지 않았다.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc  # noqa: E402

ROOT = Path(__file__).parent.parent
MAC = "00:50:56:AB:12:34"


class _Proc:
    def __init__(self, out=b""):
        self.stdout = out
        self.stderr = b""
        self.returncode = 0


def _stub(monkeypatch, ports=(443,)):
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: list(ports))
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: None)
    monkeypatch.setattr(sc, "local_arp_mac", lambda ip: "")


def _switch_with_mac(temp_db, mac, port="Gi1/0/24", name="SW-ACCESS-01"):
    sid = db.save_switch(temp_db, name, "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid,
                        [{"vlan": 10, "mac": mac, "port": port}])
    return sid


# ── 로컬 ARP 캐시 파싱 ──────────────────────────────────────────
_WIN_ARP = b"""
Interface: 10.20.30.5 --- 0xd
  Internet Address      Physical Address      Type
  10.20.30.77           00-50-56-ab-12-34     dynamic
"""


def test_local_arp_reads_windows_output(monkeypatch):
    monkeypatch.setattr(sc.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(_WIN_ARP))
    assert sc.local_arp_mac("10.20.30.77") == MAC


def test_local_arp_ignores_other_rows(monkeypatch):
    """arp -a가 인자를 무시하고 전체 테이블을 뱉는 환경이 있다 — 남의 MAC 금지."""
    monkeypatch.setattr(sc.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(_WIN_ARP))
    assert sc.local_arp_mac("10.20.30.99") == ""


def test_local_arp_skips_incomplete(monkeypatch):
    out = b"  10.20.30.77           00-00-00-00-00-00     invalid\n"
    monkeypatch.setattr(sc.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(out))
    assert sc.local_arp_mac("10.20.30.77") == ""


def test_local_arp_reads_linux_output(monkeypatch):
    monkeypatch.setattr(sc.os, "name", "posix")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(
        b"10.20.30.77 dev ens192 lladdr 00:50:56:ab:12:34 REACHABLE\n"))
    assert sc.local_arp_mac("10.20.30.77") == MAC


def test_local_arp_survives_missing_command(monkeypatch):
    def boom(*a, **k):
        raise OSError("arp 없음")

    monkeypatch.setattr(subprocess, "run", boom)
    assert sc.local_arp_mac("10.20.30.77") == ""


# ── MAC → 스위치/포트 조회 ──────────────────────────────────────
def test_find_location_by_mac(temp_db):
    _switch_with_mac(temp_db, MAC)
    loc = db.find_location_by_mac(temp_db, MAC)
    assert loc["switch_name"] == "SW-ACCESS-01" and loc["port"] == "Gi1/0/24"


def test_find_location_by_mac_normalizes_notation(temp_db):
    """벤더마다 표기가 다르다(0050.56ab.1234 / 00-50-56-AB-12-34)."""
    _switch_with_mac(temp_db, "0050.56ab.1234")
    assert db.find_location_by_mac(temp_db, MAC)["switch_name"] == "SW-ACCESS-01"
    assert db.find_location_by_mac(temp_db, "00-50-56-ab-12-34")["switch_name"] \
        == "SW-ACCESS-01"


def test_find_location_prefers_physical_port(temp_db):
    """포트채널 집합보다 실제 케이블이 꽂힌 물리 포트가 쓸모 있다."""
    sid = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [
        {"vlan": 10, "mac": MAC, "port": "Po10"},
        {"vlan": 10, "mac": MAC, "port": "Gi1/0/5"},
    ])
    assert db.find_location_by_mac(temp_db, MAC)["port"] == "Gi1/0/5"


def test_find_location_by_mac_rejects_garbage(temp_db):
    assert db.find_location_by_mac(temp_db, "") == {}
    assert db.find_location_by_mac(temp_db, "not-a-mac") == {}
    assert db.find_location_by_mac(temp_db, None) == {}


# ── 수집 경로 통합 ──────────────────────────────────────────────
def test_port_resolved_when_mac_comes_from_ssh(temp_db, monkeypatch):
    """스위치 ARP에 IP가 없어도, SSH로 MAC을 얻었으면 포트를 찾아야 한다."""
    _stub(monkeypatch, ports=(22,))
    _switch_with_mac(temp_db, MAC)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: 22)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")
    monkeypatch.setattr(sc, "_ssh_detail_unix", lambda ip, u, pw, port=22: {
        "hostname": "h", "os_info": "Linux", "mac": MAC, "cpu_cores": 4,
        "cpu_model": "X", "mem_total_mb": 8000, "disk_total_gb": 50.0})
    sid = db.save_server(temp_db, "SRV", "10.20.30.77")
    sc.collect_server(temp_db, sid, "svc", "pw")
    row = db.get_server(temp_db, sid)
    assert row["mac"] == MAC
    assert row["switch_name"] == "SW-ACCESS-01", "MAC은 있는데 연결스위치가 비었다"
    assert row["switch_port"] == "Gi1/0/24"


def test_mac_from_local_arp_when_no_credentials(temp_db, monkeypatch):
    """계정이 없어도 같은 서브넷 서버는 MAC·포트가 잡혀야 한다."""
    _stub(monkeypatch)
    _switch_with_mac(temp_db, MAC)
    monkeypatch.setattr(sc, "local_arp_mac", lambda ip: MAC)
    sid = db.save_server(temp_db, "SRV", "10.20.30.77")
    sc.collect_server(temp_db, sid, None, None)
    row = db.get_server(temp_db, sid)
    assert row["mac"] == MAC
    assert row["switch_name"] == "SW-ACCESS-01"


def test_local_arp_not_used_when_switch_arp_has_it(temp_db, monkeypatch):
    """스위치가 알려준 값이 우선 — 로컬 캐시로 덮어쓰지 않는다."""
    _stub(monkeypatch)
    monkeypatch.setattr(sc, "local_arp_mac", lambda ip: "AA:AA:AA:AA:AA:AA")
    monkeypatch.setattr(db, "find_mac_location",
                        lambda p, ip: {"mac": MAC, "switch_name": "SW-X",
                                       "switch_id": 1, "port": "Gi1/0/1"})
    sid = db.save_server(temp_db, "SRV", "10.20.30.77")
    sc.collect_server(temp_db, sid, None, None)
    assert db.get_server(temp_db, sid)["mac"] == MAC


def test_existing_location_is_not_overwritten(temp_db, monkeypatch):
    """이미 찾은 연결 위치를 재조회로 덮어쓰면 안 된다(불필요한 요동)."""
    _stub(monkeypatch)
    _switch_with_mac(temp_db, MAC, port="Gi1/0/24", name="SW-ACCESS-01")
    monkeypatch.setattr(db, "find_mac_location",
                        lambda p, ip: {"mac": MAC, "switch_name": "SW-FIRST",
                                       "switch_id": 99, "port": "Gi9/9/9"})
    sid = db.save_server(temp_db, "SRV", "10.20.30.77")
    sc.collect_server(temp_db, sid, None, None)
    row = db.get_server(temp_db, sid)
    assert row["switch_name"] == "SW-FIRST" and row["switch_port"] == "Gi9/9/9"


def test_no_mac_no_crash(temp_db, monkeypatch):
    _stub(monkeypatch)
    sid = db.save_server(temp_db, "SRV", "10.20.30.78")
    sc.collect_server(temp_db, sid, None, None)
    row = db.get_server(temp_db, sid)
    assert not row.get("switch_name")


def test_resolution_is_logged():
    src = (ROOT / "core" / "server_collector.py").read_text(encoding="utf-8")
    assert "server_port_resolved_by_mac" in src
    assert "server_mac_from_local_arp" in src


def test_local_arp_handles_korean_locale(monkeypatch):
    """한국어 Windows는 'dynamic'이 아니라 '동적'으로 찍는다(실측 확인).

    타입 컬럼 문자열에 기대면 한국어 콘솔에서 전부 실패한다 — IP와 MAC만 본다.
    cp949 바이트가 utf-8 디코드에서 깨져도 IP·MAC은 ASCII라 영향이 없어야 한다.
    """
    ko = ("\xc0\xce\xc5\xcd\xc6\xe4\xc0\xcc\xbd\xba: 10.20.30.5 --- 0xd\n"
          "  \xc0\xce\xc5\xcd\xb3\xd7 \xc1\xd6\xbc\xd2      "
          "\xb9\xb0\xb8\xae\xc0\xfb \xc1\xd6\xbc\xd2      \xc0\xaf\xc7\xfc\n"
          "  10.20.30.77           00-50-56-ab-12-34     \xb5\xbf\xc0\xfb\n"
          ).encode("latin-1")
    monkeypatch.setattr(sc.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(ko))
    assert sc.local_arp_mac("10.20.30.77") == MAC


def test_local_arp_rejects_broadcast_and_multicast_rows(monkeypatch):
    """브로드캐스트 항목을 서버 MAC으로 넣으면 안 된다."""
    monkeypatch.setattr(sc.os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(
        b"  192.168.153.255       ff-ff-ff-ff-ff-ff     static\n"))
    assert sc.local_arp_mac("192.168.153.255") == ""
