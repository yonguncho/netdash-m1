# -*- coding: utf-8 -*-
"""관제 '재수집'이 대역 전체가 아니라 그 설비 하나만 재확인 (v6.9.0).

사용자 요청: "관제 페이지에서 설비 연결 실패에 출력되는 설비에 대해 재수집
버튼을 누르면 해당 대역 전체에 대해 재수집이 진행되는데, 재수집 버튼을
클릭한 설비에 대해서만 해당 스위치 접속해서 재확인하는 동작이 나을 것 같다."

기존에는 /api/facility/recollect 가 그 IP가 속한 대역 전체를 처음부터
ping sweep 했다(대역이 /23이면 15분+). 이 파일은 게이트웨이 스위치에 붙어
**그 IP 하나만** ping·ARP 조회하고, 같은 대역의 다른 설비 행은 건드리지
않는 것을 검증한다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility  # noqa: E402

ROOT = Path(__file__).parent.parent


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _seed_switch(temp_db, name="TPS11", ip="10.9.0.11", vendor="cisco_ios"):
    sid = db.save_switch(temp_db, name, ip, vendor)
    facility.remember_band(temp_db, "10.9.0.0/29", sid)
    return sid


class _FakeConn(object):
    """netmiko.ConnectHandler 대역 — ping 1회 + ARP 조회만 응답한다."""

    def __init__(self, arp_text="", ping_ok=True, **kw):
        self.arp_text = arp_text
        self.ping_ok = ping_ok
        self.pings = []
        self.arp_reads = 0

    def check_enable_mode(self):
        return True

    def disconnect(self):
        pass

    def send_command(self, cmd, read_timeout=10):
        if cmd.startswith("terminal"):
            return ""
        if cmd == "show vrf":
            return ""            # VRF 없음 — 글로벌 대역
        if cmd.startswith("ping"):
            self.pings.append(cmd)
            if not self.ping_ok:
                raise TimeoutError("ping timeout")
            return "!!!!!"
        if cmd.startswith("show ip arp") or cmd.startswith("show iparp"):
            self.arp_reads += 1
            return self.arp_text
        return ""


def _patch_conn(monkeypatch, conn):
    import netmiko as _nm
    monkeypatch.setattr(_nm, "ConnectHandler", lambda **kw: conn)


# ── 그 설비 하나만 ping/ARP 조회한다(대역 전체 스윕 없음) ────────
def test_pings_only_the_target_ip(temp_db, monkeypatch):
    _seed_switch(temp_db)
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.cc00.0105  ARPA  Gi1/0/5\n")
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0},
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.6", "mac": "AA:00:00:00:00:06",
         "switch_name": "", "port": "", "online": 0},
    ])
    ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    assert ok, msg
    assert len(conn.pings) == 1, "여러 IP를 ping했다 — 대역 전체 스윕이 됐다"
    assert "10.9.0.5" in conn.pings[0]
    assert conn.arp_reads == 1


def test_other_hosts_in_same_subnet_are_untouched(temp_db, monkeypatch):
    """같은 대역의 다른 설비 행은 값이 그대로여야 한다."""
    sid = _seed_switch(temp_db)
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.cc00.0105  ARPA  Gi1/0/5\n")
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0},
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.6", "mac": "AA:00:00:00:00:06",
         "switch_name": "OLD-SWITCH", "port": "Gi1/0/6", "online": 1},
    ])
    facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    other = [h for h in db.get_facility_hosts(temp_db) if h["ip"] == "10.9.0.6"][0]
    assert other["online"] == 1
    assert other["switch_name"] == "OLD-SWITCH" and other["port"] == "Gi1/0/6"


# ── 온라인/오프라인 판정 ─────────────────────────────────────────
def test_marks_online_when_arp_reports_it(temp_db, monkeypatch):
    sid = _seed_switch(temp_db)
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.cc00.0105  ARPA  Gi1/0/5\n")
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0}])
    ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    assert ok and "온라인" in msg
    row = [h for h in db.get_facility_hosts(temp_db) if h["ip"] == "10.9.0.5"][0]
    assert row["online"] == 1


def test_marks_offline_when_arp_has_no_entry(temp_db, monkeypatch):
    """ping은 갔지만 ARP에 안 잡히면(응답 없음) 오프라인으로 남는다."""
    sid = _seed_switch(temp_db)
    conn = _FakeConn(arp_text="")   # ARP 테이블에 해당 IP 없음
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "SW-OLD", "port": "Gi1/0/5", "online": 1}])
    ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    assert ok and "오프라인" in msg
    row = [h for h in db.get_facility_hosts(temp_db) if h["ip"] == "10.9.0.5"][0]
    assert row["online"] == 0
    # 위치를 새로 못 찾았다고 이전 위치 정보를 지우면 안 된다(마지막 위치 참고용)
    assert row["switch_name"] == "SW-OLD" and row["port"] == "Gi1/0/5"


def test_ping_failure_does_not_abort_the_check(temp_db, monkeypatch):
    """ping이 실패해도(장비가 ICMP를 막는 경우가 흔하다) ARP 조회로 계속 판정한다."""
    sid = _seed_switch(temp_db)
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.cc00.0105  ARPA  Gi1/0/5\n",
                     ping_ok=False)
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0}])
    ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    assert ok and "온라인" in msg, "ping 실패만으로 오프라인 처리하면 오탐이 늘어난다"


# ── 연결 위치 갱신 ───────────────────────────────────────────────
def test_updates_switch_port_from_mac_table(temp_db, monkeypatch):
    """MAC이 스위치의 MAC 테이블에 있으면 연결 위치를 새로 채운다."""
    gw = _seed_switch(temp_db)
    edge = db.save_switch(temp_db, "EDGE-SW", "10.9.0.20", "cisco_ios")
    snap = db.save_snapshot(temp_db, edge)
    # ARP 파서가 "aabb.0000.0005"(Cisco dot 표기)를 콜론 표기로 정규화하므로
    # ("aa:bb:00:00:00:05") MAC 테이블도 같은 값으로 맞춘다.
    db.save_mac_entries(temp_db, snap, edge,
                        [{"vlan": 10, "mac": "aa:bb:00:00:00:05", "port": "Gi1/0/12"}])
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.0000.0005  ARPA  Vlan10\n")
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "",
         "switch_name": "", "port": "", "online": 0}])
    facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    row = [h for h in db.get_facility_hosts(temp_db) if h["ip"] == "10.9.0.5"][0]
    assert row["switch_name"] == "EDGE-SW" and row["port"] == "Gi1/0/12"


# ── 사전 조건 실패 ───────────────────────────────────────────────
def test_no_gateway_remembered(temp_db):
    ok, msg = facility.recollect_single_host(temp_db, "10.5.0.0/24", "10.5.0.9", "u", "p")
    assert not ok and "게이트웨이" in msg


def test_ip_outside_subnet_rejected(temp_db):
    _seed_switch(temp_db)
    ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.99.99.99", "u", "p")
    assert not ok


def test_ssh_connect_failure_reported(temp_db, monkeypatch):
    _seed_switch(temp_db)
    import netmiko as _nm

    def boom(**kw):
        raise TimeoutError("connect timeout")

    monkeypatch.setattr(_nm, "ConnectHandler", boom)
    ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
    assert not ok and "스위치 접속 실패" in msg


# ── 스레드 세이프티: 대역 전체 스캔 상태를 건드리지 않는다 ──────
def test_does_not_touch_global_running_flag(temp_db, monkeypatch):
    """단일 설비 재확인은 _status.running을 켜지 않는다 — 대역 스캔과 경합하면
    안 된다는 사용자 요청의 핵심이다."""
    sid = _seed_switch(temp_db)
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.cc00.0105  ARPA  Gi1/0/5\n")
    _patch_conn(monkeypatch, conn)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0}])
    with facility._lock:
        facility._status.update(running=True, subnet="10.20.0.0/24")
    try:
        ok, msg = facility.recollect_single_host(temp_db, "10.9.0.0/29", "10.9.0.5", "u", "p")
        assert ok, msg
        assert facility.get_status()["running"] is True, \
            "다른 대역 스캔 상태를 건드렸다"
        assert facility.get_status()["subnet"] == "10.20.0.0/24"
    finally:
        with facility._lock:
            facility._status.update(running=False, subnet=None)


# ── 라우트 배선 ──────────────────────────────────────────────────
def test_route_uses_single_host_function(cli, monkeypatch):
    """PUT/POST 라우트가 실제로 recollect_single_host를 타는지 종단으로 확인."""
    p = Path.cwd() / "netdash.db"
    sid = _seed_switch(p)
    from core import credentials
    blob = credentials.encrypt_credential("u", "p")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(p, sid, blob)
    db.save_facility_hosts(p, [
        {"subnet": "10.9.0.0/29", "ip": "10.9.0.5", "mac": "AA:00:00:00:00:05",
         "switch_name": "", "port": "", "online": 0}])
    conn = _FakeConn(arp_text="Internet  10.9.0.5   0  aabb.cc00.0105  ARPA  Gi1/0/5\n")
    _patch_conn(monkeypatch, conn)
    r = cli.post("/api/facility/recollect", json={"ip": "10.9.0.5"})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True and "message" in body
    assert len(conn.pings) == 1, "라우트를 거쳤는데 여러 IP를 ping했다"


def test_route_no_longer_starts_band_scan():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index("def facility_recollect():")
    block = src[i:i + 2200]
    assert "recollect_single_host" in block
    assert "start_collect_band" not in block


def test_route_requires_ip():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index("def facility_recollect():")
    block = src[i:i + 700]
    assert 'if not ip:' in block
