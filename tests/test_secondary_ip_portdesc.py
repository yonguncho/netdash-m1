# -*- coding: utf-8 -*-
"""v3.43: FortiGate secondary IP + 설비 포트 Description 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from core.firewall import fortigate

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_fortigate_secondary_ips_parsed():
    results = [
        {"name": "port1", "ip": "10.0.0.1 255.255.255.0", "vdom": "root", "type": "physical",
         "secondaryip": [
             {"ip": "10.0.1.1 255.255.255.0"},
             {"ip": "10.0.2.1 255.255.255.0"}]},
        {"name": "port2", "ip": "10.9.0.1 255.255.255.0"},   # secondary 없음
    ]
    secs = fortigate._cmdb_secondaries(results)
    assert len(secs) == 2
    assert secs[0] == {"name": "port1 (2nd)", "ip": "10.0.1.1", "mask": "255.255.255.0",
                       "vdom_zone": "root", "type": "secondary"}
    assert all(s["name"] == "port1 (2nd)" for s in secs)


def test_fetch_interfaces_merges_secondary(monkeypatch):
    """monitor 기본 IP + cmdb secondary가 함께 반환."""
    class R:
        def __init__(self, code, payload):
            self.status_code = code
            self._p = payload
        def raise_for_status(self):
            pass
        def json(self):
            return self._p

    class S:
        def get(self, url, timeout=15):
            if "monitor/system/interface" in url:
                return R(200, {"results": {"port1": {"name": "port1", "ip": "10.0.0.1/24"}}})
            return R(200, {"results": [
                {"name": "port1", "ip": "10.0.0.1 255.255.255.0",
                 "secondaryip": [{"ip": "10.0.1.1 255.255.255.0"}]}]})
    ifaces = fortigate._fetch_interfaces(S(), "https://x:443", "10.0.0.99")
    names = [i["name"] for i in ifaces]
    assert "port1" in names and "port1 (2nd)" in names


def test_port_descriptions_query(temp_db):
    """get_port_descriptions: 최신 스냅샷 포트 설명 조회."""
    sid = db.save_switch(temp_db, "SW-D", "10.0.0.5", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_ports(temp_db, snap, sid, [
        {"name": "Gi1/0/5", "status": "up", "description": "AP-3F-회의실"},
        {"name": "Gi1/0/6", "status": "up", "description": ""}])
    descs = db.get_port_descriptions(temp_db)
    assert descs.get((sid, "gi1/0/5")) == "AP-3F-회의실"
    assert (sid, "gi1/0/6") not in descs   # 빈 설명 제외


def test_facility_port_desc_ui_and_export():
    html = HTML.read_text(encoding="utf-8")
    assert "<th>포트 설명</th>" in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "port_desc" in js and "연결 스위치에서 수집한 포트 설명" in js
    # export 컬럼
    from core import facility
    assert "포트 설명" in facility._EXPORT_COLS


def test_facility_collect_fills_port_desc(temp_db, monkeypatch):
    """대역 수집 시 연결 스위치 포트의 Description이 설비 행에 채워진다."""
    import netmiko as _nm
    from core import facility

    sw = db.save_switch(temp_db, "ACC-SW", "10.9.0.11", "cisco")
    snap = db.save_snapshot(temp_db, sw)
    # 설비 MAC이 Gi1/0/5(설명 'CCTV-정문')에서 학습됨(파서 정규화 형식=콜론)
    db.save_mac_entries(temp_db, snap, sw, [
        {"vlan": 1, "mac": "aa:bb:cc:00:00:54", "port": "Gi1/0/5", "type": "dynamic"}])
    db.save_ports(temp_db, snap, sw, [
        {"name": "Gi1/0/5", "status": "up", "description": "CCTV-정문"}])
    monkeypatch.setattr(facility, "_SWEEP_PING_GAP", 0)

    class FakeConn:
        def __init__(self, **k): pass
        def check_enable_mode(self): return True
        def disconnect(self): pass
        def send_command(self, cmd, read_timeout=10):
            if cmd.startswith("ping") or cmd.startswith("terminal"):
                return ""
            if cmd == "show vrf":
                return "% Invalid input"
            if cmd == "show ip arp":
                return "Internet  10.9.0.5  0  aabb.cc00.0054  ARPA  Vlan1\n"
            return ""
    monkeypatch.setattr(_nm, "ConnectHandler", FakeConn)
    monkeypatch.setattr(facility, "_set", lambda **k: None)

    facility.collect_band(temp_db, sw, "10.9.0.0/29", "u", "p")
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.9.0.5"]["port"] == "Gi1/0/5"
    assert hosts["10.9.0.5"]["port_desc"] == "CCTV-정문"
