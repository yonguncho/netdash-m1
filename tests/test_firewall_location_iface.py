# -*- coding: utf-8 -*-
"""방화벽 위치(서버실) + 인터페이스 IP 파싱 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from core.firewall import fortigate, paloalto

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


# ─── FortiGate 인터페이스 IP ─────────────────────────────
def test_fortigate_split_ip_mask():
    assert fortigate._split_ip_mask("10.0.0.1 255.255.255.0") == ("10.0.0.1", "255.255.255.0")
    assert fortigate._split_ip_mask("10.0.0.1/24") == ("10.0.0.1", "24")
    assert fortigate._split_ip_mask("10.0.0.1") == ("10.0.0.1", "")
    assert fortigate._split_ip_mask("") == ("", "")


def test_fortigate_parse_monitor_interfaces_dict():
    # monitor 응답: results가 dict{name:{...}} (실제 런타임 IP)
    results = {
        "port1": {"name": "port1", "ip": "10.10.10.1 255.255.255.0", "vdom": "root"},
        "port2": {"name": "port2", "ip": "0.0.0.0 0.0.0.0"},  # 미할당 → 제외
        "port3": {"name": "port3", "ip": "192.168.1.1", "mask": 24},
    }
    ifaces = fortigate._parse_monitor_interfaces(results)
    by = {i["name"]: i for i in ifaces}
    assert by["port1"]["ip"] == "10.10.10.1" and by["port1"]["mask"] == "255.255.255.0"
    assert "port2" not in by
    assert by["port3"]["ip"] == "192.168.1.1" and by["port3"]["mask"] == "24"


def test_fortigate_get_with_retry_429(monkeypatch):
    """429 응답이면 Retry-After 대기 후 재시도, 정상 응답은 즉시 반환."""
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda s: None)

    class R:
        def __init__(self, code, retry_after=None):
            self.status_code = code
            self.headers = {"Retry-After": retry_after} if retry_after else {}

    class S:
        def __init__(self, codes):
            self.codes = list(codes)
            self.calls = 0
        def get(self, url, timeout=15):
            self.calls += 1
            return R(self.codes.pop(0))

    s = S([429, 429, 200])
    r = fortigate._get_with_retry(s, "https://x/api")
    assert r.status_code == 200 and s.calls == 3
    s2 = S([200])
    assert fortigate._get_with_retry(s2, "u").status_code == 200 and s2.calls == 1


def test_fortigate_collect_single_session(monkeypatch):
    """collect()가 세션 1개로 인터페이스+ARP 수집(로그인 1회 — 429 방지)."""
    sessions = {"n": 0}

    def fake_make_session(host, port, token, u, p, verify, source_ip=None):
        sessions["n"] += 1
        class S:
            def get(self, url, timeout=15):
                class R:
                    status_code = 200
                    headers = {}
                    def raise_for_status(self):
                        pass
                    def json(self):
                        if "monitor/system/interface" in url:
                            return {"results": {"port1": {"name": "port1", "ip": "10.0.0.1/24"}}}
                        return {"results": [{"ip": "10.0.0.5", "mac": "AA:BB:CC:00:11:22",
                                             "interface": "port1"}]}
                return R()
        return S(), "https://x:443"
    monkeypatch.setattr(fortigate, "_make_session", fake_make_session)

    res = fortigate.collect("10.0.0.99")
    assert sessions["n"] == 1                     # 세션(로그인) 1회만
    assert len(res["interfaces"]) == 1 and len(res["arp"]) == 1


# ─── PaloAlto 논리 인터페이스 IP ─────────────────────────────
def test_paloalto_parse_logical_interfaces():
    out = (
        "total configured logical interfaces: 3\n"
        "name                id  vsys zone      forwarding   tag  address\n"
        "--------------------------------------------------------------------\n"
        "ethernet1/1         16  1    trust     vr:default    0   10.0.0.1/24\n"
        "ethernet1/2         17  1    untrust   vr:default    0   203.0.113.5/29\n"
        "loopback.1          20  1    mgmt      vr:default    0   N/A\n")
    ifaces = paloalto.parse_logical_interfaces(out)
    by = {i["name"]: i for i in ifaces}
    assert by["ethernet1/1"]["ip"] == "10.0.0.1" and by["ethernet1/1"]["mask"] == "24"
    assert by["ethernet1/2"]["ip"] == "203.0.113.5"
    assert by["loopback.1"]["ip"] == ""  # N/A → IP 없음


# ─── 방화벽 위치 저장/조회 ─────────────────────────────
def test_save_firewall_with_location(temp_db):
    fid = db.save_firewall(temp_db, "FW1", "fortigate", "10.0.0.1", 443, "token", location="A09U27")
    fw = db.get_firewall(temp_db, fid)
    assert fw["location"] == "A09U27"


def test_update_firewall_location(temp_db):
    fid = db.save_firewall(temp_db, "FW1", "fortigate", "10.0.0.2", 443, "token")
    db.update_firewall(temp_db, fid, location="B12U05")
    assert db.get_firewall(temp_db, fid)["location"] == "B12U05"


def test_firewalls_endpoint_injects_room(client):
    client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.3",
                                         "name": "SRV-FW", "location": "A09U27"})
    fws = client.get("/api/firewalls").get_json()["firewalls"]
    fw = [f for f in fws if f["host"] == "10.0.0.3"][0]
    assert fw["room_rack"] == "A09" and fw["room_unit"] == 27


# ─── UI 요소 ─────────────────────────────
def test_firewall_location_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="fw-location"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "_fwCardHTML" in js
    assert "renderRoomRackView" in js
    # 방화벽도 서버실 랙 뷰에 포함(detail-fw 유닛)
    assert "data-action='detail-fw'" in js
