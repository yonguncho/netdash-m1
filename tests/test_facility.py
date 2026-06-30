"""설비 현황 — MAC 대조 + 저장/조회 + API 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
HTML = ROOT / "web" / "templates" / "index.html"


def test_mac_to_switchport(temp_db):
    sid = db.save_switch(temp_db, "SW12", "10.0.0.12", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [
        {"switch_id": sid, "vlan": 100, "mac": "00:50:56:a1:b2:c3", "port": "Gi1/0/10", "type": "dynamic"}])
    m = db.get_mac_to_switchport(temp_db)
    assert "00:50:56:a1:b2:c3" in m
    entry = m["00:50:56:a1:b2:c3"][0]
    assert entry[1] == "SW12" and entry[2] == "Gi1/0/10"


def test_save_get_facility(temp_db):
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.92.174.0/23", "ip": "10.92.174.200", "mac": "00:50:56:a1:b2:c3",
         "switch_id": 1, "switch_name": "SW12", "port": "Gi1/0/10", "online": 1}])
    hosts = db.get_facility_hosts(temp_db)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "10.92.174.200"
    assert hosts[0]["port"] == "Gi1/0/10"
    assert hosts[0]["online"] == 1


def test_facility_collect_validates(client):
    # 대역 누락
    assert client.post("/api/facility/collect", json={"switch_id": 1}).status_code == 400
    # 잘못된 CIDR
    sid = client.post("/api/switches/manual", json={"ip": "10.0.0.11", "name": "GW", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.post("/api/facility/collect", json={"switch_id": sid, "subnet": "not-cidr"})
    assert r.status_code == 400
    # 너무 큰 대역(/16)
    r2 = client.post("/api/facility/collect", json={"switch_id": sid, "subnet": "10.0.0.0/16"})
    assert r2.status_code == 400
    # 계정 없음(저장 cred 없음) → 400
    r3 = client.post("/api/facility/collect", json={"switch_id": sid, "subnet": "10.0.0.0/24"})
    assert r3.status_code == 400


def test_facility_list_endpoint(client):
    r = client.get("/api/facility")
    b = r.get_json()
    assert "hosts" in b and "status" in b


def test_parse_connected_subnets():
    from core import facility
    route = (
        "Codes: C - connected, S - static\n"
        "C    10.92.174.0/23 is directly connected, Vlan100\n"
        "C    10.92.176.0/24 is directly connected, Vlan200\n"
        "C    10.0.0.0/8 is directly connected, Vlan1\n")  # /8 너무 큼 → 제외
    iface = "Vlan100 is up\n  Internet address is 10.92.174.11/23\n"
    subnets = facility._parse_connected_subnets(route, iface)
    assert "10.92.174.0/23" in subnets
    assert "10.92.176.0/24" in subnets
    assert "10.0.0.0/8" not in subnets   # /22 초과 제외
    # 중복 제거(route+iface 같은 대역)
    assert subnets.count("10.92.174.0/23") == 1


def test_facility_detect_validates(client):
    sid = client.post("/api/switches/manual", json={"ip": "10.0.0.11", "name": "GW", "vendor": "cisco"}).get_json()["switch_id"]
    # 계정 없음 → 400
    r = client.post("/api/facility/detect-subnets", json={"switch_id": sid})
    assert r.status_code == 400


def test_facility_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-tab="facility"' in html
    assert 'id="facility-table-body"' in html
    assert 'id="btn-fac-detect"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "function loadFacility" in js
    assert "/api/facility/collect" in js
    assert "/api/facility/detect-subnets" in js
