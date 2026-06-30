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


def test_clear_facility_subnet(temp_db):
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.5", "mac": "aa", "online": 1},
        {"subnet": "10.2.0.0/24", "ip": "10.2.0.5", "mac": "bb", "online": 1}])
    db.clear_facility_subnet(temp_db, "10.1.0.0/24")
    hosts = db.get_facility_hosts(temp_db)
    subs = {h["subnet"] for h in hosts}
    assert "10.1.0.0/24" not in subs
    assert "10.2.0.0/24" in subs


def test_start_collect_sets_running_under_lock():
    """TOCTOU: 두 번째 호출은 즉시 거부(첫 호출이 lock 내 running=True)."""
    from core import facility
    facility._status["running"] = False
    # 실제 스레드는 SSH 시도 후 곧 실패하지만, 두 번째 즉시 호출은 running=True로 거부
    facility._status["running"] = True
    assert facility.start_collect_band(":memory:", 1, "10.0.0.0/30", "u", "p") is False
    facility._status["running"] = False


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


def test_is_physical_port():
    from core import facility
    assert facility._is_physical_port("Gi1/0/5") is True
    assert facility._is_physical_port("Te1/1/1") is True
    assert facility._is_physical_port("Eth1/10") is True
    assert facility._is_physical_port("Fa0/1") is True
    # 논리 포트는 직접연결 아님
    assert facility._is_physical_port("Po1") is False
    assert facility._is_physical_port("Port-channel10") is False
    assert facility._is_physical_port("Vl1380") is False
    assert facility._is_physical_port("Vlan100") is False
    assert facility._is_physical_port("") is False


def test_choose_attachment_prefers_physical_access_port():
    """같은 MAC이 액세스 스위치(Gi, MAC 1개)와 코어 Po에 보이면 → 액세스 Gi 선택, direct=True."""
    from core import facility
    matches = [
        (1, "ACCESS-SW", "Gi1/0/5"),    # 진짜 액세스 포트
        (2, "CORE-SW", "Po1"),          # 포트채널 업링크 경유
    ]
    port_counts = {(1, "gi1/0/5"): 1, (2, "po1"): 200}
    sid, sname, port, direct, via = facility._choose_attachment(matches, port_counts)
    assert sname == "ACCESS-SW" and port == "Gi1/0/5"
    assert direct is True
    assert any("CORE-SW:Po1" in v for v in via)


def test_choose_attachment_logical_only_not_direct():
    """물리 포트 관측 없이 Po/Vl만 보이면 direct=False(직접연결 미확인)."""
    from core import facility
    matches = [(2, "CORE-SW", "Po1"), (3, "TPS-SW", "Vl1380")]
    sid, sname, port, direct, via = facility._choose_attachment(matches, {})
    assert direct is False


def test_choose_attachment_trunk_physical_not_direct():
    """물리 포트라도 MAC 수가 많으면(트렁크) direct=False."""
    from core import facility
    matches = [(1, "SW-A", "Te1/1/1")]
    port_counts = {(1, "te1/1/1"): 150}  # 트렁크
    sid, sname, port, direct, via = facility._choose_attachment(matches, port_counts)
    assert port == "Te1/1/1" and direct is False


def test_get_port_mac_counts(temp_db):
    sid = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [
        {"switch_id": sid, "vlan": 1, "mac": "00:00:00:00:00:01", "port": "Gi1/0/1", "type": "dynamic"},
        {"switch_id": sid, "vlan": 1, "mac": "00:00:00:00:00:02", "port": "Po1", "type": "dynamic"},
        {"switch_id": sid, "vlan": 1, "mac": "00:00:00:00:00:03", "port": "Po1", "type": "dynamic"}])
    counts = db.get_port_mac_counts(temp_db)
    assert counts[(sid, "gi1/0/1")] == 1
    assert counts[(sid, "po1")] == 2


def test_save_facility_direct_via_roundtrip(temp_db):
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.9", "mac": "aa", "switch_id": 1,
         "switch_name": "ACCESS-SW", "port": "Gi1/0/5", "online": 1, "direct": 0,
         "via": "CORE-SW:Po1"}])
    h = db.get_facility_hosts(temp_db)[0]
    assert h["direct"] == 0
    assert h["via"] == "CORE-SW:Po1"


def test_facility_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'data-tab="facility"' in html
    assert 'id="facility-table-body"' in html
    assert 'id="btn-fac-detect"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "function loadFacility" in js
    assert "/api/facility/collect" in js
    assert "/api/facility/detect-subnets" in js
