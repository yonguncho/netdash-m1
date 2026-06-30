"""종합 검색(등록 스위치·방화벽 + ARP + 장부) 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


def test_search_registered_switch(temp_db):
    db.save_switch(temp_db, "CORE-SW", "10.0.0.10", "cisco_ios")
    res = db.search_everywhere(temp_db, "10.0.0.10")
    assert any(r["source"] == "등록 스위치" and r["ip"] == "10.0.0.10" for r in res)


def test_search_registered_firewall(temp_db):
    db.save_firewall(temp_db, "FW1", "fortigate", "10.0.0.20", 443)
    res = db.search_everywhere(temp_db, "10.0.0.20")
    assert any(r["source"] == "등록 방화벽" and r["ip"] == "10.0.0.20" for r in res)


def test_search_partial_match(temp_db):
    db.save_switch(temp_db, "ACC-SW", "192.168.1.50", "cisco_ios")
    res = db.search_everywhere(temp_db, "192.168.1")
    assert any(r["ip"] == "192.168.1.50" for r in res)


def test_search_by_name(temp_db):
    db.save_switch(temp_db, "DIST-SW-3F", "10.1.1.1", "cisco_ios")
    res = db.search_everywhere(temp_db, "DIST-SW")
    assert any(r["label"] == "DIST-SW-3F" for r in res)


def test_search_empty_query(temp_db):
    assert db.search_everywhere(temp_db, "") == []


def test_search_facility_host_by_ip(temp_db):
    """수집된 설비 IP 검색 — facility_hosts 포함 (회귀: 이전엔 0건)."""
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.92.174.0/23", "ip": "10.92.174.200", "mac": "00:50:56:a1:b2:c3",
         "switch_id": 1, "switch_name": "SW12", "port": "Gi1/0/10", "online": 1}])
    res = db.search_everywhere(temp_db, "10.92.174.200")
    assert any(r["source"] == "설비 현황" and r["ip"] == "10.92.174.200" for r in res)


def test_search_by_mac(temp_db):
    """MAC 부분 검색 — MAC 테이블 + 설비 모두 (회귀: 이전엔 0건)."""
    sid = db.save_switch(temp_db, "SW12", "10.0.0.12", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [
        {"switch_id": sid, "vlan": 100, "mac": "00:50:56:a1:b2:c3", "port": "Gi1/0/10", "type": "dynamic"}])
    res = db.search_everywhere(temp_db, "b2:c3")
    assert any(r["source"] == "MAC 테이블" for r in res)


def test_api_search_returns_results(client):
    client.post("/api/switches/manual", json={"ip": "10.2.2.2", "name": "SW-X", "vendor": "cisco"})
    r = client.get("/api/search?ip=10.2.2.2")
    body = r.get_json()
    assert "results" in body
    assert body["count"] >= 1
    assert any(x["ip"] == "10.2.2.2" for x in body["results"])
