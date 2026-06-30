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


def test_api_search_returns_results(client):
    client.post("/api/switches/manual", json={"ip": "10.2.2.2", "name": "SW-X", "vendor": "cisco"})
    r = client.get("/api/search?ip=10.2.2.2")
    body = r.get_json()
    assert "results" in body
    assert body["count"] >= 1
    assert any(x["ip"] == "10.2.2.2" for x in body["results"])
