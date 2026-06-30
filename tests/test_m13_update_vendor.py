"""M13: 벤더 정규화(수집 device_type) + 스위치/방화벽 수정 기능 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, collector


# ── 벤더 정규화 (수집 device_type 오류 수정) ───────────────────────
def test_norm_vendor():
    assert collector._norm_vendor("cisco") == "cisco_ios"
    assert collector._norm_vendor("arista") == "arista_eos"
    assert collector._norm_vendor("extreme") == "extreme_exos"
    assert collector._norm_vendor("juniper") == "juniper_junos"
    # 이미 정확한 netmiko type은 그대로
    assert collector._norm_vendor("cisco_ios") == "cisco_ios"
    assert collector._norm_vendor("arista_eos") == "arista_eos"
    # 대소문자/공백
    assert collector._norm_vendor(" Cisco ") == "cisco_ios"
    # 미지정(None/빈/unknown)은 Cisco IOS로 fallback
    assert collector._norm_vendor(None) == "cisco_ios"
    assert collector._norm_vendor("unknown") == "cisco_ios"


# ── DB 수정 ────────────────────────────────────────────────────────
def test_update_switch_db(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco")
    assert db.update_switch(temp_db, sid, name="SW1-NEW", ip="10.0.0.2", vendor="cisco_ios") is True
    sw = db.get_switch(temp_db, sid)
    assert sw["name"] == "SW1-NEW"
    assert sw["ip"] == "10.0.0.2"
    assert sw["vendor"] == "cisco_ios"
    # 없는 id
    assert db.update_switch(temp_db, 9999, name="X") is False


def test_update_firewall_db(temp_db):
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.3", 443)
    assert db.update_firewall(temp_db, fid, name="FW-NEW", host="10.0.0.4", port=8443) is True
    fw = db.get_firewall(temp_db, fid)
    assert fw["name"] == "FW-NEW"
    assert fw["host"] == "10.0.0.4"
    assert fw["port"] == 8443
    assert db.update_firewall(temp_db, 9999, name="X") is False


# ── 엔드포인트 ─────────────────────────────────────────────────────
def test_api_update_switch(client):
    sid = client.post("/api/switches/manual", json={"ip": "10.0.0.5", "name": "SW", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.put(f"/api/switches/{sid}", json={"name": "SW-EDIT", "ip": "10.0.0.6", "vendor": "cisco_ios"})
    assert r.status_code == 200
    assert client.put("/api/switches/9999", json={"name": "X"}).status_code == 404


def test_api_update_switch_ssrf(client):
    sid = client.post("/api/switches/manual", json={"ip": "10.0.0.7", "name": "SW", "vendor": "cisco"}).get_json()["switch_id"]
    # 공인 IP로 수정 시도 → 거부
    r = client.put(f"/api/switches/{sid}", json={"ip": "8.8.8.8"})
    assert r.status_code == 400


def test_api_update_firewall(client):
    fid = client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.8", "name": "FW"}).get_json()["firewall_id"]
    r = client.put(f"/api/firewalls/{fid}", json={"name": "FW-EDIT", "host": "10.0.0.9", "port": 8443})
    assert r.status_code == 200
    assert client.put("/api/firewalls/9999", json={"name": "X"}).status_code == 404


def test_api_update_firewall_bad_vendor(client):
    fid = client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.10", "name": "FW"}).get_json()["firewall_id"]
    r = client.put(f"/api/firewalls/{fid}", json={"vendor": "checkpoint"})
    assert r.status_code == 400


def test_appjs_edit_functions():
    src = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function editSwitch" in src
    assert "function editFirewall" in src
    assert "_editSwitchId" in src
    assert "_editFirewallId" in src


def test_appjs_no_inline_onclick():
    """CSP default-src 'self'는 inline onclick을 차단 → 이벤트 위임 사용 확인."""
    src = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "onclick=" not in src, "inline onclick은 CSP에 차단됨 — data-action 위임 사용"
    assert "data-action=" in src
    assert 'closest("[data-action]")' in src


def test_collector_read_timeout_moved_to_send_command():
    """read_timeout은 ConnectHandler 생성자가 아닌 send_command 인자여야 함."""
    src = (Path(__file__).parent.parent / "core" / "collector.py").read_text(encoding="utf-8")
    assert "send_command(command, read_timeout=read_timeout)" in src
    # device dict 정의에 read_timeout 키가 없어야(생성자 인자 금지)
    import re
    device_block = re.search(r'device = \{.*?\}', src, re.DOTALL)
    assert device_block and '"read_timeout"' not in device_block.group(0)


# ── v3.5.2 검증 후속 수정 ──────────────────────────────────────────
def test_paging_cmd_per_vendor():
    """EXOS는 terminal length 0가 아니라 disable clpaging."""
    assert collector._PAGING_CMD["extreme_exos"] == "disable clpaging"
    assert collector._PAGING_CMD["cisco_ios"] == "terminal length 0"
    # 미정의 벤더는 None(페이징 생략)
    assert collector._PAGING_CMD.get("paloalto_panos") is None


def test_csp_allows_inline_style():
    """CSP: script는 'self'(인라인 차단) 유지, style은 인라인 허용."""
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    assert "style-src 'self' 'unsafe-inline'" in src
    assert "script-src 'self'" in src


def test_update_switch_duplicate_name_conflict(client):
    """이름 중복 수정 시 500이 아니라 409."""
    client.post("/api/switches/manual", json={"ip": "10.1.0.1", "name": "DUP-A", "vendor": "cisco"})
    sid_b = client.post("/api/switches/manual", json={"ip": "10.1.0.2", "name": "DUP-B", "vendor": "cisco"}).get_json()["switch_id"]
    r = client.put(f"/api/switches/{sid_b}", json={"name": "DUP-A"})
    assert r.status_code == 409


def test_update_firewall_duplicate_host_conflict(client):
    """host 중복 수정 시 409."""
    client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.1.1.1", "name": "FA"})
    fb = client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.1.1.2", "name": "FB"}).get_json()["firewall_id"]
    r = client.put(f"/api/firewalls/{fb}", json={"host": "10.1.1.1"})
    assert r.status_code == 409
