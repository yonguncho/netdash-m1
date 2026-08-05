# -*- coding: utf-8 -*-
"""FortiGate 라이선스·객체 수 수집 (v6.27.0).

승인된 마지막 항목: REST monitor/license/status(구독 만료일) +
cmdb 객체 수(주소·주소그룹·서비스·VIP·IP풀).
"""
import datetime
from pathlib import Path

from core import db, wallstats
from core.firewall import fortigate as fgw

ROOT = Path(__file__).parent.parent

# FortiOS 7.x monitor/license/status 형태(중첩 forticare + 최상위 구독들)
_LIC_RESULTS = {
    "forticare": {"status": "registered", "support": {
        "hardware": {"status": "licensed", "support_level": "Premium",
                     "expires": 1790000000},
        "enhanced": {"status": "licensed", "expires": 1790000000}}},
    "antivirus": {"status": "licensed", "expires": 1750000000},   # 과거 → 만료 판정용
    "ips": {"status": "expired", "expires": 1720000000},
    "web_filtering": {"status": "no_license"},                    # 미보유 → 제외
    "appctrl": {"status": "licensed", "expires": 1790000000},
}


def test_parse_license_status_shapes():
    lic = fgw.parse_license_status(_LIC_RESULTS)
    by = {x["key"]: x for x in lic}
    assert "web_filtering" not in by, "미보유 구독은 잡음 — 제외"
    assert by["forticare_hardware"]["name"] == "FortiCare 하드웨어"
    assert by["antivirus"]["expires"] == datetime.date.fromtimestamp(1750000000).isoformat()
    assert by["ips"]["status"] == "expired"
    assert len(lic) == 5    # forticare 2 + antivirus + ips + appctrl


def test_parse_license_garbage():
    assert fgw.parse_license_status(None) == []
    assert fgw.parse_license_status({"x": "notdict"}) == []
    assert fgw.parse_license_status({"av": {"status": "licensed", "expires": "bad"}}) \
        [0]["expires"] is None


class _Resp:
    def __init__(self, code, body):
        self.status_code = code
        self._body = body

    def json(self):
        return self._body


def test_fetch_objects_counts_names(monkeypatch):
    """format=name 목록 길이 = 개수. 404 경로는 항목에서 빠진다."""
    def fake_get(sess, url, timeout=15, retries=3):
        if "firewall/address?" in url:
            return _Resp(200, {"results": [{"name": "a"}] * 120})
        if "firewall/addrgrp?" in url:
            return _Resp(200, {"results": [{"name": "g"}] * 8})
        if "service/custom?" in url:
            return _Resp(200, {"results": [{"name": "s"}] * 40})
        return _Resp(404, {})
    monkeypatch.setattr(fgw, "_get_with_retry", fake_get)
    out = fgw._fetch_objects(None, "https://x", "x")
    assert out == {"address": 120, "addrgrp": 8, "service": 40, "total": 168}


def test_collect_includes_license_and_objects_keys(monkeypatch):
    """collect() 반환에 license/objects가 실려야 merge가 저장한다."""
    monkeypatch.setattr(fgw, "_make_session", lambda *a, **k: (None, "https://x"))
    monkeypatch.setattr(fgw, "_fetch_interfaces", lambda *a: [])
    monkeypatch.setattr(fgw, "_fetch_arp", lambda *a: [])
    monkeypatch.setattr(fgw, "_fetch_ha", lambda *a: None)
    monkeypatch.setattr(fgw, "_fetch_vpn", lambda *a: None)
    monkeypatch.setattr(fgw, "_fetch_policy_stats", lambda *a: None)
    monkeypatch.setattr(fgw, "_fetch_sysinfo", lambda *a: None)
    monkeypatch.setattr(fgw, "_fetch_license", lambda *a: [{"key": "ips", "name": "IPS",
                                                            "status": "licensed",
                                                            "expires": "2027-01-01"}])
    monkeypatch.setattr(fgw, "_fetch_objects", lambda *a: {"address": 3, "total": 3})
    r = fgw.collect("h")
    assert r["license"][0]["key"] == "ips" and r["objects"]["total"] == 3


def _fw(p, name="FW-A"):
    with db.get_db(p) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                           "VALUES (?,?,?,?)", (name, "fortigate", "10.0.0.1", "done"))
        return cur.lastrowid


def test_merge_saves_license_and_objects(temp_db):
    from core import collector
    fid = _fw(temp_db)
    collector.merge_fw_extra(temp_db, {"id": fid, "vendor": "fortigate", "host": "10.0.0.1"},
                             {"license": [{"key": "ips", "name": "IPS",
                                           "status": "licensed", "expires": "2027-01-01"}],
                              "objects": {"address": 5, "total": 5}}, {})
    m = db.get_device_env(temp_db, "firewall", fid)["metrics"]
    assert m["license"][0]["name"] == "IPS" and m["objects"]["total"] == 5


def test_wallstats_license_levels(temp_db):
    """만료/90일 임박/정상 판정 + 만료·임박 우선 정렬 + KPI 카운트."""
    fid = _fw(temp_db)
    today = datetime.date.today()
    db.save_device_metrics(temp_db, "firewall", fid, {
        "license": [
            {"key": "a", "name": "안티바이러스", "status": "licensed",
             "expires": (today + datetime.timedelta(days=400)).isoformat()},
            {"key": "b", "name": "IPS", "status": "licensed",
             "expires": (today + datetime.timedelta(days=30)).isoformat()},
            {"key": "c", "name": "웹 필터", "status": "expired",
             "expires": (today - datetime.timedelta(days=10)).isoformat()},
        ],
        "objects": {"address": 120, "addrgrp": 8, "service": 40, "vip": 3,
                    "total": 171}})
    f = wallstats.build(temp_db)["firewalls"]
    levels = [x["level"] for x in f["license_rows"]]
    assert levels == ["expired", "imminent", "ok"], "만료·임박이 위로 와야 한다"
    assert f["license_bad"] == 2
    assert f["objects_rows"][0]["total"] == 171 and f["objects_rows"][0]["fw"] == "FW-A"


def test_wall_ui_license_and_object_column():
    """v6.28: 라이선스는 별도 카드가 아니라 장비 카드 fact 행으로 통합
    (사용자 지적 — CPU/MEM 있는 박스에서 같이). KPI·객체 열은 유지."""
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert "라이선스 만료·임박" in js, "KPI 카드"
    assert "d.license" in js, "장비 카드에 라이선스 fact"
    assert "objects_rows" in js and ">객체</th>" in js
    app = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "m.license" in app and "m.objects" in app
