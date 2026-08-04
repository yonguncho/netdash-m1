# -*- coding: utf-8 -*-
"""관제 통합 대시보드 — 탭 + 통계 (v6.20.0).

사용자 요청: 관제 페이지가 리스트만 뿌리지 말고 스위치·방화벽·설비 탭으로 나뉘어
그래프·표로 통계를 보여주는 통합 대시보드가 되어야 한다.
"""
from core import db, wallstats


def _seed(p):
    a = db.save_switch(p, "BB-01", "10.0.0.1", "cisco_nxos")
    b = db.save_switch(p, "TPS-01", "10.0.0.2", "cisco_ios")
    c = db.save_switch(p, "TPS-02", "10.0.0.3", "cisco_ios")
    db.set_switch_status(p, a, "done")
    db.set_switch_status(p, b, "done")
    db.set_switch_status(p, c, "failed")
    for sid, ports in ((a, [("Eth1/1", "up"), ("Eth1/2", "up"), ("Eth1/3", "notconnect")]),
                       (b, [("Gi1/0/1", "connected"), ("Gi1/0/2", "notconnect")])):
        snap = db.save_snapshot(p, sid)
        db.save_ports(p, snap, sid, [
            {"switch_id": sid, "name": n, "status": st, "vlan": 1, "speed": "1000",
             "description": ""} for n, st in ports])
    with db.get_db(p) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) VALUES (?,?,?,?)",
                     ("FW-01", "fortigate", "10.0.0.10", "done"))
    db.save_facility_hosts(p, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.5", "mac": "aa:bb:cc:00:00:05",
         "online": 1, "direct": 1, "switch_name": "TPS-01", "port": "Gi1/0/1"},
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.6", "mac": "aa:bb:cc:00:00:06",
         "online": 0, "direct": 0},
        {"subnet": "10.2.0.0/24", "ip": "10.2.0.7", "mac": "aa:bb:cc:00:00:07",
         "online": 1, "direct": 1, "switch_name": "TPS-01", "port": "Gi1/0/2"},
    ])
    return a, b, c


def test_switch_stats(temp_db):
    _seed(temp_db)
    s = wallstats.build(temp_db)["switches"]
    assert s["total"] == 3
    assert s["by_status"]["done"] == 2 and s["by_status"]["failed"] == 1
    assert s["ports"]["total"] == 5 and s["ports"]["up"] == 3
    assert s["ports"]["down"] == 2 and s["ports"]["pct"] == 60
    assert {v["name"] for v in s["by_vendor"]} == {"cisco_nxos", "cisco_ios"}


def test_port_status_covers_vendor_wording(temp_db):
    """'up'과 'connected'가 벤더마다 다르다 — 둘 다 사용 중으로 센다."""
    _seed(temp_db)
    assert wallstats.build(temp_db)["switches"]["ports"]["up"] == 3


def test_top_ports_sorted_by_utilisation(temp_db):
    a, b, _ = _seed(temp_db)
    top = wallstats.build(temp_db)["switches"]["top_ports"]
    assert top[0]["name"] == "BB-01"          # 2/3 = 67% > 1/2 = 50%
    assert top[0]["pct"] == 67 and top[0]["up"] == 2 and top[0]["total"] == 3


def test_facility_stats(temp_db):
    _seed(temp_db)
    c = wallstats.build(temp_db)["facility"]
    assert c["total"] == 3 and c["online"] == 2 and c["offline"] == 1
    assert c["direct"] == 2 and c["indirect"] == 1
    subs = {x["name"]: x for x in c["by_subnet"]}
    assert subs["10.1.0.0/24"]["count"] == 2 and subs["10.1.0.0/24"]["online"] == 1
    assert {x["name"]: x["count"] for x in c["by_switch"]}["TPS-01"] == 2


def test_firewall_stats_aggregates_metrics(temp_db):
    _seed(temp_db)
    fid = db.list_firewalls(temp_db)[0]["id"]
    db.save_device_metrics(temp_db, "firewall", fid, {
        "cpu_pct": 22, "mem_pct": 61, "disk_pct": 30, "sessions": 5000, "level": "normal",
        "vpn": {"tunnel_total": 5, "tunnel_up": 3, "ssl_users": 7},
        "policy": {"total": 240, "unused": 31, "disabled": 4},
        "sensors": {"alarms": ["PS2 Status"], "psu_count": 2},
    })
    f = wallstats.build(temp_db)["firewalls"]
    assert f["total"] == 1
    assert f["vpn"]["tunnels"] == 5 and f["vpn"]["up"] == 3 and f["vpn"]["down"] == 2
    assert f["policy"]["total"] == 240 and f["policy"]["unused"] == 31
    assert f["sensors"]["alarms"] == 1 and f["sensors"]["psu"] == 2
    assert f["load"][0]["cpu"] == 22 and f["load"][0]["name"] == "FW-01"


def test_empty_db_returns_zeroes_not_error(temp_db):
    st = wallstats.build(temp_db)
    assert st["switches"]["total"] == 0
    assert st["facility"]["total"] == 0
    assert st["firewalls"]["total"] == 0


def test_stats_endpoint(client):
    r = client.get("/api/wall/stats")
    assert r.status_code == 200
    d = r.get_json()
    for k in ("switches", "firewalls", "facility"):
        assert k in d


def test_wall_page_has_tabs_and_charts():
    from pathlib import Path
    root = Path(__file__).parent.parent
    html = (root / "web" / "templates" / "wall.html").read_text(encoding="utf-8")
    js = (root / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    css = (root / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    for t in ("wtab-switch", "wtab-firewall", "wtab-facility", "wall-tabs"):
        assert t in html, t
    assert "function donut" in js and "function barList" in js
    assert "renderSwitchTab" in js and "renderFirewallTab" in js and "renderFacilityTab" in js
    assert ".wall-tab" in css and ".wdonut" in css
    # 폐쇄망이라 외부 차트 라이브러리를 끌어오면 안 된다
    assert "cdn." not in js and "http://" not in js


def test_summary_tab_still_shows_problem_list():
    """통계를 더하되 기존 장애 목록을 없애면 안 된다 — 관제의 본래 목적이다."""
    from pathlib import Path
    root = Path(__file__).parent.parent
    html = (root / "web" / "templates" / "wall.html").read_text(encoding="utf-8")
    assert 'id="wall-problems"' in html and 'id="wtab-summary"' in html


def test_stats_poll_is_slower_than_problem_poll():
    """집계 쿼리를 10초마다 돌리면 관제 화면이 DB를 계속 붙잡는다."""
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert "setInterval(refreshStats, 30000)" in js
    assert "setInterval(refresh, 10000)" in js
