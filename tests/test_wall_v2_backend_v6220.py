# -*- coding: utf-8 -*-
"""관제 대시보드 2차 개편 — 백엔드 (v6.22.0).

사용자 요청: get sys perf status로 CPU/MEM/세션 수집, 방화벽별 VPN 터널·정책·
수집상태 리스트, 설비 연결실패 다발 스위치 Top, 대역별 IP 통계.
(화면 개편은 목업 승인 후 — 이 파일은 디자인과 무관한 수집·집계만 검증한다.)
"""
from core import db, wallstats
from core.firewall import fortiperf, fortisensor

PERF_NEW = """
CPU states: 3% user 2% system 0% nice 95% idle 0% iowait 0% irq 0% softirq
CPU0 states: 4% user 2% system 0% nice 94% idle 0% iowait 0% irq 0% softirq
Memory: 2061108k total, 673556k used (32.7%), 1240848k free (60.2%), 146704k freeable (7.1%)
Average network usage: 121 / 97 kbps in 1 minute, 100 / 80 kbps in 10 minutes
Average sessions: 4823 sessions in 1 minute, 4790 sessions in 10 minutes
Average session setup rate: 12 sessions per second in last 1 minute
Uptime: 20 days,  1 hours,  5 minutes
"""


def test_perf_status_new_format():
    p = fortiperf.parse_perf_status(PERF_NEW)
    assert p["cpu_pct"] == 5            # 100 - 95 idle (CPU0 개별 코어 줄은 무시)
    assert p["mem_pct"] == 33 and p["mem_total_mb"] == 2013
    assert p["sessions"] == 4823 and p["session_rate"] == 12
    assert p["net_in_kbps"] == 121 and p["net_out_kbps"] == 97
    assert p["uptime_sec"] == 20 * 86400 + 3600 + 300


def test_perf_status_old_memory_format():
    p = fortiperf.parse_perf_status(
        "CPU states: 10% user 5% system 0% nice 85% idle\n"
        "Memory states: 32% used\n"
        "Average sessions: 100 sessions in 1 minute\n")
    assert p["cpu_pct"] == 15 and p["mem_pct"] == 32 and p["sessions"] == 100


def test_perf_status_garbage_returns_empty():
    """권한 부족·오류 출력을 지표로 오인하면 안 된다."""
    assert fortiperf.parse_perf_status("Unknown action 0\n") == {}
    assert fortiperf.parse_perf_status("") == {}


def test_perf_uptime_without_days():
    p = fortiperf.parse_perf_status("Uptime: 5 hours, 12 minutes\n")
    assert p["uptime_sec"] == 5 * 3600 + 12 * 60


def test_collect_ssh_all_combines_both_commands(monkeypatch):
    monkeypatch.setattr(fortisensor, "_ssh_run", lambda *a, **k: {
        "execute sensor list": "DTS CPU0         alarm=0 value=45    C\n",
        "get system performance status": PERF_NEW})
    out = fortisensor.collect_ssh_all("10.0.0.1", "admin", "pw")
    assert out["sensors"]["max_temp_c"] == 45
    assert out["perf"]["cpu_pct"] == 5


def test_collect_ssh_all_vm_without_sensors(monkeypatch):
    """VM 모델: 센서 없음 + 성능만 — sensors=None으로 구분한다."""
    monkeypatch.setattr(fortisensor, "_ssh_run", lambda *a, **k: {
        "execute sensor list": "Command fail. Return code -61\n",
        "get system performance status": PERF_NEW})
    out = fortisensor.collect_ssh_all("10.0.0.1", "admin", "pw")
    assert out["sensors"] is None and out["perf"]["sessions"] == 4823


def test_merge_fills_gaps_but_snmp_wins(temp_db, monkeypatch):
    """SSH perf는 빈 값만 채운다 — SNMP가 넣은 CPU를 덮으면 안 된다."""
    from core import collector
    with db.get_db(temp_db) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                           ("FW-01", "fortigate", "10.0.0.1"))
        fid = cur.lastrowid
    db.save_device_metrics(temp_db, "firewall", fid, {"cpu_pct": 11})
    monkeypatch.setattr(fortisensor, "_ssh_run", lambda *a, **k: {
        "execute sensor list": "",
        "get system performance status": PERF_NEW})
    collector.merge_fw_extra(temp_db, {"id": fid, "vendor": "fortigate", "host": "10.0.0.1"},
                             {}, {"username": "a", "password": "b"})
    m = db.get_device_env(temp_db, "firewall", fid)["metrics"]
    assert m["cpu_pct"] == 11, "SNMP 값이 이겨야 한다"
    assert m["mem_pct"] == 33 and m["sessions"] == 4823, "빈 곳은 SSH가 채운다"
    assert m["level"] == "normal"


# --- wallstats 확장 ----------------------------------------------------------

def _fw(p, name, host, status="done"):
    with db.get_db(p) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                           "VALUES (?,?,?,?)", (name, "fortigate", host, status))
        return cur.lastrowid


def test_fw_status_and_policy_and_vpn_rows(temp_db):
    a = _fw(temp_db, "FW-A", "10.0.0.1", "done")
    b = _fw(temp_db, "FW-B", "10.0.0.2", "failed")
    db.save_device_metrics(temp_db, "firewall", a, {
        "policy": {"total": 412, "proxy_total": 31, "unused": 37, "disabled": 9},
        "vpn": {"tunnel_total": 3, "tunnel_up": 2, "tunnels": [
            {"name": "T-UP1", "status": "up", "peer": "203.0.113.5"},
            {"name": "T-UP2", "status": "up", "peer": "203.0.113.6"},
            {"name": "T-DN1", "status": "down", "peer": "203.0.113.9"}]}})
    f = wallstats.build(temp_db)["firewalls"]
    st = {x["name"]: x["status"] for x in f["fw_status_list"]}
    assert st == {"FW-A": "done", "FW-B": "failed"}
    assert f["policy_rows"] == [{"name": "FW-A", "total": 412, "proxy_total": 31,
                                 "unused": 37, "disabled": 9}]
    assert f["policy"]["proxy_total"] == 31
    v = f["vpn_rows"][0]
    assert v["name"] == "FW-A" and v["up"] == ["T-UP1", "T-UP2"]
    assert v["down"] == [{"name": "T-DN1", "peer": "203.0.113.9"}]


def test_unconfigured_fw_absent_from_policy_and_vpn_rows(temp_db):
    """지표 없는 방화벽은 정책·VPN 목록에 나오지 않는다(빈 줄 금지) —
    단 수집 상태 목록에는 나온다(미수집도 상태다)."""
    _fw(temp_db, "FW-EMPTY", "10.0.0.9", "new")
    f = wallstats.build(temp_db)["firewalls"]
    assert f["policy_rows"] == [] and f["vpn_rows"] == []
    assert f["fw_status_list"][0]["name"] == "FW-EMPTY"


def test_facility_offline_by_switch_last7days(temp_db):
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.5", "mac": "aa:01",
         "online": 0, "direct": 1, "switch_name": "TPS-01", "port": "1"},
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.6", "mac": "aa:02",
         "online": 0, "direct": 1, "switch_name": "TPS-02", "port": "2"}])
    for _ in range(3):
        db.save_device_event(temp_db, "device_offline", "warning",
                             subnet="10.1.0.0/24", ip="10.1.0.5")
    db.save_device_event(temp_db, "device_offline", "warning",
                         subnet="10.1.0.0/24", ip="10.1.0.6")
    c = wallstats.build(temp_db)["facility"]
    top = {x["name"]: x["count"] for x in c["offline_by_switch"]}
    assert top == {"TPS-01": 3, "TPS-02": 1}
    assert c["offline_24h"] == 4


# --- v2 화면 (목업 승인본 적용) ----------------------------------------------

def test_stats_carry_ids_for_click_through(temp_db):
    """Top10 클릭→상세 연동에는 스위치 id가 필요하다."""
    sw = db.save_switch(temp_db, "SW-TOP", "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sw)
    db.save_ports(temp_db, snap, sw, [
        {"switch_id": sw, "name": "Gi1/0/1", "status": "connected", "vlan": 1,
         "speed": "1000", "description": ""}])
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.5", "mac": "aa:01",
         "online": 1, "direct": 1, "switch_name": "SW-TOP", "port": "Gi1/0/1"}])
    st = wallstats.build(temp_db)
    assert st["switches"]["top_ports"][0]["id"] == sw
    assert st["facility"]["by_switch"][0]["id"] == sw


def test_devices_list_only_firewalls_with_metrics(temp_db):
    """장비 카드는 지표가 수집된 방화벽만 — 빈 카드 금지(사용자 요구)."""
    a = _fw(temp_db, "FW-A", "10.0.0.1")
    _fw(temp_db, "FW-EMPTY", "10.0.0.9")
    db.save_device_metrics(temp_db, "firewall", a, {
        "cpu_pct": 30, "mem_pct": 50, "version": "v7.2.5",
        "vpn": {"tunnel_total": 2, "tunnel_up": 1, "tunnels": [
            {"name": "T-UP", "status": "up", "peer": "1.1.1.1"},
            {"name": "T-DN", "status": "down", "peer": "2.2.2.2"}]},
        "policy": {"total": 100, "proxy_total": 5}})
    devs = wallstats.build(temp_db)["firewalls"]["devices"]
    assert len(devs) == 1
    d = devs[0]
    assert d["name"] == "FW-A" and d["cpu"] == 30
    assert d["tunnels_down"] == [{"name": "T-DN", "peer": "2.2.2.2"}]
    assert d["tunnels_up"] == ["T-UP"]
    assert d["policy_total"] == 100 and d["proxy_total"] == 5


def test_wall_v2_ui_markers():
    from pathlib import Path
    root = Path(__file__).parent.parent
    js = (root / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    css = (root / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    # Top10 클릭 → 본 화면 상세 딥링크
    assert "data-swid" in js and '"/#switch=" + row.getAttribute' in js
    # 방화벽 장비 카드·수집상태·정책 표
    assert "renderFirewallTab" in js and "fw_status_list" in js and "policy_rows" in js
    assert "tunnels_down" in js, "끊긴 터널 목록을 보여줘야 한다"
    # 새 디자인 클래스
    for cls in (".wrank__no", ".fwc__hd", ".wmeter", ".wkpi__c", ".pulse--bad"):
        assert cls in css, cls
    # 폐쇄망 — 외부 리소스 금지
    assert "cdn." not in css and "https://" not in css


def test_main_page_opens_detail_from_hash():
    """/#switch=<id> 로 열면 본 화면이 해당 스위치 상세를 연다."""
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function _openHashDetail" in js
    assert "#switch=(" in js.replace("\\", "") or "switch=(" in js
    assert "_openHashDetail()" in js, "폴링 후 호출돼야 한다(목록 로드 전이면 재시도)"


# --- v3 방화벽 탭 (사용자 지적 반영: 터널 상시 표시 + 사유 있는 전 장비 표) ----

def test_fw_tab_v3_shows_connected_tunnels_too():
    """'연결'도 모니터링이다 — 끊김이 있을 때만 터널을 보여주면 안 된다."""
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert "downs.length || ups.length" in js, \
        "터널 섹션은 up만 있어도 나와야 한다(예전엔 down 있을 때만)"
    assert "tst--up" in js and "tst--dn" in js, "터널마다 연결/끊김 배지"
    assert "VPN 터널 모니터링" in js
    assert "vgrp__fw" in js, "방화벽별로 묶어 어느 방화벽의 터널인지 보여야 한다"


def test_fw_tab_v3_tables_list_all_firewalls_with_reason():
    """지표 없는 방화벽을 말없이 빼지 않는다 — '왜 안 나오는지'가 줄에 적힌다."""
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert "function whyEmpty" in js
    assert "지표 없음" in js and "미수집" in js
    # 부하·정책 표 모두 전 장비 목록(stList) 기준으로 돈다
    assert js.count("stList.map(function (x)") >= 3, "부하/정책/수집상태 표가 전 장비 기준이어야 한다"


def test_snmp_settings_label_covers_all_uses():
    """커뮤니티 입력란이 '서버 전용'처럼 보여 사용자가 못 찾았다 — 라벨 교정."""
    from pathlib import Path
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "FortiGate 부하" in html and "스위치/방화벽 온도" in html
    assert "SNMP 허용 호스트" in html, "장비 쪽 hosts 등록 안내도 있어야 한다"


def test_snmp_probe_failure_tells_where_community_is(tmp_path, monkeypatch):
    """확인 실패 메시지가 '어디서 고치는지'를 알려줘야 한다."""
    from pathlib import Path
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    assert "⚙설정 → SNMP 커뮤니티" in src
    assert "커뮤니티가 틀리면 오류 없이 무응답" in src
