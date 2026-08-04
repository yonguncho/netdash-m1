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
