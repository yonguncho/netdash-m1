# -*- coding: utf-8 -*-
"""상태 감시 폴러 — 포트 DOWN·설비 끊김 10분 감지 (v6.28.0).

사용자 지적: 포트 상태는 하루 2회 수집 때만, 설비 온라인은 하루 1회 스캔 때만
갱신됐다(60초 monitor_known_hosts는 MAC 테이블 기반이라 사실상 수집 주기에 묶임).
"""
from pathlib import Path

from core import db, status_monitor

ROOT = Path(__file__).parent.parent


# --- 포트 상태 기준선 --------------------------------------------------------

def test_port_state_roundtrip(temp_db):
    db.save_port_state(temp_db, 1, {"Gi1/0/1": 1, "Gi1/0/2": 2})
    assert db.get_port_state(temp_db, 1) == {"Gi1/0/1": 1, "Gi1/0/2": 2}
    # 교체 저장 — 사라진 포트는 기준에서도 제거
    db.save_port_state(temp_db, 1, {"Gi1/0/1": 2})
    assert db.get_port_state(temp_db, 1) == {"Gi1/0/1": 2}


def _events(p, kind):
    return [e for e in db.list_device_events(p, limit=100) if e["kind"] == kind]


def test_port_down_transition_fires_event(temp_db, monkeypatch):
    sw = db.save_switch(temp_db, "SW-A", "10.0.0.1", "cisco_ios")
    walks = [{"Gi1/0/1": 1, "Gi1/0/2": 1},     # 1주기: 기준선
             {"Gi1/0/1": 2, "Gi1/0/2": 1},     # 2주기: 1포트 다운
             {"Gi1/0/1": 1, "Gi1/0/2": 1}]     # 3주기: 복구
    it = iter(walks)
    monkeypatch.setattr(status_monitor, "_walk_oper_status",
                        lambda ip, c, budget=10.0: next(it))
    assert status_monitor.check_ports(temp_db, "public") == (0, 0)  # 기준선만
    assert status_monitor.check_ports(temp_db, "public") == (1, 0)
    ev = _events(temp_db, "port_down")
    assert len(ev) == 1 and "Gi1/0/1" in ev[0]["message"] and "SW-A" in ev[0]["message"]
    assert status_monitor.check_ports(temp_db, "public") == (0, 1)
    assert len(_events(temp_db, "port_up")) == 1
    assert sw


def test_first_observation_never_alarms(temp_db, monkeypatch):
    """재기동·신규 스위치 첫 관측은 기준만 잡는다 — 재기동 때마다 알람 금지."""
    db.save_switch(temp_db, "SW-B", "10.0.0.2", "cisco_ios")
    monkeypatch.setattr(status_monitor, "_walk_oper_status",
                        lambda ip, c, budget=10.0: {"Gi1/0/1": 2})   # 처음부터 down
    assert status_monitor.check_ports(temp_db, "public") == (0, 0)
    assert _events(temp_db, "port_down") == []


def test_snmp_dead_switch_skipped(temp_db, monkeypatch):
    """SNMP 미지원 스위치는 조용히 건너뛰고 나머지는 계속."""
    db.save_switch(temp_db, "SW-DEAD", "10.0.0.3", "cisco_ios")
    db.save_switch(temp_db, "SW-OK", "10.0.0.4", "cisco_ios")

    def walk(ip, c, budget=10.0):
        if ip == "10.0.0.3":
            raise RuntimeError("no snmp")
        return {"Gi1/0/1": 1}
    monkeypatch.setattr(status_monitor, "_walk_oper_status", walk)
    status_monitor.check_ports(temp_db, "public")
    assert db.get_port_state(temp_db, 2) == {"Gi1/0/1": 1}


def test_logical_ports_filtered():
    assert status_monitor._is_physical("Gi1/0/1")
    assert status_monitor._is_physical("Ethernet1/24")
    for bad in ("Vlan100", "Po124", "Loopback0", "Tunnel1", "Null0", ""):
        assert not status_monitor._is_physical(bad), bad


# --- 설비 직접 ping ----------------------------------------------------------

def _seed_fac(p):
    db.save_facility_hosts(p, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.%d" % i, "mac": "aa:%02x" % i,
         "online": 1, "direct": 1, "switch_name": "SW", "port": "Gi1/0/%d" % i}
        for i in range(2, 7)])


def test_facility_debounce_two_misses(temp_db, monkeypatch):
    """무응답 1회로는 안 끊는다 — 2회(2주기) 연속이어야 확정."""
    _seed_fac(temp_db)
    status_monitor._miss.clear()
    monkeypatch.setattr(status_monitor, "_ping",
                        lambda ip, timeout_ms=1000: ip != "10.1.0.3")
    d, r, s = status_monitor.check_facility(temp_db)
    assert (d, r) == (0, 0), "1회차는 디바운스"
    d, r, s = status_monitor.check_facility(temp_db)
    assert (d, r) == (1, 0), "2회차에 확정"
    h = [x for x in db.get_facility_hosts(temp_db) if x["ip"] == "10.1.0.3"][0]
    assert h["online"] == 0
    ev = _events(temp_db, "device_offline")
    assert len(ev) == 1 and "10.1.0.3" in ev[0]["message"]


def test_facility_recovery_immediate(temp_db, monkeypatch):
    _seed_fac(temp_db)
    db.set_facility_online(temp_db, "10.1.0.0/24", "10.1.0.4", False)
    status_monitor._miss.clear()
    monkeypatch.setattr(status_monitor, "_ping", lambda ip, timeout_ms=1000: True)
    d, r, s = status_monitor.check_facility(temp_db)
    assert (d, r) == (0, 1)
    assert len(_events(temp_db, "device_online")) == 1


def test_band_unreachable_guard(temp_db, monkeypatch):
    """온라인이던 대역이 통째로 무응답 = PC 라우팅 불가 — 무더기 허위 알람 금지."""
    _seed_fac(temp_db)
    status_monitor._miss.clear()
    monkeypatch.setattr(status_monitor, "_ping", lambda ip, timeout_ms=1000: False)
    for _ in range(3):                    # 디바운스를 넘겨도
        d, r, s = status_monitor.check_facility(temp_db)
        assert d == 0 and s == 1, "대역 전멸은 끊김이 아니라 스킵"
    assert _events(temp_db, "device_offline") == []


def test_already_offline_not_realarmed(temp_db, monkeypatch):
    _seed_fac(temp_db)
    db.set_facility_online(temp_db, "10.1.0.0/24", "10.1.0.5", False)
    status_monitor._miss.clear()
    monkeypatch.setattr(status_monitor, "_ping",
                        lambda ip, timeout_ms=1000: ip != "10.1.0.5")
    for _ in range(3):
        status_monitor.check_facility(temp_db)
    assert _events(temp_db, "device_offline") == []


# --- 설정·연동 ----------------------------------------------------------------

def test_poll_minutes_setting(temp_db):
    assert status_monitor.poll_minutes(temp_db) == 10
    db.set_setting(temp_db, "status_poll_minutes", "0")
    assert status_monitor.poll_minutes(temp_db) == 0


def test_poll_once_survives_both_failures(temp_db, monkeypatch):
    """포트·설비 어느 쪽이 죽어도 폴러는 예외를 올리지 않는다."""
    monkeypatch.setattr(status_monitor, "check_ports",
                        lambda *a: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(status_monitor, "check_facility",
                        lambda *a: (_ for _ in ()).throw(RuntimeError("y")))
    from core import collector
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    assert status_monitor.poll_once(temp_db) == (0, 0, 0, 0, 0)


def test_wall_ticker_maps_port_events():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert "port_down" in js and "포트 다운" in js and "port_up" in js


def test_settings_expose_status_interval():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="ac-status-minutes"' in html
    assert "status_poll_minutes" in js


# --- 관제 방화벽 탭 v4 (사용자 지적: HA 일관성·라이선스 통합·커스터마이즈) -----

def test_devices_ha_fallback_rest_and_vip(temp_db):
    """SNMP가 HA를 안 줘도 REST ha_info 또는 VIP 공유로 이중화를 표기한다."""
    from core import wallstats
    import json
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status, ha_info) "
                     "VALUES ('FW-R','fortigate','10.0.0.1','done',?)",
                     (json.dumps({"mode": "a-p", "hbdev": []}),))
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-V1','fortigate','10.0.0.2','done')")
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-V2','fortigate','10.0.0.2','done')")
    for f in db.list_firewalls(temp_db):
        db.save_device_metrics(temp_db, "firewall", f["id"], {"cpu_pct": 10})
    devs = {d["name"]: d for d in wallstats.build(temp_db)["firewalls"]["devices"]}
    assert devs["FW-R"]["ha"] == "a-p", "REST ha_info 폴백"
    assert devs["FW-V1"]["ha"] == "이중화(VIP 공유)", "VIP 쌍 폴백"
    assert devs["FW-V2"]["ha"] == "이중화(VIP 공유)"


def test_devices_carry_license_with_levels(temp_db):
    from core import wallstats
    import datetime
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-L','fortigate','10.0.0.9','done')")
    fid = db.list_firewalls(temp_db)[-1]["id"]
    db.save_device_metrics(temp_db, "firewall", fid, {
        "cpu_pct": 5,
        "license": [{"key": "ips", "name": "IPS", "status": "expired",
                     "expires": (datetime.date.today()
                                 - datetime.timedelta(days=3)).isoformat()}]})
    d = wallstats.build(temp_db)["firewalls"]["devices"][-1]
    assert d["license"][0]["level"] == "expired"


def test_wall_v4_ui_markers():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    # 라이선스 별도 카드 제거(장비 카드로 통합)
    assert "h3>라이선스" not in js
    assert "라이선스" in js                       # 카드 fact 행으로는 존재
    # 장비 선택 칩 + MEM 추이 + 위젯 편집
    assert "data-fwdev" in js and "ch-fw-mem" in js
    assert "function applyLayout" in js and "wall_layout_v1" in js
    assert "wall-edit-btn" in js
    # 여백 정리(카드가 행 높이로 늘어나지 않게)
    assert "align-items:start" in css
    assert ".wchip" in css and ".wtool" in css
