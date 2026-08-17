# -*- coding: utf-8 -*-
"""v6.40.0 — 설비 연결 이력 타임라인 (사용자 요청).

"설비가 연결됐다 끊기고 또 연결되면 그 히스토리를 알고 싶다. 진단 결과에서
과거 연결 시점을 하나씩 찾는 건 번거롭다 — 타임테이블로 관제·설비 현황
양쪽에서 설비를 클릭하면 파악되게."
"""
import datetime as dt
import os
import tempfile

import pytest

from core import db, wallstats


@pytest.fixture()
def dbf():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def _fac(dbf, ip, online):
    db.save_facility_hosts(dbf, [{"subnet": "10.1.0.0/24", "ip": ip, "mac": "aa:01",
                                  "switch_name": "SW1", "port": "Gi1/0/3",
                                  "online": online}])


def _ev(dbf, ip, days_ago, kind):
    with db.get_db(dbf) as conn:
        conn.execute(
            "INSERT INTO device_events (ts, kind, ip, severity) "
            "VALUES (datetime('now','localtime',?),?,?, 'info')",
            ("-%d days" % days_ago, kind, ip))
        conn.commit()


def _states(h):
    return [s["state"] for s in h["segments"]]


# ── 구간 계산 ─────────────────────────────────────────────────────

def test_segments_follow_events(dbf):
    """연결 → 끊김 → 재연결 → 끊김이 그대로 구간이 된다."""
    _fac(dbf, "10.1.0.7", 0)
    for d, k in ((20, "device_online"), (12, "device_offline"),
                 (8, "device_online"), (3, "device_offline")):
        _ev(dbf, "10.1.0.7", d, k)
    h = wallstats.facility_history(dbf, "10.1.0.7", days=30)
    assert _states(h) == ["unknown", "online", "offline", "online", "offline"]
    assert h["flaps"] == 2                     # 끊김 2회
    assert h["now_online"] is False


def test_first_segment_is_unknown_not_guessed(dbf):
    """첫 이벤트 이전은 관측이 없다 — 모르는 걸 '연결'로 칠하면 거짓말이 된다."""
    _fac(dbf, "10.1.0.8", 1)
    _ev(dbf, "10.1.0.8", 5, "device_online")
    h = wallstats.facility_history(dbf, "10.1.0.8", days=30)
    assert h["segments"][0]["state"] == "unknown"
    assert h["segments"][-1]["state"] == "online"


def test_no_events_uses_current_state(dbf):
    """이벤트가 없다 = 이 기간에 변화가 없었다는 뜻이다(빈 화면이 아니라)."""
    _fac(dbf, "10.1.0.9", 1)
    h = wallstats.facility_history(dbf, "10.1.0.9", days=7)
    assert _states(h) == ["online"]
    assert h["events"] == [] and h["flaps"] == 0


def test_offline_minutes_accumulates(dbf):
    _fac(dbf, "10.1.0.10", 0)
    _ev(dbf, "10.1.0.10", 10, "device_online")
    _ev(dbf, "10.1.0.10", 8, "device_offline")     # 8일 전부터 지금까지 끊김
    h = wallstats.facility_history(dbf, "10.1.0.10", days=30)
    # 대략 8일(오차 허용) — 분 단위 반올림 때문에 정확히 같지 않을 수 있다
    assert 7 * 1440 <= h["offline_minutes"] <= 9 * 1440


def test_events_are_newest_first(dbf):
    """목록은 최신이 위 — 방금 무슨 일이 있었는지가 먼저 보여야 한다."""
    _fac(dbf, "10.1.0.11", 0)
    _ev(dbf, "10.1.0.11", 9, "device_online")
    _ev(dbf, "10.1.0.11", 2, "device_offline")
    h = wallstats.facility_history(dbf, "10.1.0.11", days=30)
    assert h["events"][0]["online"] is False       # 최근 = 끊김
    assert h["events"][-1]["online"] is True


def test_window_excludes_older_events(dbf):
    _fac(dbf, "10.1.0.12", 1)
    _ev(dbf, "10.1.0.12", 40, "device_offline")    # 조회 창 밖
    _ev(dbf, "10.1.0.12", 2, "device_online")
    h = wallstats.facility_history(dbf, "10.1.0.12", days=7)
    assert len(h["events"]) == 1 and h["events"][0]["online"] is True


def test_other_ip_events_are_not_mixed(dbf):
    _fac(dbf, "10.1.0.13", 0)
    _ev(dbf, "10.1.0.13", 3, "device_offline")
    _ev(dbf, "10.9.9.9", 3, "device_offline")      # 다른 설비
    h = wallstats.facility_history(dbf, "10.1.0.13", days=30)
    assert len(h["events"]) == 1


def test_unknown_ip_is_not_an_error(dbf):
    h = wallstats.facility_history(dbf, "10.99.99.99", days=30)
    assert h["events"] == [] and h["now_online"] is None


def test_switch_and_port_are_included(dbf):
    """이력만 보여주면 '어디 꽂힌 건지'를 다시 찾아야 한다."""
    _fac(dbf, "10.1.0.14", 0)
    h = wallstats.facility_history(dbf, "10.1.0.14", days=30)
    assert h["switch_name"] == "SW1" and h["port"] == "Gi1/0/3"


# ── 화면 배선 ─────────────────────────────────────────────────────

def _read(*parts):
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), *parts)
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_api_route_exists():
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod)
    assert '"/api/facility/history"' in src
    assert "facility_history(db_path, ip, days=days)" in src


def test_wall_js_history_from_zone_popup():
    js = _read("web", "static", "wall.js")
    assert "function openFacHistory(" in js
    assert "data-fachist='" in js and "[data-fachist]" in js
    assert "/api/facility/history?ip=" in js
    assert "hist-back" in js, "구역 목록으로 돌아갈 수 있어야 한다"


def test_app_js_history_in_facility_diagnose():
    js = _read("web", "static", "app.js")
    assert "function loadFacilityHistory(" in js
    assert "loadFacilityHistory(ip)" in js
    html = _read("web", "templates", "index.html")
    assert 'id="diag-history"' in html


def test_history_box_hidden_for_other_diagnoses():
    """설비 이력이 스위치·방화벽 진단 팝업에 남아 붙으면 안 된다."""
    js = _read("web", "static", "app.js")
    for fn in ("function diagnoseSwitch(", "function diagnoseFirewall("):
        i = js.index(fn)
        blk = js[i:i + 700]
        assert "diag-history" in blk, "%s 에서 이력 영역을 숨기지 않는다" % fn


# ── 관제 설비 탭: 연결 실패 설비 목록 (v6.40.1) ───────────────────
# 사용자 요청: 요약·장애 탭에만 있던 '끊긴 설비' 목록이 설비 탭에도 있어야 한다.
# 현재 끊긴 설비 / 연결 스위치·포트 / 끊긴 시점.

def _offline_list(dbf):
    return wallstats.build(dbf)["facility"]


def test_offline_hosts_listed_with_switch_and_port(dbf):
    _fac(dbf, "10.1.0.20", 0)
    f = _offline_list(dbf)
    assert f["offline_hosts_total"] == 1
    h = f["offline_hosts"][0]
    assert h["ip"] == "10.1.0.20"
    assert h["switch_name"] == "SW1" and h["port"] == "Gi1/0/3"


def test_offline_hosts_include_disconnect_time(dbf):
    _fac(dbf, "10.1.0.21", 0)
    _ev(dbf, "10.1.0.21", 2, "device_offline")
    h = _offline_list(dbf)["offline_hosts"][0]
    assert h["since"], "끊긴 시점이 비었다"
    assert h["minutes"] is not None and h["minutes"] > 0


def test_offline_hosts_without_event_say_so(dbf):
    """끊긴 시각을 모르면 비워 둔다 — 마지막 수집 시각을 쓰면 거짓이 된다
    (수집만 돌아도 값이 바뀐다)."""
    _fac(dbf, "10.1.0.22", 0)
    h = _offline_list(dbf)["offline_hosts"][0]
    assert h["since"] == "" and h["minutes"] is None


def test_offline_hosts_sorted_recent_first(dbf):
    """방금 생긴 장애가 먼저 보여야 한다. 시각 모르는 건 맨 뒤."""
    _fac(dbf, "10.1.0.30", 0)
    _fac(dbf, "10.1.0.31", 0)
    _fac(dbf, "10.1.0.32", 0)
    _ev(dbf, "10.1.0.30", 5, "device_offline")
    _ev(dbf, "10.1.0.31", 1, "device_offline")
    ips = [h["ip"] for h in _offline_list(dbf)["offline_hosts"]]
    assert ips == ["10.1.0.31", "10.1.0.30", "10.1.0.32"], ips


def test_online_hosts_are_excluded(dbf):
    _fac(dbf, "10.1.0.40", 1)
    assert _offline_list(dbf)["offline_hosts"] == []


def test_offline_hosts_carry_zone(dbf):
    """구역까지 있어야 목록에서 바로 '어디로 가야 하나'가 보인다."""
    with db.get_db(dbf) as conn:
        db.save_switch(dbf, "SW1", "10.9.9.1", "cisco_ios")
        conn.execute("UPDATE switches SET hostname=? WHERE name='SW1'",
                     ("TPS-F1B02_1F01_FA_SW1",))
        conn.commit()
    _fac(dbf, "10.1.0.50", 0)
    h = _offline_list(dbf)["offline_hosts"][0]
    assert h["zone"] == "1공장 Assembly(B02) 1층 TPS01", h["zone"]


def test_wall_js_renders_offline_hosts_card():
    js = _read("web", "static", "wall.js")
    assert "function offlineHostsCard(" in js
    assert "offlineHostsCard(c.offline_hosts" in js
    assert "연결 실패 설비" in js
    assert "끊긴 시점" in js
    # 목록 행에서 바로 이력으로 — 같은 진입점을 재사용한다
    assert "data-fachist='" in js
