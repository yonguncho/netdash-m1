# -*- coding: utf-8 -*-
"""설비 '연결 끊김 + 연결된 스위치 없음' 오탐 — 원인 2건의 회귀 테스트.

증상: 스위치는 정상 수집(status=done)됐는데 관제에서 설비가 연결 끊김으로 뜨고
      설비 상세의 '연결 스위치'가 비어 있다.

원인 ① MAC 명령만 실패한 수집이 MAC 0건 스냅샷을 새로 만들면, 그 스냅샷이
       '최신'이 되면서 그 스위치의 MAC 매핑이 통째로 사라진다
       → 뒤에 붙은 설비가 전부 'MAC 실종'으로 오프라인 처리된다.
원인 ② 연결 스위치/포트는 대역 스캔 때만 계산돼, 스캔 시점에 스위치가 아직
       수집 전이면 이후 스위치를 수집해도 영영 빈칸으로 남는다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility

MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"


def _collect(temp_db, switch_id, macs, ports=None):
    """수집 1회 = 스냅샷 1개. macs=[] 면 'MAC 명령만 실패한 수집'을 흉내낸다."""
    snap = db.save_snapshot(temp_db, switch_id)
    db.save_ports(temp_db, snap, switch_id, ports or [
        {"name": "Gi1/0/1", "status": "connected", "vlan": "10", "description": ""}])
    db.save_mac_entries(temp_db, snap, switch_id, macs)
    return snap


MAC_OTHER = "aa:bb:cc:99:99:99"


@pytest.fixture
def wired(temp_db):
    """스위치 2대 + 1번 스위치 액세스 포트에 설비 1대가 붙어 있는 상태.

    두 번째 스위치를 반드시 둔다 — 실환경은 스위치가 여러 대다. 1대뿐이면
    MAC이 0건일 때 mac_alive가 통째로 비어 monitor_known_hosts의
    '수집 전이면 판단 보류' 가드에 걸려, 정작 재현하려는 버그가 가려진다.
    """
    sid = db.save_switch(temp_db, "ACC-SW-01", "10.0.5.1", "cisco_ios")
    db.set_switch_status(temp_db, sid, "done")
    _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_A, "port": "Gi1/0/1"}])

    other = db.save_switch(temp_db, "ACC-SW-99", "10.0.5.99", "cisco_ios")
    db.set_switch_status(temp_db, other, "done")
    _collect(temp_db, other, [{"vlan": "20", "mac": MAC_OTHER, "port": "Gi1/0/1"}])

    db.save_facility_hosts(temp_db, [{
        "subnet": "10.0.9.0/24", "ip": "10.0.9.10", "mac": MAC_A,
        "switch_id": sid, "switch_name": "ACC-SW-01", "port": "Gi1/0/1",
        "online": 1, "direct": 1, "via": None, "port_desc": None}])
    facility._miss_counts.clear()
    return temp_db, sid


# ── 원인 ① MAC 0건 스냅샷이 매핑을 지우던 문제 ────────────────────
def test_empty_mac_snapshot_does_not_wipe_mapping(wired):
    temp_db, sid = wired
    assert MAC_A in db.get_mac_to_switchport(temp_db)

    # MAC 명령만 실패한 재수집(포트는 정상, MAC 0건) — 수집 자체는 성공 처리된다
    _collect(temp_db, sid, [])
    db.set_switch_status(temp_db, sid, "done")

    mapping = db.get_mac_to_switchport(temp_db)
    assert MAC_A in mapping, "MAC 0건 스냅샷 하나에 그 스위치의 MAC 매핑이 통째로 사라졌다"
    assert mapping[MAC_A][0][1] == "ACC-SW-01"


def test_port_mac_counts_use_same_snapshot_basis(wired):
    """매칭과 포트 MAC 수의 기준이 어긋나면 직접연결 판정이 뒤틀린다."""
    temp_db, sid = wired
    _collect(temp_db, sid, [])
    counts = db.get_port_mac_counts(temp_db)
    assert counts.get((sid, "gi1/0/1")) == 1, counts


def test_facility_not_marked_offline_by_empty_mac_collection(wired):
    """이 버그의 실제 증상 — 스위치는 정상인데 설비가 연결 끊김으로 바뀌던 것."""
    temp_db, sid = wired
    _collect(temp_db, sid, [])          # MAC 명령만 실패한 수집

    # 감시 주기를 디바운스 임계치 이상 돌려도 오프라인이 되면 안 된다
    for _ in range(facility._MISS_THRESHOLD + 1):
        facility.monitor_known_hosts(temp_db)

    h = db.get_facility_hosts(temp_db)[0]
    assert h["online"] == 1, "MAC 명령 실패만으로 설비가 '연결 끊김'이 됐다"
    assert h["switch_name"] == "ACC-SW-01"


def test_real_disconnect_still_detected(wired):
    """폴백 때문에 진짜 끊김을 놓치면 안 된다 — MAC이 담긴 정상 수집에서 사라지면 오프라인.

    디바운스 기준이 '감시 주기 횟수'가 아니라 '서로 다른 MAC 스냅샷'이므로,
    실제 재수집(새 스냅샷)을 임계치만큼 반복해야 끊김으로 판정된다.
    """
    temp_db, sid = wired
    for _ in range(facility._MISS_THRESHOLD):
        # 다른 설비 MAC은 학습됐고 우리 설비 MAC만 사라진 '정상 수집'
        _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_B, "port": "Gi1/0/2"}])
        facility.monitor_known_hosts(temp_db)

    h = db.get_facility_hosts(temp_db)[0]
    assert h["online"] == 0, "실제 연결 끊김을 감지하지 못했다"


def test_debounce_still_applies(wired):
    """새 스냅샷 1회 실종으로는 끊김 처리하지 않는다."""
    temp_db, sid = wired
    _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_B, "port": "Gi1/0/2"}])
    facility.monitor_known_hosts(temp_db)
    assert db.get_facility_hosts(temp_db)[0]["online"] == 1


def test_same_snapshot_repeated_does_not_count(wired):
    """같은 MAC 스냅샷을 여러 번 본 것은 새 근거가 아니다(조용한 설비 오탐 방지)."""
    temp_db, sid = wired
    _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_B, "port": "Gi1/0/2"}])
    for _ in range(6):
        facility.monitor_known_hosts(temp_db)
    assert db.get_facility_hosts(temp_db)[0]["online"] == 1, \
        "스냅샷이 그대로인데 감시 주기만으로 끊김 처리됐다"


# ── 원인 ② 연결 스위치가 스캔 때만 계산되던 문제 ──────────────────
def test_switch_link_filled_after_switch_is_collected(temp_db):
    """설비를 먼저 스캔하고 스위치를 나중에 수집한 순서 — 실제로 흔한 순서다."""
    # 설비 스캔 시점: 스위치가 아직 수집 전이라 연결 스위치를 못 찾음
    sid = db.save_switch(temp_db, "ACC-SW-02", "10.0.5.2", "cisco_ios")
    db.save_facility_hosts(temp_db, [{
        "subnet": "10.0.9.0/24", "ip": "10.0.9.20", "mac": MAC_A,
        "switch_id": None, "switch_name": None, "port": None,
        "online": 1, "direct": 0, "via": None, "port_desc": None}])
    facility._miss_counts.clear()

    # 뒤늦게 스위치 수집 → MAC 테이블 확보
    _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_A, "port": "Gi1/0/5"}],
             ports=[{"name": "Gi1/0/5", "status": "connected", "vlan": "10",
                     "description": "PLC-01"}])
    db.set_switch_status(temp_db, sid, "done")

    facility.monitor_known_hosts(temp_db)

    h = db.get_facility_hosts(temp_db)[0]
    assert h["switch_name"] == "ACC-SW-02", \
        "스위치를 수집했는데도 설비의 연결 스위치가 비어 있다(재스캔 전까지 안 채워짐)"
    assert h["port"] == "Gi1/0/5"
    assert h["direct"] == 1
    assert h["port_desc"] == "PLC-01"


def test_switch_link_follows_port_move(wired):
    """설비가 다른 포트로 옮겨가면 감시에서 위치가 갱신된다."""
    temp_db, sid = wired
    _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_A, "port": "Gi1/0/9"}],
             ports=[{"name": "Gi1/0/9", "status": "connected", "vlan": "10",
                     "description": ""}])
    facility.monitor_known_hosts(temp_db)
    assert db.get_facility_hosts(temp_db)[0]["port"] == "Gi1/0/9"


def test_relink_does_not_flip_online_state(temp_db):
    """연결 스위치를 채우는 것과 온라인 판정은 별개 — 오프라인 설비를 멋대로 켜지 않는다."""
    sid = db.save_switch(temp_db, "ACC-SW-03", "10.0.5.3", "cisco_ios")
    _collect(temp_db, sid, [{"vlan": "10", "mac": MAC_B, "port": "Gi1/0/1"}])
    db.save_facility_hosts(temp_db, [{
        "subnet": "10.0.9.0/24", "ip": "10.0.9.30", "mac": MAC_A,
        "switch_id": None, "switch_name": None, "port": None,
        "online": 0, "direct": 0, "via": None, "port_desc": None}])
    facility._miss_counts.clear()
    facility.monitor_known_hosts(temp_db)
    h = db.get_facility_hosts(temp_db)[0]
    assert h["online"] == 0            # MAC이 없으니 계속 오프라인
    assert not h["switch_name"]        # 연결 스위치도 여전히 미확인


def test_monitor_skips_while_band_scan_running(wired, monkeypatch):
    """대역 스캔 중에는 감시가 개입하지 않는다(스캔이 곧 정확히 갱신)."""
    temp_db, sid = wired
    monkeypatch.setattr(facility, "get_status", lambda: {"running": True})
    assert facility.monitor_known_hosts(temp_db) == (0, 0)


# ── 수집기: MAC 빈 출력 경고 ──────────────────────────────────────
def test_collector_warns_on_empty_mac_output():
    src = (Path(__file__).parent.parent / "core" / "collector.py").read_text(encoding="utf-8")
    assert "mac_table_empty_keeping_previous" in src, \
        "MAC 명령 실패가 조용히 지나가면 원인 추적이 불가능하다"
