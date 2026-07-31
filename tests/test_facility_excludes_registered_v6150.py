"""등록된 스위치·방화벽·서버는 설비 현황에서 제외 (v6.15.0).

사용자 신고: 10.92.140.0/22를 수집하면 그 대역 안에 있는 TPS 스위치
10.92.140.13 자신이 '설비'로 잡힌다. BB의 MAC 테이블에서 이 스위치 MAC은
Po124(업링크)에 보이므로 '직접 연결 미확인 / BB Po 경유로만 관측'으로 뜬다.
설비 기준으로는 옳은 판정인데 **대상이 설비가 아니다** — 스위치는 스위치 현황에
따로 있다.

화면(설비·관제·엑셀)에서 거르면 세 곳을 챙겨야 하므로 **저장 경계**에서 막는다.
"""
from core import db, facility


def _reg(p):
    """TPS 스위치 + 방화벽 + 서버를 등록한 상태."""
    sw = db.save_switch(p, "SKBA_F1_TPS_01", "10.92.140.13", "cisco_ios")
    with db.get_db(p) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                     ("FW-01", "fortigate", "10.92.140.20"))
        conn.execute("INSERT INTO servers (name, ip) VALUES (?,?)",
                     ("SRV-01", "10.92.140.30"))
    return sw


_SCAN = [
    {"subnet": "10.92.140.0/22", "ip": "10.92.140.13", "mac": "aa:bb:cc:00:00:13",
     "online": 1, "direct": 0, "switch_name": "BB", "port": "Po124"},   # 등록 스위치
    {"subnet": "10.92.140.0/22", "ip": "10.92.140.20", "mac": "aa:bb:cc:00:00:20",
     "online": 1, "direct": 1},                                          # 등록 방화벽
    {"subnet": "10.92.140.0/22", "ip": "10.92.140.30", "mac": "aa:bb:cc:00:00:30",
     "online": 1, "direct": 1},                                          # 등록 서버
    {"subnet": "10.92.140.0/22", "ip": "10.92.140.88", "mac": "aa:bb:cc:00:00:88",
     "online": 0, "direct": 0},                                          # 진짜 설비
]


def test_save_skips_registered_devices(temp_db):
    _reg(temp_db)
    db.save_facility_hosts(temp_db, _SCAN)
    ips = {h["ip"] for h in db.get_facility_hosts(temp_db)}
    assert ips == {"10.92.140.88"}, "등록 장비가 설비로 저장되면 안 된다"


def test_replace_subnet_skips_registered_devices(temp_db):
    """쓰기 구현이 둘이라 양쪽 다 막혀 있어야 한다."""
    _reg(temp_db)
    db.replace_facility_subnet(temp_db, "10.92.140.0/22", _SCAN)
    ips = {h["ip"] for h in db.get_facility_hosts(temp_db)}
    assert ips == {"10.92.140.88"}


def test_unregistered_hosts_are_kept(temp_db):
    """등록 장비가 하나도 없으면 아무것도 걸러지지 않는다(회귀 방지)."""
    db.save_facility_hosts(temp_db, _SCAN)
    assert len(db.get_facility_hosts(temp_db)) == 4


def test_purge_removes_previously_saved_rows(temp_db):
    """예전 스캔으로 이미 저장된 등록 장비 행도 걷어낸다."""
    db.save_facility_hosts(temp_db, _SCAN)      # 등록 전이라 4건 모두 저장됨
    assert len(db.get_facility_hosts(temp_db)) == 4
    _reg(temp_db)                                # 이제 3건이 등록 장비
    assert db.purge_registered_devices_from_facility(temp_db) == 3
    assert {h["ip"] for h in db.get_facility_hosts(temp_db)} == {"10.92.140.88"}


def test_rematch_purges_registered_devices(temp_db):
    """사용자가 누르는 '새로고침'에서 정리된다 — 재수집을 강요하지 않는다."""
    db.save_facility_hosts(temp_db, _SCAN)
    _reg(temp_db)
    facility.rematch(temp_db)
    assert {h["ip"] for h in db.get_facility_hosts(temp_db)} == {"10.92.140.88"}


def test_registered_device_ips_covers_all_three_pages(temp_db):
    _reg(temp_db)
    ips = db.registered_device_ips(temp_db)
    assert {"10.92.140.13", "10.92.140.20", "10.92.140.30"} <= ips


def test_purge_with_no_registered_devices_is_noop(temp_db):
    db.save_facility_hosts(temp_db, _SCAN)
    assert db.purge_registered_devices_from_facility(temp_db) == 0
    assert len(db.get_facility_hosts(temp_db)) == 4


def test_rematch_endpoint_reports_excluded_count(tmp_path, monkeypatch):
    """화면이 '몇 건 제외됐는지' 알 수 있어야 한다 — 조용히 사라지면 오해한다."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()

    db.save_facility_hosts(dbp, _SCAN)
    _reg(dbp)
    res = application.test_client().post("/api/facility/rematch").get_json()
    assert res["ok"] is True and res["excluded"] == 3


def test_ui_explains_exclusion():
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "등록 장비 " in js and "제외" in js
