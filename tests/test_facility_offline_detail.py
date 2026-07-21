# -*- coding: utf-8 -*-
"""설비 연결 실패 표기 — 포트 미기재 장비의 상황별 상세."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db


def test_wall_facility_detail_variants(tmp_path, monkeypatch):
    """관제 '설비 연결 실패' detail: 직접포트 / 경유 / 포트미확인 / 위치미확인."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()

    db.save_facility_hosts(dbp, [
        {"subnet": "10.0.0.0/24", "ip": "10.0.0.1", "mac": "AA:01",
         "switch_name": "SW-A", "port": "Gi1/0/1", "direct": 1, "online": 0},
        {"subnet": "10.0.0.0/24", "ip": "10.0.0.2", "mac": "AA:02",
         "switch_name": "SW-B", "port": "", "via": "SW-CORE Po1", "direct": 0, "online": 0},
        {"subnet": "10.0.0.0/24", "ip": "10.0.0.3", "mac": "AA:03",
         "switch_name": "SW-C", "port": "", "direct": 1, "online": 0},
        {"subnet": "10.0.0.0/24", "ip": "10.0.0.4", "mac": "AA:04",
         "switch_name": "", "port": "", "online": 0},
    ])
    cats = application.test_client().get("/api/wall").get_json()["categories"]
    fac = [c for c in cats if c["key"] == "facility"][0]["items"]
    by_ip = {i["name"]: i["detail"] for i in fac}
    assert by_ip["10.0.0.1"] == "SW-A · Gi1/0/1"          # 직접 연결
    assert by_ip["10.0.0.2"] == "경유 SW-CORE Po1"          # 경유(via)
    assert by_ip["10.0.0.3"] == "SW-C (포트 미확인)"         # 스위치만 알고 포트 미상
    assert by_ip["10.0.0.4"] == "위치 미확인 · 10.0.0.0/24"  # 아무 매칭 없음
    # 정렬: 직접 포트 확인된 것이 맨 앞(미확인은 뒤)
    assert fac[0]["name"] == "10.0.0.1"
    assert fac[-1]["name"] == "10.0.0.4"


def test_mac_alive_keeps_online_when_arp_missing(temp_db, monkeypatch):
    """ICMP 차단 장비: ARP엔 없어도 MAC 테이블에 살아있으면 online 유지."""
    from core import facility
    # 이전 스캔에서 online이던 설비(MAC BB:AA...)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.5.0.0/24", "ip": "10.5.0.7", "mac": "BB:AA:CC:DD:EE:01",
         "switch_name": "SW-L2", "port": "Gi1/0/7", "direct": 1, "online": 1}])
    # MAC 테이블엔 그 MAC이 여전히 존재(포트 UP)
    monkeypatch.setattr(db, "get_mac_to_switchport",
                        lambda dbp: {"bb:aa:cc:dd:ee:01": [(1, "SW-L2", "Gi1/0/7")]})
    # 이번 스캔은 ping 무응답 → ARP 비어(by_ip 빈 dict)
    facility._apply_scan(temp_db, "10.5.0.0/24", {})
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.5.0.7"]["online"] == 1        # MAC 생존 → online 유지
    # 오프라인 이벤트도 안 생겨야 함
    offs = [e for e in db.list_device_events(temp_db, limit=20)
            if e["kind"] == "device_offline" and e["ip"] == "10.5.0.7"]
    assert not offs


def test_reconcile_online_by_mac(temp_db, monkeypatch):
    """오프라인 설비의 MAC이 스위치 MAC 테이블에 살아있으면 주기 재조정에서 online 복원."""
    from core import facility
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.8.0.0/24", "ip": "10.8.0.9", "mac": "CC:DD:EE:00:00:09",
         "switch_name": "SW", "port": "Gi1/0/9", "direct": 1, "online": 0},
        {"subnet": "10.8.0.0/24", "ip": "10.8.0.10", "mac": "CC:DD:EE:00:00:10",
         "switch_name": "SW", "port": "Gi1/0/10", "direct": 1, "online": 0}])
    # 9번 MAC만 스위치 MAC 테이블에 살아있음
    monkeypatch.setattr(db, "get_mac_to_switchport",
                        lambda dbp: {"cc:dd:ee:00:00:09": [(1, "SW", "Gi1/0/9")]})
    n = facility.reconcile_online_by_mac(temp_db)
    assert n == 1
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.8.0.9"]["online"] == 1     # MAC 살아있음 → 복원
    assert hosts["10.8.0.10"]["online"] == 0    # MAC 없음 → 유지


def test_mac_gone_marks_offline(temp_db, monkeypatch):
    """MAC 테이블에도 없고 ARP에도 없으면 오프라인(정상 감지 유지)."""
    from core import facility
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.5.0.0/24", "ip": "10.5.0.8", "mac": "BB:AA:CC:DD:EE:02",
         "switch_name": "SW-L2", "port": "Gi1/0/8", "direct": 1, "online": 1}])
    monkeypatch.setattr(db, "get_mac_to_switchport", lambda dbp: {})
    facility._apply_scan(temp_db, "10.5.0.0/24", {})
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.5.0.8"]["online"] == 0


def test_offline_event_includes_last_location(tmp_path, monkeypatch):
    """연결 끊김 알람 메시지에 마지막 확인 스위치/포트가 병기된다."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector, facility
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()

    # 온라인 상태로 위치가 확인된 설비 1건 저장
    db.save_facility_hosts(dbp, [
        {"subnet": "10.9.0.0/24", "ip": "10.9.0.5", "mac": "BB:05",
         "switch_name": "SW-EDGE", "port": "Gi1/0/9", "direct": 1, "online": 1}])
    # 이번 스캔에 응답 없음(by_ip 비움) → 오프라인 전이 + 이벤트
    facility._apply_scan(dbp, "10.9.0.0/24", {})
    events = db.list_device_events(dbp, limit=20)
    offs = [e for e in events if e["kind"] == "device_offline" and e["ip"] == "10.9.0.5"]
    assert offs, "device_offline 이벤트가 생성되지 않음"
    assert "SW-EDGE" in offs[0]["message"] and "Gi1/0/9" in offs[0]["message"]
