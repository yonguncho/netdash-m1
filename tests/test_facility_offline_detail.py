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
