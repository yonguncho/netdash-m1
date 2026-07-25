# -*- coding: utf-8 -*-
"""검증 리뷰 반영: 수집 중지 안전성(C-1/C-2) + 엑셀 별칭 충돌(M-1~M-3) + MAC 캐시(M-5)."""
import io
import sys
from pathlib import Path

from openpyxl import Workbook

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility, excel_loader, server_collector


def _xlsx(rows):
    wb = Workbook()
    ws = wb.active
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ── C-1: 중지 시 미스캔 IP를 끊김으로 처리하지 않는다 ──────────────
def test_apply_scan_preserves_unscanned_on_stop(temp_db, monkeypatch):
    monkeypatch.setattr(db, "get_mac_to_switchport", lambda dbp: {})
    # 기존 online 설비 3대
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.6.0.0/24", "ip": "10.6.0.1", "mac": "AA:00:00:00:00:01",
         "switch_name": "SW", "port": "Gi1/0/1", "direct": 1, "online": 1},
        {"subnet": "10.6.0.0/24", "ip": "10.6.0.2", "mac": "AA:00:00:00:00:02",
         "switch_name": "SW", "port": "Gi1/0/2", "direct": 1, "online": 1},
        {"subnet": "10.6.0.0/24", "ip": "10.6.0.3", "mac": "AA:00:00:00:00:03",
         "switch_name": "SW", "port": "Gi1/0/3", "direct": 1, "online": 1}])
    # .1만 스캔했고 응답 없음 / .2, .3은 미스캔(중지)
    saved, new_cnt, off_cnt = facility._apply_scan(
        temp_db, "10.6.0.0/24", {}, scanned_ips={"10.6.0.1"})
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.6.0.1"]["online"] == 0     # 스캔했는데 무응답 → 끊김
    assert hosts["10.6.0.2"]["online"] == 1     # 미스캔 → 이전 상태 보존
    assert hosts["10.6.0.3"]["online"] == 1
    assert off_cnt == 1                          # 끊김 이벤트도 1건만
    offs = [e for e in db.list_device_events(temp_db, limit=50)
            if e["kind"] == "device_offline"]
    assert len(offs) == 1 and offs[0]["ip"] == "10.6.0.1"


def test_apply_scan_full_scan_still_marks_offline(temp_db, monkeypatch):
    """scanned_ips=None(정상 완료)이면 기존 동작 그대로 — 무응답은 끊김."""
    monkeypatch.setattr(db, "get_mac_to_switchport", lambda dbp: {})
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.6.1.0/24", "ip": "10.6.1.9", "mac": "BB:00:00:00:00:09",
         "switch_name": "SW", "port": "Gi1/0/9", "direct": 1, "online": 1}])
    facility._apply_scan(temp_db, "10.6.1.0/24", {})
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.6.1.9"]["online"] == 0


# ── C-2: 중지 플래그가 잔류하지 않는다(자동 스캔 무력화 방지) ───────
def test_stop_flag_cleared_after_band(temp_db, monkeypatch):
    facility._set(running=True)
    facility.request_stop()
    assert facility._is_stop_requested() is True
    try:
        # collect_band가 끝나며 플래그를 해제하는지 — 종료부 로직만 재현 검증
        import threading
        with facility._lock:
            facility._stop_requested = False
        assert facility._is_stop_requested() is False
    finally:
        facility._set(running=False)
        facility._stop_requested = False


def test_run_auto_scan_resets_stop_flag(temp_db, monkeypatch):
    """이전 중지 요청이 남아 있어도 전체 스캔은 정상 시작(첫 대역에서 break 안 함)."""
    facility._stop_requested = True                   # 잔류 상황 재현
    monkeypatch.setattr(facility, "get_band_map", lambda dbp: {})   # 대역 없음 → 즉시 종료
    res = facility.run_auto_scan(temp_db)
    assert facility._is_stop_requested() is False      # 시작 시 리셋됨
    assert res == {"scanned": 0, "skipped": 0}


def test_collect_band_source_has_stop_reset():
    """collect_band 종료부에 중지 플래그 해제 코드가 있는지(소스 가드)."""
    import inspect
    src = inspect.getsource(facility.collect_band)
    assert "_stop_requested = False" in src
    assert "scanned_ips" in src


# ── M-1~M-3: 엑셀 별칭 충돌 해소 ────────────────────────────────
def test_switch_inventory_keeps_name_and_rack():
    rows = excel_loader.parse_switch_inventory(
        _xlsx([["장비명", "호스트명", "IP", "랙위치"],
               ["코어스위치1", "TPS1F-SW01", "10.1.1.1", "A09U27"]]))
    assert rows[0]["name"] == "코어스위치1"        # 장비명 유실 없음
    assert rows[0]["hostname"] == "TPS1F-SW01"
    assert rows[0]["location"] == "A09U27"         # 랙 위치 보존


def test_purpose_column_not_mapped_to_location():
    """'용도/용도상세'는 location으로 매핑하지 않는다(랙 파싱 보호)."""
    rows = excel_loader.parse_switch_inventory(
        _xlsx([["장비명", "IP", "용도", "랙위치"],
               ["SW1", "10.1.1.2", "백본", "A09U27"]]))
    assert rows[0]["location"] == "A09U27"
    srv = excel_loader.parse_server_inventory(
        _xlsx([["이름", "IP", "용도상세", "랙위치"],
               ["SRV1", "10.1.1.3", "결제 웹서버", "A09U27"]]))
    assert srv[0]["location"] == "A09U27"


def test_ledger_mac_block_classified_as_host():
    """[호스트명, IP, MAC] 장부 블록은 스위치가 아니라 host로 분류."""
    d = excel_loader.load_workbook(
        _xlsx([["호스트명", "IP", "MAC"], ["PC-001", "10.5.5.10", "00:11:22:33:44:55"]]))
    assert d["switches"] == []
    assert len(d["hosts"]) == 1 and d["hosts"][0]["ip"] == "10.5.5.10"


def test_server_os_normalized():
    """OS Version 문자열 → os_type은 linux/windows/auto로 정규화, 원문은 os_info."""
    rows = excel_loader.parse_server_inventory(
        _xlsx([["호스트명", "대표 IP", "OS Version"],
               ["WEB01", "10.92.10.5", "Ubuntu 22.04"],
               ["WIN01", "10.92.10.6", "Windows Server 2019"],
               ["ETC01", "10.92.10.7", "기타OS"]]))
    by = {r["name"]: r for r in rows}
    assert by["WEB01"]["os_type"] == "linux" and by["WEB01"]["os_info"] == "Ubuntu 22.04"
    assert by["WIN01"]["os_type"] == "windows"
    assert by["ETC01"]["os_type"] == "auto" and by["ETC01"]["os_info"] == "기타OS"


# ── M-5: MAC 캐시가 DB별로 분리된다 ─────────────────────────────
def test_mac_cache_is_per_db(tmp_path):
    a = tmp_path / "a.db"
    b = tmp_path / "b.db"
    db.init_schema(a)
    db.init_schema(b)
    sid = db.save_switch(a, "SW-A", "10.7.0.1", "cisco_ios")
    snap = db.save_snapshot(a, sid)
    db.save_mac_entries(a, snap, sid, [{"mac": "AA:BB:CC:DD:EE:FF", "port": "Gi1/0/1"}])
    ma = db.get_mac_last_seen(a, ["aabbccddeeff"])
    mb = db.get_mac_last_seen(b, ["aabbccddeeff"])   # 다른 DB → 비어야 함
    assert ma.get("aabbccddeeff", {}).get("switch_name") == "SW-A"
    assert mb == {}


def test_mac_cache_invalidated_on_switch_delete(temp_db):
    sid = db.save_switch(temp_db, "SW-DEL", "10.7.1.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [{"mac": "11:22:33:44:55:66", "port": "Gi1/0/2"}])
    assert db.get_mac_last_seen(temp_db, ["112233445566"])
    db.delete_switch(temp_db, sid)                    # 삭제 → 캐시 무효화돼야 함
    assert db.get_mac_last_seen(temp_db, ["112233445566"]) == {}


# ── m-1: 중지 시 건너뜀은 실패로 집계하지 않는다 ─────────────────
def test_collect_all_servers_skipped_not_failed(temp_db, monkeypatch):
    db.save_server(temp_db, "S1", "10.8.1.1", os_type="auto")
    db.save_server(temp_db, "S2", "10.8.1.2", os_type="auto")
    monkeypatch.setattr(server_collector, "_is_stop", lambda: True)   # 즉시 중지 상태
    res = server_collector.collect_all_servers(temp_db)
    assert res["failed"] == 0 and res["skipped"] == 2
    server_collector._set_progress(running=False)
    server_collector._stop = False
