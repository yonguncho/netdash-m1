"""과거 MAC 이력도 업링크를 배제해야 한다 (v6.14.0).

재재신고: 10.92.140.88은 TPS 10.92.140.13의 액세스 포트에 물려 있고 그 포트가
DOWN이다. 링크가 죽었으니 TPS의 MAC 테이블에서 사라졌고, 현재 어느 스위치에도
이 MAC이 없다 → `_choose_attachment`는 아무것도 못 고른다.

그런데 화면에는 여전히 백본 `SKBA_F1_N9508_FA_BB_1 1/24`가 나왔다. 표시가
**과거 이력 폴백**(`_build_mac_last_map`)에서 왔기 때문이다. 이 맵은 MAC별로
'스냅샷 id가 가장 큰' 관측 하나만 고르므로, 백본이 TPS보다 나중에 수집되기만
하면 백본의 업링크 관측이 이긴다. v6.13.0의 업링크 판정은 이 경로에 없었다.

호출처가 셋(설비 현황·관제·엑셀 내보내기)이라 맵 빌더 자체를 고친다.
"""
from core import db


def _seed(p, bb_last):
    """설비 MAC이 TPS 액세스 포트와 백본 업링크 양쪽 과거 스냅샷에 있는 상태.

    bb_last=True면 백본을 나중에 수집(= 백본 snapshot_id가 더 큼).
    """
    bb = db.save_switch(p, "SKBA_F1_N9508_FA_BB1", "10.92.140.1", "cisco_nxos")
    tps = db.save_switch(p, "SKBA_F1_TPS_01", "10.92.140.13", "cisco_ios")
    mac = "00:11:22:33:44:88"
    order = [(tps, "1/0/25"), (bb, "Eth1/24")] if bb_last else [(bb, "Eth1/24"), (tps, "1/0/25")]
    for sid, port in order:
        snap = db.save_snapshot(p, sid)
        db.save_mac_entries(p, snap, sid, [
            {"switch_id": sid, "vlan": 140, "mac": mac, "port": port, "type": "dynamic"}])
    # 백본 Eth1/24는 TPS로 가는 업링크(CDP로 확인됨) + Po124 멤버
    snap = db.save_snapshot(p, bb)
    db.save_port_channels(p, snap, bb, [{"port_channel": "Po124", "members": ["Eth1/24"]}])
    db.save_neighbors(p, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "SKBA_F1_TPS_01",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    return bb, tps, mac


def _hist(p, mac):
    return db.get_mac_last_seen(p, [mac])[mac.replace(":", "")]


def test_history_prefers_access_port_over_newer_uplink_observation(temp_db):
    """백본이 더 나중에 수집돼도 액세스 포트 이력이 이겨야 한다 — 신고된 그 상황."""
    bb, tps, mac = _seed(temp_db, bb_last=True)
    h = _hist(temp_db, mac)
    assert h["switch_name"] == "SKBA_F1_TPS_01", \
        "업링크 관측이 최신이라는 이유로 백본을 '마지막 위치'로 쓰면 안 된다"
    assert h["port"] == "1/0/25"
    assert h["via_uplink"] is False


def test_history_still_prefers_newest_among_access_ports(temp_db):
    """업링크가 아닌 관측끼리는 기존대로 최신이 이긴다(회귀 방지)."""
    a = db.save_switch(temp_db, "SW-A", "10.0.0.1", "cisco_ios")
    b = db.save_switch(temp_db, "SW-B", "10.0.0.2", "cisco_ios")
    mac = "00:11:22:33:44:99"
    for sid, port in ((a, "Gi1/0/1"), (b, "Gi1/0/2")):
        snap = db.save_snapshot(temp_db, sid)
        db.save_mac_entries(temp_db, snap, sid, [
            {"switch_id": sid, "vlan": 10, "mac": mac, "port": port, "type": "dynamic"}])
    assert _hist(temp_db, mac)["switch_name"] == "SW-B"


def test_history_falls_back_to_uplink_but_marks_it(temp_db):
    """업링크 관측밖에 없으면 위치를 버리지 않되 via_uplink로 표시한다.

    '어디에도 없음'보다 '여기까지만 확인됨'이 추적에 쓸모 있다 — 다만 화면이
    '연결됨'으로 읽지 않도록 구분자가 필요하다.
    """
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    db.save_switch(temp_db, "TPS", "10.92.140.13", "cisco_ios")
    mac = "00:11:22:33:44:77"
    snap = db.save_snapshot(temp_db, bb)
    db.save_mac_entries(temp_db, snap, bb, [
        {"switch_id": bb, "vlan": 140, "mac": mac, "port": "Eth1/24", "type": "dynamic"}])
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "TPS",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    h = _hist(temp_db, mac)
    assert h["switch_name"] == "BACKBONE" and h["via_uplink"] is True


def test_find_location_by_mac_skips_uplink_physical_port(temp_db):
    """서버 현황이 쓰는 경로도 같은 구멍이 있었다 — '물리 포트 우선'이 업링크를 뽑았다."""
    bb, tps, mac = _seed(temp_db, bb_last=True)
    loc = db.find_location_by_mac(temp_db, mac)
    assert loc["switch_name"] == "SKBA_F1_TPS_01" and loc["port"] == "1/0/25"


def test_find_location_by_mac_marks_uplink_only(temp_db):
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    db.save_switch(temp_db, "TPS", "10.92.140.13", "cisco_ios")
    mac = "00:11:22:33:44:66"
    snap = db.save_snapshot(temp_db, bb)
    db.save_mac_entries(temp_db, snap, bb, [
        {"switch_id": bb, "vlan": 140, "mac": mac, "port": "Eth1/24", "type": "dynamic"}])
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "TPS",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    assert db.find_location_by_mac(temp_db, mac)["via_uplink"] is True


def test_facility_ui_distinguishes_uplink_only_history():
    """화면이 '과거 연결'과 '업링크에서만 관측'을 구분해 표기해야 한다."""
    from pathlib import Path
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "hist_via_uplink" in js
    assert "과거에도 업링크에서만 관측" in js


# --- 포트 Description 단서: 링크 DOWN이면 이게 유일한 단서다 ------------------

def _seed_desc(p):
    """TPS 1/0/24 설명에 설비 IP가 적혀 있고, 그 설비 MAC은 어디에도 없는 상태.

    링크가 DOWN이라 MAC을 새로 학습할 수 없는 실제 상황.
    """
    tps = db.save_switch(p, "SKBA_F1_TPS_01", "10.92.140.13", "cisco_ios")
    snap = db.save_snapshot(p, tps)
    db.save_ports(p, snap, tps, [
        {"switch_id": tps, "name": "1/0/24", "status": "notconnect",
         "vlan": 140, "speed": "auto", "description": "10.92.140.88 설비"},
        {"switch_id": tps, "name": "1/0/26", "status": "connected",
         "vlan": 140, "speed": "1000", "description": "10.92.140.9 다른설비"}])
    return tps


def test_description_clue_found_when_mac_is_nowhere(temp_db):
    """MAC이 어느 테이블에도 없어도 포트 설명으로 위치를 알려줘야 한다."""
    _seed_desc(temp_db)
    d = db.find_port_by_description(temp_db, "10.92.140.88")
    assert d and d["switch_name"] == "SKBA_F1_TPS_01" and d["port"] == "1/0/24"


def test_description_match_respects_ip_boundary(temp_db):
    """'10.92.140.9'가 '10.92.140.98'에 걸리면 안 된다 — 부분 문자열 오탐."""
    tps = db.save_switch(temp_db, "TPS", "10.92.140.13", "cisco_ios")
    snap = db.save_snapshot(temp_db, tps)
    db.save_ports(temp_db, snap, tps, [
        {"switch_id": tps, "name": "1/0/1", "status": "connected", "vlan": 1,
         "speed": "1000", "description": "10.92.140.98 설비"}])
    assert db.find_port_by_description(temp_db, "10.92.140.9") is None
    assert db.find_port_by_description(temp_db, "10.92.140.98")["port"] == "1/0/1"


def test_description_same_switch_two_ports_still_names_the_switch(temp_db):
    """같은 IP가 두 포트에 적혀 있어도 스위치는 확정 — 예전엔 통째로 버렸다.

    옛 포트 라벨을 지우지 않고 새 포트에도 적는 일이 흔하다.
    """
    tps = db.save_switch(temp_db, "TPS", "10.92.140.13", "cisco_ios")
    snap = db.save_snapshot(temp_db, tps)
    db.save_ports(temp_db, snap, tps, [
        {"switch_id": tps, "name": "1/0/24", "status": "notconnect", "vlan": 140,
         "speed": "auto", "description": "10.92.140.88 (구)"},
        {"switch_id": tps, "name": "1/0/25", "status": "notconnect", "vlan": 140,
         "speed": "auto", "description": "10.92.140.88"}])
    d = db.find_port_by_description(temp_db, "10.92.140.88")
    assert d["switch_name"] == "TPS" and d["port"] is None
    assert set(d["ambiguous_ports"]) == {"1/0/24", "1/0/25"}


def test_description_ambiguous_across_switches_returns_nothing(temp_db):
    """서로 다른 스위치에 적혀 있으면 어느 쪽인지 알 수 없다 — 오탐 방지."""
    for name, ip in (("SW-A", "10.0.0.1"), ("SW-B", "10.0.0.2")):
        sid = db.save_switch(temp_db, name, ip, "cisco_ios")
        snap = db.save_snapshot(temp_db, sid)
        db.save_ports(temp_db, snap, sid, [
            {"switch_id": sid, "name": "Gi1/0/1", "status": "connected", "vlan": 1,
             "speed": "1000", "description": "10.92.140.88"}])
    assert db.find_port_by_description(temp_db, "10.92.140.88") is None


def test_batch_lookup_matches_single(temp_db):
    """배치와 단건이 같은 답을 내야 한다(구현이 갈라지지 않게 단건이 배치를 쓴다)."""
    _seed_desc(temp_db)
    batch = db.find_ports_by_description(temp_db, ["10.92.140.88", "10.92.140.9"])
    assert batch["10.92.140.88"] == db.find_port_by_description(temp_db, "10.92.140.88")
    assert batch["10.92.140.9"] == db.find_port_by_description(temp_db, "10.92.140.9")


def test_wall_shows_description_clue_for_down_facility(tmp_path, monkeypatch):
    """관제 '설비 연결 실패'에 포트 설명 단서가 나와야 한다 — 신고된 그 화면.

    링크 DOWN이라 MAC은 어디에도 없지만 TPS 1/0/24 설명에 IP가 적혀 있다.
    지금까지 관제에는 이 단서가 연결돼 있지 않아 '위치 미확인'으로만 나왔다.
    """
    monkeypatch.chdir(tmp_path)
    import app as app_module
    application = app_module.create_app(demo_mode=True)
    from core import collector
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()

    _seed_desc(dbp)
    db.save_facility_hosts(dbp, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.88", "mac": "00:11:22:33:44:88",
         "switch_name": "", "port": "", "online": 0, "direct": 0}])
    cats = application.test_client().get("/api/wall").get_json()["categories"]
    fac = [c for c in cats if c["key"] == "facility"][0]["items"]
    detail = {i["name"]: i["detail"] for i in fac}["10.92.140.88"]
    assert "포트 설명에 이 IP 기재" in detail
    assert "SKBA_F1_TPS_01" in detail and "1/0/24" in detail


def test_export_uses_description_clue_and_marks_uplink_history(temp_db):
    """엑셀 내보내기도 같은 단서를 써야 한다 — 세 번째 경로(화면·관제·엑셀)."""
    from core import exporter
    tps = _seed_desc(temp_db)
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    mac = "00:11:22:33:44:88"
    snap = db.save_snapshot(temp_db, bb)
    db.save_mac_entries(temp_db, snap, bb, [
        {"switch_id": bb, "vlan": 140, "mac": mac, "port": "Eth1/24", "type": "dynamic"}])
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "SKBA_F1_TPS_01",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.88", "mac": mac,
         "switch_name": "", "port": "", "online": 0, "direct": 0}])
    row = [r for r in exporter.facility_rows(temp_db) if r["IP"] == "10.92.140.88"][0]
    assert "포트 설명에 이 IP 기재" in row["비고"] and "1/0/24" in row["비고"]
    assert "과거에도 업링크에서만 관측" in row["비고"], \
        "업링크 이력을 '과거 연결'로 쓰면 백본에 꽂혀 있었다고 읽힌다"
    assert tps


def test_export_enriches_uplink_only_rows_too(temp_db):
    """이름이 있어도 direct=0이면 보강 대상 — 예전엔 완전히 빈 것만 봤다."""
    from core import exporter
    _seed_desc(temp_db)
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.88", "mac": "00:11:22:33:44:88",
         "switch_name": "BACKBONE", "port": "Po124", "online": 0, "direct": 0}])
    row = [r for r in exporter.facility_rows(temp_db) if r["IP"] == "10.92.140.88"][0]
    assert "포트 설명에 이 IP 기재" in row["비고"]
