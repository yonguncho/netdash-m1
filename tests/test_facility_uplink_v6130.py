"""업링크 판정을 MAC 개수가 아니라 '너머에 스위치가 있는가'로 (v6.13.0).

재신고: v6.11.0을 냈는데도 설비 10.92.140.88이 백본 SKBA_F1_N9508_FA_BB1의
Eth1/24 (Po124)에 '직접 연결'로 표시된다. 실제 백본 1/24 앞단은 TPS 스위치
10.92.140.13이고, 설비는 그 TPS의 1/0/25에 물려 있다.

v6.11.0은 "Po의 MAC 수가 많으면 트렁크"로 걸렀는데, 업링크라도 그 뒤 장비가
대부분 꺼져 있거나 조용하면 학습 MAC이 몇 개뿐이라 그 검사를 통과해 버린다.
스위치가 그 포트 너머에 있다는 사실은 개수와 무관한 확정 근거다.
"""
from core import db, facility

# temp_db / client 픽스처는 conftest.py 공용 정의를 쓴다.


# --- 순수 함수: uplinks 인자가 개수 휴리스틱을 이긴다 -------------------------

def test_uplink_beats_low_mac_count_on_port_channel():
    """MAC 수가 적어도(≤4) 업링크로 알려진 Po는 직접연결이 아니다.

    이게 v6.11.0에 남아 있던 구멍이다 — 백본 Po124 뒤 장비 대부분이 오프라인이면
    학습 MAC이 1~2개로 떨어져 '액세스 포트'처럼 보였다.
    """
    matches = [(1, "SKBA_F1_N9508_FA_BB1", "Po124")]
    port_counts = {(1, "po124"): 2}          # v6.11.0 기준이면 '직접'으로 통과
    pc_map = {(1, "po124"): ["Eth1/24"]}
    uplinks = {(1, "po124"), (1, "eth1/24")}
    sid, sname, port, direct, via = facility._choose_attachment(
        matches, port_counts, pc_map, uplinks)
    assert direct is False
    assert port == "Po124", "업링크는 물리 멤버로 풀어 보여주지 않는다(직결 오해 방지)"


def test_uplink_beats_low_mac_count_on_physical_port():
    """같은 구멍이 물리 포트에도 있다 — 유일한 물리 관측이면 무조건 direct였다."""
    matches = [(1, "BACKBONE", "Ethernet1/24")]
    port_counts = {(1, "ethernet1/24"): 1}
    uplinks = {(1, "ethernet1/24")}
    sid, sname, port, direct, via = facility._choose_attachment(
        matches, port_counts, {}, uplinks)
    assert direct is False


def test_access_switch_wins_over_backbone_uplink():
    """설비 MAC이 백본 업링크와 TPS 액세스 포트 양쪽에서 보이면 TPS를 고른다."""
    matches = [(1, "SKBA_F1_N9508_FA_BB1", "Po124"), (2, "TPS-10.92.140.13", "1/0/25")]
    port_counts = {(1, "po124"): 2, (2, "1/0/25"): 1}
    pc_map = {(1, "po124"): ["Eth1/24"]}
    uplinks = {(1, "po124"), (1, "eth1/24")}
    sid, sname, port, direct, via = facility._choose_attachment(
        matches, port_counts, pc_map, uplinks)
    assert sname == "TPS-10.92.140.13" and port == "1/0/25" and direct is True


def test_all_uplink_still_reports_location_but_not_direct():
    """관측이 업링크뿐이면(액세스 스위치 미수집/에이징) 위치는 알려주되 직접은 아니다.

    빈칸으로 두면 '어디에도 안 보인다'가 되어 오히려 추적이 어려워진다.
    """
    matches = [(1, "BACKBONE", "Po124")]
    port_counts = {(1, "po124"): 2}
    pc_map = {(1, "po124"): ["Eth1/24"]}
    sid, sname, port, direct, via = facility._choose_attachment(
        matches, port_counts, pc_map, {(1, "po124"), (1, "eth1/24")})
    assert sname == "BACKBONE" and direct is False and port == "Po124"


def test_no_uplink_info_keeps_v6110_behaviour():
    """업링크 정보가 없으면(CDP 미수집 등) 기존 MAC 개수 판정 그대로."""
    matches = [(1, "BACKBONE", "Po10")]
    pc_map = {(1, "po10"): ["Eth1/1", "Eth1/2"]}
    sid, sname, port, direct, via = facility._choose_attachment(
        matches, {(1, "po10"): 2}, pc_map, set())
    assert direct is True and "Eth1/1" in port


# --- uplink_ports(): DB에서 업링크 포트를 뽑아내는가 -------------------------

def test_uplink_ports_from_cdp_neighbor(temp_db):
    """CDP 이웃의 remote_ip가 등록 스위치면 그 local_port는 업링크."""
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    tps = db.save_switch(temp_db, "TPS", "10.92.140.13", "cisco_ios")
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Ethernet1/24", "remote_name": "TPS",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    up = facility.uplink_ports(temp_db)
    assert (bb, "ethernet1/24") in up
    assert tps  # 등록돼 있어야 인정된다


def test_uplink_ports_ignores_non_switch_neighbor(temp_db):
    """IP전화·AP 같은 미등록 이웃은 업링크가 아니다(액세스 포트를 잃으면 안 된다)."""
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Ethernet1/5", "remote_name": "SEP0011AABB",
         "remote_port": "Port 1", "remote_ip": "10.92.140.77", "platform": "IP Phone"}])
    assert (bb, "ethernet1/5") not in facility.uplink_ports(temp_db)


def test_uplink_ports_propagates_member_to_port_channel(temp_db):
    """멤버 Eth1/24가 업링크면 그것을 묶은 Po124도 업링크."""
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    db.save_switch(temp_db, "TPS", "10.92.140.13", "cisco_ios")
    snap = db.save_snapshot(temp_db, bb)
    db.save_port_channels(temp_db, snap, bb,
                          [{"port_channel": "Po124", "members": ["Eth1/24"]}])
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "TPS",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    up = facility.uplink_ports(temp_db)
    assert (bb, "eth1/24") in up and (bb, "po124") in up


def test_uplink_ports_matches_neighbor_by_name_when_ip_missing(temp_db):
    """LLDP는 remote_ip가 비는 경우가 흔하다 — 이름으로도 등록 스위치를 찾는다."""
    bb = db.save_switch(temp_db, "BACKBONE", "10.92.140.1", "cisco_nxos")
    db.save_switch(temp_db, "SKBA_F1_TPS_01", "10.92.140.13", "cisco_ios")
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Eth1/24",
         "remote_name": "SKBA_F1_TPS_01(FDO123).example.com",
         "remote_port": "Gi1/0/49", "remote_ip": "", "platform": "C9300"}])
    assert (bb, "eth1/24") in facility.uplink_ports(temp_db)


# --- 종단 재현: 사용자가 신고한 그 화면 --------------------------------------

def test_rematch_does_not_call_backbone_uplink_direct(temp_db):
    """10.92.140.88 재현 — 백본 Po124 하나만 관측돼도 '직접 연결'로 쓰지 않는다."""
    bb = db.save_switch(temp_db, "SKBA_F1_N9508_FA_BB1", "10.92.140.1", "cisco_nxos")
    db.save_switch(temp_db, "SKBA_F1_TPS_01", "10.92.140.13", "cisco_ios")
    snap = db.save_snapshot(temp_db, bb)
    # 설비가 오프라인이라 TPS의 MAC은 에이징으로 사라지고 백본 Po124 관측만 남음
    db.save_mac_entries(temp_db, snap, bb, [
        {"switch_id": bb, "vlan": 140, "mac": "00:11:22:33:44:88",
         "port": "Po124", "type": "dynamic"}])
    db.save_port_channels(temp_db, snap, bb,
                          [{"port_channel": "Po124", "members": ["Eth1/24"]}])
    db.save_neighbors(temp_db, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "SKBA_F1_TPS_01",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.88", "mac": "00:11:22:33:44:88",
         "online": 0, "direct": 1, "switch_id": bb,
         "switch_name": "SKBA_F1_N9508_FA_BB1", "port": "Eth1/24 (Po124)"}])

    facility.rematch(temp_db)

    h = [x for x in db.get_facility_hosts(temp_db) if x["ip"] == "10.92.140.88"][0]
    assert not h["direct"], "백본 업링크를 직접 연결로 표시하면 안 된다"
    assert "Eth1/24" not in (h["port"] or ""), \
        "멤버포트로 풀어 보여주면 백본에 꽂혀 있다는 오해를 준다"


# --- 판정 근거(explain) — 사용자가 화면에서 직접 확인할 수 있어야 한다 -------

def _seed_backbone_case(p):
    bb = db.save_switch(p, "SKBA_F1_N9508_FA_BB1", "10.92.140.1", "cisco_nxos")
    db.save_switch(p, "SKBA_F1_TPS_01", "10.92.140.13", "cisco_ios")
    snap = db.save_snapshot(p, bb)
    db.save_mac_entries(p, snap, bb, [
        {"switch_id": bb, "vlan": 140, "mac": "00:11:22:33:44:88",
         "port": "Po124", "type": "dynamic"}])
    db.save_port_channels(p, snap, bb, [{"port_channel": "Po124", "members": ["Eth1/24"]}])
    db.save_neighbors(p, bb, [
        {"switch_id": bb, "local_port": "Eth1/24", "remote_name": "SKBA_F1_TPS_01",
         "remote_port": "Gi1/0/49", "remote_ip": "10.92.140.13", "platform": "C9300"}])
    db.save_facility_hosts(p, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.88", "mac": "00:11:22:33:44:88",
         "online": 0, "direct": 1, "switch_id": bb,
         "switch_name": "SKBA_F1_N9508_FA_BB1", "port": "Eth1/24 (Po124)"}])
    return bb


def test_explain_shows_uplink_evidence(temp_db):
    """'왜 백본으로 나오냐'에 답할 재료가 전부 담겨야 한다."""
    _seed_backbone_case(temp_db)
    r = facility.explain_attachment(temp_db, "10.92.140.88")
    assert r["ok"] is True
    o = [x for x in r["observations"] if x["port"] == "Po124"][0]
    assert o["is_uplink"] is True
    assert o["members"] == ["Eth1/24"]
    assert any(n["remote_ip"] == "10.92.140.13" for n in o["neighbors"]), \
        "업링크로 본 근거(CDP 이웃)를 보여줘야 한다"
    assert r["decision"]["direct"] is False


def test_explain_flags_stored_vs_recomputed_mismatch(temp_db):
    """저장값(백본 직결)과 재계산이 다르면 화면이 그 차이를 알 수 있어야 한다."""
    _seed_backbone_case(temp_db)
    r = facility.explain_attachment(temp_db, "10.92.140.88")
    assert r["stored"]["direct"] == 1
    assert r["decision"]["direct"] is False


def test_explain_unknown_ip_is_error_not_crash(temp_db):
    r = facility.explain_attachment(temp_db, "10.0.0.254")
    assert r["ok"] is False and "10.0.0.254" in r["error"]


def test_explain_endpoint_requires_ip(client):
    r = client.get("/api/facility/explain")
    assert r.status_code == 400 and r.get_json()["ok"] is False


def test_explain_endpoint_unknown_ip_is_not_500(client):
    """목록에 없는 IP는 500이 아니라 사유가 담긴 200으로 답해야 한다."""
    r = client.get("/api/facility/explain?ip=203.0.113.9")
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is False and "203.0.113.9" in body["error"]
