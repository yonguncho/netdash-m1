# -*- coding: utf-8 -*-
"""v6.39.3 — 관제: 설비 연결 실패를 TPS 구역(물리 위치)별로 집계 (사용자 요청).

"연결 실패가 발생한 TPS 구역을 알고 싶다. 스위치 기반으로 TPS 위치를 알 수
있을 텐데, 위치 정보와 카운트를 보게 해달라."

관제에서 필요한 건 '어느 스위치'가 아니라 **어디로 가야 하나**다.
"""
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


def _sw(dbf, name, ip, hostname=None):
    db.save_switch(dbf, name, ip, "cisco_ios")
    with db.get_db(dbf) as conn:
        conn.execute("UPDATE switches SET hostname=? WHERE ip=?",
                     (hostname or name, ip))
        conn.commit()


def _fac(dbf, subnet, ip, sw, online):
    db.save_facility_hosts(dbf, [{"subnet": subnet, "ip": ip,
                                  "switch_name": sw, "online": online}])


def _zones(dbf):
    return wallstats.build(dbf)["facility"]["offline_by_location"]


# ── 위치 집계 ─────────────────────────────────────────────────────

def test_groups_by_tps_label(dbf):
    _sw(dbf, "TPS-F1B02_1F01_FA_SW1", "10.1.1.1")
    _fac(dbf, "10.1.0.0/24", "10.1.0.1", "TPS-F1B02_1F01_FA_SW1", 0)
    _fac(dbf, "10.1.0.0/24", "10.1.0.2", "TPS-F1B02_1F01_FA_SW1", 1)
    z = _zones(dbf)
    assert len(z) == 1
    assert z[0]["label"] == "1공장 Assembly(B02) 1층 TPS01"
    assert z[0]["offline"] == 1 and z[0]["total"] == 2
    assert z[0]["phase"] == 1 and z[0]["floor"] == 1 and z[0]["tps"] == "01"


def test_merges_switches_in_same_tps(dbf):
    """같은 TPS에 스위치가 여러 대여도 현장은 한 곳이다."""
    _sw(dbf, "TPS-F1B02_1F01_FA_SW1", "10.1.1.1")
    _sw(dbf, "TPS-F1B02_1F01_FA_SW2", "10.1.1.2")
    _fac(dbf, "10.1.0.0/24", "10.1.0.1", "TPS-F1B02_1F01_FA_SW1", 0)
    _fac(dbf, "10.1.0.0/24", "10.1.0.2", "TPS-F1B02_1F01_FA_SW2", 0)
    z = _zones(dbf)
    assert len(z) == 1 and z[0]["offline"] == 2
    assert set(z[0]["switches"]) == {"TPS-F1B02_1F01_FA_SW1", "TPS-F1B02_1F01_FA_SW2"}


def test_sorted_by_offline_desc(dbf):
    _sw(dbf, "TPS-F1B02_1F01_FA_SW1", "10.1.1.1")
    _sw(dbf, "TPS-F2B1A_3F05_SW1", "10.2.1.1")
    for i in range(3):
        _fac(dbf, "10.1.0.0/24", "10.1.0.%d" % i, "TPS-F1B02_1F01_FA_SW1", 0)
    _fac(dbf, "10.2.0.0/24", "10.2.0.1", "TPS-F2B1A_3F05_SW1", 0)
    z = _zones(dbf)
    assert [x["offline"] for x in z] == [3, 1]
    assert z[0]["phase"] == 1 and z[1]["phase"] == 2


def test_zones_without_failure_are_excluded(dbf):
    """실패가 없는 구역은 관제에 올릴 것이 없다."""
    _sw(dbf, "TPS-F1B02_1F01_FA_SW1", "10.1.1.1")
    _fac(dbf, "10.1.0.0/24", "10.1.0.1", "TPS-F1B02_1F01_FA_SW1", 1)
    assert _zones(dbf) == []


def test_unparseable_switch_goes_to_unknown(dbf):
    """위치를 못 읽는다고 조용히 빼면 합계가 안 맞아 '왜 적지?'가 된다."""
    _sw(dbf, "SW-CORE-01", "10.9.9.9")
    _fac(dbf, "10.9.0.0/24", "10.9.0.1", "SW-CORE-01", 0)
    z = _zones(dbf)
    assert len(z) == 1 and z[0]["label"] == "위치 미확인"
    assert z[0]["phase"] is None


def test_falls_back_to_location_text(dbf):
    """호스트네임 패턴이 없어도 스위치에 적어둔 위치가 있으면 그걸 쓴다."""
    _sw(dbf, "SW-OLD", "10.8.8.8")
    with db.get_db(dbf) as conn:
        conn.execute("UPDATE switches SET location='본관 3층 통신실' WHERE ip='10.8.8.8'")
        conn.commit()
    _fac(dbf, "10.8.0.0/24", "10.8.0.1", "SW-OLD", 0)
    z = _zones(dbf)
    assert z[0]["label"] == "본관 3층 통신실"


def test_facility_without_switch_is_still_counted(dbf):
    """연결 스위치를 못 찾은 설비도 실패면 어딘가엔 나와야 한다."""
    _fac(dbf, "10.7.0.0/24", "10.7.0.1", "", 0)
    z = _zones(dbf)
    assert z and z[0]["offline"] == 1


def test_hostname_pattern_wins_over_name(dbf):
    """표시 이름은 임의로 바꿔도 hostname이 실제 장비 값이다."""
    _sw(dbf, "임의이름", "10.1.1.5", hostname="TPS-F1B02_1F01_FA_SW9")
    _fac(dbf, "10.1.0.0/24", "10.1.0.9", "임의이름", 0)
    assert _zones(dbf)[0]["label"] == "1공장 Assembly(B02) 1층 TPS01"


# ── 화면 ──────────────────────────────────────────────────────────

def test_wall_js_renders_zone_card():
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "web", "static", "wall.js")
    with open(p, encoding="utf-8") as f:
        js = f.read()
    assert "function tpsOfflineCard(" in js
    assert "tpsOfflineCard(c.offline_by_location" in js
    assert "연결 실패 구역 (TPS)" in js
    # 구역 전체가 끊긴 경우를 구분해야 스위치·전원을 먼저 볼 수 있다
    assert "구역 전체" in js


# ── 장애 카드 격자 정렬 ───────────────────────────────────────────

def _read(*parts):
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), *parts)
    with open(p, encoding="utf-8") as f:
        return f.read()


def test_problem_cards_use_uniform_grid():
    """사용자 지적: 카드가 '긴 네모, 짧은 네모'로 섞여 가시성이 떨어졌다.
    flex-wrap은 내용 길이가 곧 카드 폭이 된다 — 격자로 폭을 통일한다."""
    css = _read("web", "static", "wall.css")
    blk = css[css.index(".wall-cat__grid {"):]
    blk = blk[:blk.index("}")]
    assert "display: grid" in blk
    assert "auto-fill" in blk and "minmax(" in blk
    # 줄이 바뀌어도 높이가 유지돼야 한다(같은 줄만 맞추면 다시 들쭉날쭉)
    assert "grid-auto-rows: 1fr" in blk
    assert "flex-wrap" not in blk


def test_problem_card_truncates_long_text():
    """폭을 고정하면 긴 값이 넘친다 — 자르되 전체는 툴팁으로 볼 수 있어야 한다."""
    css = _read("web", "static", "wall.css")

    def rule(sel):
        """같은 선택자가 뒤에서 한 번 더(폰트 크기 등) 정의되므로 전부 합쳐 본다."""
        out, i = "", 0
        while True:
            i = css.find(sel + " {", i)
            if i < 0:
                return out
            out += css[i:css.index("}", i)]
            i += 1

    assert "text-overflow: ellipsis" in rule(".pcard__name")
    assert "-webkit-line-clamp" in rule(".pcard__why"), \
        "사유는 판단에 필요해 두 줄까지 허용한다"
    js = _read("web", "static", "wall.js")
    i = js.index("class='pcard'")
    assert "title='" in js[i - 200:i + 200], "잘린 전체 값을 볼 툴팁이 없다"


# ── 끊긴 설비의 스위치 보강 (v6.39.4) ─────────────────────────────
# 사용자 지적: 연결 실패 구역이 죄다 '위치 미확인'으로 나온다.
# 끊긴 설비는 MAC이 에이징으로 지워져 switch_name이 비는데, 그것만 보면
# 정작 '연결 실패'가 전부 위치 미확인이 된다. 설비 현황 화면과 같은
# 3단계(현재 MAC → 과거 이력 → 포트 설명)로 찾아야 한다.

def _tps_switch(dbf, name, ip, hostname):
    db.save_switch(dbf, name, ip, "cisco_ios")
    sw = [s for s in db.get_switches(dbf) if s["ip"] == ip][0]
    with db.get_db(dbf) as conn:
        conn.execute("UPDATE switches SET hostname=? WHERE id=?", (hostname, sw["id"]))
        conn.commit()
    return sw


def _snapshot_with(dbf, sw, mac=None, port_desc=None, days_ago=1):
    with db.get_db(dbf) as conn:
        conn.execute("INSERT INTO snapshots (switch_id, collected_at) "
                     "VALUES (?, datetime('now', ?))", (sw["id"], "-%d day" % days_ago))
        snap = conn.execute("SELECT MAX(id) FROM snapshots").fetchone()[0]
        if mac:
            conn.execute("INSERT INTO mac_entries (snapshot_id, switch_id, mac, port, vlan) "
                         "VALUES (?,?,?,?,10)", (snap, sw["id"], mac, "Gi1/0/5"))
        if port_desc:
            conn.execute("INSERT INTO ports (snapshot_id, switch_id, name, status, description) "
                         "VALUES (?,?,?,'down',?)", (snap, sw["id"], "Gi1/0/9", port_desc))
        conn.commit()


def test_offline_facility_located_via_mac_history(dbf):
    """끊겨서 MAC이 사라진 설비도 과거 이력으로 구역을 찾는다."""
    sw = _tps_switch(dbf, "TPS-SW-A", "10.1.1.1", "TPS-F1B02_1F01_FA_SW1")
    _snapshot_with(dbf, sw, mac="aabbccddee01")
    db.save_facility_hosts(dbf, [{"subnet": "10.5.0.0/24", "ip": "10.5.0.11",
                                  "mac": "aa:bb:cc:dd:ee:01",
                                  "switch_name": "", "online": 0}])
    z = _zones(dbf)
    assert z and z[0]["label"] == "1공장 Assembly(B02) 1층 TPS01", z
    assert "TPS-SW-A" in z[0]["switches"]


def test_offline_facility_located_via_port_description(dbf):
    """MAC 이력조차 없으면 포트 설명에 적힌 IP가 최후 단서다."""
    sw = _tps_switch(dbf, "TPS-SW-B", "10.2.1.1", "TPS-F2B1A_3F05_SW1")
    _snapshot_with(dbf, sw, port_desc="facility 10.6.0.22")
    db.save_facility_hosts(dbf, [{"subnet": "10.6.0.0/24", "ip": "10.6.0.22",
                                  "mac": "ff:ff:ff:ff:ff:ff",
                                  "switch_name": "", "online": 0}])
    z = _zones(dbf)
    assert z and z[0]["label"] == "2공장 Assembly(B1A) 3층 TPS05", z


def test_uplink_only_history_is_not_used_as_location(dbf):
    """업링크에서만 보인 이력은 '지나간 길목'이지 설치 위치가 아니다 —
    그걸 위치로 쓰면 엉뚱한 구역이 뜬다(설비 현황도 같은 기준)."""
    from core import wallstats as ws
    sw = _tps_switch(dbf, "BB-SW", "10.3.1.1", "TPS-F1B02_1F01_FA_SW1")
    _snapshot_with(dbf, sw, mac="aabbccddee99")
    db.save_facility_hosts(dbf, [{"subnet": "10.7.0.0/24", "ip": "10.7.0.5",
                                  "mac": "aa:bb:cc:dd:ee:99",
                                  "switch_name": "", "online": 0}])
    import unittest.mock as mock
    real = db.get_mac_last_seen

    def fake(path, macs=None):
        out = real(path, macs) or {}
        for k in out:
            out[k]["via_uplink"] = True      # 업링크 관측으로 바꿔치기
        return out

    with mock.patch.object(db, "get_mac_last_seen", fake):
        z = ws.build(dbf)["facility"]["offline_by_location"]
    assert z and z[0]["label"] == "위치 미확인", z


def test_online_facility_without_switch_does_not_create_zone(dbf):
    """정상인 설비는 구역을 만들지 않는다(실패가 있는 곳만 관제에 올린다)."""
    db.save_facility_hosts(dbf, [{"subnet": "10.8.0.0/24", "ip": "10.8.0.1",
                                  "mac": "aa:00", "switch_name": "", "online": 1}])
    assert _zones(dbf) == []
