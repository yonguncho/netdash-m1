# -*- coding: utf-8 -*-
"""관제 카테고리 전체 일괄 재수집 (v6.10.0).

사용자 요청: "관제 페이지에서 설비 연결 실패한 건에 대해 개별적으로 재수집할
수 있지만, 설비 연결 실패한 건 또는 도달 불가 건, 수집 실패에 대해 이런
카테고리 각각에 대해 전체 장비를 한번에 수집하는 기능도 만들면 좋을 것
같다."

세 카테고리 각각에 '전체 재수집' 버튼을 추가한다.
  · 설비 연결 실패(facility) — 대역별로 세션을 재사용해 오프라인 IP만 ping.
  · 도달 불가(unreach) / 수집 실패(failed) — 스위치 카테고리. 관제는 계정
    입력 팝업이 없는 화면이므로, 각 스위치에 저장된 계정을 그대로 쓰고
    없으면 건너뛴다(조용히 빠뜨리지 않고 skipped_no_cred로 집계).
"""
import sys
from pathlib import Path

import pytest
from openpyxl import Workbook  # noqa: F401  (미사용 — 다른 테스트 관례와 맞춘 import 자리)

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility  # noqa: E402

ROOT = Path(__file__).parent.parent


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class _FakeConn(object):
    """netmiko.ConnectHandler 대역 — 요청받은 IP만 응답 여부를 정할 수 있다."""

    def __init__(self, online_ips=None, **kw):
        self.online_ips = set(online_ips or [])
        self.pinged = []
        self.arp_reads = 0

    def check_enable_mode(self):
        return True

    def disconnect(self):
        pass

    def send_command(self, cmd, read_timeout=10):
        if cmd.startswith("terminal"):
            return ""
        if cmd == "show vrf":
            return ""
        if cmd.startswith("ping"):
            ip = cmd.split()[1]
            self.pinged.append(ip)
            return "!!!!!" if ip in self.online_ips else "....."
        if cmd.startswith("show ip arp") or cmd.startswith("show iparp"):
            self.arp_reads += 1
            return "\n".join(
                "Internet  %s   0  aabb.cc00.%04x  ARPA  Gi1/0/1" % (ip, i + 1)
                for i, ip in enumerate(sorted(self.online_ips)))
        return ""


def _patch_conns(monkeypatch, conn_by_switch_ip):
    """스위치 관리 IP별로 다른 FakeConn을 준다(대역이 여럿일 때 검증용)."""
    import netmiko as _nm
    monkeypatch.setattr(_nm, "ConnectHandler",
                        lambda **kw: conn_by_switch_ip[kw["ip"]])



def _save_cred(db_path, switch_id, user="u", pw="p"):
    from core import credentials
    blob = credentials.encrypt_credential(user, pw)
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(db_path, switch_id, blob)


# ── 설비 연결 실패: 대역별로 세션 재사용, 오프라인 IP만 ping ────
def test_bulk_groups_by_subnet_one_connect_each(temp_db, monkeypatch):
    sw1 = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    sw2 = db.save_switch(temp_db, "GW2", "10.9.2.1", "cisco_ios")
    facility.remember_band(temp_db, "10.9.1.0/29", sw1)
    facility.remember_band(temp_db, "10.9.2.0/29", sw2)
    _save_cred(temp_db, sw1)
    _save_cred(temp_db, sw2)
    conn1 = _FakeConn(online_ips={"10.9.1.5"})
    conn2 = _FakeConn(online_ips=set())
    _patch_conns(monkeypatch, {"10.9.1.1": conn1, "10.9.2.1": conn2})
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0},
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.6", "mac": "", "online": 0},
        {"subnet": "10.9.2.0/29", "ip": "10.9.2.5", "mac": "", "online": 0},
    ])
    result = facility.recollect_offline_facility(temp_db)
    assert result["checked"] == 3
    assert result["online"] == 1 and result["still_offline"] == 2
    assert conn1.arp_reads == 1 and conn2.arp_reads == 1, "대역마다 접속을 한 번만 해야 한다"
    assert set(conn1.pinged) == {"10.9.1.5", "10.9.1.6"}, \
        "그 대역의 오프라인 IP만 ping해야 한다(대역 전체 스윕이면 안 된다)"


def test_bulk_does_not_touch_already_online_hosts(temp_db, monkeypatch):
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    facility.remember_band(temp_db, "10.9.1.0/29", sw)
    _save_cred(temp_db, sw)
    conn = _FakeConn(online_ips={"10.9.1.5"})
    _patch_conns(monkeypatch, {"10.9.1.1": conn})
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0},
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.9", "mac": "AA:BB:CC:00:00:09",
         "switch_name": "EDGE", "port": "Gi1/0/9", "online": 1},
    ])
    facility.recollect_offline_facility(temp_db)
    assert "10.9.1.9" not in conn.pinged, "이미 온라인인 설비까지 ping하면 안 된다"
    row = [h for h in db.get_facility_hosts(temp_db) if h["ip"] == "10.9.1.9"][0]
    assert row["switch_name"] == "EDGE" and row["port"] == "Gi1/0/9"


def test_bulk_switch_filter_narrows_targets(temp_db, monkeypatch):
    """칩 필터가 걸려 있으면 그 연결 스위치의 오프라인 설비만 대상이다."""
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    facility.remember_band(temp_db, "10.9.1.0/29", sw)
    _save_cred(temp_db, sw)
    conn = _FakeConn(online_ips=set())
    _patch_conns(monkeypatch, {"10.9.1.1": conn})
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0,
         "switch_name": "EDGE-A"},
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.6", "mac": "", "online": 0,
         "switch_name": "EDGE-B"},
    ])
    result = facility.recollect_offline_facility(temp_db, switch_filter="EDGE-A")
    assert result["checked"] == 1
    assert conn.pinged == ["10.9.1.5"]


def test_bulk_no_gateway_and_no_cred_reported(temp_db, monkeypatch):
    """게이트웨이 미기억·계정 없음은 조용히 넘어가지 않고 집계돼야 한다."""
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    # remember_band를 안 해서 band_map에 없다
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0}])
    result = facility.recollect_offline_facility(temp_db)
    assert result["checked"] == 0
    assert "10.9.1.0/29" in result["no_gateway"]

    facility.remember_band(temp_db, "10.9.1.0/29", sw)
    # 여전히 계정이 없다(스위치에 cred_blob도 없고 pcprofile도 없음)
    result2 = facility.recollect_offline_facility(temp_db)
    assert "10.9.1.0/29" in result2["no_cred"]


def test_bulk_emits_recovery_event_only_for_newly_online(temp_db, monkeypatch):
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    facility.remember_band(temp_db, "10.9.1.0/29", sw)
    _save_cred(temp_db, sw)
    conn = _FakeConn(online_ips={"10.9.1.5"})
    _patch_conns(monkeypatch, {"10.9.1.1": conn})
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0}])
    facility.recollect_offline_facility(temp_db)
    events = db.list_device_events(temp_db, limit=20)
    assert any(e.get("kind") == "device_online" and e.get("ip") == "10.9.1.5"
              for e in events)


def test_bulk_empty_when_nothing_offline(temp_db):
    result = facility.recollect_offline_facility(temp_db)
    assert result == {"checked": 0, "online": 0, "still_offline": 0,
                       "no_gateway": [], "no_cred": [], "errors": {}}


# ── gateway_credential: app.py 중복 로직을 중앙화한 것 ──────────
def test_gateway_credential_prefers_stored_over_pcprofile(temp_db):
    from core import credentials, pcprofile
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    blob = credentials.encrypt_credential("stored-user", "stored-pw")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(temp_db, sw, blob)
    pcprofile.save_profile(temp_db, "common-user", "common-pw", source_ip="10.1.1.1")
    u, p = facility.gateway_credential(temp_db, sw)
    assert (u, p) == ("stored-user", "stored-pw")


def test_gateway_credential_falls_back_to_pcprofile(temp_db):
    from core import pcprofile
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    pcprofile.save_profile(temp_db, "common-user", "common-pw", source_ip="10.1.1.1")
    u, p = facility.gateway_credential(temp_db, sw)
    assert (u, p) == ("common-user", "common-pw")


def test_gateway_credential_none_when_neither(temp_db):
    sw = db.save_switch(temp_db, "GW1", "10.9.1.1", "cisco_ios")
    assert facility.gateway_credential(temp_db, sw) == (None, None)


# ── /api/facility/recollect-offline 라우트 ──────────────────────
def test_route_facility_bulk_wired(cli, monkeypatch):
    p = Path.cwd() / "netdash.db"
    sw = db.save_switch(p, "GW1", "10.9.1.1", "cisco_ios")
    facility.remember_band(p, "10.9.1.0/29", sw)
    from core import credentials
    blob = credentials.encrypt_credential("u", "p")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(p, sw, blob)
    conn = _FakeConn(online_ips={"10.9.1.5"})
    _patch_conns(monkeypatch, {"10.9.1.1": conn})
    db.save_facility_hosts(p, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0}])
    r = cli.post("/api/facility/recollect-offline", json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body["ok"] is True and body["checked"] == 1 and body["online"] == 1


def test_route_facility_bulk_passes_switch_filter(cli, monkeypatch):
    p = Path.cwd() / "netdash.db"
    sw = db.save_switch(p, "GW1", "10.9.1.1", "cisco_ios")
    facility.remember_band(p, "10.9.1.0/29", sw)
    from core import credentials
    blob = credentials.encrypt_credential("u", "p")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(p, sw, blob)
    conn = _FakeConn(online_ips=set())
    _patch_conns(monkeypatch, {"10.9.1.1": conn})
    db.save_facility_hosts(p, [
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.5", "mac": "", "online": 0,
         "switch_name": "EDGE-A"},
        {"subnet": "10.9.1.0/29", "ip": "10.9.1.6", "mac": "", "online": 0,
         "switch_name": "EDGE-B"},
    ])
    r = cli.post("/api/facility/recollect-offline", json={"switch": "EDGE-A"})
    body = r.get_json()
    assert body["checked"] == 1


# ── /api/wall/recollect-switches 라우트 ──────────────────────────
def test_route_switch_bulk_rejects_bad_category(cli):
    r = cli.post("/api/wall/recollect-switches", json={"category": "nope"})
    assert r.status_code == 400


def test_route_switch_bulk_uses_stored_credential_and_skips_missing(cli, monkeypatch):
    p = Path.cwd() / "netdash.db"
    s1 = db.save_switch(p, "SW1", "10.0.0.1", "cisco_ios")
    s2 = db.save_switch(p, "SW2", "10.0.0.2", "cisco_ios")
    from core import credentials
    blob = credentials.encrypt_credential("u", "p")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(p, s1, blob)   # s2는 계정 없음 — 건너뛰어야 한다
    with db.get_db(p) as conn:
        conn.execute("UPDATE switches SET status='failed' WHERE id IN (?, ?)", (s1, s2))

    calls = []
    import core.collector as _col
    monkeypatch.setattr(_col, "collect_switch",
                        lambda dbp, sid, u, pw, enable_secret=None: (
                            calls.append(sid), {"status": "queued"})[1])

    r = cli.post("/api/wall/recollect-switches", json={"category": "failed"})
    assert r.status_code == 202, r.get_data(as_text=True)
    body = r.get_json()
    assert body["queued"] == 1 and body["skipped_no_cred"] == 1
    assert calls == [s1]


def test_route_switch_bulk_unreach_uses_reachability_state(cli, monkeypatch):
    p = Path.cwd() / "netdash.db"
    s1 = db.save_switch(p, "SW1", "10.0.0.1", "cisco_ios")
    from core import credentials
    blob = credentials.encrypt_credential("u", "p")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(p, s1, blob)

    from core import reachability
    monkeypatch.setattr(reachability, "_state", {s1: False})

    calls = []
    import core.collector as _col
    monkeypatch.setattr(_col, "collect_switch",
                        lambda dbp, sid, u, pw, enable_secret=None: (
                            calls.append(sid), {"status": "queued"})[1])

    r = cli.post("/api/wall/recollect-switches", json={"category": "unreach"})
    assert r.status_code == 202
    assert calls == [s1]


def test_route_switch_bulk_merges_into_progress_tracker(cli, monkeypatch):
    """진행 상태(_sw_bulk)에 반영돼야 다른 화면의 진행바에서도 보인다."""
    p = Path.cwd() / "netdash.db"
    s1 = db.save_switch(p, "SW1", "10.0.0.1", "cisco_ios")
    with db.get_db(p) as conn:
        conn.execute("UPDATE switches SET status='failed' WHERE id=?", (s1,))
    from core import credentials
    blob = credentials.encrypt_credential("u", "p")
    if not blob:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    db.update_cred_blob(p, s1, blob)

    import core.collector as _col
    monkeypatch.setattr(_col, "collect_switch",
                        lambda dbp, sid, u, pw, enable_secret=None: {"status": "queued"})

    import app as _app_mod
    cli.post("/api/wall/recollect-switches", json={"category": "failed"})
    assert s1 in (_app_mod._sw_bulk.get("ids") or [])


# ── 화면 배선 ────────────────────────────────────────────────────
def test_wall_js_has_bulk_buttons_for_three_categories():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert 'c.key === "unreach" || c.key === "failed"' in js
    assert "data-bulk-cat='facility'" in js
    assert "/api/facility/recollect-offline" in js
    assert "/api/wall/recollect-switches" in js


def test_wall_js_bulk_facility_carries_switch_filter():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    i = js.index("function startBulk(")
    block = js[i:i + 900]
    assert "data-bulk-switch" in block


def test_wall_css_has_bulk_button_style():
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    assert ".wall-cat__bulk" in css
