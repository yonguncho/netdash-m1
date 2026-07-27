# -*- coding: utf-8 -*-
"""전체 기능 검토(5개 영역 병렬 검수)에서 나온 결함의 회귀 테스트.

각 테스트는 발견된 증상 하나에 대응한다. 주석의 '증상'은 수정 전 실제 동작이다.
"""
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, facility, instance_lock, server_collector as sc

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


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


# ── 데이터 파괴 ───────────────────────────────────────────────────
def test_reimporting_excel_keeps_location_and_vm(temp_db):
    """증상: 같은 엑셀을 다시 등록하면 배치·수집해 둔 위치·VM·OS가 지워졌다."""
    sid = db.save_server(temp_db, "S1", "10.1.0.1", os_type="linux", location="A09U27",
                         is_vm=1)
    # 엑셀 재등록 = 이름·IP만 있는 upsert
    db.save_server(temp_db, "S1", "10.1.0.1")
    row = db.get_server(temp_db, sid)
    assert row["location"] == "A09U27", "위치가 지워졌다"
    assert row["is_vm"] == 1, "VM 표시가 지워졌다"
    assert row["os_type"] == "linux", "OS가 초기화됐다"


def test_save_server_updates_only_given_fields(temp_db):
    sid = db.save_server(temp_db, "S2", "10.1.0.2", os_type="aix", location="A01U01")
    db.save_server(temp_db, "S2-renamed", "10.1.0.2", location="A02U02")
    row = db.get_server(temp_db, sid)
    assert row["name"] == "S2-renamed" and row["location"] == "A02U02"
    assert row["os_type"] == "aix", "지정하지 않은 OS가 덮어써졌다"


def test_unprivileged_collect_keeps_confirmed_os(temp_db, monkeypatch):
    """증상: AIX로 확정한 서버가 '22번 열림 → linux'로 덮어써졌다."""
    monkeypatch.setattr(sc, "scan_ports", lambda ip, ports=None, timeout=1.0: [22])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(sc, "netbios_name", lambda ip, timeout=2: "")
    for os_type in ("aix", "solaris", "hpux", "esxi", "windows"):
        sid = db.save_server(temp_db, "SRV-" + os_type, "10.2.0.%d" % (hash(os_type) % 200 + 1),
                             os_type=os_type)
        sc.collect_server(temp_db, sid, None, None)
        assert db.get_server(temp_db, sid)["os_type"] == os_type, os_type


def test_auto_os_still_inferred_when_unset(temp_db, monkeypatch):
    """확정 OS 보존이 '자동 추정 자체를 막는 것'이 되면 안 된다."""
    monkeypatch.setattr(sc, "scan_ports", lambda ip, ports=None, timeout=1.0: [22])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(sc, "netbios_name", lambda ip, timeout=2: "")
    sid = db.save_server(temp_db, "AUTO", "10.2.1.1", os_type="auto")
    sc.collect_server(temp_db, sid, None, None)
    assert db.get_server(temp_db, sid)["os_type"] == "linux"


# ── 서버 수정 ─────────────────────────────────────────────────────
def test_server_edit_can_change_ip_and_clear_location(cli):
    """증상: 수정 모달에서 IP를 바꿔도 무시되고, 위치는 비울 수 없었다(200 OK만)."""
    sid = cli.post("/api/servers", json={"name": "E1", "ip": "10.3.0.1",
                                         "location": "A09U27"}).get_json()["id"]
    r = cli.put("/api/servers/%d" % sid, json={"ip": "10.3.0.9", "location": ""})
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    row = [s for s in cli.get("/api/servers").get_json()["servers"] if s["id"] == sid][0]
    assert row["ip"] == "10.3.0.9", "IP 변경이 무시됐다"
    assert not row["location"], "위치를 비울 수 없다"


def test_server_edit_rejects_duplicate_ip(cli):
    a = cli.post("/api/servers", json={"name": "A", "ip": "10.3.1.1"}).get_json()["id"]
    cli.post("/api/servers", json={"name": "B", "ip": "10.3.1.2"})
    assert cli.put("/api/servers/%d" % a, json={"ip": "10.3.1.2"}).status_code == 409


def test_switch_edit_can_clear_hostname_and_location(cli):
    """증상: 잘못 들어간 호스트네임·위치를 지워도 200 OK만 뜨고 값이 남았다."""
    sid = cli.post("/api/switches/manual",
                   json={"name": "SW", "ip": "10.4.0.1", "vendor": "cisco_ios",
                         "hostname": "H1", "location": "LOC1"}).get_json()["switch_id"]
    assert cli.put("/api/switches/%d" % sid,
                   json={"hostname": "", "location": ""}).status_code == 200
    sw = [s for s in cli.get("/api/state").get_json()["switches"] if s["id"] == sid][0]
    assert not sw.get("hostname"), "호스트네임이 안 지워졌다"
    assert not sw.get("location"), "위치가 안 지워졌다"


def test_switch_name_survives_blank_edit(cli):
    """이름은 표의 주 식별자라 빈 값으로 지워지면 안 된다."""
    sid = cli.post("/api/switches/manual",
                   json={"name": "KEEP", "ip": "10.4.1.1"}).get_json()["switch_id"]
    cli.put("/api/switches/%d" % sid, json={"name": ""})
    sw = [s for s in cli.get("/api/state").get_json()["switches"] if s["id"] == sid][0]
    assert sw["name"] == "KEEP"


def test_switch_name_is_visible_in_table_and_export(cli):
    """증상: 등록한 이름이 표에도 CSV에도 없어 미수집 스위치를 IP로만 구분해야 했다."""
    cli.post("/api/switches/manual", json={"name": "1공장-A동-01", "ip": "10.4.2.1"})
    html = cli.get("/").get_data(as_text=True)
    head = html[html.index('id="sw-check-all"'):html.index('id="switch-table-body"')]
    assert ">이름</th>" in head
    csv = cli.get("/api/export/switches?fmt=csv").get_data().decode("utf-8-sig")
    assert "1공장-A동-01" in csv


# ── 설비 오탐 ─────────────────────────────────────────────────────
def test_unscanned_ips_are_not_marked_offline(temp_db):
    """증상: ping을 못 보낸 IP도 '연결 끊김'으로 찍혔다."""
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.5.0.0/29", "ip": "10.5.0.%d" % i, "mac": "aa:00:00:00:00:%02d" % i,
         "switch_id": None, "switch_name": None, "port": None, "online": 1,
         "direct": 0, "via": None, "port_desc": None} for i in (1, 2, 3)])
    # 1번만 실제로 확인됨 → 2·3번은 '확인 못 함'
    by_ip = {"10.5.0.1": {"subnet": "10.5.0.0/29", "ip": "10.5.0.1",
                          "mac": "aa:00:00:00:00:01", "switch_id": None,
                          "switch_name": None, "port": None, "online": 1,
                          "direct": 0, "via": None, "port_desc": None}}
    facility._apply_scan(temp_db, "10.5.0.0/29", by_ip, scanned_ips={"10.5.0.1"})
    states = {h["ip"]: h["online"] for h in db.get_facility_hosts(temp_db)}
    assert states == {"10.5.0.1": 1, "10.5.0.2": 1, "10.5.0.3": 1}, states


def test_collect_band_reports_stopped_flag():
    """전체 대역 스캔이 남은 대역을 멈추려면 중지 여부가 반환값에 있어야 한다."""
    import inspect
    src = inspect.getsource(facility.collect_band)
    assert '"stopped": stopped_at is not None' in src
    auto = inspect.getsource(facility.run_auto_scan)
    assert '.get("stopped")' in auto, "전체 스캔이 중지 결과를 확인하지 않는다"


def test_offline_debounce_needs_new_mac_snapshot(temp_db):
    """증상: MAC 스냅샷이 그대로인데 감시 주기만 2번 돌면 끊김 처리됐다(조용한 PLC 오탐)."""
    sid = db.save_switch(temp_db, "SW", "10.6.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_mac_entries(temp_db, snap, sid, [{"vlan": "1", "mac": "bb:00:00:00:00:99",
                                              "port": "Gi1/0/1"}])
    db.save_facility_hosts(temp_db, [{
        "subnet": "10.6.9.0/24", "ip": "10.6.9.10", "mac": "bb:00:00:00:00:01",
        "switch_id": None, "switch_name": None, "port": None, "online": 1,
        "direct": 0, "via": None, "port_desc": None}])
    facility._miss_counts.clear()
    for _ in range(6):                       # 같은 스냅샷으로 6주기(=6분) 감시
        facility.monitor_known_hosts(temp_db)
    assert db.get_facility_hosts(temp_db)[0]["online"] == 1, \
        "MAC 스냅샷이 안 바뀌었는데 끊김으로 처리됐다"

    # 스위치를 실제로 재수집(새 스냅샷)해 두 세대 연속 실종이면 그때 끊김
    for _ in range(facility._MISS_THRESHOLD):
        s = db.save_snapshot(temp_db, sid)
        db.save_mac_entries(temp_db, s, sid, [{"vlan": "1", "mac": "bb:00:00:00:00:99",
                                               "port": "Gi1/0/1"}])
        facility.monitor_known_hosts(temp_db)
    assert db.get_facility_hosts(temp_db)[0]["online"] == 0, "실제 끊김을 감지하지 못했다"


# ── 다중 PC 안전 ──────────────────────────────────────────────────
def test_lock_failure_does_not_grant_promotion(tmp_path):
    """증상: 락 파일을 못 열면 '획득 성공'을 돌려줘 주 서버가 둘이 될 수 있었다."""
    missing = tmp_path / "no_such_share" / "data"
    ok, info = instance_lock.acquire(str(missing), "http://x", allow_unlocked=False)
    assert ok is False, "락을 확인하지 못했는데 승격을 허용했다"
    # 기동 시(best-effort)는 종전대로 진행 허용
    ok2, _ = instance_lock.acquire(str(missing), "http://x", allow_unlocked=True)
    assert ok2 is True


def test_lock_error_log_hides_absolute_path():
    """netdash.log는 공유폴더에 쌓인다 — 내부 경로가 그대로 남으면 안 된다."""
    msg = instance_lock._safe_err(
        OSError(2, "No such file or directory",
                r"Z:\share\netdash_data\netdash_server.lock"))
    assert "netdash_data" not in msg and "Z:\\" not in msg, msg


def test_promote_releases_lock_on_failure():
    import inspect
    import app as _app
    src = inspect.getsource(_app._watch_and_promote)
    assert "instance_lock.release()" in src, \
        "승격 실패 시 락을 놓지 않으면 어떤 PC도 주 서버가 될 수 없다"
    assert "allow_unlocked=False" in src


# ── 재시작 복구 ───────────────────────────────────────────────────
def test_stale_collecting_reset_covers_servers_and_firewalls(temp_db):
    """증상: 재시작 후에도 서버·방화벽에 '수집중' 뱃지가 영구히 남았다."""
    sid = db.save_server(temp_db, "S", "10.7.0.1")
    db.update_server(temp_db, sid, status="collecting")
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.7.0.2", 443)
    db.set_firewall_status(temp_db, fid, "collecting")
    swid = db.save_switch(temp_db, "SW", "10.7.0.3", "cisco_ios")
    db.set_switch_status(temp_db, swid, "collecting")

    db.reset_stale_collecting(temp_db)
    assert db.get_server(temp_db, sid)["status"] == "failed"
    assert db.get_firewall(temp_db, fid)["status"] == "failed"
    assert [s for s in db.get_switches(temp_db) if s["id"] == swid][0]["status"] == "failed"


# ── 조용한 실패 ───────────────────────────────────────────────────
def test_collect_and_delete_report_failures():
    """증상: 개별 수집·삭제가 423/409/404에도 아무 안내 없이 조용히 끝났다."""
    # 파일 내 정의 순서에 의존하지 않도록 각 함수 시작점에서 일정 범위만 본다
    for fn, label in (("function collectSwitch(", "개별 수집"),
                      ("function deleteSwitch(", "개별 삭제")):
        i = APPJS.index(fn)
        block = APPJS[i:i + 1400]
        assert "res.ok" in block, label + " 실패가 사용자에게 전달되지 않는다"
        assert "alert(" in block, label + " 실패 시 알림이 없다"


def test_downloads_do_not_navigate_away():
    """증상: 다운로드가 404/500이면 브라우저가 JSON 페이지로 이동해 화면이 날아갔다."""
    assert "function downloadFile(" in APPJS
    assert 'window.location = "/api/' not in APPJS, "직접 이동하는 다운로드가 남아 있다"


def test_server_selection_buttons_resync_on_render():
    block = APPJS[APPJS.index("function renderServers("):]
    block = block[:block.index("\n(function ()")]
    assert "_updateSrvSelBtns()" in block, "재렌더 후 선택 개수가 어긋난 채 남는다"


# ── 알림 유실 ─────────────────────────────────────────────────────
def test_failed_email_is_retried_not_dropped():
    import inspect
    from core import notifier
    src = inspect.getsource(notifier._loop)
    assert "if sent:" in src and "_PENDING_MAX" in src, \
        "발송 실패 시 알람을 버리면 이메일 알림이 영영 안 간다"
