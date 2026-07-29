# -*- coding: utf-8 -*-
"""백로그 B-1·B-2 — '진단'이 실제로는 수집이던 문제.

증상(수정 전):
  · 서버 "전체 진단"은 "계정 없이 확인합니다"라고 안내하면서 collect-all을 호출해
    세션 계정·서버별 저장 계정으로 실제 SSH 접속을 했다.
  · 방화벽 "전체 진단"은 collect-all을 호출해 인터페이스·ARP를 덮어쓰고 status를 바꿨다.
"""
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc

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


# ── 서버 진단은 계정을 쓰지 않는다 ────────────────────────────────
def test_no_cred_skips_saved_credentials(temp_db, monkeypatch):
    """저장 계정이 있어도 진단(no_cred)에서는 쓰지 않아야 한다."""
    from core import credentials
    sid = db.save_server(temp_db, "S", "10.70.0.1")
    blob = credentials.encrypt_credential("root", "pw")
    if blob:                                  # 비Windows에서는 저장 자체가 안 됨
        db.update_server_cred(temp_db, sid, blob)

    seen = []
    monkeypatch.setattr(sc, "collect_server",
                        lambda dbp, i, u=None, p=None: seen.append((u, p)) or {"status": "done"})
    sc.collect_all_servers(db_path=temp_db, no_cred=True)
    assert seen == [(None, None)], "진단인데 계정이 넘어갔다: %r" % (seen,)


def test_normal_collect_still_uses_saved_credentials(temp_db, monkeypatch):
    """분리했다고 정상 수집에서까지 저장 계정을 안 쓰면 안 된다."""
    from core import credentials
    sid = db.save_server(temp_db, "S", "10.70.0.2")
    blob = credentials.encrypt_credential("root", "pw")
    if not blob:
        pytest.skip("DPAPI 미지원 환경")
    db.update_server_cred(temp_db, sid, blob)
    seen = []
    monkeypatch.setattr(sc, "collect_server",
                        lambda dbp, i, u=None, p=None: seen.append((u, p)) or {"status": "done"})
    sc.collect_all_servers(db_path=temp_db)
    assert seen == [("root", "pw")]


def test_no_cred_ignores_common_credentials(temp_db, monkeypatch):
    seen = []
    db.save_server(temp_db, "S", "10.70.0.3")
    monkeypatch.setattr(sc, "collect_server",
                        lambda dbp, i, u=None, p=None: seen.append((u, p)) or {"status": "done"})
    sc.collect_all_servers(db_path=temp_db, common_user="u", common_pass="p", no_cred=True)
    assert seen == [(None, None)]


def test_diagnose_all_endpoint_uses_no_cred(cli, monkeypatch):
    """엔드포인트가 실제로 no_cred=True를 넘기는지."""
    cli.post("/api/servers", json={"name": "S", "ip": "10.70.1.1"})
    cli.post("/api/session/credential",
             json={"username": "srv", "password": "pw", "kind": "server"})
    captured = {}
    from core import server_collector
    monkeypatch.setattr(server_collector, "collect_all_servers",
                        lambda **kw: captured.update(kw) or {"done": 0})
    assert cli.post("/api/servers/diagnose-all").status_code == 202
    time.sleep(0.3)
    assert captured.get("no_cred") is True, captured
    assert not captured.get("common_user"), "세션 계정이 진단에 넘어갔다"


def test_diagnose_all_does_not_touch_specs(cli, monkeypatch):
    """진단이 수집해 둔 사양(CPU·메모리·장착구성)을 지우면 안 된다."""
    from core import server_collector
    monkeypatch.setattr(server_collector, "scan_ports",
                        lambda ip, ports=None, timeout=1.0: [22])
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(server_collector, "netbios_name", lambda ip, timeout=2: "")
    sid = cli.post("/api/servers", json={"name": "S", "ip": "10.70.2.1"}).get_json()["id"]
    p = Path.cwd() / "netdash.db"
    db.update_server(p, sid, cpu_model="Xeon", cpu_cores=16, mem_total_mb=65536,
                     mem_modules=json.dumps([{"size_mb": 32768, "type": "DDR4"}]),
                     mem_slots_total=4)
    assert cli.post("/api/servers/diagnose-all").status_code == 202
    # 무자격 경로도 네트워크를 탄다 — 로컬 ARP(~0.4초)와 SNMP 폴백(2초 타임아웃
    # ×2회 = ~4초)이 실측으로 걸린다. 4초만 기다리면 경합으로 간헐 실패한다.
    for _ in range(150):
        time.sleep(0.1)
        if not server_collector.get_progress().get("running"):
            break
    row = db.get_server(p, sid)
    assert row["cpu_cores"] == 16 and row["mem_total_mb"] == 65536
    assert len(json.loads(row["mem_modules"])) == 1
    assert row["open_ports"], "진단이 무자격 정보(열린 포트)는 갱신해야 한다"


def test_diagnose_all_rejects_when_busy(cli, monkeypatch):
    from core import server_collector
    monkeypatch.setattr(server_collector, "get_progress", lambda: {"running": True})
    assert cli.post("/api/servers/diagnose-all").status_code == 409


# ── 방화벽 진단은 수집하지 않는다 ─────────────────────────────────
def test_firewall_diagnose_does_not_overwrite_data(cli, monkeypatch):
    from core import connectivity
    monkeypatch.setattr(connectivity, "test_tcp",
                        lambda host, port, timeout=3, source_ip=None: True)
    monkeypatch.setattr(connectivity, "test_firewall",
                        lambda *a, **k: {"ok": True, "stage": "auth", "detail": "연결 및 인증 성공"})
    fid = cli.post("/api/firewalls",
                   json={"name": "FW", "vendor": "fortigate", "host": "10.71.0.1",
                         "port": 443}).get_json()["firewall_id"]
    p = Path.cwd() / "netdash.db"
    db.save_firewall_interfaces(p, fid, [{"name": "port1", "ip": "10.71.0.1",
                                          "mask": "255.255.255.0", "vdom_zone": "root"}])
    db.set_firewall_status(p, fid, "done")

    assert cli.post("/api/firewalls/diagnose-all").status_code == 202
    for _ in range(40):
        time.sleep(0.1)
        if not cli.get("/api/firewalls/diagnose-all/status").get_json().get("running"):
            break
    s = cli.get("/api/firewalls/diagnose-all/status").get_json()
    assert s["done"] >= 1 and s["results"], s
    r = s["results"][0]
    assert r["tcp_mgmt"] is True and r["auth_ok"] is True
    # 수집을 하지 않았으므로 인터페이스와 상태는 그대로
    detail = cli.get("/api/firewalls/%d" % fid).get_json()
    assert len(detail.get("interfaces") or []) == 1, "진단이 인터페이스를 덮어썼다"
    assert db.get_firewall(p, fid)["status"] == "done", "진단이 상태를 바꿨다"


def test_firewall_diagnose_rejects_concurrent(cli):
    import app as _app
    with _app._fw_diag_lock:
        _app._fw_diag["running"] = True
    try:
        assert cli.post("/api/firewalls/diagnose-all").status_code == 409
    finally:
        with _app._fw_diag_lock:
            _app._fw_diag["running"] = False


# ── 화면이 진단 경로를 부르는가 ───────────────────────────────────
def test_ui_calls_diagnose_endpoints_not_collect():
    assert '"/api/servers/diagnose-all"' in APPJS
    assert '"/api/firewalls/diagnose-all"' in APPJS
    # 진단 버튼 블록에서 collect-all을 부르지 않는다
    i = APPJS.index("btn-server-diagnose")
    assert "/api/servers/collect-all\"" not in APPJS[i:i + 900], \
        "서버 전체 진단이 여전히 수집을 호출한다"
    j = APPJS.index("btn-fw-diagnose-all")
    assert "/api/firewalls/collect-all\"" not in APPJS[j:j + 900], \
        "방화벽 전체 진단이 여전히 수집을 호출한다"


def test_ui_states_that_diagnose_skips_ssh():
    i = APPJS.index("btn-server-diagnose")
    assert "SSH 접속은 하지 않으므로" in APPJS[i:i + 900]
    j = APPJS.index("btn-fw-diagnose-all")
    assert "수집은 하지 않습니다" in APPJS[j:j + 900]
