# -*- coding: utf-8 -*-
"""방화벽 현황 단순화 + get system status + EOS/EoES 수명주기 (v6.25.0).

사용자 요청: 방화벽 현황은 리스트만(상단 통계·부하·온도 컬럼 제거),
모델·버전 컬럼을 get sys status 기준으로. 보유 모델 1000D/1500D/1100E와
FortiOS 6.0~7.4의 수명주기 조사·표시.
"""
import datetime
from pathlib import Path

from core import fortilifecycle as lc
from core.firewall import fortiperf

ROOT = Path(__file__).parent.parent
TODAY = datetime.date(2026, 8, 4)     # 표 작성 기준일과 같은 날로 고정(만료 계산 안정)


# --- 내장 수명주기 표 (조사 출처는 모듈 docstring에 기록) ---------------------

def test_hw_1000d_supported_until_2028():
    r = lc.lookup("FortiGate-1000D", None, today=TODAY)
    assert r["hw"]["eos"] == "2028-04-16" and r["hw"]["eoo"] == "2023-04-16"
    assert r["hw"]["status"] == "ok"


def test_hw_1500d_already_expired():
    """1500D는 2025-04-15로 이미 하드웨어 지원 종료 — 사용자에게 중요한 발견."""
    r = lc.lookup("FG-1500D", None, today=TODAY)
    assert r["hw"]["status"] == "expired"
    assert "2025-04-15" in r["hw"]["message"]
    assert r["level"] == "expired"


def test_hw_1100e_no_published_dates():
    """1100E는 수명주기 미발표(작성 시점 지원 중) — 추측해서 날짜를 만들지 않는다."""
    r = lc.lookup("FortiGate-1100E", None, today=TODAY)
    assert r["hw"]["eos"] is None and r["hw"]["status"] == "unknown"
    assert "미발표" in r["hw"]["message"]


def test_os_branches():
    cases = {
        "v6.0.9": ("2022-09-29", "expired"),
        "v6.2.12": ("2023-09-28", "expired"),
        "v6.4.15": ("2024-09-30", "expired"),
        "v7.0.14": ("2025-09-30", "expired"),     # 오늘(2026-08) 기준 이미 지남
        "v7.2.5,build1517": ("2026-09-30", "imminent"),   # 57일 남음
        "v7.4.4": ("2027-11-11", "eoes_passed"),  # EoES 2026-05-11 지남
    }
    for ver, (eos, status) in cases.items():
        r = lc.lookup(None, ver, today=TODAY)
        assert r["os"]["eos"] == eos, ver
        assert r["os"]["status"] == status, (ver, r["os"])


def test_unknown_model_returns_nothing_not_a_guess():
    r = lc.lookup("FortiGate-9999Z", "v9.9", today=TODAY)
    assert r["hw"] is None and r["os"] is None and r["level"] == "unknown"


def test_model_normalisation_variants():
    for m in ("FortiGate-1000D", "FG-1000D", "fg_1000d", "FGT 1000D", "1000D"):
        assert lc.lookup(m, None, today=TODAY)["hw"] is not None, m


def test_as_of_date_always_included():
    """내장 표는 낡는다 — 화면이 '언제 기준인지' 보여줄 수 있어야 한다."""
    r = lc.lookup("1000D", "v7.2.1", today=TODAY)
    assert r["as_of"] == lc.AS_OF


# --- get system status 파싱 --------------------------------------------------

def test_parse_sys_status():
    out = fortiperf.parse_sys_status(
        "Version: FortiGate-1100E v7.2.5,build1517,230330 (GA.F)\n"
        "Serial-Number: FG1K1E0000000000\n"
        "Hostname: FW-HQ-01\n")
    assert out["model"] == "FortiGate-1100E" and out["version"] == "v7.2.5"
    assert out["serial"] == "FG1K1E0000000000" and out["hostname"] == "FW-HQ-01"


def test_parse_sys_status_garbage():
    assert fortiperf.parse_sys_status("Unknown action 0") == {}
    assert fortiperf.parse_sys_status("") == {}


def test_ssh_batch_includes_get_system_status(monkeypatch):
    from core.firewall import fortisensor
    seen = {}

    def fake(host, u, p, commands, port=22, timeout=20):
        seen["cmds"] = list(commands)
        return {c: "" for c in commands}
    monkeypatch.setattr(fortisensor, "_ssh_run", fake)
    fortisensor.collect_ssh_all("10.0.0.1", "a", "b")
    assert "get system status" in seen["cmds"]


def test_sys_status_model_overrides_snmp_version(temp_db, monkeypatch):
    """표기 기준은 get sys status(사용자 지정) — SNMP가 먼저 넣었어도 덮는다."""
    from core import db, collector
    from core.firewall import fortisensor
    with db.get_db(temp_db) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                           ("FW-01", "fortigate", "10.0.0.1"))
        fid = cur.lastrowid
    db.save_device_metrics(temp_db, "firewall", fid, {"version": "v7.2.5,build1517"})
    monkeypatch.setattr(fortisensor, "_ssh_run", lambda *a, **k: {
        "execute sensor list": "",
        "get system performance status": "",
        "get system status":
            "Version: FortiGate-1500D v7.0.14,build0601 (GA.M)\nHostname: FW\n"})
    collector.merge_fw_extra(temp_db, {"id": fid, "vendor": "fortigate", "host": "10.0.0.1"},
                             {}, {"username": "a", "password": "b"})
    m = db.get_device_env(temp_db, "firewall", fid)["metrics"]
    assert m["model"] == "FortiGate-1500D" and m["version"] == "v7.0.14"


# --- 방화벽 현황 단순화 -------------------------------------------------------

def test_firewall_page_has_no_dashboard():
    """상단 통계는 관제에서만 — 방화벽 현황은 리스트만(사용자 지시)."""
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="fw-dashboard"' not in html
    assert "renderFirewallDashboard" not in js


def test_firewall_table_columns_model_version_not_load_temp():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    # 방화벽 표 헤더 구간
    i = html.index('id="fw-check-all"')
    head = html[i:i + 900]
    assert ">모델</th>" in head and ">버전</th>" in head
    assert ">부하</th>" not in head and ">온도</th>" not in head
    assert "function fwModelCell" in js and "function fwVersionCell" in js
    assert "fwLoadCell(f)" not in js and "tempCell(f)" not in js


def test_firewall_list_api_carries_model_and_lifecycle(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import db, collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    with db.get_db(dbp) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                           ("FW-L", "fortigate", "10.0.0.1"))
        fid = cur.lastrowid
    db.save_device_metrics(dbp, "firewall", fid, {
        "model": "FortiGate-1500D", "version": "v7.2.5"})
    fws = application.test_client().get("/api/firewalls").get_json()["firewalls"]
    row = [f for f in fws if f["name"] == "FW-L"][0]
    assert row["fw_model"] == "FortiGate-1500D" and row["fw_version"] == "v7.2.5"
    assert row["lifecycle"]["hw"]["status"] in ("expired", "imminent")
    assert row["lifecycle"]["as_of"]


def test_lifecycle_badge_ui():
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function lifeBadge" in js
    assert "지원 종료" in js and "EOS 임박" in js
