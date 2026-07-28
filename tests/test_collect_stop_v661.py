# -*- coding: utf-8 -*-
"""'수집 중지'가 먹지 않던 문제 (v6.6.1).

사용자 보고: "수집 중일 때 수집 중지를 누르면 수집 중지가 안 되는데?"

원인 두 가지.
① 설비 대역 스캔: `start_collect_band` 가 running=True로 만들고 스레드를 띄운 뒤,
   워커가 `collect_band` 진입 시 `_stop_requested = False` 로 **초기화**했다.
   그 사이에 누른 중지는 요청이 True로 접수되고도 통째로 지워져, /23 대역이면
   15분 넘게 계속 돌았다.
② 화면: 진행바를 1.5초마다 다시 그리면서 '⏹ 수집 중지' 버튼을 **새로 만들어**,
   눌러도 아무 일 없는 것처럼 보였다(실제로는 접수돼 마무리 중).
"""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import facility, server_collector as sc  # noqa: E402

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


# ── ① 설비: 시작 직후 중지 경합 ──────────────────────────────────
def test_stop_right_after_start_is_not_swallowed(monkeypatch):
    seen = {}

    def fake_band(*a, **k):
        time.sleep(0.25)                      # 스레드 진입 지연
        for i in range(40):
            if facility._is_stop_requested():
                seen["at"] = i
                with facility._lock:
                    facility._status["running"] = False
                return {"stopped": True}
            time.sleep(0.05)
        seen["at"] = None
        with facility._lock:
            facility._status["running"] = False
        return {"stopped": False}

    with facility._lock:
        facility._status["running"] = False
    facility._stop_requested = False
    monkeypatch.setattr(facility, "collect_band", fake_band)
    assert facility.start_collect_band("db", 1, "10.0.0.0/29", "u", "p") is True
    time.sleep(0.05)
    assert facility.request_stop() is True
    time.sleep(2.5)
    assert seen.get("at") is not None, "중지 요청이 지워져 스캔이 끝까지 돌았다"


def test_collect_band_does_not_reset_stop_flag():
    src = (ROOT / "core" / "facility.py").read_text(encoding="utf-8")
    i = src.index("def collect_band(")
    body = src[i:i + 6000]
    assert "_stop_requested = False   # 새 스캔 시작" not in body, \
        "워커가 플래그를 초기화하면 시작 직후의 중지가 사라진다"


def test_start_resets_stop_flag_before_thread():
    src = (ROOT / "core" / "facility.py").read_text(encoding="utf-8")
    i = src.index("def start_collect_band(")
    body = src[i:i + 2000]
    assert "_stop_requested = False" in body
    assert body.index("_stop_requested = False") < body.index("threading.Thread"), \
        "스레드를 띄운 뒤에 초기화하면 경합이 남는다"


# ── 중지 요청 상태 노출 ─────────────────────────────────────────
def test_facility_status_exposes_stopping():
    with facility._lock:
        facility._status.update(running=True)
    facility._stop_requested = True
    try:
        assert facility.get_status().get("stopping") is True
    finally:
        facility._stop_requested = False
        with facility._lock:
            facility._status.update(running=False)
    assert facility.get_status().get("stopping") is False


def test_server_progress_exposes_stopping():
    with sc._prog_lock:
        sc._progress.update(running=True)
    sc._stop = True
    try:
        assert sc.get_progress().get("stopping") is True
    finally:
        sc._stop = False
        with sc._prog_lock:
            sc._progress.update(running=False)


def test_switch_and_firewall_status_expose_stopping():
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    i = src.index("def bulk_collect_status(")
    assert '"stopping"' in src[i:i + 1200]
    j = src.index("def collect_all_firewalls_status(")
    assert 'st["stopping"]' in src[j:j + 500]


# ── ② 화면: 중지 후 버튼이 되살아나지 않는다 ────────────────────
def test_progress_bar_keeps_stopping_state():
    i = APPJS.index("var stopBtn =")
    body = APPJS[i:i + 900]
    assert "st.stopping" in body, "중지 요청 뒤에도 버튼을 새로 그리면 안 먹은 것처럼 보인다"
    assert "중지 중…" in body and "disabled" in body


def test_stop_button_hidden_when_not_running():
    i = APPJS.index("var stopBtn =")
    body = APPJS[i:i + 900]
    assert "st.running && stopUrl" in body


# ── 서버실 위치 표기 통일 ───────────────────────────────────────
def test_serverroom_location_unified_label():
    """'D10랙 U40' 처럼 화면마다 다르던 라벨 → '서버실 (D10U40)' 로 통일."""
    i = APPJS.index("function locationCell(")
    body = APPJS[i:i + 900]
    assert '"서버실"' in body, "서버실 통일 표기가 없다"
    assert "cell-inline" in body, "원문 코드를 같은 줄에 병기해야 한다"
    assert "room_rack" in body


def test_firewall_uses_shared_location_cell():
    i = APPJS.index("tbody.innerHTML = firewalls.map(")
    body = APPJS[i:i + 900]
    assert "locationCell(f)" in body
    assert "room_label" not in body, "방화벽만 다른 규칙을 쓰면 또 갈린다"


def test_cell_inline_class_defined():
    css = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")
    assert ".cell-inline" in css


# ── 방화벽 이중화 역할 ──────────────────────────────────────────
def test_ha_role_from_name_suffix():
    from app import fw_ha_role
    for name, role in [("FW_M", "master"), ("FW_B", "backup"),
                       ("FW1", "master"), ("FW2", "backup"),
                       ("FW01", "master"), ("FW02", "backup"),
                       ("FW-Master", "master"), ("FW-Backup", "backup"),
                       ("FW-Active", "master"), ("FW-Standby", "backup")]:
        assert fw_ha_role(name) == role, name
    assert fw_ha_role("FW") is None


def test_real_ha_info_beats_name_rule():
    """장비에서 수집한 실제 HA 상태가 이름 규칙보다 우선한다."""
    from app import fw_ha_role
    assert fw_ha_role("FW2", "", {"role": "master"}) == "master"
    assert fw_ha_role("FW1", "", {"state": "backup"}) == "backup"


def test_ha_role_annotated_for_shared_ip_pair():
    from app import annotate_fw_ha
    rows = [{"id": 1, "name": "FW1", "host": "10.5.5.1", "status": "done"},
            {"id": 2, "name": "FW2", "host": "10.5.5.1", "status": "failed"}]
    annotate_fw_ha(rows)
    assert rows[0]["ha_role"] == "master" and rows[1]["ha_role"] == "backup"
    assert rows[1]["status_display"] == "done"


def test_ha_role_not_set_for_standalone():
    """단독 장비에 숫자 접미사만으로 역할을 붙이면 오해를 만든다."""
    from app import annotate_fw_ha
    rows = [{"id": 1, "name": "FW01", "host": "10.5.5.9", "status": "done"}]
    annotate_fw_ha(rows)
    assert rows[0].get("ha_role") is None


def test_ha_role_badge_rendered():
    assert "f.ha_role" in APPJS and "Master" in APPJS and "Backup" in APPJS


# ── 서버 SSH 터미널 제거 ────────────────────────────────────────
def test_server_ssh_terminal_removed():
    """서버는 SSH 포트가 막힌 경우가 많아 이 버튼이 무의미하다(사용자 요청)."""
    assert "terminal-server" not in APPJS
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    srv_head = html[html.index('id="srv-check-all"'):html.index('id="server-table-body"')]
    assert "SSH 터미널" not in srv_head


def test_switch_and_firewall_terminal_kept():
    """스위치·방화벽의 터미널은 그대로 있어야 한다(과잉 제거 방지)."""
    assert "terminal-switch" in APPJS and "terminal-fw" in APPJS


# ── 사양 미수집 진단 ────────────────────────────────────────────
def test_spec_empty_leaves_diagnostic_hint():
    src = (ROOT / "core" / "server_collector.py").read_text(encoding="utf-8")
    assert "server_spec_empty" in src
    assert "_spec_hint" in src, "왜 사양이 비었는지 화면에 남지 않으면 진단이 불가능하다"
    i = src.index('_hint = d.pop("_spec_hint", None)')
    assert "errors.append(_hint)" in src[i:i + 200]


# ── 서버 일괄 수집: 중지가 실제로 남은 대상을 건너뛴다 ──────────
def test_server_bulk_stop_skips_remaining(temp_db, monkeypatch):
    from core import db
    for i in range(12):
        db.save_server(temp_db, "SRV-%02d" % i, "10.60.0.%d" % (i + 1))
    tried = []

    def slow(dbp, sid, u, pw):
        tried.append(sid)
        time.sleep(0.4)
        return {"status": "done"}

    monkeypatch.setattr(sc, "collect_server", slow)
    th = threading.Thread(target=sc.collect_all_servers,
                          kwargs={"db_path": temp_db, "max_workers": 4}, daemon=True)
    th.start()
    time.sleep(0.2)
    assert sc.request_stop() is True
    th.join(timeout=20)
    assert len(tried) < 12, "중지 후에도 전부 수집했다(%d대)" % len(tried)
    assert "중지됨" in sc.get_progress().get("message", "")
