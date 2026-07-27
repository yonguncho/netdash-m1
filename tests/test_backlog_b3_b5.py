# -*- coding: utf-8 -*-
"""백로그 B-3·B-5.

B-3 토폴로지 '서버실 불러오기'가 저장된 구성도를 자동 덮어썼다(되돌리기 없음).
B-5 스위치 일괄 수집에 진행바도 '수집 중지'도 없었다(200대를 걸면 alert 한 번이 전부).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, db

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
APPPY = (ROOT / "app.py").read_text(encoding="utf-8")


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


# ── B-3 ───────────────────────────────────────────────────────────
def test_load_from_serverroom_snapshots_before_replacing():
    i = APPJS.index('id="btn-topo-draft"') if 'id="btn-topo-draft"' in APPJS \
        else APPJS.index("btn-topo-draft")
    block = APPJS[i:i + 1800]
    assert "_tSnapshotForUndo()" in block, "되돌릴 스냅샷 없이 교체한다"
    assert "_tSuppressSave = true" in block, \
        "불러오기 직후 자동 저장이 서버 구성도를 덮어쓴다"


def test_autosave_is_suppressible_and_respects_readonly():
    i = APPJS.index("function _tAutoSave(")
    block = APPJS[i:i + 700]
    assert "_tSuppressSave" in block
    assert "window._ndReadOnly" in block, "읽기 전용인데 저장을 계속 시도한다"


def test_clear_also_snapshots():
    i = APPJS.index('getElementById("btn-topo-clear")')
    block = APPJS[i:i + 700]
    assert "_tSnapshotForUndo()" in block


def test_undo_button_exists_and_wired():
    assert 'id="btn-topo-undo"' in HTML
    assert "function _tRestoreUndo(" in APPJS
    i = APPJS.index('getElementById("btn-topo-undo")')
    assert "_tRestoreUndo()" in APPJS[i:i + 400]


def test_confirm_text_is_honest():
    i = APPJS.index("btn-topo-draft")
    block = APPJS[i:i + 1200]
    assert "저장된 구성도" in block, "저장본도 바뀐다는 사실을 알리지 않는다"
    assert "저장 전이면 사라집니다" not in block, "사실과 다른 안내가 남아 있다"


def test_readonly_flag_is_set_by_banner():
    assert "window._ndReadOnly = true" in APPJS
    assert "window._ndReadOnly = false" in APPJS


# ── B-5 ───────────────────────────────────────────────────────────
def test_bulk_collect_status_and_stop_routes_exist():
    assert '"/api/switches/bulk-collect/status"' in APPPY
    assert '"/api/switches/bulk-collect/stop"' in APPPY


def test_status_reports_not_running_before_any_batch(cli):
    s = cli.get("/api/switches/bulk-collect/status").get_json()
    assert s["running"] is False and s["total"] == 0


def test_stop_without_batch_is_rejected(cli):
    r = cli.post("/api/switches/bulk-collect/stop")
    assert r.status_code == 400, r.get_data(as_text=True)[:120]


def test_cancel_pending_clears_queue_and_flags(temp_db, monkeypatch):
    """대기 중인 작업을 비우고 '수집 중' 표시를 풀어 재수집이 가능해야 한다."""
    collector.init_collector()
    # 워커가 바로 집어가지 않도록 큐만 직접 채운다
    sid = db.save_switch(temp_db, "SW", "10.99.0.1", "cisco_ios")
    db.set_switch_status(temp_db, sid, "collecting")
    with collector._collector_lock:
        collector._collecting_switches.add(sid)
    collector._worker_queue.put_nowait((temp_db, sid))

    n = collector.cancel_pending()
    assert n >= 1
    assert sid not in collector.collecting_ids(), "'수집 중' 표시가 남아 재수집이 막힌다"
    row = [s for s in db.get_switches(temp_db) if s["id"] == sid][0]
    assert row["status"] != "collecting"


def test_cancel_pending_is_safe_when_empty():
    collector.init_collector()
    assert collector.cancel_pending() == 0


def test_collecting_ids_returns_copy():
    collector.init_collector()
    got = collector.collecting_ids()
    got.add(999999)
    assert 999999 not in collector.collecting_ids(), "내부 집합이 그대로 새어나온다"


def test_ui_shows_progress_and_stop():
    i = APPJS.index("function _runBulkCollect(")
    block = APPJS[i:i + 1600]
    assert "/api/switches/bulk-collect/status" in block
    assert "/api/switches/bulk-collect/stop" in block
    assert 'id="sw-bulk-progress"' in HTML
