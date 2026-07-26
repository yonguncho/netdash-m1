# -*- coding: utf-8 -*-
"""수집 상태 플래그 해제 보장 — 예외가 나도 '이미 수집 중'에 갇히지 않아야 한다.

배경: 일괄 수집은 백그라운드 스레드에서 돈다. 스레드가 예외로 죽으면 running 플래그가
True로 남고, 이후 모든 수집 요청이 409("이미 수집 중입니다")로 영구 거부된다.
DB 잠금(unable to open database file)처럼 현장에서 실제로 나는 오류에서 재현된다.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import app as app_mod
from core import db


def _boom(*a, **k):
    raise RuntimeError("db locked: unable to open database file")


def test_firewall_bulk_releases_running_on_error(monkeypatch):
    """방화벽 일괄 수집 중 예외 → running 플래그가 반드시 해제된다."""
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_firewall(dbp, "FW-ERR", "fortigate", "10.90.0.1", port=443)

    # 상태 갱신이 실패하는 상황(현장 db_error) 재현
    monkeypatch.setattr(app_mod.db, "set_firewall_status", _boom)
    app_mod._fw_all.update(running=True, total=1, done=0, ok=0,
                           message="시작 중", stop=False)

    app_mod._run_collect_all_firewalls(dbp, None)

    assert app_mod._fw_all["running"] is False, \
        "예외 후 running이 True로 남아 다음 수집이 영구 409가 됨"


def test_firewall_bulk_releases_running_on_list_error(monkeypatch):
    """목록 조회 자체가 실패해도 running이 해제된다."""
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    monkeypatch.setattr(app_mod.db, "list_firewalls", _boom)
    app_mod._fw_all.update(running=True, total=0, done=0, ok=0,
                           message="시작 중", stop=False)

    app_mod._run_collect_all_firewalls(dbp, None)

    assert app_mod._fw_all["running"] is False


def test_firewall_bulk_can_restart_after_error(monkeypatch, client):
    """예외로 끝난 뒤에도 다음 수집 요청이 409가 아니라 수락된다."""
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_firewall(dbp, "FW-ERR2", "fortigate", "10.90.0.2", port=443)

    monkeypatch.setattr(app_mod.db, "set_firewall_status", _boom)
    app_mod._fw_all.update(running=True, total=1, done=0, ok=0,
                           message="시작 중", stop=False)
    app_mod._run_collect_all_firewalls(dbp, None)

    r = client.post("/api/firewalls/collect-all", json={})
    assert r.status_code == 202, "예외 후 재시작이 막힘: %s" % r.get_data(as_text=True)
    client.post("/api/firewalls/collect-all/stop")


def test_notifier_queue_full_is_recorded(monkeypatch):
    """알람 큐가 가득 차면 조용히 버리지 않고 흔적(집계+로그)을 남긴다."""
    import queue as _q

    from core import notifier

    monkeypatch.setattr(notifier, "_queue", _q.Queue(maxsize=1))
    monkeypatch.setattr(notifier, "_dropped", 0)
    logged = []
    monkeypatch.setattr(notifier.utils, "log_event",
                        lambda *a, **k: logged.append((a, k)))

    notifier.notify({"kind": "device_offline"})     # 큐에 들어감
    notifier.notify({"kind": "device_offline"})     # 포화 → 버려짐

    assert notifier.dropped_count() == 1, "유실 집계가 되지 않음"
    assert any("notifier_queue_full" in str(a) for a, _ in logged), "유실 로그 없음"
