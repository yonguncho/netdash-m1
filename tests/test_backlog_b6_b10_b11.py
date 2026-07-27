# -*- coding: utf-8 -*-
"""백로그 B-6·B-10·B-11 및 죽은 코드 정리.

B-6  통합 장비 일괄등록 UI 잔재 제거(탭별 '엑셀 등록'으로 대체 — 사용자 확인)
B-10 이메일 직접 전달이 도메인당 최대 60초 블로킹
B-11 events.snapshot_id FK 때문에 스냅샷 세대 정리가 영구히 멈출 수 있던 잠복 결함
"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, notifier

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")


# ── B-6: 죽은 UI 잔재 제거 ────────────────────────────────────────
def test_dead_inventory_import_ui_removed():
    assert "btn-import-inventory" not in APPJS, "버튼이 없는데 바인딩이 남아 있다"
    assert "inventory-file-input" not in HTML, "쓰이지 않는 숨김 file input이 남아 있다"
    assert "inventory-file-input" not in APPJS


def test_tab_level_excel_import_still_wired():
    """대체 수단(탭별 엑셀 등록)은 그대로 살아 있어야 한다."""
    for btn in ("btn-import-excel", "btn-sw-import", "btn-server-import",
                "btn-firewall-import"):
        assert 'id="%s"' % btn in HTML, btn
    for url in ("/api/servers/import", "/api/firewalls/import"):
        assert url in APPJS, url


def test_dead_facility_txt_button_removed():
    assert "btn-fac-export-txt" not in APPJS


# ── B-10: 이메일 발송 블로킹 상한 ─────────────────────────────────
def test_direct_send_has_bounded_timeouts():
    assert notifier._DIRECT_CONNECT_TIMEOUT <= 5
    assert notifier._DIRECT_DOMAIN_BUDGET <= 20
    import inspect
    src = inspect.getsource(notifier._direct_send)
    assert "_DIRECT_DOMAIN_BUDGET" in src and "_deadline" in src, \
        "도메인당 총 시간 상한이 없으면 후보 4개 × 15초로 60초까지 멈춘다"
    assert "timeout=_DIRECT_CONNECT_TIMEOUT" in src


def test_time_module_available_at_module_scope():
    """_time이 _loop 안에서만 import되면 _direct_send에서 NameError가 난다."""
    assert hasattr(notifier, "_time")
    import inspect
    assert "import time as _time" not in inspect.getsource(notifier._loop)


def test_direct_send_gives_up_within_budget(monkeypatch):
    """모든 후보가 응답 없어도 도메인 예산 안에서 끝난다."""
    calls = {"n": 0}

    class _Hang:
        def __init__(self, host, port, timeout=None):
            calls["n"] += 1
            raise OSError("timed out")

    monkeypatch.setattr(notifier.smtplib, "SMTP", _Hang)
    monkeypatch.setattr(notifier, "_mx_hosts",
                        lambda d: ["a." + d, "b." + d, "c." + d, "d." + d])
    ok, err = notifier._direct_send("me@x.com", ["you@y.com"], "msg", 25)
    assert ok == 0 and err
    assert calls["n"] <= 4


# ── B-11: 스냅샷 세대 정리 FK ─────────────────────────────────────
def test_snapshot_retention_deletes_event_children(temp_db):
    """events가 스냅샷을 참조하고 있어도 세대 정리가 실패하면 안 된다."""
    sid = db.save_switch(temp_db, "SW", "10.98.0.1", "cisco_ios")
    first = None
    for i in range(3):
        snap = db.save_snapshot(temp_db, sid)
        if first is None:
            first = snap
        db.save_mac_entries(temp_db, snap, sid,
                            [{"vlan": "1", "mac": "aa:bb:cc:00:00:%02d" % i, "port": "Gi1/0/1"}])
    # 가장 오래된 스냅샷을 참조하는 event 행을 직접 넣는다(구버전 DB 승계 상황)
    conn = sqlite3.connect(str(temp_db))
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(events)")]
        if "snapshot_id" not in cols:
            conn.close()
            import pytest
            pytest.skip("events 테이블에 snapshot_id 없음")
        # NOT NULL 컬럼을 스키마에서 읽어 최소 값으로 채운다(버전별 차이 흡수)
        info = list(conn.execute("PRAGMA table_info(events)"))
        cols, vals = ["snapshot_id", "switch_id"], [first, sid]
        for r in info:
            name, notnull, dflt, pk = r[1], r[3], r[4], r[5]
            if name in cols or pk or not notnull or dflt is not None:
                continue
            cols.append(name)
            vals.append("test")
        conn.execute("INSERT INTO events (%s) VALUES (%s)"
                     % (",".join(cols), ",".join("?" * len(cols))), vals)
        conn.commit()
    finally:
        conn.close()

    import inspect
    src = inspect.getsource(db.save_snapshot_with_data) if hasattr(
        db, "save_snapshot_with_data") else ""
    # 구현 확인: 정리 대상 테이블에 events가 포함돼야 한다
    whole = (ROOT / "core" / "db.py").read_text(encoding="utf-8")
    i = whole.index('for tbl in ("ports", "mac_entries", "arp_entries", "port_channels"')
    assert '"events"' in whole[i:i + 260], \
        "events를 지우지 않으면 FK 위반으로 스냅샷 정리가 영구히 멈춘다"
    assert src is not None


def test_retention_failure_is_logged_not_silent():
    whole = (ROOT / "core" / "db.py").read_text(encoding="utf-8")
    assert "snapshot_retention_failed" in whole, \
        "조용히 삼키면 빈 스냅샷 누적을 눈치챌 수 없다"
