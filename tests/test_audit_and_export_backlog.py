# -*- coding: utf-8 -*-
"""백로그 B-7·B-18·B-19 — 감사 로그 누락, 내보내기와 화면 불일치."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, exporter

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


def _labels(cli):
    rows = cli.get("/api/audit").get_json()
    rows = rows.get("logs") if isinstance(rows, dict) else rows
    return [r.get("action") or r.get("label") for r in (rows or [])]


# ── B-7: 파괴적 작업·목록 유출 경로가 감사 로그에 없었다 ──────────
def test_destructive_and_export_actions_are_audited(cli):
    p = Path.cwd() / "netdash.db"
    db.save_switch(p, "SW", "10.90.0.1", "cisco_ios")
    cli.post("/api/session/credential",
             json={"username": "u", "password": "p", "kind": "switch"})
    cli.get("/api/export/switches?fmt=csv")
    cli.post("/api/session/credential/lock", json={})

    labels = " ".join(str(x) for x in _labels(cli))
    assert "세션 수집 계정 보관" in labels, "계정 보관이 기록되지 않는다"
    assert "목록 다운로드" in labels, "전체 자산 목록 다운로드가 기록되지 않는다"
    assert "세션 수집 계정 잠금" in labels


def test_audit_labels_cover_backlog_paths():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    head = src[src.index("def _audit_label"):src.index("def audit_request")]
    for path in ("/api/facility/delete-subnet", "/api/switches/bulk-set-type",
                 "/api/session/credential", "/api/export/",
                 "/api/serverroom/export", "/api/report/pptx",
                 "/api/servers/diagnose-all", "/api/firewalls/diagnose-all"):
        assert path in head, path


# ── B-18: 스위치 내보내기 '위치'가 화면 값과 달랐다 ───────────────
def test_switch_export_has_raw_location_for_lookup(temp_db):
    sid = db.save_switch(temp_db, "SW", "10.90.1.1", "cisco_ios")
    db.update_switch(temp_db, sid, location="A09U27")
    assert "위치(원문)" in exporter.SWITCH_COLS
    row = exporter.switches_rows(temp_db)[0]
    assert row["위치(원문)"] == "A09U27", "화면 값으로 검색·VLOOKUP이 안 맞는다"
    assert row["위치"], "표시용 라벨도 함께 있어야 한다"


def test_switch_export_raw_location_empty_when_unset(temp_db):
    db.save_switch(temp_db, "SW2", "10.90.1.2", "cisco_ios")
    assert exporter.switches_rows(temp_db)[0]["위치(원문)"] == ""


# ── B-19: 방화벽 내보내기에 화면의 '연결 상태'가 없었다 ───────────
def test_firewall_export_has_reachability(temp_db):
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.90.2.1", 443)
    assert "연결 상태" in exporter.FIREWALL_COLS
    row = exporter.firewalls_rows(temp_db)[0]
    assert row["연결 상태"] == "확인 중"          # 감시 전
    db.set_firewall_reachable(temp_db, fid, True) if hasattr(
        db, "set_firewall_reachable") else None
    rows = exporter.firewalls_rows(temp_db)
    assert rows[0]["연결 상태"] in ("확인 중", "연결됨")


def test_all_exports_still_work(cli):
    for kind in ("switches", "servers", "firewalls", "serverroom", "facility"):
        for fmt in ("csv", "txt"):
            r = cli.get("/api/export/%s?fmt=%s" % (kind, fmt))
            assert r.status_code == 200, (kind, fmt, r.status_code)
            assert r.get_data(), (kind, fmt)
