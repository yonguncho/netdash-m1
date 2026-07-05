# -*- coding: utf-8 -*-
"""수집 실패 사유(last_error) 저장·표시 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, collector

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"


def test_set_status_stores_and_clears_error(temp_db):
    sid = db.save_switch(temp_db, "SW-E", "10.0.0.3", "cisco_ios")
    db.set_switch_status(temp_db, sid, "failed", error="TCP-22 도달 불가")
    sw = db.get_switch(temp_db, sid)
    assert sw["status"] == "failed" and "도달 불가" in sw["last_error"]
    # 성공하면 사유 자동 제거
    db.set_switch_status(temp_db, sid, "done")
    sw = db.get_switch(temp_db, sid)
    assert sw["status"] == "done" and not sw["last_error"]


def test_friendly_fail_reason():
    f = collector._friendly_fail_reason
    assert "장비 응답 없음" in f("TCP-22 도달 불가(응답 없음)")
    assert "제한시간" in f("수집 제한시간(480초) 초과")
    assert "인증 실패" in f("Authentication failed.")
    assert "불일치" in f("show version 프롬프트 매칭 실패(드라이버 불일치 의심)")
    assert "저장된 계정 없음" in f("No credentials available for switch 3")
    assert f("이상한 오류") == "이상한 오류"   # 미분류는 원문 유지


def test_state_exposes_last_error(client):
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = db.save_switch(dbp, "SW-ERR", "10.0.0.44", "cisco_ios")
    db.set_switch_status(dbp, sid, "failed", error="인증 실패 — 계정 확인")
    switches = client.get("/api/state").get_json()["switches"]
    sw = [s for s in switches if s["id"] == sid][0]
    assert "인증 실패" in (sw.get("last_error") or "")


def test_ui_shows_fail_reason():
    js = APP_JS.read_text(encoding="utf-8")
    assert "last_error" in js   # 표/카드에 실패 사유 표시
