"""M14: 자동 수집 설정/스케줄러 + 위치 필터 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, scheduler

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"
HTML = Path(__file__).parent.parent / "web" / "templates" / "index.html"


# ── 자동 수집 설정 API ─────────────────────────────────────────────
def test_auto_collect_default(client):
    r = client.get("/api/settings/auto_collect")
    b = r.get_json()
    assert b["enabled"] is False
    assert b["times"] == "06:00,18:00"


def test_auto_collect_set_and_get(client):
    r = client.post("/api/settings/auto_collect", json={"enabled": True, "times": "07:30, 19:00"})
    assert r.status_code == 200
    assert r.get_json()["enabled"] is True
    g = client.get("/api/settings/auto_collect").get_json()
    assert g["enabled"] is True
    assert g["times"] == "07:30,19:00"


def test_auto_collect_rejects_bad_times(client):
    # 잘못된 시각은 걸러지고 기본값으로 대체
    r = client.post("/api/settings/auto_collect", json={"enabled": True, "times": "25:99,abc"})
    assert r.get_json()["times"] == "06:00,18:00"


# ── 스케줄러 시각 파싱 ──────────────────────────────────────────────
def test_scheduler_parse_times():
    assert scheduler._parse_times("06:00,18:00") == ["06:00", "18:00"]
    assert scheduler._parse_times(" 07:00 , 21:30 ") == ["07:00", "21:30"]
    assert scheduler._parse_times("") == []


# ── 위치 필터 UI ───────────────────────────────────────────────────
def test_location_filter_ui():
    src = APP_JS.read_text(encoding="utf-8")
    assert "_applyLocFilter" in src
    assert "loc-filter-dash" in src
    assert "loc-filter-sw" in src
    html = HTML.read_text(encoding="utf-8")
    assert 'id="loc-filter-dash"' in html
    assert 'id="loc-filter-sw"' in html


def test_auto_collect_ui_present():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="modal-auto-collect"' in html
    assert 'id="btn-auto-collect"' in html
    assert 'id="cred-persist"' in html  # 자동 수집용 계정 저장 체크박스
