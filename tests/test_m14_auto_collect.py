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


# ── SSRF 재검증 (자동 수집 경로) ───────────────────────────────────
def test_ip_allowed_ssrf():
    from core import collector
    rfc1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    # 사설 대역 허용
    assert collector._ip_allowed("10.0.0.10", rfc1918) is True
    assert collector._ip_allowed("192.168.1.5", rfc1918) is True
    # 공인 IP 거부
    assert collector._ip_allowed("8.8.8.8", rfc1918) is False
    # 루프백/예약 거부
    assert collector._ip_allowed("127.0.0.1", rfc1918) is False
    assert collector._ip_allowed("169.254.1.1", rfc1918) is False
    # 잘못된 값 거부
    assert collector._ip_allowed("", rfc1918) is False
    assert collector._ip_allowed("not-an-ip", rfc1918) is False


def test_auto_collect_skips_invalid_ip(temp_db, monkeypatch):
    """자동 수집이 허용 대역 밖 IP 장비를 건너뛰는지(SSRF 재검증)."""
    from core import collector, config_loader
    # 공인 IP로 스위치 등록(우회 저장 시나리오) + 가짜 자격증명
    sid = db.save_switch(temp_db, "BAD", "8.8.8.8", "cisco_ios")
    db.update_cred_blob(temp_db, sid, "fake-blob")
    called = {"n": 0}
    monkeypatch.setattr(collector, "collect_switch", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    collector.collect_all_registered(temp_db)
    assert called["n"] == 0  # 공인 IP → collect_switch 호출 안 됨
