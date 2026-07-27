# -*- coding: utf-8 -*-
"""v5.6.0 서버 경로 하드닝 — 코드 검수(백엔드/프론트) 지적 사항의 회귀 테스트.

각 테스트는 검수 지적 항목 하나에 대응한다. 지적 내용은 주석에 근거로 남긴다.
"""
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc

APPJS = Path(__file__).parent.parent / "web" / "static" / "app.js"


@pytest.fixture
def srv_client(tmp_path, monkeypatch):
    """데모 모드 클라이언트 + 서버 1건 등록된 DB."""
    monkeypatch.chdir(tmp_path)
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ── F-1: 타입 불일치 입력이 500이 아니라 400 ──────────────────────
@pytest.mark.parametrize("body", [5, [1], "text", True])
def test_post_servers_non_object_body_is_400(srv_client, body):
    r = srv_client.post("/api/servers", json=body)
    assert r.status_code == 400, "본문이 객체가 아니면 400이어야 한다(500 아님)"


@pytest.mark.parametrize("body", [
    {"name": 123, "ip": "10.20.0.5"},          # name이 int
    {"name": "a", "ip": 1234},                 # ip가 int
    {"name": "a", "ip": "10.20.0.6", "location": 99},
    {"name": {"x": 1}, "ip": "10.20.0.7"},
    {"name": "a", "ip": "10.20.0.8", "location": {"a": 1}},
])
def test_post_servers_wrong_types_never_500(srv_client, body):
    r = srv_client.post("/api/servers", json=body)
    assert r.status_code != 500, (body, r.get_data(as_text=True)[:200])


def test_put_server_null_does_not_store_string_none(srv_client):
    """PUT {"name": null} 이 문자열 'None'으로 저장되면 안 된다."""
    sid = srv_client.post("/api/servers", json={"name": "N1", "ip": "10.20.1.1"}).get_json()["id"]
    r = srv_client.put("/api/servers/%d" % sid, json={"name": None, "location": {"a": 1}})
    assert r.status_code == 200
    row = [s for s in srv_client.get("/api/servers").get_json()["servers"] if s["id"] == sid][0]
    assert row["name"] == "N1", "null 갱신이 기존 이름을 'None'으로 덮어썼다"
    assert row.get("location") in (None, ""), row.get("location")


@pytest.mark.parametrize("body", [5, {"username": 123}, {"password": 5}])
def test_collect_all_wrong_types_never_500(srv_client, body):
    r = srv_client.post("/api/servers/collect-all", json=body)
    assert r.status_code != 500, (body, r.get_data(as_text=True)[:200])


# ── F-2: 거대 id는 500(OverflowError)이 아니라 404 ────────────────
BIG_ID = 99999999999999999999


@pytest.mark.parametrize("method,path", [
    ("put", "/api/servers/%d" % BIG_ID),
    ("delete", "/api/servers/%d" % BIG_ID),
    ("post", "/api/servers/%d/collect" % BIG_ID),
])
def test_oversized_server_id_is_404_not_500(srv_client, method, path):
    r = getattr(srv_client, method)(path, json={})
    assert r.status_code == 404, "SQLite INTEGER 범위 밖 id는 404여야 한다"


# ── F-5: ids 검증 — 워커 스레드가 조용히 죽지 않게 ────────────────
@pytest.mark.parametrize("ids", ["abc", 5, [1, "x"], [None], {"a": 1}])
def test_collect_all_invalid_ids_rejected(srv_client, ids):
    r = srv_client.post("/api/servers/collect-all", json={"ids": ids})
    assert r.status_code == 400, "검증 없이 202를 주면 수집이 시작된 줄 알고 기다리게 된다"


def test_collect_all_empty_ids_means_all(srv_client):
    """화면 규약: 체크한 서버가 없으면 빈 배열 = 전체 수집."""
    r = srv_client.post("/api/servers/collect-all", json={"ids": []})
    assert r.status_code == 202, r.get_data(as_text=True)[:200]


# ── F-3/F-4: 일괄 수집 재진입 금지(진행률·중지 플래그 오염) ────────
def test_collect_all_refuses_second_run(temp_db, monkeypatch):
    db.save_server(temp_db, "S1", "10.30.0.1")
    started = threading.Event()
    release = threading.Event()

    def slow_collect(db_path, server_id, username=None, password=None):
        started.set()
        release.wait(timeout=5)
        return {"status": "done"}

    monkeypatch.setattr(sc, "collect_server", slow_collect)
    t = threading.Thread(target=sc.collect_all_servers, args=(temp_db,), daemon=True)
    t.start()
    assert started.wait(timeout=5)

    second = sc.collect_all_servers(temp_db)          # 진행 중 두 번째 호출
    assert second.get("status") == "already_running", second
    assert sc.get_progress()["running"] is True, "첫 수집이 아직 도는데 running이 꺼졌다"

    release.set()
    t.join(timeout=10)
    assert sc.get_progress()["running"] is False


def test_stop_request_survives_second_start_attempt(temp_db, monkeypatch):
    """중지 요청 후 다른 수집이 시작해 _stop을 리셋하면 첫 수집이 안 멈춘다."""
    for i in range(4):
        db.save_server(temp_db, "S%d" % i, "10.31.0.%d" % (i + 1))
    gate = threading.Event()

    def slow_collect(db_path, server_id, username=None, password=None):
        gate.wait(timeout=5)
        return {"status": "done"}

    monkeypatch.setattr(sc, "collect_server", slow_collect)
    t = threading.Thread(target=sc.collect_all_servers,
                         kwargs={"db_path": temp_db, "max_workers": 1}, daemon=True)
    t.start()
    time.sleep(0.2)
    assert sc.request_stop() is True
    assert sc.collect_all_servers(temp_db).get("status") == "already_running"
    assert sc._is_stop() is True, "두 번째 시작 시도가 중지 요청을 취소했다"
    gate.set()
    t.join(timeout=10)


# ── F-8: 같은 서버 중복 수집 금지(수집본 상호 덮어쓰기) ───────────
def test_same_server_not_collected_twice_concurrently(temp_db, monkeypatch):
    sid = db.save_server(temp_db, "DUP", "10.32.0.1")
    inside = threading.Event()
    release = threading.Event()
    calls = []

    def fake_body(db_path, server_id, sv, username, password):
        calls.append(server_id)
        inside.set()
        release.wait(timeout=5)
        return {"status": "done"}

    monkeypatch.setattr(sc, "_collect_server_locked", fake_body)
    t = threading.Thread(target=sc.collect_server, args=(temp_db, sid), daemon=True)
    t.start()
    assert inside.wait(timeout=5)
    res = sc.collect_server(temp_db, sid)             # 같은 서버 동시 수집
    assert res["status"] == "skipped", res
    release.set()
    t.join(timeout=10)
    assert calls == [sid], "본체가 두 번 실행됐다"
    # 끝난 뒤에는 다시 수집 가능해야 한다(플래그 잔류 금지)
    release.clear()
    inside.clear()
    assert sid not in sc._inflight


# ── F-6: 세션 전용 계정은 persist로도 디스크에 남지 않는다 ────────
def test_session_credential_never_persisted_to_db(srv_client, monkeypatch):
    sid = srv_client.post("/api/servers", json={"name": "P1", "ip": "10.33.0.1"}).get_json()["id"]
    assert srv_client.post("/api/session/credential",
                           json={"username": "admin", "password": "s3cret"}).status_code == 200

    from core import server_collector
    monkeypatch.setattr(server_collector, "collect_all_servers",
                        lambda **kw: {"done": 0, "failed": 0, "skipped": 0, "total": 0})
    r = srv_client.post("/api/servers/collect-all", json={"persist": True})
    assert r.status_code == 202, r.get_data(as_text=True)[:200]

    servers = srv_client.get("/api/servers").get_json()["servers"]
    row = [s for s in servers if s["id"] == sid][0]
    assert row["has_cred"] is False, "세션 전용(메모리) 계정이 DB에 영구 저장됐다"


def test_explicit_credential_still_persists(srv_client, monkeypatch):
    """요청 본문으로 직접 준 계정은 종전대로 저장된다(기능 회귀 방지)."""
    sid = srv_client.post("/api/servers", json={"name": "P2", "ip": "10.33.0.2"}).get_json()["id"]
    from core import server_collector
    captured = {}
    monkeypatch.setattr(server_collector, "collect_all_servers",
                        lambda **kw: captured.update(kw) or {"done": 0})
    r = srv_client.post("/api/servers/collect-all",
                        json={"username": "u", "password": "p", "persist": True})
    assert r.status_code == 202
    time.sleep(0.3)
    assert captured.get("persist") is True, captured


# ── F-10: 목록 조회(GET)가 기존 서버 값을 덮어쓰지 않는다 ─────────
def test_adopt_does_not_overwrite_existing_server(temp_db):
    """구분=Server 스위치 편입 시, 같은 IP 서버가 있으면 스위치 행만 지운다."""
    sid = db.save_server(temp_db, "SRV", "10.34.0.1", os_type="linux", is_vm=1)
    db.update_server(temp_db, sid, location="A09U27", os_info="Ubuntu 22.04", cpu_cores=16)
    swid = db.save_switch(temp_db, "LOOKS-LIKE-SW", "10.34.0.1", "unknown")
    db.update_switch(temp_db, swid, device_type="Server")

    assert db.adopt_server_switches(temp_db) == 1
    s = db.get_server(temp_db, sid)
    assert s["os_type"] == "linux" and s["is_vm"] == 1, "수집해 둔 값이 덮어써졌다"
    assert s["location"] == "A09U27" and s["cpu_cores"] == 16
    assert not [w for w in db.get_switches(temp_db) if w["id"] == swid], "스위치 행이 안 지워졌다"


# ── F-12: 감사 로그 라벨 ──────────────────────────────────────────
def test_audit_labels_cover_server_write_paths():
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    head = src[src.index("def _audit_label"):src.index("def audit_request")]
    for label in ("서버 수정", "서버 삭제", "서버 일괄등록"):
        assert '"%s"' % label in head, label


# ── F-13: 읽기 전용 게이트는 인증 뒤에 등록 ───────────────────────
def test_readonly_gate_registered_after_token_validation():
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    assert src.index("def validate_api_token") < src.index("app.before_request(_ro_gate)"), \
        "읽기 전용 게이트가 토큰 검증보다 먼저 돌면 미인증자에게 주 서버 호스트명이 노출된다"


# ── 프론트: 컬럼 폭 저장 키에 컬럼 수 포함(열 추가 시 밀림 방지) ──
def test_column_width_key_includes_column_count():
    js = APPJS.read_text(encoding="utf-8")
    assert 'baseKey + ":c" + ths.length' in js, \
        "폭 저장 키에 컬럼 수가 없으면 열 추가 시 기존 저장분이 통째로 밀린다"


def test_spec_formatters_coerce_numbers():
    js = APPJS.read_text(encoding="utf-8")
    assert "function _num(" in js
    for call in ("mb = _num(mb)", "gb = _num(gb)", "_num(s.disk_total_gb)", "_num(s.cpu_cores)"):
        assert call in js, call
