"""일괄 진단(전체 스위치) — 워커 로직 + 엔드포인트 회귀."""
import time


def test_diagnose_all_worker_corrects_vendor(temp_db, monkeypatch):
    """저장 계정으로 진단 → guess가 나오면 벤더를 교정하고 결과를 누적."""
    import app as _app
    from core import db, collector, credentials

    sid = db.save_switch(temp_db, "SW135", "10.92.152.12", "unknown")  # 벤더 미지정
    # 자격증명 저장 경로를 결정적으로(모의)
    monkeypatch.setattr(db, "get_switch_credential", lambda p, s: "blob")
    monkeypatch.setattr(credentials, "decrypt_credential", lambda b: "u|p")
    # 진단이 벤더 + OS/모델/시리얼까지 반환(사전정보 보강 경로)
    monkeypatch.setattr(collector, "diagnose_switch",
                        lambda sw, u, pw, source_ip=None: {
                            "guess": "extreme_exos", "os_version": "EXOS 31.7.2.28",
                            "model": "X440G2-24t-10G4", "serial": "1234N-56789"})
    # 상태 초기화(엔드포인트가 하는 일)
    _app._diag_all.update(running=True, total=1, done=0, corrected=0, results=[], error=None)
    _app._run_diagnose_all(temp_db, None)

    assert _app._diag_all["running"] is False
    assert _app._diag_all["done"] == 1
    assert _app._diag_all["corrected"] == 1
    row = db.get_switch(temp_db, sid)
    assert row["vendor"] == "extreme_exos"          # 교정됨
    assert row["model"] == "X440G2-24t-10G4"        # 모델 채움
    assert row["serial"] == "1234N-56789"           # 시리얼 채움
    assert row["os_version"] == "EXOS 31.7.2.28"    # 버전 채움


def test_diagnose_all_endpoint_starts_and_status(client):
    """POST가 202로 시작하고 status 엔드포인트가 진행 상태를 돌려준다(스위치 0대여도 안전)."""
    r = client.post("/api/switches/diagnose-all", json={})
    assert r.status_code in (202, 409)   # 202 시작 or 이미 진행중
    body = r.get_json()
    assert "total" in body or "error" in body
    # 백그라운드 완료 대기(스위치 0대라 즉시 끝남)
    for _ in range(50):
        s = client.get("/api/switches/diagnose-all/status").get_json()
        if not s["running"]:
            break
        time.sleep(0.05)
    s = client.get("/api/switches/diagnose-all/status").get_json()
    assert set(["running", "total", "done", "corrected", "results"]).issubset(s.keys())
