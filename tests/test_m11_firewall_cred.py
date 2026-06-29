"""M11 F2: 방화벽 API Key/자격증명 저장 + 수집 시 사용 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, credentials
from core import firewall as fw_mod

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"


def test_firewall_cred_blob_column(temp_db):
    """firewalls.cred_blob 저장/조회."""
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.1", 443)
    assert db.get_firewall_credential(temp_db, fid) is None
    db.save_firewall_credential(temp_db, fid, "ENCRYPTED_BLOB_X")
    assert db.get_firewall_credential(temp_db, fid) == "ENCRYPTED_BLOB_X"


def test_add_firewall_saves_cred_when_dpapi(client, monkeypatch):
    """추가 시 자격증명이 암호화되어 저장된다(DPAPI mock)."""
    # DPAPI 미설치 환경에서도 테스트되도록 encrypt_text를 mock
    monkeypatch.setattr(credentials, "encrypt_text", lambda text: "BLOB::" + text)
    r = client.post("/api/firewalls", json={
        "vendor": "fortigate", "host": "10.0.0.30", "name": "FW-CRED", "token": "secret-token"})
    assert r.status_code == 201
    assert r.get_json().get("cred_saved") is True
    from config import get_config
    db_path = get_config(demo_mode=True).get_db_path()
    fid = r.get_json()["firewall_id"]
    blob = db.get_firewall_credential(db_path, fid)
    assert blob is not None and blob.startswith("BLOB::")


def test_collect_uses_saved_cred(client, monkeypatch):
    """수집 시 요청에 자격증명이 없으면 저장된 자격증명을 복호화해 사용."""
    import json as _json
    # 저장: encrypt_text mock, 수집: decrypt_text mock + collect_firewall capture
    monkeypatch.setattr(credentials, "encrypt_text", lambda text: "ENC:" + text)
    monkeypatch.setattr(credentials, "decrypt_text",
                        lambda blob: blob[4:] if blob and blob.startswith("ENC:") else None)
    captured = {}
    def fake_collect(vendor, host, port=None, token="", username="", password="", verify_ssl=False):
        captured.update({"token": token, "username": username, "password": password})
        return {"interfaces": [], "arp": []}
    monkeypatch.setattr(fw_mod, "collect_firewall", fake_collect)

    fid = client.post("/api/firewalls", json={
        "vendor": "fortigate", "host": "10.0.0.31", "token": "saved-tok"}).get_json()["firewall_id"]
    # 요청에 자격증명 없이 수집 → 저장된 토큰 사용
    r = client.post(f"/api/firewalls/{fid}/collect", json={})
    assert r.status_code == 200
    assert captured["token"] == "saved-tok"


def test_add_modal_has_cred_fields(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="fw-add-token"' in body
    assert 'id="fw-add-username"' in body
    assert 'id="fw-add-password"' in body


# ── Opus R1 critical: cred_blob 노출 금지 회귀 ─────────────────────
def test_cred_blob_not_exposed_in_list(client, monkeypatch):
    """GET /api/firewalls 응답에 cred_blob이 포함되면 안 된다."""
    monkeypatch.setattr(credentials, "encrypt_text", lambda text: "ENC:" + text)
    client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.40", "token": "t"})
    r = client.get("/api/firewalls")
    assert r.status_code == 200
    for fw in r.get_json()["firewalls"]:
        assert "cred_blob" not in fw


def test_cred_blob_not_exposed_in_detail(client, monkeypatch):
    """GET /api/firewalls/<id> 응답에 cred_blob이 포함되면 안 된다."""
    monkeypatch.setattr(credentials, "encrypt_text", lambda text: "ENC:" + text)
    fid = client.post("/api/firewalls", json={"vendor": "fortigate", "host": "10.0.0.41", "token": "t"}).get_json()["firewall_id"]
    r = client.get(f"/api/firewalls/{fid}")
    assert r.status_code == 200
    assert "cred_blob" not in r.get_json()["firewall"]


def test_db_layer_strips_cred_blob(temp_db, monkeypatch):
    """db.list_firewalls/get_firewall도 cred_blob을 제외한다."""
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.42", 443)
    db.save_firewall_credential(temp_db, fid, "SECRET_BLOB")
    assert "cred_blob" not in db.get_firewall(temp_db, fid)
    assert all("cred_blob" not in f for f in db.list_firewalls(temp_db))
    # 단, 전용 조회는 여전히 동작
    assert db.get_firewall_credential(temp_db, fid) == "SECRET_BLOB"
