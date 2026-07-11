# -*- coding: utf-8 -*-
"""enable secret 별도 입력 지원 테스트 — 세션 저장/디바이스 secret/UI 필드."""
import sys
import inspect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import credentials, collector


def test_session_credential_carries_enable_secret():
    """save_credential(enable_secret=...) → load_credential에 동반."""
    try:
        credentials.save_credential(99991, "admin", "loginpw", enable_secret="enpw")
        cred = credentials.load_credential(99991)
        assert cred["username"] == "admin"
        assert cred["password"] == "loginpw"
        assert cred["enable_secret"] == "enpw"
    finally:
        credentials.clear_session_switch(99991)


def test_session_credential_enable_secret_default_none():
    """미지정 시 enable_secret=None (기존 동작 — password가 secret)."""
    try:
        credentials.save_credential(99992, "admin", "loginpw")
        cred = credentials.load_credential(99992)
        assert cred.get("enable_secret") is None
    finally:
        credentials.clear_session_switch(99992)


def test_ssh_collect_accepts_enable_secret_param():
    """_ssh_collect 시그니처에 enable_secret 존재 + secret 결정 로직."""
    sig = inspect.signature(collector._ssh_collect)
    assert "enable_secret" in sig.parameters
    src = inspect.getsource(collector._ssh_collect)
    assert 'enable_secret or password' in src


def test_collect_switch_accepts_enable_secret_param():
    sig = inspect.signature(collector.collect_switch)
    assert "enable_secret" in sig.parameters


def test_ui_has_enable_secret_fields():
    """수집/일괄수집 모달에 enable secret 입력 필드."""
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="cred-enable"' in html
    assert 'id="bulk-enable"' in html
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "enable_secret" in js


def test_worker_falls_back_to_persisted_enable_secret():
    """워커가 세션에 없으면 app_settings blob(enable_secret_<id>)을 복호화."""
    src = inspect.getsource(collector)
    assert 'enable_secret_%d' in src
    assert "decrypt_text" in src
