"""M10 3단계: 방화벽 UI 정적 검증."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"


def test_firewall_tab_has_controls(client):
    body = client.get("/").data.decode("utf-8")
    assert 'id="btn-add-firewall"' in body
    assert 'id="firewall-table-body"' in body
    assert 'id="modal-add-firewall"' in body
    assert 'id="modal-fw-collect"' in body


def test_firewall_placeholder_removed(client):
    body = client.get("/").data.decode("utf-8")
    assert "다음 버전에서 제공" not in body


def test_firewall_vendor_options(client):
    body = client.get("/").data.decode("utf-8")
    assert 'value="fortigate"' in body
    assert 'value="paloalto"' in body


def test_appjs_firewall_functions():
    src = APP_JS.read_text(encoding="utf-8")
    assert "function loadFirewalls" in src
    assert "function renderFirewalls" in src
    assert "function openFwCollect" in src
    assert "function showFirewallDetail" in src


def test_appjs_firewall_tab_wired():
    src = APP_JS.read_text(encoding="utf-8")
    assert 'btn.dataset.tab === "firewall"' in src


def test_appjs_firewall_uses_eschtml():
    src = APP_JS.read_text(encoding="utf-8")
    start = src.index("function renderFirewalls")
    end = src.index("\nfunction ", start + 1)
    assert "escHtml(" in src[start:end]
