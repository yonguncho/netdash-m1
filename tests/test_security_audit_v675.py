# -*- coding: utf-8 -*-
"""보안 감사 반영 (v6.7.5).

claude-security 플러그인 연동 준비 중 병렬 감사 5축에서 나온 지적을 반영한다.
각 항목은 '고치기 전에 실제로 취약함'을 재현해 확인한 것만 담았다.
(SNMP 응답 위조·잘린 패킷·예산 초과는 test_snmp_collect_v671.py 에 있다)
"""
import ipaddress
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import app as appmod  # noqa: E402
from core import credentials, db, session_creds, utils  # noqa: E402

ROOT = Path(__file__).parent.parent


# ── 장비 주소를 바꾸면 저장 계정을 지운다 ───────────────────────
# 저장 계정은 '그 주소의 장비'에 주기로 한 것이다. 주소만 바꾸고 계정을 남기면
# 그 계정이 새 주소로 전송된다(웹셸·수집·diagnose) → 자격증명 탈취.
def _blob(u="admin", p="s3cret"):
    b = credentials.encrypt_credential(u, p)
    if not b:
        pytest.skip("이 환경에서 자격증명 암호화 불가")
    return b


def test_switch_ip_change_clears_credential(temp_db):
    sid = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    db.update_cred_blob(temp_db, sid, _blob())
    db.set_setting(temp_db, "enable_secret_%d" % sid, "ena")
    assert db.get_switch_credential(temp_db, sid)
    db.clear_switch_credential(temp_db, sid)
    assert not db.get_switch_credential(temp_db, sid)
    assert not (db.get_setting(temp_db, "enable_secret_%d" % sid, "") or ""), \
        "enable secret이 남으면 새 주소로 그대로 전송된다"


def test_server_credential_clear(temp_db):
    sid = db.save_server(temp_db, "SRV", "10.0.0.9")
    db.update_server_cred(temp_db, sid, _blob())
    assert db.get_server_credential(temp_db, sid)
    db.clear_server_credential(temp_db, sid)
    assert not db.get_server_credential(temp_db, sid)


def test_ip_change_routes_clear_credentials():
    """PUT 라우트가 실제로 지우는지(엔드포인트 배선) 확인."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    for marker in ("switch_ip_changed_cred_cleared",
                   "firewall_host_changed_cred_cleared",
                   "server_ip_changed_cred_cleared"):
        assert marker in src, marker
    assert "db.clear_switch_credential(db_path, switch_id)" in src
    assert "db.clear_firewall_credential(db_path, fid)" in src
    assert "db.clear_server_credential(db_path, server_id)" in src


# ── SSRF: 0.0.0.0 이 루프백 차단을 우회했다 ─────────────────────
def test_unspecified_address_rejected():
    """0.0.0.0은 is_loopback/is_reserved 어디에도 안 걸리는데 로컬로 연결된다."""
    a = ipaddress.IPv4Address("0.0.0.0")
    assert not (a.is_loopback or a.is_reserved or a.is_link_local or a.is_multicast), \
        "전제가 바뀌었다 — 이 테스트의 의미를 다시 확인할 것"
    with pytest.raises(ValueError):
        appmod.validate_ipv4("0.0.0.0")


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0"])
def test_dangerous_addresses_still_rejected(ip):
    with pytest.raises(ValueError):
        appmod.validate_ipv4(ip)


def test_normal_addresses_still_accepted():
    """과잉 차단 방지 — 폐쇄망 사설 대역은 그대로 통과해야 한다."""
    for ip in ("10.1.2.3", "172.16.0.5", "192.168.1.1"):
        assert appmod.validate_ipv4(ip) == ip


# ── SMTP 서버 주소 검증 ─────────────────────────────────────────
# 저장된 SMTP 계정이 그대로 전송되는 곳인데 검증이 없었다.
def test_smtp_host_rejects_loopback_and_linklocal():
    for bad in ("127.0.0.1", "0.0.0.0", "169.254.169.254", "localhost",
                "LOCALHOST", "evil.localhost"):
        with pytest.raises(ValueError):
            appmod.validate_smtp_host(bad)


def test_smtp_host_accepts_normal():
    assert appmod.validate_smtp_host("10.0.0.25") == "10.0.0.25"
    assert appmod.validate_smtp_host("smtp.corp.local") == "smtp.corp.local"


def test_smtp_host_rejects_garbage():
    for bad in ("", "   ", "a b", "http://x", "x" * 300):
        with pytest.raises(ValueError):
            appmod.validate_smtp_host(bad)


# ── 로그 마스킹이 실제로 동작한다 ───────────────────────────────
def test_sensitive_keys_are_masked():
    """예전에는 민감 키의 '값을 재귀'시켜 평문이 그대로 통과했다."""
    m = utils._mask_sensitive_data
    assert m({"password": "hunter2"})["password"] == "***"
    assert m({"token": "abc123"})["token"] == "***"
    assert m({"enable_secret": "ena"})["enable_secret"] == "***"
    assert m({"community": "public"})["community"] == "***"


def test_nested_dicts_are_masked():
    """중첩 dict는 아예 훑지도 않았다."""
    got = utils._mask_sensitive_data({"data": {"password": "hunter2"}})
    assert got["data"]["password"] == "***"
    deep = utils._mask_sensitive_data({"a": [{"token": "t"}]})
    assert deep["a"][0]["token"] == "***"


def test_non_sensitive_values_survive():
    """과잉 마스킹으로 진단 정보를 잃으면 안 된다."""
    got = utils._mask_sensitive_data({"ip": "10.0.0.1", "count": 5})
    assert got == {"ip": "10.0.0.1", "count": 5}


def test_redaction_filter_applies_to_child_loggers():
    """루트 로거의 '필터'는 자식 로거 레코드에 적용되지 않는다 — 핸들러에 걸어야 한다."""
    seen = []

    class Cap(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    root = logging.getLogger()
    h = Cap()
    root.addHandler(h)
    try:
        appmod._attach_redaction_to_handlers()
        logging.getLogger("core.test_child").warning(
            'GET /?token=SUPERSECRETVALUE HTTP/1.1')
        assert seen, "핸들러가 레코드를 못 받았다"
        assert "SUPERSECRETVALUE" not in " ".join(seen), seen
    finally:
        root.removeHandler(h)


# ── 세션 계정이 TTL을 넘겨 메모리에 남지 않는다 ─────────────────
def test_purge_expired_returns_count_and_clears():
    session_creds.clear()
    session_creds.set_credential("10.0.0.7", "u", "p", ttl=1, kind="switch")
    with session_creds._lock:
        for v in session_creds._store.values():
            v["exp"] = 0                      # 만료시킨다
    assert session_creds.purge_expired() >= 1
    with session_creds._lock:
        assert not session_creds._store, "만료 항목이 메모리에 남았다"


def test_scheduler_calls_purge():
    src = (ROOT / "core" / "scheduler.py").read_text(encoding="utf-8")
    assert "session_creds.purge_expired()" in src, \
        "주기 호출이 없으면 아무도 다시 안 찾는 계정은 영영 안 지워진다"


# ── 프론트 이스케이프 ───────────────────────────────────────────
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


def test_firewall_interface_mask_is_escaped():
    """마스크는 장비가 주는 문자열 그대로다(파싱 실패 시 원문 반환)."""
    i = APPJS.index("var pfx = _fmtPrefix(i.mask);")
    block = APPJS[i:i + 900]
    assert "escHtml(pfx)" in block, "마스크가 이스케이프되지 않는다"
    assert 'escHtml(pfx || "-")' in block


def test_topology_node_attrs_are_escaped():
    i = APPJS.index("var col = escHtml(n.color")
    block = APPJS[i:i + 200]
    assert "_num(n.w)" in block and "_num(n.h)" in block, "크기가 숫자로 강제되지 않는다"


def test_topology_save_validates_node_fields():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index("invalid node color")
    assert "isinstance(_v, (int, float))" in src[i - 400:i + 400]


def test_creds_delete_button_quotes_are_encoded():
    """encodeURIComponent는 작은따옴표를 인코딩하지 않는다 — 속성이 깨진다."""
    i = APPJS.index("creds-del")
    assert 'replace(/\'/g, "%27")' in APPJS[i:i + 400]
