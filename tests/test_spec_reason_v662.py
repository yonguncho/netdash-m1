# -*- coding: utf-8 -*-
"""서버 사양이 안 잡힐 때 '왜'가 화면에 남는다 (v6.6.2).

사용자 보고: "사양이 수집 안 되는데 로그에 server_spec_empty도 없고 접근 로그만
있다." → 계정이 없으면 SSH 상세를 **아예 시도하지 않는데 아무 안내도 없었다.**
그래서 화면은 '정상'인데 사양만 비고, 로그에도 단서가 없었다.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc  # noqa: E402

ROOT = Path(__file__).parent.parent


def _stub_unpriv(monkeypatch, ports=(22, 443)):
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: list(ports))
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "host01")
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: 22)


def test_no_credential_says_why(temp_db, monkeypatch):
    _stub_unpriv(monkeypatch)
    sid = db.save_server(temp_db, "SRV", "10.88.0.1")
    sc.collect_server(temp_db, sid, None, None)
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "계정" in err and "사양" in err, "계정이 없어 건너뛴 사실이 안 보인다: %r" % err


def test_auth_failure_says_why(temp_db, monkeypatch):
    _stub_unpriv(monkeypatch)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")

    def boom(ip, u, pw, port=22):
        raise Exception("Authentication failed.")

    monkeypatch.setattr(sc, "_ssh_detail_unix", boom)
    sid = db.save_server(temp_db, "SRV2", "10.88.0.2")
    sc.collect_server(temp_db, sid, "svc", "wrong")
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "인증 실패" in err, err
    assert "공통 계정" in err, "OS가 다른 서버에 공통 계정이 안 되는 점을 알려야 한다"


def test_specs_empty_after_ssh_says_why(temp_db, monkeypatch):
    """접속은 됐는데 사양 명령만 무응답인 경우."""
    _stub_unpriv(monkeypatch)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")
    monkeypatch.setattr(sc, "_ssh_detail_unix",
                        lambda ip, u, pw, port=22: {"hostname": "h", "os_info": "Linux"})
    sid = db.save_server(temp_db, "SRV3", "10.88.0.3")
    sc.collect_server(temp_db, sid, "svc", "pw")
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "사양 명령" in err, err


def test_successful_spec_collect_has_no_false_warning(temp_db, monkeypatch):
    """사양이 정상 수집되면 경고를 붙이면 안 된다(과잉 경고 방지)."""
    _stub_unpriv(monkeypatch)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")
    monkeypatch.setattr(sc, "_ssh_detail_unix", lambda ip, u, pw, port=22: {
        "hostname": "h", "os_info": "Linux", "cpu_model": "Xeon", "cpu_cores": 8,
        "mem_total_mb": 32009, "disk_total_gb": 500.0, "disk_used_gb": 380.0})
    sid = db.save_server(temp_db, "SRV4", "10.88.0.4")
    sc.collect_server(temp_db, sid, "svc", "pw")
    row = db.get_server(temp_db, sid)
    assert row.get("cpu_cores") == 8 and row.get("mem_total_mb") == 32009
    assert not (row.get("last_error") or ""), row.get("last_error")


def test_skip_is_logged():
    src = (ROOT / "core" / "server_collector.py").read_text(encoding="utf-8")
    assert "server_no_credential_skip_detail" in src
    assert "server_spec_empty_after_ssh" in src
