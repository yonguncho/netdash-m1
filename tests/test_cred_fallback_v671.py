# -*- coding: utf-8 -*-
"""수집 팝업의 공통 계정이 서버별 저장 계정을 덮어쓰던 문제 (v6.7.1).

사용자 보고: "authentication (keyboard-interactive) failed 가 대부분이다."
→ 폴백(keyboard-interactive)은 동작했고 **자격증명 자체가 거부**된 것.

원인: 수집 팝업에 공통 계정을 입력하면 그 값이 **서버별 저장 계정을 덮어쓴다.**
OS가 섞인 환경(Windows·RHEL·SUSE·Debian)에서는 계정이 서버마다 다르므로
대부분의 서버에서 인증이 실패할 수밖에 없다.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import credentials, db, server_collector as sc  # noqa: E402


def _stub(monkeypatch, ports=(22,)):
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: list(ports))
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: 22)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")


def _save_cred(temp_db, sid, user, pw):
    blob = credentials.encrypt_credential(user, pw)
    assert blob, "이 환경에서 자격증명 암호화가 되지 않음"
    db.update_server_cred(temp_db, sid, blob)


# ── 후보 목록 ────────────────────────────────────────────────────
def test_candidates_input_then_saved(temp_db):
    sid = db.save_server(temp_db, "S", "10.7.7.1")
    _save_cred(temp_db, sid, "rhel-admin", "pw-rhel")
    got = sc._cred_candidates(temp_db, sid, "common", "pw-common")
    assert [(c[0], c[2]) for c in got] == [("common", "입력 계정"),
                                           ("rhel-admin", "저장 계정")]


def test_candidates_deduplicated(temp_db):
    """같은 계정을 두 번 시도하면 계정 잠금만 앞당긴다."""
    sid = db.save_server(temp_db, "S", "10.7.7.2")
    _save_cred(temp_db, sid, "same", "pw")
    got = sc._cred_candidates(temp_db, sid, "same", "pw")
    assert len(got) == 1


def test_candidates_capped_at_two(temp_db):
    sid = db.save_server(temp_db, "S", "10.7.7.3")
    _save_cred(temp_db, sid, "a", "1")
    assert len(sc._cred_candidates(temp_db, sid, "b", "2")) <= 2


# ── 실제 폴백 동작 ──────────────────────────────────────────────
def test_saved_credential_used_when_common_rejected(temp_db, monkeypatch):
    """공통 계정이 거부되면 그 서버에 저장된 계정으로 재시도해야 한다."""
    _stub(monkeypatch)
    sid = db.save_server(temp_db, "RHEL", "10.7.7.10")
    _save_cred(temp_db, sid, "rhel-admin", "pw-rhel")
    tried = []

    def detail(ip, u, pw, port=22):
        tried.append(u)
        if u != "rhel-admin":
            raise Exception("Authentication (keyboard-interactive) failed.")
        return {"hostname": "rhel01", "os_info": "Linux", "cpu_model": "Xeon",
                "cpu_cores": 8, "mem_total_mb": 32009, "disk_total_gb": 100.0}

    monkeypatch.setattr(sc, "_ssh_detail_unix", detail)
    sc.collect_server(temp_db, sid, "common", "pw-common")
    row = db.get_server(temp_db, sid)
    assert tried == ["common", "rhel-admin"], tried
    assert row["cpu_cores"] == 8, "저장 계정으로 재시도했으면 사양이 채워져야 한다"
    assert not (row.get("last_error") or ""), row.get("last_error")


def test_no_retry_on_non_auth_error(temp_db, monkeypatch):
    """인증 문제가 아니면(네트워크 등) 계정을 바꿔 재시도하지 않는다."""
    _stub(monkeypatch)
    sid = db.save_server(temp_db, "S", "10.7.7.11")
    _save_cred(temp_db, sid, "saved", "pw")
    tried = []

    def detail(ip, u, pw, port=22):
        tried.append(u)
        raise Exception("timed out")

    monkeypatch.setattr(sc, "_ssh_detail_unix", detail)
    sc.collect_server(temp_db, sid, "common", "pw-common")
    assert tried == ["common"], "인증 오류가 아닌데 다른 계정으로 재시도했다"


def test_all_candidates_rejected_reports_which(temp_db, monkeypatch):
    _stub(monkeypatch)
    sid = db.save_server(temp_db, "S", "10.7.7.12")
    _save_cred(temp_db, sid, "saved", "pw")

    def detail(ip, u, pw, port=22):
        raise Exception("Authentication (keyboard-interactive) failed.")

    monkeypatch.setattr(sc, "_ssh_detail_unix", detail)
    sc.collect_server(temp_db, sid, "common", "pw-common")
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "인증 실패" in err and "입력 계정" in err and "저장 계정" in err, err


def test_single_credential_still_works(temp_db, monkeypatch):
    """저장 계정이 없는 서버는 예전처럼 입력 계정 하나로 동작한다."""
    _stub(monkeypatch)
    sid = db.save_server(temp_db, "S", "10.7.7.13")
    monkeypatch.setattr(sc, "_ssh_detail_unix", lambda ip, u, pw, port=22: {
        "hostname": "h", "os_info": "Linux", "cpu_cores": 4, "mem_total_mb": 8000,
        "cpu_model": "X", "disk_total_gb": 50.0})
    sc.collect_server(temp_db, sid, "only", "pw")
    assert db.get_server(temp_db, sid)["cpu_cores"] == 4


def test_auth_error_detection():
    assert sc._is_auth_error(Exception("Authentication (keyboard-interactive) failed."))
    assert sc._is_auth_error(Exception("Authentication (password) failed."))
    assert not sc._is_auth_error(Exception("timed out"))
    assert not sc._is_auth_error(Exception("No route to host"))
