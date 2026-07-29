# -*- coding: utf-8 -*-
"""사양 수집 경로 진단 도구 (v6.8.0).

사용자 보고가 "사양이 여전히 수집 안 된다"로 반복됐다. 수집 경로가 넷
(SSH → WinRM → WMI DCOM → SNMP)인데 화면에는 마지막 사유 한 줄만 남아,
어느 단계에서 막혔는지 알 수 없었다 → 추측으로 고치는 일이 반복됐다.

이 도구는 네 경로를 순서대로 직접 두들겨 결과를 그대로 보여준다.
exe에서도 `netdash.exe --diag-server <IP>` 로 쓸 수 있어야 현장에서 쓸모가 있다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts import diag_server_spec as diag  # noqa: E402

ROOT = Path(__file__).parent.parent


@pytest.fixture
def quiet(monkeypatch):
    """비밀번호 입력을 막고(테스트가 멈추지 않게) 출력만 모은다."""
    monkeypatch.setattr(diag.getpass, "getpass", lambda *a, **k: "pw")
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(" ".join(map(str, a))))
    return out


def test_unreachable_host_stops_early(quiet, monkeypatch):
    """열린 포트가 없으면 나머지 경로를 두들겨 시간을 낭비하지 않는다."""
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [])
    called = {"n": 0}
    monkeypatch.setattr(diag.snmp_collect, "collect",
                        lambda *a, **k: called.__setitem__("n", 1))
    assert diag.run_diagnosis("10.0.0.1") == 1
    joined = "\n".join(quiet)
    assert "도달 불가" in joined
    assert called["n"] == 0, "도달 불가인데 SNMP까지 시도했다"


def test_ssh_success_reports_and_stops(quiet, monkeypatch):
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [22])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: 22)
    monkeypatch.setattr(diag.sc, "_ssh_detail_unix", lambda ip, u, pw, port=22: {
        "cpu_model": "Xeon", "cpu_cores": 8, "mem_total_mb": 32000,
        "disk_total_gb": 500.0})
    assert diag.run_diagnosis("10.0.0.1", "svc") == 0
    assert "사양 수집됨" in "\n".join(quiet)


def test_ssh_auth_failure_explains_account(quiet, monkeypatch):
    """계정 거부는 '그 서버의 계정인지'가 핵심 단서다."""
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [22])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: 22)

    def boom(ip, u, pw, port=22):
        raise Exception("Authentication (keyboard-interactive) failed.")

    monkeypatch.setattr(diag.sc, "_ssh_detail_unix", boom)
    monkeypatch.setattr(diag.wmi_collect, "transports_for", lambda p: [])
    monkeypatch.setattr(diag.snmp_collect, "collect",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("무응답")))
    diag.run_diagnosis("10.0.0.1", "svc")
    joined = "\n".join(quiet)
    assert "계정 거부" in joined and "공통 계정" in joined


def test_rdp_only_suggests_enabling_winrm(quiet, monkeypatch):
    """RDP만 열린 서버는 조치가 분명하다 — 대상에서 WinRM을 켜면 된다."""
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [3389])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: None)
    monkeypatch.setattr(diag.snmp_collect, "collect",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("무응답")))
    diag.run_diagnosis("10.0.0.1", "admin")
    assert "Enable-PSRemoting" in "\n".join(quiet)


def test_winrm_success_reports(quiet, monkeypatch):
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [3389, 5985])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: None)
    monkeypatch.setattr(diag.wmi_collect, "available", lambda: True)
    monkeypatch.setattr(diag.wmi_collect, "collect",
                        lambda ip, u, p, transport="dcom", port=None: {
                            "cpu_cores": 16, "mem_total_mb": 65536,
                            "disk_total_gb": 900.0})
    assert diag.run_diagnosis("10.0.0.1", "admin") == 0
    assert "winrm" in "\n".join(quiet)


def test_snmp_without_specs_points_at_mib(quiet, monkeypatch):
    """응답은 오는데 사양이 없으면 RHEL 기본 snmpd.conf 문제다."""
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [443])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: None)
    monkeypatch.setattr(diag.wmi_collect, "transports_for", lambda p: [])
    monkeypatch.setattr(diag.snmp_collect, "collect",
                        lambda *a, **k: {"hostname": "h", "os_info": "Linux"})
    diag.run_diagnosis("10.0.0.1")
    assert "1.3.6.1.2.1.25" in "\n".join(quiet)


def test_password_is_never_printed(quiet, monkeypatch):
    """진단 출력을 그대로 붙여넣게 안내하므로 비밀번호가 섞이면 안 된다."""
    monkeypatch.setattr(diag.getpass, "getpass", lambda *a, **k: "SUPERSECRET")
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [22])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: 22)
    monkeypatch.setattr(diag.sc, "_ssh_detail_unix",
                        lambda ip, u, pw, port=22: {"cpu_cores": 4,
                                                    "mem_total_mb": 8000})
    diag.run_diagnosis("10.0.0.1", "svc")
    assert "SUPERSECRET" not in "\n".join(quiet)


def test_password_not_taken_from_command_line():
    """명령행 비밀번호는 같은 PC의 다른 사용자에게 보인다."""
    src = (ROOT / "scripts" / "diag_server_spec.py").read_text(encoding="utf-8")
    assert "getpass" in src
    assert "--password" not in src and "--pw" not in src


def test_exe_exposes_diag_flag():
    """현장에서 쓰려면 exe에서 바로 돌아가야 한다(개발 환경만으론 무의미)."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "--diag-server" in src
    assert "run_diagnosis(" in src
    spec = (ROOT / "netdash.spec").read_text(encoding="utf-8")
    assert "scripts.diag_server_spec" in spec, "exe 번들에 포함되지 않는다"


def test_diagnosis_is_read_only():
    """진단이 DB나 장비 상태를 바꾸면 문제 재현이 흐려진다."""
    src = (ROOT / "scripts" / "diag_server_spec.py").read_text(encoding="utf-8")
    for bad in ("update_server", "save_server", "set_setting", "collect_server"):
        assert bad not in src, bad
