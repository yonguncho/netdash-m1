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


def test_output_survives_korean_console(monkeypatch):
    """한국어 콘솔은 cp949다 - 인코딩 안 되는 문자는 '?'로 깨진다.

    사용자가 이 출력을 그대로 복사해 붙이도록 안내하므로 깨지면 읽기 나빠진다.
    실제로 exe 출력에서 em-dash가 '?'로 나오는 것을 확인하고 넣은 방어다.
    출력 문장에는 **다른 모듈의 오류 메시지가 그대로 실려 오므로**, 이 파일만
    깨끗이 쓰는 것으로는 부족하다 → 출력 직전에 거른다.
    (관련: netdash_cp949_console 메모)
    """
    out = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: out.append(a[0]))
    # core 모듈이 실제로 쓰는 em-dash 섞인 문구
    diag._p("SNMP 응답 없음 — 서버에 snmpd가 떠 있지 않습니다")
    diag._p("따옴표 ‘작은’ “큰” 그리고 줄임표…")
    assert out, "출력이 없다"
    for line in out:
        line.encode("cp949")        # 깨지면 여기서 UnicodeEncodeError
    assert "—" not in "".join(out) and "…" not in "".join(out)


def test_sanitizer_keeps_meaning():
    """과잉 치환으로 문장이 뭉개지면 진단 가치가 떨어진다."""
    out = []
    import builtins
    real = builtins.print
    builtins.print = lambda *a, **k: out.append(a[0])
    try:
        diag._p("포트 5985 열림 — Enable-PSRemoting -Force 실행")
    finally:
        builtins.print = real
    assert "Enable-PSRemoting -Force" in out[0]
    assert "5985" in out[0]


def _cp949_ok(ch):
    try:
        ch.encode("cp949")
        return True
    except UnicodeEncodeError:
        return False


# ── 화면에서도 돌아야 한다(콘솔을 못 쓰는 환경) ─────────────────
def test_web_wrapper_returns_lines(monkeypatch):
    """CLI를 못 쓰는 환경이 있다 - 같은 진단을 화면에서 볼 수 있어야 한다."""
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [])
    rc, lines = diag.diagnose_lines("10.0.0.1")
    assert rc == 1 and lines, "출력 줄이 비었다"
    assert any("도달 불가" in l for l in lines)


def test_web_wrapper_does_not_prompt(monkeypatch):
    """웹 요청에서 getpass가 뜨면 서버 스레드가 멈춘다."""
    def boom(*a, **k):
        raise AssertionError("getpass가 호출됐다")
    monkeypatch.setattr(diag.getpass, "getpass", boom)
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [])
    diag.diagnose_lines("10.0.0.1", user="admin", password="pw")


def test_spec_diag_endpoint_exists():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "/api/servers/<int:server_id>/diag-spec" in src
    i = src.index("def diag_server_spec_endpoint(")
    block = src[i:i + 2500]
    assert "validate_ipv4(" in block, "SSRF 검증이 없다"
    assert "validate_credential(" in block, "자격증명 검증이 없다"
    assert "get_server_credential" in block, "저장 계정을 안 쓴다"


def test_spec_diag_button_in_ui():
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "diag-spec" in js and "_addSpecDiagButton" in js
    assert "사양 수집 경로 진단" in js


def test_wmi_failure_reason_not_truncated_in_diag(quiet, monkeypatch):
    """레지스트리 명령이 잘리면 사용자가 그대로 실행할 수 없다."""
    monkeypatch.setattr(diag.sc, "scan_ports", lambda ip, *a, **k: [135, 3389])
    monkeypatch.setattr(diag.sc, "find_ssh_port", lambda ip, p, **k: None)
    monkeypatch.setattr(diag.wmi_collect, "available", lambda: True)

    def boom(ip, u, p, transport="dcom", port=None):
        raise RuntimeError(diag.wmi_collect._short_error(
            "New-CimSession : 액세스가 거부되었습니다."))

    monkeypatch.setattr(diag.wmi_collect, "collect", boom)
    monkeypatch.setattr(diag.snmp_collect, "collect",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("무응답")))
    diag.run_diagnosis("10.0.0.1", "localadmin")
    joined = "\n".join(quiet)
    assert "LocalAccountTokenFilterPolicy" in joined
    assert joined.count("New-ItemProperty") >= 1
