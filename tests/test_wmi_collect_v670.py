# -*- coding: utf-8 -*-
"""Windows 서버 사양 수집 — WMI/DCOM 폴백 (v6.7.0).

SSH가 닫혔거나 인증이 막힌 Windows 서버는 사양(CPU·메모리·디스크)을 읽을 방법이
없었다. Windows는 WMI로 이 정보를 노출하므로, NetDash가 도는 Windows PC에서
PowerShell CIM 세션(DCOM, 135)을 열어 원격 조회한다.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc, wmi_collect  # noqa: E402

ROOT = Path(__file__).parent.parent

_WMI_OK = {
    "hostname": "WIN-APP01", "os_info": "Microsoft Windows Server 2016 10.0.14393",
    "cpu_model": "Intel(R) Xeon(R) Silver 4110", "cpu_cores": 8,
    "mem_total_mb": 32647, "disk_total_gb": 475.1, "disk_used_gb": 366.6,
    "mem_slots": 4, "mac": "00:50:56:C0:00:08",
    "mem_modules": [{"size_mb": 16384, "locator": "DIMM A", "speed": 2400,
                     "maker": "80CE000080CE", "part": "M471A2K43CB1-CRC"}],
    "disk_devices": [{"name": "\\\\.\\PHYSICALDRIVE0", "model": "TOSHIBA KSG60ZMV512G",
                      "size_gb": 476.9, "kind": "SCSI"}],
}


class _Proc:
    def __init__(self, rc=0, out=b"", err=b""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


# ── 전제 조건 ────────────────────────────────────────────────────
def test_only_tried_when_rpc_port_open():
    assert wmi_collect.can_try([135, 445]) is True
    assert wmi_collect.can_try([22, 443]) is False
    assert wmi_collect.can_try([]) is False


def test_rpc_port_is_scanned():
    assert 135 in sc.COMMON_PORTS, "135를 스캔하지 않으면 WMI를 시도할 수 없다"


def test_password_not_passed_on_command_line(monkeypatch):
    """명령행은 같은 PC의 다른 사용자에게도 보인다 — 환경변수로 넘겨야 한다."""
    seen = {}

    def fake_run(args, **kw):
        seen["args"] = args
        seen["env"] = kw.get("env") or {}
        return _Proc(0, json.dumps(_WMI_OK).encode())

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    wmi_collect.collect("10.1.1.5", "admin", "s3cret")
    assert "s3cret" not in " ".join(seen["args"]), "비밀번호가 명령행에 노출됐다"
    assert seen["env"].get("ND_WMI_PW") == "s3cret"
    assert seen["env"].get("ND_WMI_HOST") == "10.1.1.5"


def test_uses_dcom_not_winrm():
    """폐쇄망 서버는 WinRM(5985)이 꺼진 경우가 많다 — DCOM이어야 한다."""
    assert "New-CimSessionOption -Protocol Dcom" in wmi_collect._PS
    assert "-SessionOption $opt" in wmi_collect._PS


def test_powershell_script_is_syntactically_valid():
    """문법이 깨지면 모든 서버에서 실패한다 — 실제 파서로 검사."""
    if sys.platform != "win32":
        pytest.skip("Windows 전용")
    p = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "$e=$null;[System.Management.Automation.Language.Parser]::ParseInput("
         "[Console]::In.ReadToEnd(),[ref]$null,[ref]$e)|Out-Null;"
         "if($e.Count -eq 0){'OK'}else{$e[0].Message}"],
        input=wmi_collect._PS.encode("utf-8"), capture_output=True, timeout=90)
    assert b"OK" in p.stdout, p.stdout[:300] + p.stderr[:300]


# ── 오류 메시지 ──────────────────────────────────────────────────
def test_error_messages_are_actionable():
    f = wmi_collect._short_error
    assert "권한" in f("Access is denied.")
    assert "RPC" in f("The RPC server is unavailable.")
    assert "인증" in f("Logon failure: unknown user name or bad password")


def test_error_extracted_from_clixml():
    """-EncodedCommand 실행의 stderr는 CLIXML로 감싸여 온다."""
    clixml = ('#< CLIXML<Objs><S S="Error">New-CimSession : Access is denied._x000D__x000A_'
              '</S></Objs>')
    assert "권한" in wmi_collect._short_error(clixml)


def test_failure_raises_with_reason(monkeypatch):
    monkeypatch.setattr(subprocess, "run",
                        lambda a, **k: _Proc(1, b"", b"The RPC server is unavailable."))
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    with pytest.raises(RuntimeError) as e:
        wmi_collect.collect("10.1.1.5", "admin", "pw")
    assert "RPC" in str(e.value)


# ── 수집 경로 통합 ──────────────────────────────────────────────
def _stub_scan(monkeypatch, ports):
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: list(ports))
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)


def test_wmi_fills_specs_when_ssh_closed(temp_db, monkeypatch):
    """SSH가 닫힌 Windows 서버(135만 열림)에서 사양이 채워져야 한다."""
    _stub_scan(monkeypatch, [135, 445, 3389])
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    monkeypatch.setattr(wmi_collect, "collect", lambda ip, u, p, timeout=60: dict(_WMI_OK))
    sid = db.save_server(temp_db, "WIN2016", "10.2.2.10")
    sc.collect_server(temp_db, sid, "admin", "pw")
    row = db.get_server(temp_db, sid)
    assert row["cpu_cores"] == 8 and row["mem_total_mb"] == 32647
    assert row["disk_total_gb"] == 475.1
    assert "DIMM A" in (row.get("mem_modules") or "")
    assert "TOSHIBA" in (row.get("disk_devices") or "")
    assert row["os_type"] == "windows"


def test_wmi_normalizes_jedec_maker(temp_db, monkeypatch):
    """WMI가 주는 제조사 코드(80CE…)를 SSH 경로와 같은 규칙으로 정리한다."""
    _stub_scan(monkeypatch, [135])
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    monkeypatch.setattr(wmi_collect, "collect", lambda ip, u, p, timeout=60: dict(_WMI_OK))
    sid = db.save_server(temp_db, "WIN", "10.2.2.11")
    sc.collect_server(temp_db, sid, "admin", "pw")
    mods = json.loads(db.get_server(temp_db, sid)["mem_modules"])
    assert mods[0]["maker"] == "Samsung"
    assert "MT/s" in str(mods[0]["speed"])


def test_wmi_not_tried_for_linux_ports(temp_db, monkeypatch):
    """리눅스 서버(22만 열림)에 WMI를 시도하면 무의미한 대기가 생긴다."""
    called = {"n": 0}
    _stub_scan(monkeypatch, [22, 443])
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: None)
    monkeypatch.setattr(wmi_collect, "available", lambda: True)

    def boom(*a, **k):
        called["n"] += 1
        raise AssertionError("리눅스 서버에 WMI를 시도했다")

    monkeypatch.setattr(wmi_collect, "collect", boom)
    sid = db.save_server(temp_db, "RHEL", "10.2.2.12")
    sc.collect_server(temp_db, sid, "svc", "pw")
    assert called["n"] == 0


def test_wmi_skipped_when_ssh_already_got_specs(temp_db, monkeypatch):
    """SSH로 이미 사양을 얻었으면 WMI를 다시 부르지 않는다."""
    called = {"n": 0}
    _stub_scan(monkeypatch, [22, 135])
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: 22)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")
    monkeypatch.setattr(sc, "_ssh_detail_unix", lambda ip, u, pw, port=22: {
        "hostname": "h", "os_info": "Linux", "cpu_model": "Xeon", "cpu_cores": 4,
        "mem_total_mb": 16000, "disk_total_gb": 100.0})
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    monkeypatch.setattr(wmi_collect, "collect",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    sid = db.save_server(temp_db, "SRV", "10.2.2.13")
    sc.collect_server(temp_db, sid, "svc", "pw")
    assert called["n"] == 0


def test_wmi_failure_is_reported(temp_db, monkeypatch):
    _stub_scan(monkeypatch, [135, 445])
    monkeypatch.setattr(wmi_collect, "available", lambda: True)

    def fail(*a, **k):
        raise RuntimeError("WMI 접근 거부 — 계정 권한(로컬 Administrators) 확인")

    monkeypatch.setattr(wmi_collect, "collect", fail)
    sid = db.save_server(temp_db, "WIN", "10.2.2.14")
    sc.collect_server(temp_db, sid, "admin", "pw")
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "WMI" in err and "권한" in err, err
