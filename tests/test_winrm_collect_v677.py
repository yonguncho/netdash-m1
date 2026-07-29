# -*- coding: utf-8 -*-
"""RDP만 보이는 Windows 서버의 사양 수집 — WinRM 경로 (v6.7.7).

사용자 보고: "서버 사양이 수집 안 되는데 RDP는 접속된다. 계정을 입력하면
RDP로 접속해 수집할 방법이 있나?"

RDP 자체로는 명령을 실행할 수 없다(화면 전송 프로토콜이라 조회 API가 없다).
하지만 RDP가 열렸다는 건 **Windows이고 그 계정이 대화형 로그온에 유효하다**는
뜻이고, 그런 서버는 대개 WinRM(5985)이 함께 열려 있다.

기존 코드는 DCOM(135)만 시도했다. 135는 RPC 엔드포인트 매퍼 + **동적 포트**가
필요해 방화벽이 가장 먼저 막는 대역이라, 하드닝된 서버에서 통째로 실패했다.
WinRM은 고정 단일 포트고 Windows Server 2012 R2+ 는 기본으로 켜져 있다.
"""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc, wmi_collect  # noqa: E402

ROOT = Path(__file__).parent.parent

_OK = {"hostname": "WIN-RDP01", "os_info": "Microsoft Windows Server 2019",
       "cpu_model": "Intel(R) Xeon(R) Gold 6248", "cpu_cores": 16,
       "mem_total_mb": 65536, "disk_total_gb": 900.0, "disk_used_gb": 400.0}


class _Proc:
    def __init__(self, rc=0, out=b"", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _stub_scan(monkeypatch, ports):
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: list(ports))
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: None)
    monkeypatch.setattr(sc, "local_arp_mac", lambda ip: "")


# ── 전송 선택 ───────────────────────────────────────────────────
def test_winrm_tried_when_only_rdp_and_winrm_open():
    """135가 막혀도 5985가 열려 있으면 수집할 수 있어야 한다."""
    assert wmi_collect.transports_for([3389, 5985]) == [("winrm", 5985)]
    assert wmi_collect.can_try([3389, 5985]) is True


def test_winrm_preferred_over_dcom():
    """DCOM은 135가 열려도 동적 포트가 막혀 실패하는 일이 잦다 — 단일 포트 우선."""
    tr = wmi_collect.transports_for([135, 5985])
    assert tr[0] == ("winrm", 5985), tr
    assert ("dcom", 135) in tr, "DCOM도 폴백으로 남아야 한다"


def test_https_winrm_supported():
    assert ("winrm", 5986) in wmi_collect.transports_for([5986])


def test_rdp_alone_is_not_enough():
    """RDP로는 조회할 수 없다 — 헛되이 시도해 기다리면 안 된다."""
    assert wmi_collect.transports_for([3389]) == []
    assert wmi_collect.can_try([3389]) is False


def test_transport_reaches_powershell(monkeypatch):
    """선택한 전송이 실제로 자식 프로세스까지 전달되는가."""
    seen = {}
    monkeypatch.setattr(wmi_collect, "available", lambda: True)

    def fake(args, **kw):
        seen.update(kw.get("env") or {})
        import json as _j
        return _Proc(0, _j.dumps(_OK).encode())

    monkeypatch.setattr(subprocess, "run", fake)
    wmi_collect.collect("10.1.1.5", "admin", "pw", transport="winrm", port=5986)
    assert seen.get("ND_WMI_TRANSPORT") == "winrm"
    assert seen.get("ND_WMI_PORT") == "5986"


def test_password_still_not_on_command_line(monkeypatch):
    seen = {}
    monkeypatch.setattr(wmi_collect, "available", lambda: True)

    def fake(args, **kw):
        seen["args"] = args
        import json as _j
        return _Proc(0, _j.dumps(_OK).encode())

    monkeypatch.setattr(subprocess, "run", fake)
    wmi_collect.collect("10.1.1.5", "admin", "s3cret", transport="winrm")
    assert "s3cret" not in " ".join(seen["args"])


def test_powershell_script_has_both_branches():
    assert "New-CimSessionOption -Protocol Dcom" in wmi_collect._PS
    assert "-Protocol Wsman" in wmi_collect._PS
    assert "-UseSsl" in wmi_collect._PS, "5986(HTTPS) 경로가 없다"


def test_powershell_script_is_syntactically_valid():
    """분기가 늘었으니 문법이 깨지면 모든 서버에서 실패한다 — 실제 파서로 검사."""
    if sys.platform != "win32":
        pytest.skip("Windows 전용")
    p = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "$e=$null;[System.Management.Automation.Language.Parser]::ParseInput("
         "[Console]::In.ReadToEnd(),[ref]$null,[ref]$e)|Out-Null;"
         "if($e.Count -eq 0){'OK'}else{$e[0].Message}"],
        input=wmi_collect._PS.encode("utf-8"), capture_output=True, timeout=90)
    assert b"OK" in p.stdout, p.stdout[:300] + p.stderr[:300]


# ── 한국어 Windows 오류 디코딩 ──────────────────────────────────
def test_korean_stderr_is_decoded():
    """한국어 Windows는 stderr가 cp949다 — utf-8로만 읽으면 글자가 깨진다."""
    ko = "액세스가 거부되었습니다".encode("cp949")
    assert "액세스가 거부" in wmi_collect._dec(ko)


def test_korean_errors_map_to_guidance():
    """깨진 채로 두면 아래 안내가 하나도 안 맞아 사용자는 원인을 못 찾는다."""
    f = wmi_collect._short_error
    assert "권한" in f("New-CimSession : 액세스가 거부되었습니다.")
    assert "WinRM" in f("대상에서 서비스가 실행되고 있는지 확인하십시오")


def test_trustedhosts_guidance_is_actionable():
    """WinRM 최대 걸림돌 — 서버가 아니라 이 PC 설정이라 모르면 못 고친다."""
    msg = wmi_collect._short_error(
        "The WinRM client cannot process the request. ... TrustedHosts ...")
    assert "TrustedHosts" in msg and "Set-Item" in msg


def test_utf8_still_works():
    assert "hello" in wmi_collect._dec(b"hello")


# ── 수집 경로 통합 ──────────────────────────────────────────────
def test_specs_collected_over_winrm(temp_db, monkeypatch):
    """RDP+WinRM만 열린 서버에서 사양이 채워져야 한다."""
    _stub_scan(monkeypatch, [3389, 5985])
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    used = {}

    def fake(ip, u, p, timeout=60, transport="dcom", port=None):
        used["transport"], used["port"] = transport, port
        return dict(_OK)

    monkeypatch.setattr(wmi_collect, "collect", fake)
    sid = db.save_server(temp_db, "WIN-RDP", "10.7.7.50")
    sc.collect_server(temp_db, sid, "admin", "pw")
    row = db.get_server(temp_db, sid)
    assert used["transport"] == "winrm" and used["port"] == 5985
    assert row["cpu_cores"] == 16 and row["mem_total_mb"] == 65536
    assert row["os_type"] == "windows"


def test_falls_back_to_dcom_when_winrm_fails(temp_db, monkeypatch):
    """WinRM이 막혀 있으면 DCOM으로 넘어가야 한다."""
    _stub_scan(monkeypatch, [135, 3389, 5985])
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    tried = []

    def fake(ip, u, p, timeout=60, transport="dcom", port=None):
        tried.append(transport)
        if transport == "winrm":
            raise RuntimeError("WinRM 응답 없음")
        return dict(_OK)

    monkeypatch.setattr(wmi_collect, "collect", fake)
    sid = db.save_server(temp_db, "WIN", "10.7.7.51")
    sc.collect_server(temp_db, sid, "admin", "pw")
    assert tried == ["winrm", "dcom"], tried
    assert db.get_server(temp_db, sid)["cpu_cores"] == 16


def test_auth_failure_does_not_retry_every_transport(temp_db, monkeypatch):
    """계정 문제면 전송을 바꿔도 같다 — 계정 잠금만 앞당긴다."""
    _stub_scan(monkeypatch, [135, 5985])
    monkeypatch.setattr(wmi_collect, "available", lambda: True)
    tried = []

    def fake(ip, u, p, timeout=60, transport="dcom", port=None):
        tried.append(transport)
        raise RuntimeError("WMI 인증 실패 — 계정/비밀번호 확인")

    monkeypatch.setattr(wmi_collect, "collect", fake)
    sid = db.save_server(temp_db, "WIN", "10.7.7.52")
    sc.collect_server(temp_db, sid, "admin", "pw")
    assert tried == ["winrm"], tried


def test_rdp_only_server_reports_why(temp_db, monkeypatch):
    """RDP만 열린 서버는 수집 경로가 없다 — 사유가 화면에 남아야 한다."""
    _stub_scan(monkeypatch, [3389])
    sid = db.save_server(temp_db, "WIN", "10.7.7.53")
    sc.collect_server(temp_db, sid, "admin", "pw")
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert err, "사양을 못 얻었는데 사유가 비어 있다"
