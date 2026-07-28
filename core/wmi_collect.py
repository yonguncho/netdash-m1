# -*- coding: utf-8 -*-
"""Windows 서버 사양 수집 — WMI/DCOM(135·445) 경로.

SSH가 닫힌 Windows 서버는 사양(CPU·메모리·디스크)을 읽을 방법이 없었다.
Windows는 원래 WMI로 이 정보를 노출하므로, **NetDash가 도는 Windows PC에서**
PowerShell CIM 세션(DCOM)을 열어 원격 조회한다.

  - 필요한 포트: 135(RPC 엔드포인트 매퍼) + 동적 포트. 445만 열린 환경도 흔하지만
    DCOM은 135가 필요하다 → 135가 안 보이면 시도하지 않는다(불필요한 대기 방지).
  - WinRM(5985)이 아니라 DCOM을 쓴다. 폐쇄망 서버는 WinRM이 꺼진 경우가 많다.
  - 비밀번호는 **명령행이 아니라 환경변수**로 자식 프로세스에 넘긴다
    (명령행은 같은 PC의 다른 사용자에게도 보인다).
"""
import base64
import json
import os
import subprocess

from . import utils

# WMI(DCOM) 시도 전제 — 이 포트가 열려 있어야 의미가 있다
WMI_PORTS = (135,)

_PS = r"""
$ErrorActionPreference = 'Stop'
# 진행률 표시가 stderr에 CLIXML로 섞여 오류 판독을 방해한다 → 끈다
$ProgressPreference = 'SilentlyContinue'
$sec  = ConvertTo-SecureString $env:ND_WMI_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:ND_WMI_USER, $sec)
$opt  = New-CimSessionOption -Protocol Dcom
$s    = New-CimSession -ComputerName $env:ND_WMI_HOST -Credential $cred -SessionOption $opt -OperationTimeoutSec 25
try {
  $cs  = Get-CimInstance -CimSession $s Win32_ComputerSystem
  $os  = Get-CimInstance -CimSession $s Win32_OperatingSystem
  $cpu = @(Get-CimInstance -CimSession $s Win32_Processor)
  $ld  = @(Get-CimInstance -CimSession $s Win32_LogicalDisk -Filter "DriveType=3")
  $mem = @(Get-CimInstance -CimSession $s Win32_PhysicalMemory)
  $arr = @(Get-CimInstance -CimSession $s Win32_PhysicalMemoryArray)
  $dd  = @(Get-CimInstance -CimSession $s Win32_DiskDrive)
  $nic = @(Get-CimInstance -CimSession $s Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True")
  $sizeSum = ($ld | Measure-Object -Property Size -Sum).Sum
  $freeSum = ($ld | Measure-Object -Property FreeSpace -Sum).Sum
  $out = [ordered]@{
    hostname      = $cs.Name
    os_info       = ($os.Caption + ' ' + $os.Version).Trim()
    cpu_model     = $cpu[0].Name
    cpu_cores     = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    mem_total_mb  = [math]::Round($cs.TotalPhysicalMemory / 1MB)
    disk_total_gb = if ($sizeSum) { [math]::Round($sizeSum / 1GB, 1) } else { 0 }
    disk_used_gb  = if ($sizeSum) { [math]::Round(($sizeSum - $freeSum) / 1GB, 1) } else { 0 }
    mem_slots     = ($arr | Measure-Object -Property MemoryDevices -Sum).Sum
    mac           = ($nic | Where-Object { $_.MACAddress } | Select-Object -First 1).MACAddress
    mem_modules   = @($mem | ForEach-Object { [ordered]@{
                      size_mb  = [math]::Round($_.Capacity / 1MB)
                      locator  = $_.DeviceLocator
                      speed    = $_.Speed
                      maker    = $_.Manufacturer
                      part     = ($_.PartNumber -replace '\s+$', '')
                    } })
    disk_devices  = @($dd | ForEach-Object { [ordered]@{
                      name    = $_.DeviceID
                      model   = $_.Model
                      size_gb = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
                      kind    = $_.InterfaceType
                    } })
  }
  $out | ConvertTo-Json -Depth 4 -Compress
} finally { Remove-CimSession $s -ErrorAction SilentlyContinue }
"""


def available():
    """이 PC에서 WMI 경로를 쓸 수 있는가(Windows + PowerShell)."""
    return os.name == "nt"


def can_try(open_ports):
    """열린 포트로 보아 WMI(DCOM)를 시도할 만한가."""
    return bool(set(open_ports or []) & set(WMI_PORTS))


def collect(ip, username, password, timeout=60):
    """원격 Windows에서 사양을 읽어 dict로 반환. 실패하면 예외.

    반환 키: hostname, os_info, mac, cpu_model, cpu_cores, mem_total_mb,
             disk_total_gb, disk_used_gb, mem_modules(list), disk_devices(list),
             mem_slots(int)
    """
    if not available():
        raise RuntimeError("WMI 수집은 Windows에서만 가능합니다")
    enc = base64.b64encode(_PS.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    # 비밀번호를 인자로 넘기지 않는다 — 명령행은 다른 사용자에게도 보인다.
    env.update(ND_WMI_HOST=str(ip), ND_WMI_USER=str(username), ND_WMI_PW=str(password))
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
        capture_output=True, timeout=timeout, env=env, creationflags=creationflags)
    out = (p.stdout or b"").decode("utf-8", "replace").strip()
    err = (p.stderr or b"").decode("utf-8", "replace").strip()
    if p.returncode != 0 or not out:
        raise RuntimeError(_short_error(err) or "WMI 조회 실패(응답 없음)")
    try:
        data = json.loads(out)
    except ValueError:
        raise RuntimeError("WMI 응답을 해석하지 못했습니다")
    if isinstance(data, list):
        data = data[0] if data else {}
    utils.log_event("info", "wmi_collect_ok", ip=ip,
                    cores=data.get("cpu_cores"), mem_mb=data.get("mem_total_mb"))
    return data


def _short_error(text):
    """PowerShell 오류 원문 → 사용자에게 보여줄 짧은 한글 사유.

    -EncodedCommand 실행 시 stderr가 CLIXML로 감싸여 오므로 실제 문구만 뽑는다.
    """
    import re as _re
    m = _re.findall(r'<S S="Error">([^<]{5,300})</S>', text or "")
    if m:
        text = " ".join(x.replace("_x000D__x000A_", " ") for x in m[:2])
    t = (text or "").lower()
    if "access is denied" in t or "액세스가 거부" in t:
        return "WMI 접근 거부 — 계정 권한(로컬 Administrators) 확인"
    if "rpc server is unavailable" in t or "0x800706ba" in t:
        return "WMI 연결 실패 — 방화벽에서 RPC(135) 및 동적 포트 허용 필요"
    if "logon failure" in t or "user name or password" in t:
        return "WMI 인증 실패 — 계정/비밀번호 확인"
    if "not recognized" in t or "term 'new-cimsession'" in t:
        return "이 PC의 PowerShell이 CIM을 지원하지 않습니다"
    first = (text or "").splitlines()[0] if text else ""
    return ("WMI: " + first[:110]) if first else ""
