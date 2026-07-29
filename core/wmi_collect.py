# -*- coding: utf-8 -*-
"""Windows 서버 사양 수집 — WMI 경로(DCOM 135 / WinRM 5985·5986).

SSH가 닫힌 Windows 서버는 사양(CPU·메모리·디스크)을 읽을 방법이 없었다.
Windows는 원래 WMI로 이 정보를 노출하므로, **NetDash가 도는 Windows PC에서**
PowerShell CIM 세션을 열어 원격 조회한다.

전송 경로가 둘이고, 열린 포트에 따라 골라 쓴다.

  - **WinRM(5985/5986)** — 고정 단일 포트라 방화벽을 통과하기 쉽고, Windows
    Server 2012 R2 이상은 기본으로 켜져 있다. RDP(3389)만 열려 보이는 서버도
    대개 5985가 함께 열려 있다.
  - **DCOM(135)** — 135(RPC 엔드포인트 매퍼) + **동적 포트**가 필요하다.
    방화벽이 가장 먼저 막는 대역이라 폐쇄망에서 자주 실패한다.

예전에는 DCOM만 시도해서, 135가 막히고 5985만 열린 서버(하드닝된 구성에서
흔하다)는 사양이 통째로 비었다.

  - 비밀번호는 **명령행이 아니라 환경변수**로 자식 프로세스에 넘긴다
    (명령행은 같은 PC의 다른 사용자에게도 보인다).
"""
import base64
import json
import os
import subprocess

from . import utils

# 전송별 전제 포트 — 열려 있어야 시도할 의미가 있다(불필요한 대기 방지)
WMI_PORTS = (135,)                 # DCOM
WINRM_PORTS = (5985, 5986)         # WinRM(HTTP/HTTPS)

_PS = r"""
$ErrorActionPreference = 'Stop'
# 진행률 표시가 stderr에 CLIXML로 섞여 오류 판독을 방해한다 → 끈다
$ProgressPreference = 'SilentlyContinue'
$sec  = ConvertTo-SecureString $env:ND_WMI_PW -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:ND_WMI_USER, $sec)
if ($env:ND_WMI_TRANSPORT -eq 'winrm') {
  # WinRM: 단일 포트라 방화벽 통과가 쉽다. 5986은 HTTPS(사설 인증서가 흔해
  # 인증서 검사는 건너뛴다 — 폐쇄망 IP 접속은 CN도 맞지 않는다).
  $port = [int]$env:ND_WMI_PORT
  if ($port -eq 5986) {
    $opt = New-CimSessionOption -UseSsl -SkipCACheck -SkipCNCheck
  } else {
    $opt = New-CimSessionOption -Protocol Wsman
  }
  $s = New-CimSession -ComputerName $env:ND_WMI_HOST -Credential $cred -SessionOption $opt -Port $port -OperationTimeoutSec 25
} else {
  $opt = New-CimSessionOption -Protocol Dcom
  $s   = New-CimSession -ComputerName $env:ND_WMI_HOST -Credential $cred -SessionOption $opt -OperationTimeoutSec 25
}
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


def _dec(raw):
    """PowerShell 출력 디코드. 한국어 Windows는 stderr가 cp949로 온다.

    utf-8로만 읽으면 오류 문구가 깨져서 화면에 그대로 노출되고, 아래
    _short_error의 한국어 패턴이 하나도 안 맞아 친절한 안내가 전부 무력해진다.
    """
    b = raw or b""
    for enc in ("utf-8", "cp949", "cp1252"):
        try:
            return b.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", "replace").strip()


def available():
    """이 PC에서 WMI 경로를 쓸 수 있는가(Windows + PowerShell)."""
    return os.name == "nt"


def can_try(open_ports):
    """열린 포트로 보아 WMI를 시도할 만한가(둘 중 하나라도 열려 있으면)."""
    return bool(transports_for(open_ports))


def transports_for(open_ports):
    """열린 포트 → 시도할 전송 목록 [(transport, port)].

    WinRM을 먼저 둔다 — 단일 고정 포트라 방화벽을 통과할 확률이 높고,
    DCOM은 135가 열려 있어도 동적 포트가 막혀 실패하는 경우가 흔하다.
    """
    ports = set(open_ports or [])
    out = []
    if 5985 in ports:
        out.append(("winrm", 5985))
    if 5986 in ports:
        out.append(("winrm", 5986))
    if ports & set(WMI_PORTS):
        out.append(("dcom", 135))
    return out


def collect(ip, username, password, timeout=60, transport="dcom", port=None):
    """원격 Windows에서 사양을 읽어 dict로 반환. 실패하면 예외.

    transport: "dcom"(135) 또는 "winrm"(5985/5986)
    반환 키: hostname, os_info, mac, cpu_model, cpu_cores, mem_total_mb,
             disk_total_gb, disk_used_gb, mem_modules(list), disk_devices(list),
             mem_slots(int)
    """
    if not available():
        raise RuntimeError("WMI 수집은 Windows에서만 가능합니다")
    enc = base64.b64encode(_PS.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    # 비밀번호를 인자로 넘기지 않는다 — 명령행은 다른 사용자에게도 보인다.
    env.update(ND_WMI_HOST=str(ip), ND_WMI_USER=str(username), ND_WMI_PW=str(password),
               ND_WMI_TRANSPORT=str(transport),
               ND_WMI_PORT=str(port or (5985 if transport == "winrm" else 135)))
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
        capture_output=True, timeout=timeout, env=env, creationflags=creationflags)
    out = _dec(p.stdout)
    err = _dec(p.stderr)
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
    # 한국어 Windows는 같은 오류를 한국어로 낸다 — 영어 패턴만 두면 다 빗나간다.
    if "access is denied" in t or "액세스가 거부" in t:
        return "WMI 접근 거부 — 계정 권한(로컬 Administrators) 확인"
    if "rpc server is unavailable" in t or "0x800706ba" in t or "rpc 서버를 사용할 수 없" in t:
        return "WMI 연결 실패 — 방화벽에서 RPC(135) 및 동적 포트 허용 필요"
    if "logon failure" in t or "user name or password" in t \
            or "로그온" in t and "실패" in t:
        return "WMI 인증 실패 — 계정/비밀번호 확인"
    # WinRM 서비스 미기동(대상). 한국어: "대상에서 서비스가 실행되고 ..."
    if "서비스가 실행" in t or "verify that the service on the destination" in t:
        return ("WinRM 응답 없음 — 대상 서버에서 WinRM을 켜세요"
                "(관리자 PowerShell: Enable-PSRemoting -Force)")
    # WinRM에서 가장 흔한 실패. 도메인 밖 계정으로 IP에 붙으면 Kerberos를 쓸 수
    # 없어, **NetDash가 도는 이 PC**에 그 대상을 신뢰 목록으로 등록해야 한다.
    # 서버가 아니라 클라이언트 쪽 설정이라 사유를 모르면 영영 못 고친다.
    if "trustedhosts" in t or "cannot process the request" in t:
        return ("WinRM 신뢰 목록 미등록 — 이 PC에서 관리자 PowerShell로 실행: "
                "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '대상IP' "
                "-Concatenate -Force")
    if "winrm cannot complete the operation" in t or "winrm client cannot" in t \
            or "0x80338012" in t:
        return "WinRM 연결 실패 — 대상에서 WinRM(5985) 허용 여부 확인"
    if "not recognized" in t or "term 'new-cimsession'" in t:
        return "이 PC의 PowerShell이 CIM을 지원하지 않습니다"
    first = (text or "").splitlines()[0] if text else ""
    return ("WMI: " + first[:110]) if first else ""
