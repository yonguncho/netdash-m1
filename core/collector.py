import queue
import threading
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

from . import db
from . import fixtures
from . import utils
from . import credentials
from . import ssh_compat  # 구형 장비 SSH 레거시 알고리즘 호환(import 시 적용)
from . import secpolicy
from config import get_config

logger = logging.getLogger(__name__)


def _sanitize_error_msg(error_str: str) -> str:
    """Redact sensitive info (passwords, credentials) from error messages.

    Security fix: Error logs may expose SSH credentials, file paths, or network topology.
    Remove known patterns and limit length to prevent log injection attacks.
    """
    if not error_str:
        return ""
    sanitized = re.sub(r'(password|credential|secret|key|auth)\s*[:=]\s*["\']?[^\s"\']+"?', '[REDACTED]', error_str, flags=re.I)
    sanitized = re.sub(r'/[a-zA-Z0-9/_\-\.]+\.pem', '[REDACTED]', sanitized)
    # 절대경로 제거 — netdash.log는 DB 옆(공유폴더)에 쌓이므로 경로가 남으면
    # 공유 접근 권한자 전원에게 내부 폴더 구조가 노출된다.
    sanitized = re.sub(r'\\\\[^\s\'"]+', '<path>', sanitized)          # UNC \\server\share
    sanitized = re.sub(r'[A-Za-z]:\\[^\s\'"]*', '<path>', sanitized)   # C:\...
    return sanitized[:200] if len(sanitized) > 200 else sanitized

_worker_queue = None
_worker_threads = []
_collecting_switches = set()
_collector_lock = threading.Lock()

# UI/단축 vendor 값 → netmiko device_type & config/parser 키 정규화.
# 연결 테스트(connectivity)는 매핑했으나 수집 경로는 raw vendor를 써서
# "unsupported device_type" 오류가 났다 → 동일 정규화 적용.
_NETMIKO_VENDOR = {
    "cisco": "cisco_ios",
    "nexus": "cisco_nxos",
    "cisco_nexus": "cisco_nxos",
    "arista": "arista_eos",
    "extreme": "extreme_exos",
    "extremexos": "extreme_exos",
    "extreme_xos": "extreme_exos",
    "extreme-xos": "extreme_exos",
    "exos": "extreme_exos",
    "extremenetworks": "extreme_exos",
    "juniper": "juniper_junos",
    "junos": "juniper_junos",
    "juniper_ex": "juniper_junos",
    # HP ProCurve = ArubaOS-Switch(리브랜딩) — CLI가 같아 같은 파서를 쓴다.
    "hp": "hp_procurve",
    "hpe": "hp_procurve",
    "procurve": "hp_procurve",
    "aruba_procurve": "hp_procurve",
    "arubaos_switch": "aruba_osswitch",
    "aruba_switch": "aruba_osswitch",
    # ArubaOS-CX는 CLI가 달라 별도 파서(netmiko device_type은 aruba_os)
    "aruba": "aruba_os",
    "aruba_cx": "aruba_os",
    "arubaos_cx": "aruba_os",
    "paloalto": "paloalto_panos",
    "alteon": "alteon",
    "radware": "alteon",
    "radware_alteon": "alteon",
    "nortel_alteon": "alteon",
}


def _norm_vendor(vendor):
    """벤더 값을 netmiko device_type/내부 키로 정규화(이미 정확하면 그대로).

    벤더 미지정('unknown'/빈값)은 가장 흔한 Cisco IOS로 시도(fallback).
    """
    v = (vendor or "").strip().lower()
    if v in ("", "unknown"):
        return "cisco_ios"
    return _NETMIKO_VENDOR.get(v, v)


class UnsupportedVendorError(RuntimeError):
    """파서가 없는 벤더 — 접속은 됐으나 파싱할 수 없다(0건 '성공' 위장 방지)."""


class _DriverMismatchError(RuntimeError):
    """netmiko 드라이버-장비 불일치(프롬프트 매칭 실패). 재시도 무의미 → 즉시 폴백."""


_EVENT_IFACE_RE = re.compile(
    r"((?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Eth|Gi|Te|Fa|"
    r"Port-?channel|Port|Po|Vlan|mgmt)\s?\d(?:[\d/.:]*\d)?)", re.IGNORECASE)
# 'Port' = EXOS("Port 1:5") 대응. 꼬리는 숫자로 끝나야 함 —
# "Port1:5: link down"의 구분자 콜론이 포트명에 딸려오는 것 방지.


def _extract_event_ports(events, kind):
    """log_analyzer 이벤트에서 해당 종류(flapping/looping)의 문제 포트 목록 추출."""
    ports = []
    for e in events or []:
        et = e.get("type")
        if kind == "flapping" and et != "flapping":
            continue
        if kind == "looping" and et not in ("looping", "error"):
            continue
        detail = e.get("detail") or ""
        m = _EVENT_IFACE_RE.search(detail)
        if m:
            p = m.group(1).replace(" ", "")
            if p not in ports:
                ports.append(p)
    return ports[:5]


def _friendly_fail_reason(msg):
    """수집 실패 원인을 실행 가능한 한국어 안내로 변환(원문 뒤에 병기)."""
    low = (msg or "").lower()
    if "도달 불가" in (msg or "") or "tcp-22" in low:
        return "장비 응답 없음(TCP-22 도달 불가) — 전원/케이블/방화벽 확인. " + msg
    if "수집 제한시간" in (msg or "") or "timeouterror" in low:
        return "수집 제한시간 초과(장비 응답 지연/세션 멈춤). " + msg
    if "authentication" in low or "auth" in low and "fail" in low:
        return "인증 실패 — 계정/비밀번호 확인. " + msg
    if "pattern not detected" in low or "드라이버 불일치" in (msg or "") or "명령셋 불일치" in (msg or ""):
        return "장비 OS와 명령/드라이버 불일치 — 벤더 지정 확인(자동 교정 시도됨). " + msg
    if "no credentials" in low:
        return "저장된 계정 없음 — 계정 입력 또는 '계정 저장' 후 재시도. " + msg
    if "timed out" in low or "timeout" in low:
        return "연결/응답 시간 초과 — 네트워크 경로/출발지 IP 확인. " + msg
    if "incompatible ssh" in low or "kex" in low or "no acceptable" in low:
        return "SSH 알고리즘 협상 실패(구형 장비) — 재시도 권장. " + msg
    return msg


def _run_with_timeout(fn, timeout_sec, *args, **kwargs):
    """장비당 수집 하드 타임아웃 — 어떤 이유로든(SSH 무한대기 등) 제한시간을
    넘기면 강제 실패 처리해 워커가 다음 장비로 진행하게 한다.

    별도 데몬 스레드에서 fn을 실행하고 join(timeout). 초과 시 TimeoutError.
    (버려진 스레드는 데몬이라 앱 동작에 영향 없음 — '수집중' 영구 고착 방지가 우선)
    """
    result = {}

    def _target():
        try:
            result["v"] = fn(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001 — 원예외 그대로 전달
            result["e"] = e

    th = threading.Thread(target=_target, daemon=True)
    th.start()
    th.join(timeout_sec)
    if th.is_alive():
        raise TimeoutError(
            "수집 제한시간(%d초) 초과 — 강제 종료, 다음 장비 진행" % timeout_sec)
    if "e" in result:
        raise result["e"]
    return result.get("v")


def _tcp_precheck(ip, port=22, timeout=4, source_ip=None):
    """SSH 시도 전 TCP 도달성 사전 확인.

    응답 없는 장비에 재시도 3회×30초(~100초)를 낭비하지 않고 즉시 실패 처리해
    큐의 다음 장비로 빠르게 넘어가게 한다(일괄/자동 수집 흐름 유지).
    """
    import socket
    src = (source_ip, 0) if source_ip else None
    try:
        with socket.create_connection((str(ip), int(port)), timeout=timeout, source_address=src):
            return True
    except (OSError, ValueError):
        return False


def _icmp_ping(ip, timeout_ms=1500):
    """시스템 ping으로 ICMP 도달성 확인(권한 불필요). 성공 시 True."""
    import subprocess
    import platform
    try:
        if platform.system().lower().startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), str(ip)]
        r = subprocess.run(cmd, capture_output=True, timeout=(timeout_ms / 1000.0) + 2,
                           creationflags=(0x08000000 if platform.system().lower().startswith("win") else 0))
        return r.returncode == 0
    except Exception:
        return False


def is_reachable(ip, source_ip=None, tcp_ports=(22, 443, 23, 80)):
    """장비 도달성 확인 — 등록 게이트용. TCP(관리 포트) 또는 ICMP ping 중 하나라도 응답하면 True.

    정적 IP 화이트리스트 대신 '실제 통신 가능 여부'로 등록을 허용하기 위한 판정.
    """
    for p in tcp_ports:
        if _tcp_precheck(ip, p, timeout=2, source_ip=source_ip):
            return True
    return _icmp_ping(ip)


def canonical_vendor(vendor):
    """저장용 벤더 정규화: 별칭(cisco/extreme/nexus...)을 표준 값으로.

    _norm_vendor와 달리 unknown/빈값은 'unknown' 그대로(자동 학습 대상 유지).
    UI 드롭다운·DB·표시를 하나의 표준 값(cisco_ios/extreme_exos/...)으로 통일.
    """
    v = (vendor or "").strip().lower()
    if v in ("", "unknown"):
        return "unknown"
    return _NETMIKO_VENDOR.get(v, v)


def _is_unknown_vendor(vendor):
    return (vendor or "").strip().lower() in ("", "unknown")


def _prompt_looks_alteon(text):
    """Alteon 메뉴형 CLI 프롬프트 판별.

    실장비(5224/Standard ADC) 확인 형태: '>> SKBA_... - Standard ADC - Main#'
    — '>>' 접두는 캡처 과정에서 잘릴 수 있으므로 '- Main#' 꼬리와
    'Standard ADC'/'Application Switch' 키워드도 함께 본다.
    netmiko는 send_command 결과에서 프롬프트를 잘라내므로 '출력 텍스트'가 아니라
    접속 직후 '프롬프트 자체'를 검사하는 것이 확실하다.
    """
    t = (text or "").strip()
    if not t:
        return False
    if t.startswith(">>"):
        return True
    # BUGFIX: '-Main#'만 보면 호스트명이 '...-Main'인 일반 장비(예: SW-Main#)를
    # Alteon으로 오분류 → 검증 전 DB가 alteon으로 갱신돼 수집 불능. Alteon 실제
    # 프롬프트는 'Standard ADC - Main#'처럼 하이픈 앞에 공백이 있으므로 공백을
    # 요구(일반 호스트명 'SW-Main#'는 하이픈 앞이 문자라 제외).
    if re.search(r"\s-\s*Main#?\s*$", t):
        return True
    return bool(re.search(r"standard adc|application switch", t, re.IGNORECASE))


def _looks_like_alteon(outputs):
    """수집 출력에서 Alteon(메뉴형 CLI) 시그니처 탐지.

    Alteon 프롬프트('>> Main#')는 '#'로 끝나 cisco 드라이버 접속이 '성공'하고,
    cisco 명령은 메뉴 오류 텍스트만 받아 예외 없이 '완료'되지만 데이터가 빈다.
    출력 어디든 Alteon 흔적이 보이면 alteon으로 교정해 전용 수집으로 재수집.
    """
    joined = "\n".join(str(v) for v in (outputs or {}).values())[:20000]
    # '-Main#' 단독은 일반 호스트명 오탐 → 하이픈 앞 공백 요구(위 _prompt_looks_alteon과 동일)
    return bool(re.search(r">>\s?[\w\s.-]*Main#|\s-\s*Main#|Alteon|Radware|Standard ADC",
                          joined, re.IGNORECASE))


def _detect_vendor_from_version(text):
    """show version 출력에서 실제 벤더(device_type) 학습. 못 찾으면 None.

    순서 중요: NX-OS는 'Cisco Nexus...NX-OS'라 Cisco보다 먼저 판별한다.
    """
    t = (text or "").lower()
    if not t:
        return None
    if "nx-os" in t or "nexus" in t:
        return "cisco_nxos"
    if "arista" in t:
        return "arista_eos"
    if "extremexos" in t or "exos" in t or "extreme networks" in t:
        return "extreme_exos"
    if "junos" in t or "juniper" in t:
        return "juniper_junos"
    if "alteon" in t or "radware" in t or "standard adc" in t:
        return "alteon"
    # ArubaOS-CX 가 ProCurve보다 먼저 — CX 배너에도 'aruba'가 들어간다.
    if "arubaos-cx" in t or "arubaos cx" in t:
        return "aruba_os"
    # ProCurve/ArubaOS-Switch: 배너에 'ProCurve'/'Aruba'가 있거나,
    # 이미지 스탬프 버전 표기(WC.16.10.0009 / YA.16.x)로 판별한다.
    if "procurve" in t or "arubaos-switch" in t or "aruba" in t:
        return "hp_procurve"
    if "image stamp" in t and re.search(r"\b[a-z]{2}\.\d{2}\.\d{2}", t):
        return "hp_procurve"
    if "hewlett" in t or "hp j" in t or "hpe " in t:
        return "hp_procurve"
    if "ios-xe" in t or "ios xe" in t or "cisco ios" in t or "ios software" in t or "cisco" in t:
        return "cisco_ios"
    return None


def _parse_os_version(vendor, text):
    """show version 출력에서 짧은 버전 문자열 추출(스위치 현황 표기용).

    예: 'IOS-XE 17.3.5', 'NX-OS 9.3(5)', 'EXOS 22.7.1.2', 'EOS 4.25.4M', 'JUNOS 18.4R3'
    못 찾으면 None(기존 값 유지).
    """
    t = text or ""
    if not t:
        return None
    v = (vendor or "").lower()
    patterns = {
        "cisco_nxos": [(r"NXOS:\s*version\s+(\S+)", "NX-OS "),
                       (r"system:\s+version\s+(\S+)", "NX-OS "),
                       (r"kickstart:\s*version\s+(\S+)", "NX-OS ")],
        "cisco_ios": [(r"IOS[- ]XE Software.*?Version\s+([\w.():]+)", "IOS-XE "),
                      (r"Cisco IOS Software.*?Version\s+([\w.():]+?)[,\s]", "IOS "),
                      (r"\bVersion\s+([\w.():]+?)[,\s]", "IOS ")],
        "arista_eos": [(r"Software image version:\s*(\S+)", "EOS ")],
        "extreme_exos": [(r"ExtremeXOS\s+version\s+(\S+)", "EXOS "),
                         (r"IMG:\s*(\S+)", "EXOS ")],
        "juniper_junos": [(r"Junos:\s*(\S+)", "JUNOS "),
                          (r"JUNOS.*?\[([\w.-]+)\]", "JUNOS ")],
        # ArubaOS-CX: 'Version      : FL.10.08.1010'
        "aruba_os": [(r"Version\s*:\s*([\w.]+)", "AOS-CX ")],
        # ProCurve/ArubaOS-Switch: 이미지 스탬프 줄의 'WC.16.10.0009'
        "hp_procurve": [(r"\b([A-Z]{2}\.\d{2}\.\d{2}\.\d{4})\b", "AOS-S "),
                        (r"\b([A-Z]{2}\.\d{2}\.\d{2})\b", "AOS-S "),
                        (r"Software revision\s*:\s*(\S+)", "AOS-S ")],
        "alteon": [(r"[Ss]oftware\s+[Vv]ersion:?\s*(\d[\w.]+)", "Alteon "),
                   (r"booted\s+software\s+version\s*:?\s*(\d[\w.]+)", "Alteon "),
                   (r"[Vv]ersion\s*:?\s*(\d+\.\d[\w.]*)", "Alteon ")],
    }
    # ArubaOS-Switch는 ProCurve와 같은 형식
    if v == "aruba_osswitch":
        v = "hp_procurve"
    for pat, prefix in patterns.get(v, []):
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            return (prefix + m.group(1).strip().rstrip(",")).strip()[:60]
    # 범용 폴백
    m = re.search(r"[Vv]ersion[:\s]+([\w.():-]+)", t)
    if m:
        return m.group(1).strip().rstrip(",")[:60]
    return None


def _parse_model(vendor, text):
    """show version 출력에서 하드웨어 모델명 추출. 못 찾으면 None."""
    t = text or ""
    if not t:
        return None
    v = (vendor or "").lower()
    patterns = {
        "cisco_nxos": [r"cisco\s+(Nexus\s?\S+(?:\s+\S+)?)\s+[Cc]hassis",
                       r"cisco\s+(N[0-9]K-\S+)",
                       r'PID:\s*([A-Z0-9][\w./-]+)',   # show inventory(가장 확실)
                       r"Hardware\s*\n\s*cisco\s+(\S+(?:\s+\S+)?)"],
        "cisco_ios": [r"Model Number\s*:\s*(\S+)",
                      # VG3X0(음성게이트웨이)·라우터 계열 포함. 'cisco VG320 (revision..)'
                      r"cisco\s+((?:WS|C|IE|ME|CGR|ASR|ISR|VG|CISCO)[\w-]+)\s*\(",
                      # show version 이미지명의 플랫폼 토큰(VG3X0-universalk9-M)
                      r"IOS Software,\s*([A-Z0-9]+VG[0-9X]+|VG[0-9X]+)[- ]"],
        "arista_eos": [r"^\s*Arista\s+(\S+)"],
        "extreme_exos": [r"System Type:\s*(\S+)",
                         r"PlatformName:\s*(\S+)"],
        "juniper_junos": [r"Model:\s*(\S+)"],
        "alteon": [r"(?:Application Switch|Alteon(?:\s+AAS)?)\s+(\d\S*)"],
    }
    for pat in patterns.get(v, []):
        m = re.search(pat, t, re.IGNORECASE | re.MULTILINE)
        if m:
            return m.group(1).strip().rstrip(",")[:60]
    m = re.search(r"Model(?:\s*Number)?\s*[:=]\s*(\S+)", t, re.IGNORECASE)
    if m:
        return m.group(1).strip()[:60]
    return None


def _parse_serial(vendor, text):
    """show version/inventory 출력에서 시리얼 번호 추출. 못 찾으면 None."""
    t = text or ""
    if not t:
        return None
    v = (vendor or "").lower()
    # cisco_xe/catalyst는 cisco_ios와 동일 포맷 → 같은 패턴 적용
    if v.startswith("cisco_xe") or v.startswith("cisco_ios"):
        v = "cisco_ios"
    patterns = {
        "cisco_ios": [r"System [Ss]erial [Nn]umber\s*:?\s*([A-Z0-9]+)",
                      # show inventory: 'SN: FOC2xxxxxxx'(가장 확실 — 9300L 등)
                      r"SN:\s*([A-Z0-9]+)",
                      # Catalyst 스위치 표: 'Switch Ports Model Serial No.' 아래 행 끝의 SN
                      r"^\*?\s*\d+\s+\d+\s+\S+\s+([A-Z0-9]{8,})\s*$",
                      r"Processor board ID\s+([A-Z0-9]+)"],
        "cisco_nxos": [r"SN:\s*([A-Z0-9]+)",
                       r"Processor Board ID\s+([A-Z0-9]+)"],
        "arista_eos": [r"Serial number:\s*(\S+)"],
        "extreme_exos": [r"^Switch\s*:\s*\S+\s+([0-9A-Za-z-]+)\s+Rev",
                         r"^Slot-\d+\s*:\s*\S+\s+([0-9A-Za-z-]+)\s+Rev"],
        "juniper_junos": [r"[Cc]hassis\s+serial\s+number\s*:?\s*(\S+)",
                          r"Serial [Nn]umber\s*:?\s*(\S+)"],
        "alteon": [r"Serial\s*(?:Number|No\.?)?\s*[:#]?\s*([A-Z0-9-]{5,})",
                   r"Switch\s+Serial\s+No[.:]*\s*(\S+)"],
    }
    for pat in patterns.get(v, []):
        m = re.search(pat, t, re.MULTILINE)
        if m:
            return m.group(1).strip().rstrip(",")[:60]
    m = re.search(r"[Ss]erial\s*(?:[Nn]umber|[Nn]o\.?)?\s*[:#]\s*([A-Za-z0-9-]{4,})", t)
    if m:
        return m.group(1).strip()[:60]
    return None


def collect_env_snmp(db_path, kind, device_id, ip, budget=15.0):
    """장비 환경 정보(온도·팬)를 SNMP로 읽어 저장. 반환: 저장한 dict 또는 None.

    스위치·방화벽·서버가 같은 표준 MIB(ENTITY-SENSOR-MIB)을 쓰므로 구현은 하나다.
    - 서버 사양 수집이 쓰던 SNMP 설정(사용 여부·커뮤니티)을 그대로 재사용한다.
      온도 때문에 커뮤니티를 또 입력하게 만들 이유가 없다. 설정을 안 했으면
      기본값 'public'으로 시도한다(끄려면 설정에서 SNMP를 끈다).
    - 실패는 조용히 넘긴다: 이 MIB 미지원 장비가 흔하고, SSH 수집 결과까지
      같이 버리면 손해가 더 크다. 원인은 로그로 남긴다.
    """
    if not ip:
        return None
    community = _snmp_community_if_enabled(db_path)
    if not community:
        return None
    try:
        from . import snmp_env
    except Exception:
        return None
    try:
        env = snmp_env.collect_env(ip, community, budget=budget)
    except snmp_env.SnmpClosed:
        utils.log_event("info", "env_snmp_closed", kind=kind, device_id=device_id)
        return None
    except snmp_env.SnmpError:
        utils.log_event("info", "env_snmp_no_reply", kind=kind, device_id=device_id)
        return None
    except Exception as e:
        utils.log_event("warning", "env_snmp_failed", kind=kind, device_id=device_id,
                        error=_sanitize_error_msg(str(e)))
        return None
    if not env.get("sensors"):
        # 응답은 왔는데 센서 테이블이 비었다 = 이 장비는 이 MIB을 안 쓴다.
        utils.log_event("info", "env_snmp_unsupported", kind=kind, device_id=device_id)
        return None
    db.save_device_env(db_path, kind, device_id, env, source="snmp")
    return env


def _snmp_community_if_enabled(db_path):
    """SNMP가 켜져 있으면 커뮤니티, 꺼져 있으면 None.

    주의: `snmp_community()`는 저장값이 없어도 기본값 'public'을 돌려준다
    (서버 사양 수집 때부터의 동작). 즉 커뮤니티를 설정하지 않아도 시도는 한다 —
    폐쇄망에서 public이 열려 있는 경우가 많아 그대로 두지만, '설정해야만 시도한다'는
    뜻이 아니다. 끄려면 설정에서 SNMP 자체를 꺼야 한다.
    """
    try:
        from . import server_collector as _sc
        if not _sc.snmp_enabled(db_path):
            return None
        return _sc.snmp_community(db_path) or None
    except Exception:
        return None


def collect_fw_metrics_snmp(db_path, fw):
    """FortiGate 상태 지표(CPU·메모리·디스크·세션·HA)를 SNMP로 읽어 저장.

    벤더 전용 MIB이라 FortiGate에만 시도한다. 실패는 조용히 넘긴다 —
    REST/SSH 수집 결과까지 같이 버리면 손해가 크다.
    """
    if (fw or {}).get("vendor") != "fortigate" or not fw.get("host"):
        return None
    community = _snmp_community_if_enabled(db_path)
    if not community:
        return None
    try:
        from . import snmp_fortigate
        m = snmp_fortigate.collect_health(fw["host"], community)
    except Exception as e:
        utils.log_event("info", "fw_metrics_snmp_skipped", firewall_id=fw.get("id"),
                        error=_sanitize_error_msg(str(e))[:120])
        return None
    if not m or all(m.get(k) is None for k in ("cpu_pct", "mem_pct", "sessions")):
        # 응답은 왔는데 핵심 지표가 없다 = SNMP는 되지만 이 MIB이 막혀 있다.
        utils.log_event("info", "fw_metrics_snmp_empty", firewall_id=fw.get("id"))
        return None
    # 통째로 덮으면 SSH·REST가 채운 model·vpn·policy·license가 지워진다
    # (같은 metrics_json을 세 경로가 쓴다 — dual-path). 읽어서 합쳐 쓴다.
    # 표기 기준(사용자 지정)은 SSH get sys status라 model 계열은 빈 곳만 채운다.
    try:
        cur = (db.get_device_env(db_path, "firewall", fw["id"]) or {}).get("metrics") or {}
    except Exception:
        cur = {}
    for k, v in m.items():
        if k in ("model", "version", "serial", "hostname"):
            if not cur.get(k):
                cur[k] = v
        else:
            cur[k] = v
    db.save_device_metrics(db_path, "firewall", fw["id"], cur, source="snmp")
    return cur


def save_firewall_result(db_path, fw, result, cred=None):
    """방화벽 수집 결과 저장 — 인터페이스·ARP·HA·온도·지표·센서를 한 번에.

    수집 호출부가 셋(자동 수집·수집 버튼·일괄 수집)이라 각자 저장하면 반드시
    한 곳이 빠진다. 실제로 v6.16.0의 온도·지표가 자동 수집 경로에만 붙어 있어
    '수집' 버튼으로는 채워지지 않았다. 저장은 여기 한 곳에서만 한다.
    """
    fid = fw["id"]
    db.save_firewall_interfaces(db_path, fid, result.get("interfaces") or [])
    db.save_firewall_arp(db_path, fid, result.get("arp") or [])
    if result.get("ha"):
        try:
            import json as _json
            db.set_firewall_ha_info(db_path, fid, _json.dumps(result["ha"]))
        except Exception:
            pass
    # 아래는 모두 부가 정보 — 실패해도 인터페이스/ARP 수집 성공을 취소하지 않는다.
    try:
        collect_env_snmp(db_path, "firewall", fid, fw.get("host"))
    except Exception:
        pass
    try:
        collect_fw_metrics_snmp(db_path, fw)
    except Exception:
        pass
    try:
        merge_fw_extra(db_path, fw, result, cred)
    except Exception:
        pass


def merge_fw_extra(db_path, fw, collected, cred=None):
    """방화벽 대시보드용 부가 정보를 지표에 합쳐 저장.

    - REST 수집 결과의 vpn·policy (collect_firewall이 함께 받아온다)
    - `execute sensor list` (SSH) — PSU·전압·전류·팬. SNMP 온도보다 항목이 많고
      장비가 준 alarm 플래그가 있어 임계를 우리가 추측하지 않아도 된다.

    지표는 SNMP 경로가 먼저 저장했을 수 있으므로 **읽어서 합친 뒤 다시 쓴다** —
    통째로 덮으면 CPU·메모리가 지워진다.
    """
    if (fw or {}).get("vendor") != "fortigate":
        return None
    extra = {}
    for key in ("vpn", "policy", "license", "objects"):
        v = (collected or {}).get(key)
        if v:
            extra[key] = v
    # 모델·버전(REST monitor/system/status) — SSH의 get system status가 있으면
    # 그쪽이 이겨야 하므로(사용자 지정 기준) extra가 아니라 '빈 곳 채움'으로 합류.
    sysinfo = (collected or {}).get("sysinfo") or {}

    cred = cred or {}
    user, pw = cred.get("username", ""), cred.get("password", "")
    perf = {}
    if user and pw and fw.get("host"):
        try:
            from .firewall import fortisensor
            s = fortisensor.collect_ssh_all(fw["host"], user, pw)
            if s.get("sensors"):
                extra["sensors"] = s["sensors"]
            perf = s.get("perf") or {}
        except Exception as e:
            # VM 모델은 센서가 없고, SSH가 막힌 장비도 있다 — 정상 범주다.
            utils.log_event("info", "fw_sensor_list_skipped", firewall_id=fw.get("id"),
                            error=_sanitize_error_msg(str(e))[:120])
    if not extra and not perf:
        return None
    try:
        cur = (db.get_device_env(db_path, "firewall", fw["id"]) or {}).get("metrics") or {}
    except Exception:
        cur = {}
    cur.update(extra)
    # get sys status(SSH)의 model/version은 표기 기준이라 항상 덮는다(사용자 지정).
    # 그 외(perf 지표)는 SNMP가 이미 채운 값을 그대로 두고 빈 곳만 채운다.
    for k in ("model", "version", "serial", "hostname"):
        if perf.get(k):
            cur[k] = perf.pop(k)
    for k, v in perf.items():
        if cur.get(k) is None:
            cur[k] = v
    for k, v in sysinfo.items():
        if cur.get(k) is None:
            cur[k] = v
    if any(cur.get(k) is not None for k in ("cpu_pct", "mem_pct", "disk_pct")):
        from . import snmp_fortigate as _fgm
        worst = max([p for p in (cur.get("cpu_pct"), cur.get("mem_pct"),
                                 cur.get("disk_pct")) if p is not None], default=None)
        cur["level"] = _fgm.pct_level(worst)
    db.save_device_metrics(db_path, "firewall", fw["id"], cur, source="rest+ssh")
    return cur


def _commands_for(vendor):
    """벤더의 수집 명령 집합. config에 없으면 파서 모듈 COMMANDS로 폴백."""
    cmds = get_config().get_commands(vendor)
    if cmds:
        return cmds
    try:
        from . import parsers
        parser = parsers.get_parser(vendor)
        return dict(getattr(parser, "COMMANDS", {}) or {})
    except Exception:
        return {}


# 벤더별 페이징 비활성화 명령(긴 출력 잘림 방지). EXOS는 'terminal length 0'이 아니라
# 'disable clpaging'. 미정의 벤더는 페이징 명령을 생략한다.
_PAGING_CMD = {
    "cisco_ios": "terminal length 0",
    "arista_eos": "terminal length 0",
    "extreme_exos": "disable clipaging",  # (netmiko도 세션 준비에서 자동 실행)
    "juniper_junos": "set cli screen-length 0",
}

# 포트채널 멤버 해석용 추가 명령(config 무관 항상 시도). 설비/TPS 직결이
# MAC 테이블에 Po로 보일 때 실제 물리 멤버포트를 알아내기 위함.
_PORT_CHANNEL_CMD = {
    "cisco_nxos": "show port-channel summary",
}

# 설정(running-config) 백업 명령 — 변경 diff 알람용. 설정으로 끌 수 있음.
_CONFIG_CMD = {
    "cisco_ios": "show running-config",
    "cisco_nxos": "show running-config",
    "arista_eos": "show running-config",
    "extreme_exos": "show configuration",
}


def init_collector():
    global _worker_queue, _worker_threads
    config = get_config()
    max_workers = config.get_max_concurrent()

    # Replace queue and start fresh workers (old workers are daemon threads, auto-cleanup)
    # maxsize=1000: '전체 수집'(bulk-collect, 최대 500대)이 한 번에 큐잉해도 수용.
    # (기존 100 — 워커 3개가 SSH 수집으로 천천히 빼는 동안 101번째부터 queue.Full
    #  → "Queue is full" 에러로 대부분 스킵되던 문제)
    # 실제 큐 길이는 _collecting_switches 중복 방지로 등록 스위치 수를 넘지 못하며,
    # 항목은 (db_path, switch_id) 튜플이라 메모리 부담 없음. 상한은 방어적 안전장치.
    _worker_queue = queue.Queue(maxsize=1000)
    _worker_threads = []

    for i in range(max_workers):
        t = threading.Thread(target=_worker_loop, daemon=True, name=f"collector-worker-{i}")
        t.start()
        _worker_threads.append(t)

    utils.log_event("info", "collector_init", workers=max_workers)


def shutdown_workers(timeout=5):
    """살아있는 워커 스레드에 종료 sentinel(None)을 보내고 join.

    테스트 격리용(남은 워커가 다음 테스트의 큐를 가로채는 오염 방지).
    프로덕션은 데몬 스레드라 프로세스 종료 시 자동 정리되므로 호출 불필요.
    """
    global _worker_threads
    q = _worker_queue
    threads = [t for t in (_worker_threads or []) if t.is_alive()]
    if q is None or not threads:
        _worker_threads = []
        return
    for _ in threads:
        try:
            q.put(None, block=False)
        except queue.Full:
            break
    for t in threads:
        t.join(timeout=timeout)
    _worker_threads = []


def collect_switch(db_path, switch_id, username=None, password=None, enable_secret=None):
    """Enqueue an async collection for a switch.

    M5 (async_credential): Credentials are NEVER placed in the queue payload.
    If username/password are passed directly (backward-compat), they are moved
    into the in-memory session store and the local references are dropped
    immediately. The worker loads them from the session store and clears them
    after collection completes (success or failure).

    Returns:
        dict with status 'queued' or 'error'
    """
    global _worker_queue, _collecting_switches

    utils.log_event("info", "collect_switch_requested", switch_id=switch_id)

    if _worker_queue is None:
        init_collector()

    with _collector_lock:
        if switch_id in _collecting_switches:
            utils.log_event("warning", "collect_already_in_progress", switch_id=switch_id)
            return {
                "status": "error",
                "message": f"Switch {switch_id} is already being collected"
            }

        _collecting_switches.add(switch_id)

    try:
        # M5 (CWE-522): Move directly-passed credentials into the session store so
        # the queue payload stays free of plaintext. Kept INSIDE the try so any
        # failure here also releases the in-progress mark via _abort_enqueue.
        if username is not None or password is not None:
            credentials.save_credential(switch_id, username, password,
                                        enable_secret=enable_secret)
            username = None
            password = None
            enable_secret = None
        # M5: payload carries no credentials, only the work identifiers.
        _worker_queue.put((db_path, switch_id), block=False)
        position = _worker_queue.qsize()
        utils.log_event("info", "collect_queued", switch_id=switch_id, position=position)
        return {
            "status": "queued",
            "switch_id": switch_id,
            "queue_position": position
        }
    except queue.Full:
        # M5: queue failed before the worker can run; clear session creds now.
        _abort_enqueue(switch_id)
        utils.log_event("error", "collect_queue_full", switch_id=switch_id)
        return {
            "status": "error",
            "message": "Queue is full"
        }
    except Exception as e:
        # M5 (W1): Any other enqueue-time failure must also release the
        # in-progress mark and dispose the session credential to avoid leaks.
        _abort_enqueue(switch_id)
        sanitized = _sanitize_error_msg(str(e))
        utils.log_event("error", "collect_enqueue_error", switch_id=switch_id, error=sanitized)
        return {
            "status": "error",
            "message": "Failed to enqueue collection"
        }


def _abort_enqueue(switch_id):
    """Release in-progress mark and dispose session credential after a failed enqueue."""
    with _collector_lock:
        _collecting_switches.discard(switch_id)
    credentials.clear_session_switch(switch_id)


def cancel_pending():
    """대기 중인 수집 작업을 비운다(사용자 '수집 중지'). 반환: 취소한 개수.

    이미 워커가 붙잡고 SSH 접속 중인 장비는 중간에 끊지 않는다(부분 수집 방지).
    큐에서 뺀 장비는 '수집 중' 표시를 풀어 다시 수집할 수 있게 만든다.
    """
    global _worker_queue
    if _worker_queue is None:
        return 0
    cancelled = 0
    while True:
        try:
            item = _worker_queue.get_nowait()
        except queue.Empty:
            break
        if item is None:              # 종료 sentinel은 되돌려 놓는다
            try:
                _worker_queue.put_nowait(None)
            except Exception:
                pass
            break
        try:
            _dbp, sid = item
        except Exception:
            continue
        with _collector_lock:
            _collecting_switches.discard(sid)
        try:
            credentials.clear_session_switch(sid)
        except Exception:
            pass
        # 대기 중이던 항목은 아직 수집을 시작하지 않았으므로 **이전 상태를 그대로 둔다.**
        # 예전엔 무조건 "new"로 썼는데, 큐에 있던 스위치는 아직 'collecting'이 아니라
        # 직전 결과(done/failed)를 갖고 있었다. 그래서 중지 한 번에 수집 완료 장비가
        # '미수집'으로 바뀌고, 장애(failed) 장비는 관제의 '수집 실패' 목록에서 사라졌다.
        try:
            cur = db.get_switch(_dbp, sid)
            if (cur or {}).get("status") == "collecting":
                db.set_switch_status(_dbp, sid, "new")
        except Exception:
            pass
        cancelled += 1
    if cancelled:
        utils.log_event("info", "collect_pending_cancelled", count=cancelled)
    return cancelled


def collecting_ids():
    """지금 수집 중(대기 포함)인 스위치 id 집합 — 진행바 계산용."""
    with _collector_lock:
        return set(_collecting_switches)


def _worker_loop():
    """워커 스레드 본체.

    한 항목의 처리 실패는 절대 스레드를 죽이지 못한다. 예전엔 `except` 핸들러
    안의 `db.set_switch_status(..., "failed")` 가 던지면(공유폴더 SQLite 경합 시
    get_db가 재시도 후 OperationalError를 올린다) 그 예외가 while 밖으로 나가
    **워커 3개가 전부 죽고 수집 큐가 영구 정지**했다. 게다가 `_collecting_switches`
    가 비워지지 않아 그 스위치는 재시작 전까지 "이미 수집 중"으로 영원히 잠겼다.
    """
    global _worker_queue, _collecting_switches

    while True:
        try:
            if _worker_loop_once() is False:
                return
        except Exception as e:              # noqa: BLE001 — 어떤 예외로도 죽지 않는다
            try:
                utils.log_event("error", "collect_worker_recovered",
                                error=_sanitize_error_msg(str(e)),
                                error_type=type(e).__name__)
            except Exception:
                pass
            time.sleep(0.5)                 # 폭주 방지(연속 실패 시 CPU 점유 억제)


def _worker_loop_once():
    """큐에서 한 건 처리. 종료 sentinel을 받으면 False를 반환한다."""
    global _worker_queue, _collecting_switches

    # MEDIUM FIX (CPU optimization): Remove timeout to prevent unnecessary wakeups (busy-wait)
    # Worker will block indefinitely until task arrives, reducing CPU usage
    # Note: No timeout means queue.Empty will never be raised (unreachable code removed)
    # M5 (async_credential): payload carries no credentials, only identifiers.
    item = _worker_queue.get()
    # 종료 sentinel: None을 받으면 스레드 종료. 테스트가 남긴 워커가
    # 다음 테스트의 격리 큐를 가로채 자격증명을 지우는 오염 방지
    # (프로덕션은 sentinel을 넣지 않으므로 동작 불변).
    if item is None:
        return False
    db_path, switch_id = item

    username = None
    password = None
    cred = None
    prev_status = None
    prev_alert = None
    sw_name = str(switch_id)
    sw_disp = sw_name            # 알람 메시지용(이름+IP) — 예외 조기 발생 대비 초기화
    try:
        utils.log_event("info", "collect_start", switch_id=switch_id)
        # 이전 상태/경보를 먼저 확보(전이 감지용) 후 collecting 표시
        _sw0 = db.get_switch(db_path, switch_id)
        if not _sw0:
            raise ValueError(f"Switch {switch_id} not found")
        prev_status = _sw0.get("status")
        prev_alert = _sw0.get("alert")
        sw_name = _sw0.get("name") or sw_name
        # 알람 메시지 표기용: 이름 + IP (label은 이름 그대로 유지)
        sw_disp = ("%s (%s)" % (sw_name, _sw0["ip"])) if _sw0.get("ip") else sw_name
        db.set_switch_status(db_path, switch_id, "collecting")

        switch = db.get_switch(db_path, switch_id)
        if not switch:
            raise ValueError(f"Switch {switch_id} not found")

        # 벤더 정규화(cisco→cisco_ios 등): device_type/commands/parser 일관 사용
        raw_vendor = switch["vendor"]
        is_unknown = _is_unknown_vendor(raw_vendor)
        vendor = _norm_vendor(raw_vendor)
        config = get_config()

        if config.app.get("demo_mode"):
            outputs = fixtures.get_demo_outputs_for_vendor(vendor)
            utils.log_event("info", "demo_mode_outputs", switch_id=switch_id, vendor=vendor)
        else:
            # M5 (CWE-522): Load credentials from the session store at the
            # moment of use; fail explicitly if none were supplied.
            cred = credentials.load_credential(switch_id)
            if not cred:
                raise ValueError(f"No credentials available for switch {switch_id}")
            username = cred.get("username")
            password = cred.get("password")
            # enable secret: 세션 우선, 없으면 영속 blob(app_settings) 복호화.
            # 미설정이면 _ssh_collect가 로그인 비밀번호를 secret으로 사용(기존 동작).
            enable_secret = cred.get("enable_secret")
            if not enable_secret:
                try:
                    _es_blob = db.get_setting(db_path, "enable_secret_%d" % switch_id)
                    if _es_blob:
                        enable_secret = credentials.decrypt_text(_es_blob)
                except Exception:
                    enable_secret = None
            # M12: 출발지 IP 바인딩(장비 ACL 통과) — 이 PC 프로필 우선,
            # 없으면 전역 설정, 그것도 없으면 OS 기본 라우팅.
            from . import pcprofile
            source_ip = pcprofile.get_source_ip(db_path)
            # 응답 없는 장비는 즉시 실패(재시도 낭비 없이 다음 장비로)
            if not _tcp_precheck(switch["ip"], source_ip=source_ip):
                raise ConnectionError(
                    "TCP-22 도달 불가(응답 없음) — 즉시 실패 처리, 다음 장비 진행")
            # 장비당 하드 타임아웃(기본 480초, config collector.hard_timeout).
            # SSH 무한대기·명령 타임아웃 연쇄로 '수집중' 고착 → 큐 정지 방지.
            hard_to = int(config.collector.get("hard_timeout", 480) or 480)
            if vendor == "alteon":
                # Alteon은 메뉴형 CLI(netmiko 미지원) → 전용 paramiko 수집
                outputs = _run_with_timeout(
                    _alteon_collect, hard_to,
                    switch, username, password, source_ip=source_ip)
                eff_vendor = "alteon"
            else:
                # 항상 show version부터 실행해 실제 OS를 확인하고, 그 OS의
                # 명령셋으로 수집한다. 등록 벤더가 틀려도(예: EXOS인데 cisco로
                # 등록) 자동 교정된다. 판별 실패 시엔 등록 벤더 그대로.
                try:
                    outputs, eff_vendor = _run_with_timeout(
                        _ssh_collect, hard_to,
                        switch, username, password, vendor,
                        source_ip=source_ip, detect_vendor=True,
                        enable_secret=enable_secret)
                except Exception as first_err:
                    # Alteon 프롬프트를 이미 감지했다면 프로브(추가 로그인) 없이
                    # 전용 수집으로 직행 — 구형 Alteon은 동시 관리 세션 제한이
                    # 있어 연속 로그인(프로브)이 거부될 수 있다.
                    if "alteon" in str(first_err).lower():
                        utils.log_event("info", "alteon_direct_fallback",
                                        switch_id=switch_id)
                        # 벤더를 먼저 저장 — 이번 재수집이 (세션 제한 등으로)
                        # 실패해도 다음 수집부터는 처음부터 alteon 경로
                        # (로그인 1회)로 동작한다.
                        try:
                            db.update_switch(db_path, switch_id, vendor="alteon")
                        except Exception:
                            pass
                        time.sleep(3)   # 직전 세션 정리 대기(관리 세션 제한 회피)
                        outputs = _run_with_timeout(
                            _alteon_collect, hard_to,
                            switch, username, password, source_ip=source_ip)
                        eff_vendor = "alteon"
                        probed, probe_ver = "alteon", ""
                        raise_skip = True
                    else:
                        raise_skip = False
                    # netmiko 드라이버가 프롬프트 매칭에 실패하는 장비
                    # (EXOS 증가형 프롬프트 → 'pattern not detected') 폴백:
                    # 드라이버 무관 원시 셸로 OS 탐지 → 올바른 드라이버로 재시도.
                    if not raise_skip:
                        probed, probe_ver = _probe_os(switch, username, password,
                                                      source_ip=source_ip)
                        if not probed or probed == vendor:
                            raise
                        utils.log_event("info", "vendor_probe_retry",
                                        switch_id=switch_id, probed=probed,
                                        first_error=_sanitize_error_msg(str(first_err)))
                        if probed == "alteon":
                            # Alteon은 netmiko 드라이버가 없음 → 전용 메뉴 CLI 수집
                            outputs = _run_with_timeout(
                                _alteon_collect, hard_to,
                                switch, username, password, source_ip=source_ip)
                            eff_vendor = "alteon"
                        else:
                            outputs, eff_vendor = _run_with_timeout(
                                _ssh_collect, hard_to,
                                switch, username, password, probed,
                                source_ip=source_ip, detect_vendor=False, max_retries=1,
                                enable_secret=enable_secret)
                            eff_vendor = probed
                        # 프로브에서 읽은 show version을 버전/모델 파싱에 재활용
                        if probe_ver and not outputs.get("version"):
                            outputs["version"] = probe_ver
            # 실제 OS 판별: 세션 show version 출력 우선, 없으면(원시 셸 프로브
            # 폴백 경로) eff_vendor. FIX: 예전엔 '정규화된 접속 벤더'와 비교해
            # unknown→cisco_ios처럼 정규화 결과와 감지가 같으면 DB 갱신을
            # 건너뛰어 화면에 unknown이 남았다 → '저장된 원래 벤더'와 비교.
            detected = _detect_vendor_from_version(outputs.get("version", ""))
            # Alteon(메뉴형 CLI)은 프롬프트가 '#'로 끝나 cisco 접속이 '성공'하고
            # 명령은 오류 텍스트만 받아 예외 없이 끝난다(unknown+빈 데이터).
            # 출력에 Alteon 시그니처가 보이면 전용 수집으로 즉시 재수집.
            if not detected and eff_vendor != "alteon" and _looks_like_alteon(outputs):
                utils.log_event("info", "alteon_signature_recollect",
                                switch_id=switch_id)
                outputs = _run_with_timeout(
                    _alteon_collect, hard_to,
                    switch, username, password, source_ip=source_ip)
                eff_vendor = "alteon"
                detected = "alteon"
            if not detected and eff_vendor and eff_vendor != vendor:
                detected = eff_vendor
            if detected:
                vendor = detected  # 이번 파싱도 실제 OS 파서로
                if detected != (raw_vendor or "").strip().lower():
                    try:
                        db.update_switch(db_path, switch_id, vendor=detected)
                        utils.log_event("info",
                                        "vendor_learned" if is_unknown else "vendor_corrected",
                                        switch_id=switch_id,
                                        from_vendor=raw_vendor, vendor=detected)
                    except Exception as _e:
                        utils.log_event("warning", "vendor_update_failed",
                                        switch_id=switch_id, error=_sanitize_error_msg(str(_e)))
            elif eff_vendor:
                vendor = eff_vendor

        raw_outputs_path = _save_raw_outputs(db_path, switch_id, switch["name"], outputs)
        utils.log_event("info", "raw_outputs_saved", path=str(raw_outputs_path))

        # show version(+EXOS는 show switch) 출력에서 OS 버전/모델명 추출
        ver_out = outputs.get("version", "")
        osv = _parse_os_version(vendor, ver_out) if ver_out else None
        if not osv and outputs.get("boot"):
            # Alteon 일부 장비: 버전이 /info/sys/general이 아니라 /boot/cur에
            osv = _parse_os_version(vendor, outputs.get("boot", ""))
        model = _parse_model(vendor, ver_out) if ver_out else None
        if not model and outputs.get("sysinfo"):
            # EXOS 모델(System Type:)은 show version이 아니라 show switch에 있음
            model = _parse_model(vendor, outputs.get("sysinfo", ""))
        if not model and outputs.get("inventory"):
            # NX-OS 모델은 show inventory의 PID가 가장 확실(표기 변형 무관)
            model = _parse_model(vendor, outputs.get("inventory", ""))
        # 시리얼 번호: show version → inventory → sysinfo 순으로 시도
        serial = _parse_serial(vendor, ver_out) if ver_out else None
        for _src in ("inventory", "sysinfo"):
            if not serial and outputs.get(_src):
                serial = _parse_serial(vendor, outputs.get(_src, ""))
        if osv or model or serial:
            try:
                db.update_switch(db_path, switch_id, os_version=osv,
                                 model=model, serial=serial)
            except Exception:
                pass

        parsed_data = _parse_outputs(vendor, outputs, switch_id)

        # M3: Detect disconnected MAC entries before saving new snapshot
        prev_snapshot_id = db.latest_snapshot_id(db_path, switch_id)
        if prev_snapshot_id is not None:
            # BUGFIX: 'mac' 명령이 실패(타임아웃 등)하면 outputs["mac"]="" →
            # curr_macs=[]가 되어 이전 스냅샷의 모든 MAC이 허위 disconnect
            # 이벤트(수천 건)로 저장된다. 원시 mac 출력이 비었으면(수집 실패)
            # disconnect 판정을 건너뛴다(진짜 빈 MAC 테이블도 헤더는 남으므로
            # 완전 공백 = 명령 실패로 간주).
            mac_raw = (outputs.get("mac", "") or "").strip()
            if mac_raw:
                curr_macs = [(m.get("vlan"), m.get("mac"), m.get("port"))
                            for m in parsed_data.get("macs", [])]
                db._detect_disconnected(db_path, switch_id, prev_snapshot_id, curr_macs)
            else:
                # MAC 명령 실패는 수집 자체는 성공(status=done)으로 남기 때문에
                # 조용히 지나가면 원인 추적이 어렵다. 설비 대조는 'MAC이 담긴
                # 마지막 스냅샷'으로 폴백하므로(db.get_mac_to_switchport) 끊김
                # 오탐은 나지 않지만, 계속 비면 MAC 명령 설정을 봐야 한다.
                utils.log_event("warning", "mac_table_empty_keeping_previous",
                                switch_id=switch_id,
                                hint="MAC 명령 출력이 비어 이번 스냅샷의 MAC은 0건입니다. "
                                     "설비 대조는 직전 MAC 스냅샷을 계속 사용합니다.")

        snapshot_id = db.save_snapshot(db_path, switch_id)
        db.save_ports(db_path, snapshot_id, switch_id, parsed_data.get("ports", []))
        db.save_mac_entries(db_path, snapshot_id, switch_id, parsed_data.get("macs", []))
        db.save_arp_entries(db_path, snapshot_id, switch_id, parsed_data.get("arps", []))
        # NX-OS 포트채널 멤버(Po → 물리 멤버포트) 저장 — 설비 대조 해석용
        db.save_port_channels(db_path, snapshot_id, switch_id, parsed_data.get("port_channels", []))
        # CDP/LLDP 이웃(물리 연결) 저장 — 토폴로지 정확도 향상
        if "neighbors" in parsed_data:
            nbr_list = parsed_data.get("neighbors", [])
            # 빈 목록은 저장하지 않는다 — 파서들은 실패해도 항상 "neighbors": []를
            # 넣으므로, SSH 타임아웃이나 CDP 비활성 1회로 그 스위치의 연결선이
            # 구성도에서 통째로 사라졌다(MAC·VLAN 경로는 이미 같은 방어가 있다).
            if nbr_list:
                db.save_neighbors(db_path, switch_id, nbr_list)
            else:
                existing = 0
                try:
                    existing = len([n for n in db.get_all_neighbors(db_path)
                                    if n.get("switch_id") == switch_id])
                except Exception:
                    pass
                if existing:
                    utils.log_event("warning", "neighbors_empty_keeping_previous",
                                    switch_id=switch_id, kept=existing)
            # 수집 방식 진단: CDP/LLDP/비활성(추론) 어느 경로인지 로그 + 저장
            try:
                from .parsers import neighbors as _nb
                from .parsers.cisco_ios import parse_cdp_detail as _pc  # noqa
            except Exception:
                _nb = None
            if _nb is not None:
                n_cdp = len(_nb.parse_cdp_detail(outputs.get("neighbors", "")))
                n_lldp = len(_nb.parse_lldp_detail(outputs.get("lldp", "")))
                source, note = _nb.neighbor_source_status(
                    outputs.get("neighbors", ""), outputs.get("lldp", ""), n_cdp, n_lldp)
                utils.log_event("info", "neighbor_source", switch_id=switch_id,
                                source=source, count=len(nbr_list), note=note)
                try:
                    db.set_setting(db_path, "nbrsrc_%d" % switch_id,
                                   source + ("|" + note if note else ""))
                except Exception:
                    pass
        # VLAN 이름(show vlan brief)은 스냅샷 무관 최신값으로 교체 저장
        if parsed_data.get("vlans"):
            db.save_vlan_names(db_path, switch_id, parsed_data.get("vlans", []))

        # show logging/show log 분석: 최근 15줄 + flapping/looping/err 탐지
        log_out = outputs.get("logging", "")
        if log_out:
            try:
                import json as _json
                from . import log_analyzer
                la = log_analyzer.analyze(log_out, tail=15)
                db.save_switch_logs(
                    db_path, switch_id, "\n".join(la["recent"]),
                    _json.dumps(la["events"], ensure_ascii=False), la["alert"])
                if la["alert"] in ("warning", "critical"):
                    utils.log_event("warning", "log_anomaly_detected",
                                    switch_id=switch_id, alert=la["alert"],
                                    events=len(la["events"]))
                    # 경보 전이 시에만 알람 이벤트(매 수집 스팸 방지)
                    if la["alert"] != prev_alert:
                        _kind = "looping" if la["alert"] == "critical" else "flapping"
                        # 어떤 포트가 문제인지 로그 분석 결과에서 추출해 메시지에 포함
                        _ports = _extract_event_ports(la["events"], _kind)
                        _pstr = (" [%s]" % ", ".join(_ports)) if _ports else ""
                        _kko = "루프(looping)" if _kind == "looping" else "플래핑(flapping)"
                        db.save_device_event(db_path, _kind, la["alert"], switch_id=switch_id,
                                             label=sw_name,
                                             message="%s 감지: %s%s" % (_kko, sw_disp, _pstr))
            except Exception as e:
                utils.log_event("warning", "log_analyze_skipped",
                                error=_sanitize_error_msg(str(e)))

        # 환경 정보(온도·팬) — SNMP ENTITY-SENSOR-MIB. SSH 수집과 별개 경로라
        # 실패해도 수집 전체를 망치지 않는다(이 MIB을 지원하지 않는 장비가 흔하다).
        collect_env_snmp(db_path, "switch", switch_id, switch.get("ip"))

        # 설정(running-config) 백업 + 변경 diff 알람
        cfg_out = outputs.get("config", "")
        if cfg_out and db.get_setting(db_path, "config_backup_enabled", "1") != "0":
            try:
                changed, first = db.save_config_backup(db_path, switch_id, cfg_out)
                if changed and not first:
                    db.save_device_event(db_path, "config_changed", "warning",
                                         switch_id=switch_id, label=sw_name,
                                         message="설정 변경 감지: " + sw_disp)
            except Exception as _e:
                utils.log_event("warning", "config_backup_skipped",
                                error=_sanitize_error_msg(str(_e)))

        db.set_switch_status(db_path, switch_id, "done")
        # 이전에 실패였다가 이번에 성공 → 복구 알람
        if prev_status == "failed":
            db.save_device_event(db_path, "switch_recovered", "info", switch_id=switch_id,
                                 label=sw_name, message="스위치 복구: " + sw_disp)
        utils.log_event("info", "collect_done", switch_id=switch_id, snapshot_id=snapshot_id)

    except Exception as e:
        # Sanitize error messages to prevent credential/path exposure in logs (security fix: CVE-style issue)
        sanitized_error = _sanitize_error_msg(str(e))
        utils.log_event("error", "collect_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
        db.set_switch_status(db_path, switch_id, "failed",
                             error=_friendly_fail_reason(sanitized_error))
        # 직전에 실패 상태가 아니었으면(정상→실패, 신규→실패) 연결 실패 알람
        if prev_status != "failed":
            try:
                db.save_device_event(db_path, "switch_unreachable", "warning",
                                     switch_id=switch_id, label=sw_name,
                                     message="스위치 연결 실패: " + sw_disp)
            except Exception:
                pass
    finally:
        # CWE-522 fix: Explicitly clear credentials from memory to prevent plaintext exposure
        # M5 (W2): cred is a defensive copy from load_credential; emptying the
        # dict drops the plaintext references it holds.
        if isinstance(cred, dict):
            cred.clear()
        cred = None
        username = None
        password = None
        # M5 (async_credential): Worker owns credential disposal. Clear the
        # session store entry regardless of success/failure/exception.
        credentials.clear_session_switch(switch_id)
        with _collector_lock:
            _collecting_switches.discard(switch_id)
        # CRITICAL: Safely call task_done() even if queue was replaced during test teardown
        try:
            _worker_queue.task_done()
        except ValueError:
            # Queue was replaced during reinit; ignore this error (happens in tests)
            pass


def _ssh_collect(switch, username, password, vendor, max_retries=3, source_ip=None,
                 detect_vendor=False, enable_secret=None):
    """Collect outputs from network device via SSH with exponential backoff retry logic.

    Args:
        switch: Switch dict with 'name' and 'ip'
        username: SSH username
        password: SSH password
        vendor: Device vendor/type (연결/명령 기본값)
        max_retries: Max retry attempts (default: 3) - handles transient network failures
        source_ip: M12 — bind outbound SSH to this local IP (pass device ACL). None = OS default.
        detect_vendor: True면 접속 후 show version으로 실제 벤더를 학습해 명령/파서를 그에 맞춘다.
        enable_secret: enable 비밀번호가 로그인과 다른 장비용(선택). None이면 password 사용.

    Returns:
        (outputs: dict, effective_vendor: str)  # 학습된 실제 벤더(미학습 시 입력 vendor)

    Raises:
        ImportError: If netmiko not installed
        Exception: After max_retries exhausted
    """
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise ImportError("netmiko not installed")

    config = get_config()
    commands = config.get_commands(vendor)
    eff_vendor = vendor
    ssh_timeout = config.collector.get("ssh_timeout", 30)
    read_timeout = config.collector.get("read_timeout", 60)

    # FIX: read_timeout은 netmiko send_command()의 인자이지 ConnectHandler 생성자 인자가
    # 아니다. 생성자에 넣으면 "unexpected keyword argument 'read_timeout'" 오류.
    device = {
        "device_type": vendor,
        "ip": switch["ip"],
        "username": username,
        "password": password,
        # enable secret: 별도 지정 시 그 값을, 없으면 로그인 비밀번호(많은 환경에서 동일).
        "secret": enable_secret or password,
        "conn_timeout": ssh_timeout,
        "fast_cli": False
    }

    # Exponential backoff retry loop for transient network failures (robustness improvement)
    import time
    for attempt in range(max_retries):
        utils.log_event("info", "ssh_connect", switch=switch["name"], vendor=vendor, attempt=attempt+1, max_retries=max_retries)

        try:
            outputs = {}
            conn_device = dict(device)
            if source_ip:
                # M12: 출발지 IP 바인딩한 소켓을 netmiko에 전달(재연결마다 새 소켓)
                from . import netbind
                conn_device["sock"] = netbind.bind_socket(switch["ip"], 22, source_ip, ssh_timeout)
            with ConnectHandler(**conn_device) as conn:
                # user 모드(>)면 enable 진입. IOS-XE는 user 모드에서 show 명령이
                # "% Invalid input"으로 거부되므로 특권 모드로 올라간다.
                try:
                    if hasattr(conn, "check_enable_mode") and not conn.check_enable_mode():
                        conn.enable()
                except Exception as _e:
                    utils.log_event("warning", "enable_failed",
                                    switch=switch["name"], error=_sanitize_error_msg(str(_e)))
                # 벤더별 페이징 비활성화(미정의 벤더는 생략). 실패해도 수집은 계속.
                paging = _PAGING_CMD.get(eff_vendor)
                if paging:
                    try:
                        conn.send_command(paging, read_timeout=read_timeout)
                    except Exception:
                        pass
                # Alteon 메뉴형 CLI는 프롬프트('>> ... Main#')가 '#'로 끝나 cisco
                # 접속이 '성공'해 버린다. netmiko는 출력에서 프롬프트를 잘라내므로
                # 출력 텍스트로는 못 잡음 → 접속 직후 '프롬프트 자체'를 검사.
                if detect_vendor and _prompt_looks_alteon(getattr(conn, "base_prompt", "")):
                    utils.log_event("info", "alteon_prompt_detected", switch=switch["name"])
                    raise _DriverMismatchError("alteon 메뉴형 프롬프트 감지")
                # 벤더 미지정이면 show version으로 실제 벤더 학습 → 명령/파서 그에 맞춤
                if detect_vendor:
                    try:
                        ver = conn.send_command("show version", read_timeout=20)
                        outputs["version"] = ver
                        detected = _detect_vendor_from_version(ver)
                        if detected and detected != eff_vendor:
                            eff_vendor = detected
                            commands = _commands_for(eff_vendor) or commands
                            utils.log_event("info", "vendor_detected",
                                            switch=switch["name"], vendor=eff_vendor)
                            # 학습된 벤더의 페이징도 한 번 더 적용(EXOS 등)
                            p2 = _PAGING_CMD.get(eff_vendor)
                            if p2 and p2 != paging:
                                try:
                                    conn.send_command(p2, read_timeout=read_timeout)
                                except Exception:
                                    pass
                    except Exception as _e:
                        # show version조차 프롬프트 매칭 실패 = 드라이버-장비 불일치
                        # (예: EXOS 증가형 프롬프트를 cisco 드라이버로 접속).
                        # 나머지 명령도 전부 같은 이유로 실패하므로 시간 낭비 없이
                        # 즉시 중단 → 워커가 원시 셸 OS 탐지 후 올바른 드라이버로 재시도.
                        utils.log_event("warning", "vendor_detect_failed",
                                        switch=switch["name"], error=_sanitize_error_msg(str(_e)))
                        raise _DriverMismatchError(
                            "show version 프롬프트 매칭 실패(드라이버 불일치 의심)")
                # 명령별 개별 예외 처리: 한 명령이 실패(미지원/타임아웃)해도 나머지는 수집.
                # (예: EXOS의 특정 show 명령이 없어도 전체 수집이 실패하지 않도록)
                cmd_errors = 0
                cmd_success = 0
                for key, command in commands.items():
                    try:
                        # 'show interface'(전체)는 포트 많은 섀시(N9508 등)에서 출력이
                        # 매우 커 60초로 부족 → detail/errors 계열은 타임아웃을 늘린다.
                        _rt = max(read_timeout, 150) if key in ("detail", "errors") else read_timeout
                        outputs[key] = conn.send_command(command, read_timeout=_rt)
                        cmd_success += 1
                        utils.log_event("debug", "command_executed", command=command)
                    except Exception as _ce:
                        outputs[key] = ""
                        cmd_errors += 1
                        utils.log_event("warning", "command_failed", switch=switch["name"],
                                        command=command, error=_sanitize_error_msg(str(_ce)))
                        # 성공한 명령이 하나도 없는데 2연속 실패 = 드라이버/명령셋
                        # 불일치 확정 → 남은 명령의 타임아웃 연쇄(수 분)를 낭비하지
                        # 않고 조기 중단(워커가 폴백/실패 처리 후 다음 장비 진행).
                        if cmd_success == 0 and cmd_errors >= 2:
                            raise _DriverMismatchError(
                                "초반 명령 연속 실패(%d) — 명령셋 불일치 조기 중단" % cmd_errors)
                # 모든 명령이 실패(응답 전무)면 드라이버/명령셋 불일치 → 재시도 없이 폴백
                if commands and cmd_errors == len(commands):
                    raise _DriverMismatchError("all collection commands failed")
                # 포트채널 멤버 해석 명령(config에 없어도 벤더별로 항상 시도)
                pc_cmd = _PORT_CHANNEL_CMD.get(eff_vendor)
                if pc_cmd and "port_channel" not in outputs:
                    try:
                        outputs["port_channel"] = conn.send_command(pc_cmd, read_timeout=read_timeout)
                    except Exception:
                        pass
                # 설정 백업(running-config) — 변경 diff 알람용. 실패해도 수집 계속.
                cfg_cmd = _CONFIG_CMD.get(eff_vendor)
                if cfg_cmd and "config" not in outputs:
                    try:
                        outputs["config"] = conn.send_command(cfg_cmd, read_timeout=max(read_timeout, 90))
                    except Exception:
                        pass
            return outputs, eff_vendor
        except _DriverMismatchError:
            raise  # 드라이버 불일치는 같은 드라이버로 재시도해도 무의미 → 즉시 폴백
        except Exception as e:
            # Sanitize SSH error messages to prevent credential/host info exposure (security fix)
            sanitized_error = _sanitize_error_msg(str(e))

            if attempt < max_retries - 1:
                # Exponential backoff: 1s, 2s, 4s (retry on transient failures)
                wait_time = 2 ** attempt
                utils.log_event("warning", "ssh_retry", switch=switch["name"], attempt=attempt+1, max_retries=max_retries, wait_seconds=wait_time, error_type=type(e).__name__)
                time.sleep(wait_time)
            else:
                # Final attempt failed, log and raise
                utils.log_event("error", "ssh_error", switch=switch["name"], error_type=type(e).__name__, error=sanitized_error)
                raise
        finally:
            # FIX: 매 시도마다 복사본(conn_device)만 정리한다. 이전엔 원본 device를
            # clear()해서 retry 2회차에 device/conn_device가 빈 dict가 되고 source
            # 바인딩 소켓도 사라져 재시도가 깨졌다. 원본 device는 retry 위해 유지하고,
            # 함수 종료(return/raise) 시 GC로 정리된다.
            if 'conn_device' in locals():
                # source_ip 바인딩 소켓(netbind)은 접속/인증 실패 시 paramiko가
                # 닫아주지 않아 재시도마다 핸들 누수 → 명시적 close(이중 close 무해).
                _sock = conn_device.get("sock")
                if _sock is not None:
                    try:
                        _sock.close()
                    except Exception:
                        pass
                conn_device.clear()
            username = None
            password = None
            enable_secret = None


def _alteon_read(shell, timeout=25, idle=0.6):
    """Alteon 대화형 셸에서 프롬프트/유휴까지 읽기. 'more' 페이징은 스페이스로 넘긴다."""
    import time as _t
    buf = ""
    deadline = _t.monotonic() + timeout
    last_data = _t.monotonic()
    while _t.monotonic() < deadline:
        if shell.recv_ready():
            buf += shell.recv(65535).decode("utf-8", "replace")
            last_data = _t.monotonic()
            tail = buf[-120:].lower()
            if "more" in tail or "continue" in tail or "q to quit" in tail:
                try:
                    shell.send(" ")
                except Exception:
                    pass
        else:
            if _t.monotonic() - last_data > idle:
                s = buf.rstrip()
                if (not s) or s.endswith("#") or s.endswith(">") or s.endswith("$"):
                    break
                if _t.monotonic() - last_data > idle * 4:
                    break
            _t.sleep(0.15)
    return buf


def _probe_os(switch, username, password, source_ip=None):
    """드라이버 무관 OS 탐지 — paramiko 원시 셸로 show version 실행.

    netmiko 드라이버가 프롬프트 매칭에 실패하는 장비(대표: EXOS는 명령마다
    프롬프트 번호가 증가 'SW.1 #'→'SW.2 #' → cisco 드라이버로는 'pattern not
    detected')에서도 동작한다. 프롬프트 형식을 전혀 가정하지 않고 유휴까지 읽는다.
    반환: (감지된 device_type 또는 None, show version 원문) — 원문은 버전/모델 파싱 재활용.
    """
    import paramiko
    import time as _t
    from . import ssh_compat
    ssh_compat.enable_legacy_algorithms()
    client = paramiko.SSHClient()
    secpolicy.apply_host_key_policy(client)
    sock = None
    if source_ip:
        from . import netbind
        sock = netbind.bind_socket(switch["ip"], 22, source_ip, 15)
    try:
        client.connect(switch["ip"], port=22, username=username, password=password,
                       timeout=15, allow_agent=False, look_for_keys=False, sock=sock)
        shell = client.invoke_shell(width=200, height=1000)
        _t.sleep(1.0)
        _alteon_read(shell, timeout=4)          # 배너/프롬프트 비우기(범용 리더 재사용)
        shell.send("show version\n")
        out = _alteon_read(shell, timeout=12)
        detected = _detect_vendor_from_version(out)
        # 키워드로 못 잡았어도 원시 셸 출력엔 프롬프트가 남는다 → Alteon 판별
        if not detected and _prompt_looks_alteon(out.strip().splitlines()[-1] if out.strip() else ""):
            detected = "alteon"
        if not detected and re.search(r">>\s?[\w\s.-]*Main#", out or ""):
            detected = "alteon"
        utils.log_event("info", "os_probe", switch=switch.get("name"),
                        detected=detected or "unknown")
        return detected, out
    except Exception as e:
        utils.log_event("warning", "os_probe_failed", switch=switch.get("name"),
                        error=_sanitize_error_msg(str(e)))
        return None, ""
    finally:
        try:
            client.close()
        except Exception:
            pass


def diagnose_switch(switch, username, password, source_ip=None):
    """장비 진단: TCP → SSH 로그인 → 배너/프롬프트 → show version 원문 수집.

    수집이 이상하게 동작하는 장비(벤더 미인식 등)의 실제 응답을 화면에 그대로
    보여줘 원인을 특정할 수 있게 한다. 반환 dict는 UI에 표시된다.
    """
    import paramiko
    import time as _t
    from . import ssh_compat
    res = {"tcp": False, "ssh_login": False, "prompt": "", "banner_head": "",
           "version_head": "", "guess": None, "error": ""}
    try:
        res["tcp"] = bool(_tcp_precheck(switch["ip"], 22, timeout=4, source_ip=source_ip))
    except Exception as e:
        res["error"] = "TCP-22 도달 불가: " + _sanitize_error_msg(str(e))
        return res
    if not res["tcp"]:
        res["error"] = "TCP-22 도달 불가(응답 없음)"
        return res
    ssh_compat.enable_legacy_algorithms()
    client = paramiko.SSHClient()
    secpolicy.apply_host_key_policy(client)
    sock = None
    if source_ip:
        from . import netbind
        sock = netbind.bind_socket(switch["ip"], 22, source_ip, 15)
    try:
        client.connect(switch["ip"], port=22, username=username, password=password,
                       timeout=15, allow_agent=False, look_for_keys=False, sock=sock)
        res["ssh_login"] = True
        shell = client.invoke_shell(width=200, height=1000)
        _t.sleep(1.5)
        banner = _alteon_read(shell, timeout=5)
        res["banner_head"] = (banner or "")[-600:]
        lines = [l for l in (banner or "").splitlines() if l.strip()]
        res["prompt"] = lines[-1][-120:] if lines else ""
        # Alteon(메뉴형 CLI)은 show가 아니라 /info 경로 명령을 쓴다 —
        # 프롬프트가 Alteon이면 진단도 /info/sys/general로 실제 버전을 확인.
        if _prompt_looks_alteon(res["prompt"]) or _prompt_looks_alteon(banner):
            probe_cmd = "/info/sys/general + /boot/cur"
            shell.send("/info/sys/general\n")
            out = _alteon_read(shell, timeout=10)
            # 일부 Alteon은 버전이 /info/sys/general에 없음 → /boot/cur 병행
            shell.send("/boot/cur\n")
            out = (out or "") + "\n" + (_alteon_read(shell, timeout=10) or "")
        else:
            # user 모드(>)면 enable 진입 — IOS-XE는 '>'에서 show 명령이
            # "% Invalid input"으로 거부된다(진단이 오해를 주지 않도록 특권 모드로).
            if res["prompt"].rstrip().endswith(">"):
                shell.send("enable\n")
                _t.sleep(0.8)
                er = _alteon_read(shell, timeout=5) or ""
                if "password" in er.lower():
                    shell.send((password or "") + "\n")
                    _t.sleep(0.8)
                    _alteon_read(shell, timeout=5)
            # 페이징 해제(출력 잘림 방지). 벤더 미확정이므로 IOS(terminal length 0)와
            # EXOS(disable clipaging)를 모두 보낸다 — 무관 장비는 그 명령을 무시.
            # (EXOS는 clipaging이 켜져 있으면 show version 뒤쪽의 'Switch : ... Rev'
            #  시리얼 라인이 페이징 프롬프트에서 잘려 시리얼을 못 읽던 문제.)
            shell.send("terminal length 0\n")
            _alteon_read(shell, timeout=3)
            shell.send("disable clipaging\n")
            _alteon_read(shell, timeout=3)
            probe_cmd = "show version"
            shell.send(probe_cmd + "\n")
            out = _alteon_read(shell, timeout=10)
            # 시리얼은 show inventory의 SN이 가장 확실(9300L 등 표 형식 대응)
            shell.send("show inventory\n")
            inv = _alteon_read(shell, timeout=8) or ""
            res["inventory_head"] = inv[:800]
            ser = _parse_serial("cisco_ios", out) or _parse_serial("cisco_ios", inv)
            if ser:
                res["serial"] = ser
        res["probe_cmd"] = probe_cmd
        res["version_head"] = (out or "")[:1200]
        res["guess"] = (_detect_vendor_from_version(out)
                        or _detect_vendor_from_version(banner)
                        or ("alteon" if (_prompt_looks_alteon(res["prompt"])
                                         or re.search(r">>|Alteon|Radware",
                                                      (banner or "") + (out or ""),
                                                      re.IGNORECASE)) else None))
        # 벤더가 확정되면 그 벤더 파서로 OS/버전/모델/시리얼까지 채운다(사전정보 보강).
        # EXOS는 모델(System Type)·시리얼이 show version이 아니라 show switch에 있어 추가 수집.
        g = res.get("guess")
        if g:
            sysinfo = ""
            if g == "extreme_exos":
                try:
                    shell.send("show switch\n")
                    sysinfo = _alteon_read(shell, timeout=8) or ""
                    res["sysinfo_head"] = sysinfo[:800]
                except Exception:
                    pass
            blob = "\n".join(x for x in (out, res.get("inventory_head"),
                                         sysinfo, banner) if x)
            try:
                res["os_version"] = _parse_os_version(g, out) or _parse_os_version(g, blob)
            except Exception:
                pass
            try:
                res["model"] = _parse_model(g, blob)
            except Exception:
                pass
            try:
                res["serial"] = res.get("serial") or _parse_serial(g, blob)
            except Exception:
                pass
    except Exception as e:
        res["error"] = _sanitize_error_msg(str(e))
    finally:
        try:
            client.close()
        except Exception:
            pass
    return res


def _alteon_collect(switch, username, password, source_ip=None):
    """Alteon 메뉴형 CLI 수집(netmiko 미지원 → paramiko 대화형 셸).

    각 명령은 루트('/')에서 전체 경로(/info/...)로 실행. 페이징은 스페이스로 넘김.
    한 명령이 실패해도 나머지는 계속(원본 저장으로 진단 가능). 반환: outputs dict.
    """
    import paramiko
    import time as _t
    from . import ssh_compat
    ssh_compat.enable_legacy_algorithms()  # 구형 장비 SSH 호환
    from .parsers import alteon as _alt

    host = switch["ip"]
    client = paramiko.SSHClient()
    secpolicy.apply_host_key_policy(client)
    sock = None
    if source_ip:
        from . import netbind
        sock = netbind.bind_socket(host, 22, source_ip, 30)
    outputs = {}
    try:
        client.connect(host, port=22, username=username, password=password,
                       timeout=30, allow_agent=False, look_for_keys=False, sock=sock)
        shell = client.invoke_shell(width=250, height=1000)
        _t.sleep(1.0)
        _alteon_read(shell, timeout=5)        # 로그인 배너/프롬프트 비우기
        for key, cmd in _alt.COMMANDS.items():
            try:
                shell.send("/\n")             # 루트 메뉴로 이동
                _alteon_read(shell, timeout=4)
                shell.send(cmd + "\n")
                outputs[key] = _alteon_read(shell, timeout=30)
            except Exception as _ce:
                outputs[key] = ""
                utils.log_event("warning", "alteon_command_failed",
                                switch=switch["name"], command=cmd,
                                error=_sanitize_error_msg(str(_ce)))
    finally:
        try:
            client.close()
        except Exception:
            pass
    return outputs


def _safe_dir_name(name, fallback):
    """경로 컴포넌트로 안전한 이름으로 정제.

    스위치 이름은 사용자 입력이라 '..\\' 또는 'C:\\evil' 같은 절대/상위 경로가
    들어오면 raw_outputs 루트 밖(드라이브 임의 위치)에 running-config(비밀 포함)를
    기록할 수 있다(path traversal). 경로 구분자·드라이브 문자·제어문자를 제거하고
    선행 점을 없앤다. app.py:1069의 sanitize와 동일 정책.
    """
    import re as _re
    safe = _re.sub(r"[^A-Za-z0-9._-]", "_", str(name or "").strip())
    safe = safe.lstrip(".")  # '..' / 선행 점 제거
    return safe or fallback


def _save_raw_outputs(db_path, switch_id, switch_name, outputs):
    config = get_config()
    raw_outputs_root = Path(config.get_raw_outputs_path())

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = _safe_dir_name(switch_name, "switch_%s" % switch_id)
    output_dir = raw_outputs_root / safe_name / now
    # 최종 방어: 정제 후에도 루트 밖으로 벗어나면 거부(심볼릭 링크 등 대비)
    root_resolved = raw_outputs_root.resolve()
    if root_resolved not in output_dir.resolve().parents:
        raise ValueError("raw_outputs path escape blocked: %r" % switch_name)
    output_dir.mkdir(parents=True, exist_ok=True)

    for key, content in outputs.items():
        file_path = output_dir / f"{key}.txt"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    return output_dir


def _parse_outputs(vendor, outputs, switch_id):
    utils.log_event("info", "parse_outputs", vendor=vendor, switch_id=switch_id)

    from . import parsers
    # BUGFIX: get_parser만 ValueError로 폴백해야 한다. 이전엔 parser.parse()까지
    # try에 있어 파서 내부 ValueError(예: 유니코드 노이즈)가 'parser_not_found'로
    # 둔갑해 빈 데이터로 "성공" 처리 → 허위 disconnect 캐스케이드. 파서 내부
    # 예외는 상위로 전파해 수집이 정확히 failed 처리되도록 한다.
    try:
        parser = parsers.get_parser(vendor)
    except ValueError:
        # 파서가 없으면 접속·로그인은 됐어도 얻을 수 있는 데이터가 0건이다.
        # 예전엔 빈 결과를 돌려줘 status=done(초록 '완료' 배지)이 됐고, 운영자는
        # 포트·MAC이 0인 이유를 알 수 없었다 → 명시적으로 실패 처리한다.
        utils.log_event("warning", "parser_not_found", vendor=vendor, switch_id=switch_id)
        raise UnsupportedVendorError(
            "'%s' 벤더는 아직 지원하지 않습니다(지원: %s)"
            % (vendor, ", ".join(parsers.supported_vendors())))
    return parser.parse(outputs, switch_id)


def _ip_allowed(ip, allowed_ranges):
    """SSRF 재검증: 예약/위험 대역 거부 + allowed_ip_ranges 화이트리스트.

    자동 수집은 수동 엔드포인트를 거치지 않으므로 여기서 동일 검증을 수행한다.
    """
    import ipaddress
    if not ip:
        return False
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_reserved:
        return False
    if allowed_ranges:
        for cidr in allowed_ranges:
            try:
                if addr in ipaddress.IPv4Network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    return True


def collect_all_registered(db_path):
    """자동 수집: 저장된 자격증명이 있는 모든 스위치/방화벽을 일괄 수집.

    스위치는 워커 큐로(비동기), 방화벽은 즉시 수집. 자격증명 없는 장비는 건너뜀.
    SSRF: 수동 경로와 동일하게 대상 IP를 collect 직전 재검증.
    Returns: {"switches": n, "firewalls": n}
    """
    import json as _json
    result = {"switches": 0, "firewalls": 0}
    _allowed_ranges = get_config().collector.get("allowed_ip_ranges")

    # 스위치: 저장된 계정 복호화 → 큐잉(기존 워커가 수집)
    # 스위치별 blob이 없거나 이 PC에서 복호화 불가(다른 PC가 저장한 DPAPI)면
    # 이 PC 프로필(pc_profiles — MAC 키) 계정으로 폴백.
    from . import pcprofile
    _profile_cred = pcprofile.get_credential(db_path)
    try:
        for sw in db.get_switches(db_path):
            if not _ip_allowed(sw.get("ip"), _allowed_ranges):
                utils.log_event("warning", "auto_collect_skip_invalid_ip",
                                switch_id=sw.get("id"))
                continue
            username = password = None
            blob = db.get_switch_credential(db_path, sw["id"])
            if blob:
                # 스위치 자격증명은 "username|password" 형식(credentials.encrypt_credential)
                dec = credentials.decrypt_credential(blob)
                if dec and "|" in dec:
                    username, password = dec.split("|", 1)
            if not (username and password) and _profile_cred:
                username, password = _profile_cred
                utils.log_event("info", "auto_collect_profile_cred",
                                switch_id=sw.get("id"))
            if not (username and password):
                utils.log_event("info", "auto_collect_skip_no_cred",
                                switch_id=sw.get("id"), name=sw.get("name"))
                continue
            collect_switch(db_path, sw["id"], username, password)
            result["switches"] += 1
    except Exception as e:
        utils.log_event("error", "auto_collect_switches_error", error=_sanitize_error_msg(str(e)))

    # 방화벽: 저장된 토큰/계정으로 즉시 수집
    try:
        from . import firewall as firewall_mod
        src = pcprofile.get_source_ip(db_path)
        for fw in db.list_firewalls(db_path):
            if not _ip_allowed(fw.get("host"), _allowed_ranges):
                utils.log_event("warning", "auto_collect_skip_invalid_fw_ip",
                                firewall_id=fw.get("id"))
                continue
            blob = db.get_firewall_credential(db_path, fw["id"])
            if not blob:
                continue
            dec = credentials.decrypt_text(blob)
            if not dec:
                continue
            try:
                saved = _json.loads(dec)
            except (ValueError, TypeError):
                continue
            try:
                db.set_firewall_status(db_path, fw["id"], "collecting")
                r = firewall_mod.collect_firewall(
                    fw["vendor"], fw["host"], fw.get("port"),
                    token=saved.get("token", ""), username=saved.get("username", ""),
                    password=saved.get("password", ""), source_ip=src,
                    verify_ssl=secpolicy.firewall_tls_verify())
                save_firewall_result(db_path, fw, r, saved)
                db.set_firewall_status(db_path, fw["id"], "done")
                result["firewalls"] += 1
            except Exception as e:
                db.set_firewall_status(db_path, fw["id"], "failed")
                utils.log_event("error", "auto_collect_fw_error", firewall_id=fw["id"],
                                error=_sanitize_error_msg(str(e)))
    except Exception as e:
        utils.log_event("error", "auto_collect_firewalls_error", error=_sanitize_error_msg(str(e)))

    utils.log_event("info", "auto_collect_done", switches=result["switches"], firewalls=result["firewalls"])
    return result
