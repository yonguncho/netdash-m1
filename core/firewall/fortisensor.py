# -*- coding: utf-8 -*-
"""FortiGate `execute sensor list` 파싱 — PSU·CPU·시스템 온도/전압/전류/팬.

하드웨어 모델은 이 명령으로 센서를 한 번에 내놓는다. SNMP의 ENTITY-SENSOR-MIB보다
항목이 많고(전압·전류·PSU 상태), 무엇보다 **alarm 플래그**를 함께 준다 —
수치 임계를 우리가 추측하지 않고 장비 자신의 판단을 그대로 쓸 수 있다.

출력 형식(모델·펌웨어에 따라 공백 폭이 다르다):
    Fan 1            alarm=0 value=8100  rpm
    DTS CPU0         alarm=0 value=45    C
    +3.3V            alarm=0 value=3.31  V
    PS1 VOUT1        alarm=0 value=12.09 V
    PS1 IOUT1        alarm=0 value=4.5   A
    PS1 Temp1        alarm=0 value=35    C
    PS1 Status       alarm=0 value=0

VM 모델은 센서가 없어 빈 출력이거나 오류를 낸다 — 그건 정상이므로 빈 목록을 준다.
"""
import re

# name / alarm / value / unit(없을 수 있음)
_LINE = re.compile(
    r"^\s*(?P<name>\S.*?)\s+alarm\s*=\s*(?P<alarm>\d+)\s+value\s*=\s*"
    r"(?P<value>-?\d+(?:\.\d+)?)\s*(?P<unit>[A-Za-z%]*)\s*$")

_UNIT_KIND = {"c": "temperature", "v": "voltage", "a": "current",
              "rpm": "fan", "w": "power", "%": "percent"}

# 이름으로 부품을 묶는다 — 화면에서 PSU/CPU/시스템별로 나눠 보여주기 위함.
_GROUPS = (
    (re.compile(r"^ps(\d+)\b", re.I), "PSU"),
    (re.compile(r"^(dts\s*)?cpu", re.I), "CPU"),
    (re.compile(r"^fan\b", re.I), "FAN"),
    (re.compile(r"^(temp|sys|board|ambient|inlet|outlet)", re.I), "SYSTEM"),
    (re.compile(r"^(vcc|[+-]?\d+(\.\d+)?v\b|vin|vout|vbat)", re.I), "POWER"),
)


def _group_of(name):
    for pat, label in _GROUPS:
        if pat.search(name or ""):
            return label
    return "ETC"


def parse_sensor_list(output):
    """`execute sensor list` 출력 → 센서 목록.

    반환: [{name, group, kind, value, unit, alarm(bool)}]
    형식에 안 맞는 줄(헤더·프롬프트·에러 메시지)은 조용히 건너뛴다.
    """
    out = []
    for line in (output or "").splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        name = m.group("name").strip()
        unit = (m.group("unit") or "").strip()
        try:
            val = float(m.group("value"))
        except (TypeError, ValueError):
            continue
        kind = _UNIT_KIND.get(unit.lower(), "status" if not unit else "other")
        out.append({
            "name": name[:80],
            "group": _group_of(name),
            "kind": kind,
            # 정수로 떨어지면 정수로 — 8100.0 rpm은 읽기 나쁘다
            "value": int(val) if val == int(val) else round(val, 2),
            "unit": unit,
            "alarm": m.group("alarm") != "0",
        })
    return out


def summarize(sensors):
    """센서 목록 → 화면·저장용 요약.

    등급은 **장비가 준 alarm 플래그**를 따른다. 우리가 전압·전류 임계를 추측하면
    모델마다 정상 범위가 달라 오탐이 난다(12V 레일과 3.3V 레일이 같을 리 없다).
    """
    sensors = sensors or []
    temps = [s["value"] for s in sensors if s["kind"] == "temperature"]
    fans = [s for s in sensors if s["kind"] == "fan"]
    alarms = [s["name"] for s in sensors if s["alarm"]]
    psu = sorted({s["name"].split()[0].upper()
                  for s in sensors if s["group"] == "PSU" and s["name"].split()})
    # 팬이 0 rpm이면 장비가 alarm을 안 올려도 이상 신호다(고장·미장착).
    dead_fans = [s["name"] for s in fans if s["value"] == 0]
    return {
        "sensors": sensors,
        "count": len(sensors),
        "max_temp_c": max(temps) if temps else None,
        "fan_count": len(fans),
        "psu_names": psu,
        "psu_count": len(psu),
        "alarms": alarms,
        "dead_fans": dead_fans,
        "level": "critical" if alarms else ("warning" if dead_fans else
                                            ("normal" if sensors else None)),
    }


def _ssh_run(host, username, password, commands, port=22, timeout=20):
    """SSH 한 번 접속으로 여러 명령 실행 → {명령: 출력}.

    명령마다 접속을 새로 열면 FortiGate 관리 세션 제한에 걸리고 느리다.
    한 명령이 실패해도 나머지는 계속한다(모델·권한에 따라 되는 명령이 다르다).
    """
    import paramiko
    from .. import secpolicy
    client = paramiko.SSHClient()
    secpolicy.apply_host_key_policy(client)
    out = {}
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        for cmd in commands:
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=timeout)
                out[cmd] = stdout.read().decode("utf-8", errors="replace")
            except Exception:
                out[cmd] = ""
        # FortiOS 6.x는 SSH exec 채널을 지원하지 않는다(요청 거부 또는 빈 출력,
        # 7.0부터 지원) — 전 명령이 비면 대화형 셸로 다시 실행한다.
        # 실증상: 6.x 장비만 모델명·센서·성능이 통째로 비었다(사용자 신고).
        if not any((v or "").strip() for v in out.values()):
            out = _shell_run(client, commands, timeout=timeout)
    finally:
        try:
            client.close()
        except Exception:
            pass
    return out


def _shell_run(client, commands, timeout=20):
    """대화형 셸로 명령 실행 — exec 채널이 없는 FortiOS 6.x용 폴백.

    6.x 기본 콘솔은 출력이 길면 --More--로 멈춘다 → 스페이스로 계속 넘긴다.
    프롬프트 감지 대신 '출력이 잠잠해지면 다음 명령' 방식 — 프롬프트 문자열은
    호스트네임·VDOM에 따라 달라 패턴을 못 믿는다.
    """
    import time as _t
    chan = client.invoke_shell(width=200, height=1000)
    chan.settimeout(1.0)

    def _drain(quiet_s=1.0, max_s=timeout):
        buf = b""
        quiet = 0.0
        start = _t.monotonic()
        while _t.monotonic() - start < max_s:
            got = False
            try:
                while chan.recv_ready():
                    buf += chan.recv(65535)
                    got = True
            except Exception:
                break
            if got:
                quiet = 0.0
                if b"--More--" in buf[-160:]:
                    try:
                        chan.send(" ")
                    except Exception:
                        break
            else:
                _t.sleep(0.1)
                quiet += 0.1
                if quiet >= quiet_s and buf:
                    break
                if quiet >= max(2.0, quiet_s):
                    break
        return buf

    _drain(0.8, 5)                    # 로그인 배너·프롬프트 소진
    out = {}
    for cmd in commands:
        try:
            chan.send(cmd + "\n")
        except Exception:
            out[cmd] = ""
            continue
        txt = _drain().decode("utf-8", "replace")
        txt = txt.replace("\r\n", "\n").replace("\r", "\n")
        # --More-- 잔재와 그 지우개(백스페이스·ANSI 제어열) 제거
        txt = txt.replace("--More--", "")
        txt = re.sub(r"\x1b\[[0-9;]*[A-Za-z]|\x08+", "", txt)
        lines = txt.split("\n")
        if lines and cmd in lines[0]:
            lines = lines[1:]         # 명령 에코 제거
        out[cmd] = "\n".join(lines)
    try:
        chan.close()
    except Exception:
        pass
    return out


def collect_ssh(host, username, password, port=22, timeout=20):
    """SSH로 `execute sensor list`를 실행해 요약을 반환(하위 호환)."""
    raw = _ssh_run(host, username, password, ["execute sensor list"],
                   port=port, timeout=timeout)
    return summarize(parse_sensor_list(raw.get("execute sensor list", "")))


def collect_ssh_all(host, username, password, port=22, timeout=20):
    """센서 + 성능(get system performance status)을 SSH 한 번으로 수집.

    반환: {"sensors": summarize()결과|None, "perf": parse_perf_status()결과}
    SNMP 미설정 환경에서도 SSH 계정만 있으면 CPU·메모리·세션이 채워진다.
    """
    from . import fortiperf
    raw = _ssh_run(host, username, password,
                   ["execute sensor list", "get system performance status",
                    "get system status"],
                   port=port, timeout=timeout)
    sensors = summarize(parse_sensor_list(raw.get("execute sensor list", "")))
    perf = fortiperf.parse_perf_status(raw.get("get system performance status", ""))
    # 모델·정식 버전 문자열은 get system status가 정확하다(사용자 요구 — 표에 표기)
    perf.update(fortiperf.parse_sys_status(raw.get("get system status", "")))
    return {"sensors": sensors if sensors.get("sensors") else None, "perf": perf}
