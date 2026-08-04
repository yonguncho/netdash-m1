# -*- coding: utf-8 -*-
"""FortiGate `get system performance status` 파싱 — CPU·메모리·세션·업타임.

SNMP를 설정하지 않은 환경에서도 SSH 계정만 있으면 부하를 읽을 수 있는 경로다.
(v6.18.0의 SNMP 지표와 같은 자리(metrics)에 채워지며, SNMP 값이 이미 있으면
그쪽을 우선한다 — 같은 값을 두 경로가 다투지 않게.)

출력 예(FortiOS 6.x/7.x — 버전에 따라 줄이 빠지거나 표기가 다르다):
    CPU states: 3% user 2% system 0% nice 95% idle 0% iowait 0% irq 0% softirq
    CPU0 states: ...
    Memory: 2061108k total, 673556k used (32.7%), 1240848k free (60.2%), ...
    Average network usage: 121 / 97 kbps in 1 minute, ...
    Average sessions: 4823 sessions in 1 minute, 4790 sessions in 10 minutes, ...
    Average session setup rate: 12 sessions per second in last 1 minute, ...
    Uptime: 20 days,  1 hours,  5 minutes
구형 표기:
    Memory states: 32% used
디스크는 이 명령에 없다 — REST/SNMP 쪽 값을 그대로 둔다.
"""
import re


def parse_perf_status(output):
    """`get system performance status` 출력 → dict.

    반환 키(있는 것만): cpu_pct, mem_pct, mem_total_mb, sessions,
      session_rate, net_in_kbps, net_out_kbps, uptime_sec
    형식에 안 맞으면 빈 dict — 오류 출력(권한 부족 등)을 지표로 오인하지 않는다.
    """
    out = {}
    s = output or ""

    # CPU — 전체 줄(CPU states:)의 idle에서 역산. CPU0/CPU1 개별 코어 줄은
    # 'CPU<숫자>'라 매치되지 않게 경계를 둔다.
    m = re.search(r"^\s*CPU\s+states:.*?(\d+(?:\.\d+)?)%\s*idle", s,
                  re.MULTILINE | re.IGNORECASE)
    if m:
        idle = float(m.group(1))
        if 0 <= idle <= 100:
            out["cpu_pct"] = round(100 - idle)

    # 메모리 — 신형: "Memory: ... 673556k used (32.7%)" / 구형: "Memory states: 32% used"
    m = re.search(r"^\s*Memory:\s*(\d+)k\s+total.*?used\s*\((\d+(?:\.\d+)?)%\)",
                  s, re.MULTILINE | re.IGNORECASE)
    if m:
        out["mem_total_mb"] = round(int(m.group(1)) / 1024.0)
        out["mem_pct"] = round(float(m.group(2)))
    else:
        m = re.search(r"^\s*Memory\s+states:\s*(\d+(?:\.\d+)?)%\s*used",
                      s, re.MULTILINE | re.IGNORECASE)
        if m:
            out["mem_pct"] = round(float(m.group(1)))

    # 세션 — 1분 평균을 쓴다(순간값보다 안정적).
    m = re.search(r"Average\s+sessions:\s*(\d+)\s+sessions\s+in\s+1\s+minute",
                  s, re.IGNORECASE)
    if m:
        out["sessions"] = int(m.group(1))

    m = re.search(r"Average\s+session\s+setup\s+rate:\s*(\d+)\s+sessions\s+per\s+second",
                  s, re.IGNORECASE)
    if m:
        out["session_rate"] = int(m.group(1))

    # 트래픽 — "121 / 97 kbps in 1 minute" (in/out)
    m = re.search(r"Average\s+network\s+usage:\s*(\d+)\s*/\s*(\d+)\s*kbps\s+in\s+1\s+minute",
                  s, re.IGNORECASE)
    if m:
        out["net_in_kbps"] = int(m.group(1))
        out["net_out_kbps"] = int(m.group(2))

    # 업타임 — "20 days,  1 hours,  5 minutes"
    m = re.search(r"Uptime:\s*(?:(\d+)\s*days?)?[,\s]*(?:(\d+)\s*hours?)?[,\s]*"
                  r"(?:(\d+)\s*minutes?)?", s, re.IGNORECASE)
    if m and any(m.groups()):
        d, h, mi = (int(x or 0) for x in m.groups())
        out["uptime_sec"] = d * 86400 + h * 3600 + mi * 60
    return out


def parse_sys_status(output):
    """`get system status` 출력 → {model, version, serial, hostname}.

    형식 예:
        Version: FortiGate-1100E v7.2.5,build1517,230330 (GA.F)
        Serial-Number: FG1K1E0000000000
        Hostname: FW-HQ-01
    사용자 요구: 방화벽 현황 표에 모델명·버전을 이 명령 기준으로 표기.
    """
    out = {}
    s = output or ""
    m = re.search(r"^\s*Version:\s*(FortiGate[\w-]*|FortiWiFi[\w-]*|FGT[\w-]*)\s+"
                  r"(v[\d.]+(?:,build\d+)?)", s, re.MULTILINE | re.IGNORECASE)
    if m:
        out["model"] = m.group(1)[:60]
        out["version"] = m.group(2).split(",")[0][:40]
    m = re.search(r"^\s*Serial-?Number:\s*(\S+)", s, re.MULTILINE | re.IGNORECASE)
    if m:
        out["serial"] = m.group(1)[:40]
    m = re.search(r"^\s*Hostname:\s*(\S+)", s, re.MULTILINE | re.IGNORECASE)
    if m:
        out["hostname"] = m.group(1)[:100]
    return out
