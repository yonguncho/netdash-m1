# -*- coding: utf-8 -*-
"""show logging / show log 분석 — 최근 N줄 + flapping/looping/err 탐지.

벤더(cisco_ios/cisco_nxos/arista_eos/extreme_exos) 공통 패턴 기반.
판단 기준:
  - flapping : 같은 인터페이스의 link up/down(UPDOWN)이 임계값 이상 반복
  - looping  : MAC flapping(포트 사이 이동), loop-guard/loopback/ELRP loop 검출
  - error    : err-disable 등 심각 이벤트
"""
import re

# 루프 징후 (MAC move, loop guard, loopback, Extreme ELRP)
_LOOP = re.compile(
    r"MACFLAP|MAC_MOVE|moving between (?:interfaces|ports)|LOOPGUARD|"
    r"LOOP_?BACK_?DETECT|ELRP|loop\s*detect|spanning.?tree loop",
    re.IGNORECASE)
# err-disable 등 심각
_ERR = re.compile(r"ERR_?DISABLE|err-?disabled", re.IGNORECASE)
# 링크 up/down (flapping 후보)
_FLAP = re.compile(
    r"LINK-3-UPDOWN|LINEPROTO-5-UPDOWN|link\s+(?:down|up)\b", re.IGNORECASE)
# 인터페이스 토큰 추출
_IFACE = re.compile(
    r"((?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Eth|Gi|Te|Fa|"
    r"Port-?channel|Po|Vlan|mgmt)\s?\d[\d/.:]*)", re.IGNORECASE)


def analyze(output, tail=15, flap_threshold=3):
    """로그 텍스트 분석.

    Returns: {"recent": [최근 tail줄], "events": [{type, detail, count?}], "alert": none|warning|critical}
    """
    text = output or ""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    recent = lines[-tail:] if tail else lines

    loop_lines, err_lines = [], []
    flap_iface = {}
    for ln in lines:
        if _LOOP.search(ln):
            loop_lines.append(ln.strip()[:300])
        elif _ERR.search(ln):
            err_lines.append(ln.strip()[:300])
        elif _FLAP.search(ln):
            m = _IFACE.search(ln)
            iface = m.group(1).replace(" ", "") if m else "?"
            flap_iface[iface] = flap_iface.get(iface, 0) + 1

    events = []
    for ll in loop_lines[:10]:
        events.append({"type": "looping", "detail": ll})
    for el in err_lines[:10]:
        events.append({"type": "error", "detail": el})
    for iface, cnt in sorted(flap_iface.items(), key=lambda x: -x[1]):
        if cnt >= flap_threshold:
            events.append({"type": "flapping",
                           "detail": "%s: link up/down %d회" % (iface, cnt),
                           "count": cnt})

    alert = "none"
    if any(e["type"] == "looping" for e in events):
        alert = "critical"
    elif any(e["type"] in ("flapping", "error") for e in events):
        alert = "warning"
    return {"recent": recent, "events": events, "alert": alert}
