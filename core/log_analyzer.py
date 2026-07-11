# -*- coding: utf-8 -*-
"""show logging / show log 분석 — 최근 N줄 + flapping/looping/err 탐지.

벤더(cisco_ios/cisco_nxos/arista_eos/extreme_exos) 공통 패턴 기반.
판단 기준:
  - flapping : 같은 인터페이스의 link up/down(UPDOWN)이 시간윈도우 내 임계값 이상 반복
               (타임스탬프 파싱 실패 시 총 횟수 기준으로 폴백)
  - looping  : MAC flapping(포트 사이 이동), loop-guard/loopback/ELRP loop 검출
  - error    : err-disable 등 심각 이벤트
"""
import re
from datetime import datetime

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

# 로그 줄 타임스탬프 형식 (벤더별). 연도 없는 syslog는 현재 연도로 가정 —
# 윈도우 판정은 '줄 사이 상대 간격'만 쓰므로 연말 경계 외엔 영향 없음.
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
_TS_NXOS = re.compile(  # NX-OS: 2026 Jul 11 09:12:03
    r"\b(\d{4})\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
_TS_SYSLOG = re.compile(  # IOS/Arista: Jul 11 09:12:03(.123)
    r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
_TS_EXOS = re.compile(  # EXOS: 07/11/2026 09:12:03(.12)
    r"\b(\d{2})/(\d{2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})")


def _parse_ts(line):
    """로그 줄에서 타임스탬프 추출. 실패 시 None (횟수 폴백)."""
    m = _TS_NXOS.search(line)
    if m and m.group(2) in _MONTHS:
        try:
            return datetime(int(m.group(1)), _MONTHS[m.group(2)], int(m.group(3)),
                            int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
    m = _TS_EXOS.search(line)
    if m:
        try:
            return datetime(int(m.group(3)), int(m.group(1)), int(m.group(2)),
                            int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
    m = _TS_SYSLOG.search(line)
    if m and m.group(1) in _MONTHS:
        try:  # 연도 없는 syslog — 상대 간격만 쓰므로 임의 연도(2000) 고정
            return datetime(2000, _MONTHS[m.group(1)], int(m.group(2)),
                            int(m.group(3)), int(m.group(4)), int(m.group(5)))
        except ValueError:
            return None
    return None


def _fix_year_rollover(ts_list):
    """연도 없는 syslog(연도 2000 고정)에서 12월→1월 롤오버를 +1년으로 보정.

    로그는 시간 오름차순이라는 가정. 인접 타임스탬프가 큰 음의 점프(>300일)면
    연도 롤오버로 간주해 이후 전부 +1년. NX-OS/EXOS(연도 포함) 형식은 애초에
    점프가 없어 영향 없음. 로그 출현 순서를 신뢰하므로 정렬 전에 적용.
    """
    if len(ts_list) < 2:
        return list(ts_list)
    out = [ts_list[0]]
    bump = 0
    for prev, cur in zip(ts_list, ts_list[1:]):
        if (cur - prev).total_seconds() < -300 * 86400:
            bump += 1
        try:
            out.append(cur.replace(year=cur.year + bump) if bump else cur)
        except ValueError:  # 2/29 등 — 보정 실패 시 원본 유지
            out.append(cur)
    return out


def _max_in_window(ts_list, window_min):
    """window_min 분 윈도우 내 최대 이벤트 수 (투 포인터).

    연말 롤오버 보정 후 정렬. 연도 없는 syslog에서 12월/1월 혼재 시
    ~364일 오간격으로 실제 flap이 억제되던 회귀를 방지.
    """
    ts = sorted(_fix_year_rollover(ts_list))
    best, lo = 0, 0
    for hi in range(len(ts)):
        while (ts[hi] - ts[lo]).total_seconds() > window_min * 60:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def analyze(output, tail=15, flap_threshold=3, flap_window_min=10):
    """로그 텍스트 분석.

    flapping 판정: 같은 인터페이스의 up/down이 flap_window_min 분 내에
    flap_threshold 회 이상. 타임스탬프를 못 읽는 로그는 총 횟수 기준 폴백.

    Returns: {"recent": [최근 tail줄], "events": [{type, detail, count?}], "alert": none|warning|critical}
    """
    text = output or ""
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    recent = lines[-tail:] if tail else lines

    loop_lines, err_lines = [], []
    flap_iface = {}  # iface -> {"count": 총횟수, "ts": [파싱된 타임스탬프...]}
    for ln in lines:
        if _LOOP.search(ln):
            loop_lines.append(ln.strip()[:300])
        elif _ERR.search(ln):
            err_lines.append(ln.strip()[:300])
        elif _FLAP.search(ln):
            m = _IFACE.search(ln)
            iface = m.group(1).replace(" ", "") if m else "?"
            rec = flap_iface.setdefault(iface, {"count": 0, "ts": []})
            rec["count"] += 1
            ts = _parse_ts(ln)
            if ts:
                rec["ts"].append(ts)

    events = []
    for ll in loop_lines[:10]:
        events.append({"type": "looping", "detail": ll})
    for el in err_lines[:10]:
        events.append({"type": "error", "detail": el})
    for iface, rec in sorted(flap_iface.items(), key=lambda x: -x[1]["count"]):
        cnt = rec["count"]
        if cnt < flap_threshold:
            continue
        # 타임스탬프가 충분히 파싱됐으면 시간윈도우 밀도로 판정
        if len(rec["ts"]) >= flap_threshold:
            wcnt = _max_in_window(rec["ts"], flap_window_min)
            if wcnt < flap_threshold:
                continue  # 총횟수는 많아도 시간상 분산 → flapping 아님
            events.append({"type": "flapping",
                           "detail": "%s: link up/down %d회/%d분"
                                     % (iface, wcnt, flap_window_min),
                           "count": wcnt})
        else:  # 타임스탬프 미파싱 로그 — 기존 총횟수 판정 유지
            events.append({"type": "flapping",
                           "detail": "%s: link up/down %d회" % (iface, cnt),
                           "count": cnt})

    alert = "none"
    if any(e["type"] == "looping" for e in events):
        alert = "critical"
    elif any(e["type"] in ("flapping", "error") for e in events):
        alert = "warning"
    return {"recent": recent, "events": events, "alert": alert}
