# -*- coding: utf-8 -*-
"""FortiGate 하드웨어·FortiOS 수명주기(EOS/EoES) 내장 표.

폐쇄망이라 온라인 조회가 불가능해 **작성 시점(2026-08-04) 기준의 공개 정보**를
내장한다. Fortinet은 수명주기를 API로 제공하지 않는다.

용어(Fortinet 정의):
  EOO  = End of Order       — 주문 종료
  LSED = Last Service Extension Date — 지원계약 연장 마지막 날(EOS 12개월 전)
  EoES = End of Engineering Support  — 엔지니어링 지원 종료(FortiOS: GA+36개월)
  EOS  = End of Support     — 지원 완전 종료(HW: EOO+60개월 / OS: GA+54개월)

출처(2026-08-04 확인):
  - FG-1000D: Fortinet 공식 커뮤니티 + ServiceExpress DB 일치
  - FG-1500D: it-server-room·extendsclass 2개 출처가 2025-04로 수렴
    (일부 유통사 자료는 2026-12로 표기 — 상충. 공식 포털 확인 권장이라 표에 명시)
  - FG-1100E: 수명주기 미발표(작성 시점 기준 지원 중)
  - FortiOS: endoflife.date + it-server-room 일치, 7.4는 Fortinet 공식 규칙
    (GA+36/54개월) 기준

주의: 이 표는 갱신되지 않으면 낡는다 — 조회 결과에 기준일(AS_OF)을 항상 실어
화면이 "며칠 지난 정보인지"를 보여줄 수 있게 한다.
"""
import datetime
import re

AS_OF = "2026-08-04"    # 표 작성(검증) 기준일

# 하드웨어 — 모델 정규화 키: 소문자, 'fortigate-'/'fg-' 접두 제거
HW_LIFECYCLE = {
    "1000d": {"eoo": "2023-04-16", "lsed": "2027-04-16", "eos": "2028-04-16",
              "confidence": "확인됨(Fortinet 공식)"},
    "1500d": {"eoo": "2020-04-15", "lsed": "2024-04-15", "eos": "2025-04-15",
              "confidence": "2개 출처 수렴 — 공식 포털 확인 권장(일부 자료 2026-12 표기)"},
    "1100e": {"eoo": None, "lsed": None, "eos": None,
              "confidence": "수명주기 미발표(%s 기준 지원 중)" % AS_OF},
}

# FortiOS 브랜치 — 'v7.2.5' → '7.2'
OS_LIFECYCLE = {
    "6.0": {"ga": "2018-03-29", "eoes": "2021-03-29", "eos": "2022-09-29"},
    "6.2": {"ga": "2019-03-28", "eoes": "2022-03-28", "eos": "2023-09-28"},
    "6.4": {"ga": "2020-03-31", "eoes": "2023-03-31", "eos": "2024-09-30"},
    "7.0": {"ga": "2021-03-30", "eoes": "2024-03-30", "eos": "2025-09-30"},
    "7.2": {"ga": "2022-03-31", "eoes": "2025-03-31", "eos": "2026-09-30"},
    "7.4": {"ga": "2023-05-11", "eoes": "2026-05-11", "eos": "2027-11-11"},
}


def _norm_model(model):
    """'FortiGate-1100E' / 'FG-1100E' / 'FGT_1100E' → '1100e'."""
    m = (model or "").strip().lower()
    m = re.sub(r"^(fortigate|fgt|fg)[-_\s]*", "", m)
    m = m.split(",")[0].split(" ")[0].strip()
    return m


def _branch(version):
    """'v7.2.5,build1517' / '7.2.5' → '7.2'."""
    m = re.search(r"v?(\d+)\.(\d+)", version or "")
    return "%s.%s" % (m.group(1), m.group(2)) if m else ""


def _status(eos_str, eoes_str=None, today=None):
    """날짜 → (등급, 문구). 등급: expired / imminent(180일) / eoes_passed / ok / unknown."""
    if not eos_str:
        return "unknown", "수명주기 미발표"
    today = today or datetime.date.today()
    eos = datetime.date.fromisoformat(eos_str)
    days = (eos - today).days
    if days < 0:
        return "expired", "지원 종료됨 (%s)" % eos_str
    if days <= 180:
        return "imminent", "지원 종료 임박 — %s (%d일 남음)" % (eos_str, days)
    if eoes_str:
        eoes = datetime.date.fromisoformat(eoes_str)
        if (eoes - today).days < 0:
            return "eoes_passed", "엔지니어링 지원 종료(%s) — 신규 수정 없음, EOS %s" % (eoes_str, eos_str)
    return "ok", "지원 중 (EOS %s)" % eos_str


def lookup(model=None, version=None, today=None):
    """모델·버전 → 수명주기 요약. 표에 없으면 unknown(추측하지 않는다).

    반환: {"as_of", "hw": {...}|None, "os": {...}|None, "level"}
      level: 하드웨어/OS 중 나쁜 쪽(expired > imminent > eoes_passed > ok > unknown)
    """
    out = {"as_of": AS_OF, "hw": None, "os": None}
    rank = {"expired": 4, "imminent": 3, "eoes_passed": 2, "ok": 1, "unknown": 0}
    worst = "unknown"

    key = _norm_model(model)
    if key and key in HW_LIFECYCLE:
        e = HW_LIFECYCLE[key]
        st, msg = _status(e["eos"], today=today)
        if st == "unknown" and e.get("confidence"):
            msg = e["confidence"]
        out["hw"] = dict(e, model=key.upper(), status=st, message=msg)
        if rank[st] > rank[worst]:
            worst = st

    br = _branch(version)
    if br and br in OS_LIFECYCLE:
        e = OS_LIFECYCLE[br]
        st, msg = _status(e["eos"], e["eoes"], today=today)
        out["os"] = dict(e, branch=br, status=st, message=msg)
        if rank[st] > rank[worst]:
            worst = st

    out["level"] = worst
    return out
