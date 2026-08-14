# -*- coding: utf-8 -*-
"""SNMP 환경 정보(온도·팬·전원) 수집 — ENTITY-SENSOR-MIB(RFC 3433).

CLI로 온도를 읽으면 벤더마다 출력이 달라 파서를 8개 써야 한다
(`show environment all` / `show environment temperature` / `show chassis environment`
/ `show system temperature` …). 반면 이 MIB은 Cisco·Arista·Juniper·HP/Aruba·
FortiGate 등 대부분이 같은 형식으로 노출하므로 **구현이 하나면 된다**.

읽기(GET/GETBULK)만 한다. SET은 하지 않는다 — snmp_collect와 같은 원칙.

센서 값 계산(RFC 3433):
    실제값 = entPhySensorValue / 10^precision * 10^scale지수
  precision은 소수 자릿수, scale은 units/kilo/milli 같은 배율 코드다.
  이 둘을 무시하면 밀리섭씨(45000)나 0.1도 단위(455) 장비에서 값이 통째로 틀린다.
"""
from . import utils
from .snmp_collect import _Session, SnmpError, SnmpClosed, SnmpSilent  # noqa: F401

# ENTITY-SENSOR-MIB (entPhySensorEntry)
_SENSOR_TYPE = "1.3.6.1.2.1.99.1.1.1.1"
_SENSOR_SCALE = "1.3.6.1.2.1.99.1.1.1.2"
_SENSOR_PREC = "1.3.6.1.2.1.99.1.1.1.3"
_SENSOR_VALUE = "1.3.6.1.2.1.99.1.1.1.4"
_SENSOR_STATUS = "1.3.6.1.2.1.99.1.1.1.5"
# ENTITY-MIB — 센서 이름("Temp: Inlet", "Fan 1" 등)
_PHYS_DESCR = "1.3.6.1.2.1.47.1.1.1.1.2"

# EntitySensorDataType
_T_CELSIUS = 8
_T_RPM = 10
_T_TRUTH = 12
_TYPE_NAME = {3: "voltsAC", 4: "voltsDC", 5: "amperes", 6: "watts", 7: "hertz",
              8: "celsius", 9: "percentRH", 10: "rpm", 11: "cmm", 12: "truthvalue"}

# EntitySensorDataScale — 코드 → 10의 지수
_SCALE_EXP = {1: -24, 2: -21, 3: -18, 4: -15, 5: -12, 6: -9, 7: -6, 8: -3,
              9: 0, 10: 3, 11: 6, 12: 9, 13: 12, 14: 15, 15: 18, 16: 21, 17: 24}

# EntitySensorStatus — 1 ok / 2 unavailable / 3 nonoperational
_STATUS_NAME = {1: "ok", 2: "unavailable", 3: "nonoperational"}

# 임계값 — 장비가 자체 임계를 MIB으로 주지 않는 경우가 많아 화면 표기용으로만 쓴다.
# 실제 장비 알람을 대체하지 않는다(그래서 '주의/위험'이지 '장애'가 아니다).
WARN_C = 55.0
CRIT_C = 70.0


def _idx(oid, base):
    """OID에서 base를 뗀 인덱스 문자열."""
    return oid[len(base) + 1:] if oid.startswith(base + ".") else None


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_map(rows, base):
    """[(oid, val)] → {인덱스: 값}."""
    out = {}
    for oid, val in rows or []:
        i = _idx(oid, base)
        if i is not None:
            out[i] = val
    return out


def _real_value(raw, scale_code, precision):
    """RFC 3433 배율·소수자릿수를 적용한 실제 값. 계산 불가면 None."""
    raw = _as_int(raw)
    if raw is None:
        return None
    val = float(raw)
    p = _as_int(precision) or 0
    if p:
        val /= (10.0 ** p)
    exp = _SCALE_EXP.get(_as_int(scale_code), 0)
    if exp:
        val *= (10.0 ** exp)
    return val


def temp_level(c, warn_c=None, crit_c=None):
    """온도 → 표기 등급. 임계값은 화면 표기용(장비 자체 알람을 대체하지 않는다).

    임계를 인자로 받는 이유: 장비마다 정상 온도가 다르다. 광 모듈이 꽉 찬
    코어와 액세스 스위치가 같은 기준일 수 없어, 고정값이면 한쪽은 오탐이고
    다른 쪽은 미탐이 된다. 값을 주지 않으면 기본값을 쓴다.
    """
    if c is None:
        return None
    crit = CRIT_C if crit_c is None else crit_c
    warn = WARN_C if warn_c is None else warn_c
    if c >= crit:
        return "critical"
    if c >= warn:
        return "warning"
    return "normal"


def _decode(sess, max_rows=256, warn_c=None, crit_c=None):
    """세션에서 센서 테이블을 읽어 정규화된 센서 목록을 만든다.

    세션을 인자로 받는 이유: 실장비 없이도 테스트할 수 있게 하기 위함이다
    (가짜 세션을 넣어 walk 결과만 바꿔 끼운다).
    """
    types = _to_map(sess.walk(_SENSOR_TYPE, max_rows=max_rows), _SENSOR_TYPE)
    if not types:
        return []
    values = _to_map(sess.walk(_SENSOR_VALUE, max_rows=max_rows), _SENSOR_VALUE)
    scales = _to_map(sess.walk(_SENSOR_SCALE, max_rows=max_rows), _SENSOR_SCALE)
    precs = _to_map(sess.walk(_SENSOR_PREC, max_rows=max_rows), _SENSOR_PREC)
    stats = _to_map(sess.walk(_SENSOR_STATUS, max_rows=max_rows), _SENSOR_STATUS)
    names = _to_map(sess.walk(_PHYS_DESCR, max_rows=max_rows), _PHYS_DESCR)

    sensors = []
    for i, t in types.items():
        tcode = _as_int(t)
        if tcode not in (_T_CELSIUS, _T_RPM, _T_TRUTH):
            continue                      # 전압·전류까지 담으면 화면이 잡음이 된다
        status = _STATUS_NAME.get(_as_int(stats.get(i)), "unknown")
        val = _real_value(values.get(i), scales.get(i), precs.get(i))
        if status != "ok" and val is None:
            continue                      # 값도 없고 상태도 아니면 실체가 없다
        raw_name = names.get(i)
        if isinstance(raw_name, bytes):
            raw_name = raw_name.decode("utf-8", "replace")
        name = (str(raw_name).strip() if raw_name else "") or ("sensor %s" % i)
        s = {"index": i, "name": name[:120],
             "type": _TYPE_NAME.get(tcode, str(tcode)),
             "value": round(val, 1) if val is not None else None,
             "status": status}
        if tcode == _T_CELSIUS:
            s["level"] = temp_level(val, warn_c, crit_c)
        sensors.append(s)
    sensors.sort(key=lambda x: (x["type"] != "celsius", x["name"]))
    return sensors


def summarize(sensors, warn_c=None, crit_c=None):
    """센서 목록 → 화면·저장용 요약. 임계는 설정값(없으면 기본값)."""
    temps = [s for s in sensors if s["type"] == "celsius" and s["value"] is not None]
    fans = [s for s in sensors if s["type"] == "rpm"]
    max_c = max((s["value"] for s in temps), default=None)
    # 센서가 스스로 '비정상'이라고 말하면 온도 수치와 무관하게 그걸 따른다.
    bad = [s for s in sensors if s["status"] == "nonoperational"]
    level = temp_level(max_c, warn_c, crit_c)
    if bad and level != "critical":
        level = "warning"
    return {"sensors": sensors, "temp_count": len(temps), "fan_count": len(fans),
            "max_temp_c": max_c, "level": level,
            "bad_sensors": [s["name"] for s in bad][:10]}


def collect_env(ip, community="public", timeout=2.0, budget=20.0,
                warn_c=None, crit_c=None):
    """장비 하나의 환경 정보를 SNMP로 읽는다.

    반환: {sensors, temp_count, fan_count, max_temp_c, level, bad_sensors}
    센서 테이블이 비어 있으면 sensors=[] (예외 아님 — 이 MIB을 지원하지 않는
    장비가 흔하다). 무응답·차단은 SnmpSilent/SnmpClosed 예외로 올린다.
    """
    sess = _Session(ip, community, timeout=timeout, budget=budget)
    sensors = _decode(sess, warn_c=warn_c, crit_c=crit_c)
    out = summarize(sensors, warn_c, crit_c)
    utils.log_event("info", "snmp_env_collected", ip=ip,
                    sensors=len(sensors), max_temp_c=out.get("max_temp_c"))
    return out


def probe_switch(ip, community="public", timeout=2.0, budget=25.0):
    """스위치가 SNMP로 실제 무엇을 주는지 훑는다(진단용).

    방화벽에는 진단 버튼이 있었는데 스위치에는 없어서, 온도·포트 지표가 안 채워질 때
    커뮤니티가 틀린 건지 장비가 그 MIB을 안 쓰는 건지 확인할 방법이 없었다.

    반환: {"reachable": bool, "sysdescr": str, "sysname": str,
           "sensors": n, "ports": n, "checks": [{name, ok, detail}]}
    """
    from .snmp_collect import _Session
    _SYS_DESCR_O = "1.3.6.1.2.1.1.1.0"
    _SYS_NAME_O = "1.3.6.1.2.1.1.5.0"
    _IF_NAME_O = "1.3.6.1.2.1.31.1.1.1.1"
    _IF_HC_IN_O = "1.3.6.1.2.1.31.1.1.1.6"
    _IF_IN_ERR_O = "1.3.6.1.2.1.2.2.1.14"
    _DOT3_FCS_O = "1.3.6.1.2.1.10.7.2.1.3"

    sess = _Session(ip, community, timeout=timeout, budget=budget)
    out = {"reachable": False, "sysdescr": "", "sysname": "",
           "sensors": 0, "ports": 0, "checks": []}

    def _add(name, ok, detail):
        out["checks"].append({"name": name, "ok": bool(ok), "detail": detail})

    # ① 기본 응답 — 여기서 실패하면 커뮤니티/허용호스트/방화벽 문제다
    try:
        for o, v in sess.get([_SYS_DESCR_O, _SYS_NAME_O]):
            txt = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
            if o == _SYS_DESCR_O:
                out["sysdescr"] = txt[:300]
            elif o == _SYS_NAME_O:
                out["sysname"] = txt[:120]
        out["reachable"] = bool(out["sysdescr"] or out["sysname"])
    except Exception as e:
        _add("SNMP 응답", False, "무응답: %s" % type(e).__name__)
        return out
    _add("SNMP 응답", out["reachable"],
         out["sysdescr"][:120] if out["reachable"] else "빈 응답(커뮤니티 확인)")
    if not out["reachable"]:
        return out

    # ② 온도·팬(ENTITY-SENSOR-MIB) — 없는 장비가 흔하다(정상 범주)
    try:
        sensors = _decode(sess)
        temps = [s for s in sensors if s["type"] == "celsius"]
        out["sensors"] = len(sensors)
        _add("온도 센서 (ENTITY-SENSOR-MIB)", bool(temps),
             "센서 %d개(온도 %d개)" % (len(sensors), len(temps)) if sensors
             else "이 장비는 이 MIB을 제공하지 않습니다(온도 표시 불가)")
    except Exception as e:
        _add("온도 센서 (ENTITY-SENSOR-MIB)", False, "실패: %s" % type(e).__name__)

    # ③ 포트 목록·트래픽·에러 — 폴러가 쓰는 것들
    for label, base, note in (
            ("포트 이름 (IF-MIB ifName)", _IF_NAME_O, "포트 %d개"),
            ("트래픽 카운터 (ifHCInOctets)", _IF_HC_IN_O, "%d개 포트에서 응답"),
            ("에러 카운터 (ifInErrors)", _IF_IN_ERR_O, "%d개 포트에서 응답"),
            ("CRC 카운터 (EtherLike-MIB)", _DOT3_FCS_O, "%d개 포트에서 응답")):
        try:
            rows = list(sess.walk(base, max_rows=256))
            if base == _IF_NAME_O:
                out["ports"] = len(rows)
            _add(label, bool(rows),
                 (note % len(rows)) if rows else "응답 없음(이 MIB 미지원)")
        except Exception as e:
            _add(label, False, "실패: %s" % type(e).__name__)
    return out
