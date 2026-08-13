# -*- coding: utf-8 -*-
"""FortiGate SNMP 모니터링 — FORTINET-FORTIGATE-MIB(1.3.6.1.4.1.12356.101).

FortiGate는 표준 MIB(IF-MIB·ENTITY-SENSOR-MIB 등)과 Fortinet 전용 MIB을 함께
노출한다. 온도·팬은 표준 MIB이라 snmp_env가 이미 담당하고, 여기서는 **방화벽
고유 지표**(CPU·메모리·디스크·세션·HA 동기화)를 읽는다.

읽기(GET/GETBULK)만 한다. SET은 하지 않는다.

주의 — 이 파일의 OID는 Fortinet 공개 MIB 문서 기준으로 작성했고 **실장비로
검증되지 않았다.** 그래서 두 가지를 지킨다:
  ① 값이 안 오면 그 항목만 조용히 빠진다(전체 실패로 만들지 않는다)
  ② `probe()`로 장비가 실제로 무엇을 주는지 원문을 볼 수 있게 한다
     — 화면에서 확인한 뒤에 파싱을 확정하는 방식(사양 수집 진단과 같은 패턴)
"""
import re

from . import utils
from .snmp_collect import _Session, SnmpError, SnmpClosed, SnmpSilent  # noqa: F401

# 표준 MIB
_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# Fortinet 전용 — fgSystemInfo
_FG = "1.3.6.1.4.1.12356.101"
_FG_VERSION = _FG + ".4.1.1.0"
# ENTITY-MIB 모델명(첫 섀시 항목) — SSH·REST가 안 되는 장비(특히 6.x)의 모델 폴백
_ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13.1"
_FG_CPU = _FG + ".4.1.3.0"           # %
_FG_MEM = _FG + ".4.1.4.0"           # %
_FG_MEM_CAP = _FG + ".4.1.5.0"       # KB
_FG_DISK_USED = _FG + ".4.1.6.0"     # MB
_FG_DISK_CAP = _FG + ".4.1.7.0"      # MB
_FG_SESSIONS = _FG + ".4.1.8.0"

# 코어별 CPU 테이블(fgProcessorUsage) — 일부 모델/펌웨어는 fgSysCpuUsage(스칼라)를
# 주지 않고 이 테이블만 노출한다. 평균을 내어 폴백으로 쓴다.
_FG_PROC_USAGE = _FG + ".4.4.2.1.2"

# HA — fgHaSystemMode / fgHaStatsTable
_FG_HA_MODE = _FG + ".13.1.1.0"
_FG_HA_GROUP = _FG + ".13.1.7.0"
_HA_SERIAL = _FG + ".13.2.1.1.2"
_HA_CPU = _FG + ".13.2.1.1.3"
_HA_MEM = _FG + ".13.2.1.1.4"
_HA_SESSIONS = _FG + ".13.2.1.1.6"
_HA_HOSTNAME = _FG + ".13.2.1.1.11"
_HA_SYNC = _FG + ".13.2.1.1.12"      # 1=동기화됨 계열(장비/버전마다 표기 차이)

_HA_MODE_NAME = {1: "standalone", 2: "active-active", 3: "active-passive"}

# 사용률 경고 임계 — 화면 표기용(장비 자체 알람을 대체하지 않는다)
WARN_PCT = 80
CRIT_PCT = 90


def _num(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _text(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").strip()
    return str(v).strip() if v is not None else ""


def pct_level(p):
    """사용률 → 표기 등급."""
    if p is None:
        return None
    if p >= CRIT_PCT:
        return "critical"
    if p >= WARN_PCT:
        return "warning"
    return "normal"


def _norm_version(raw):
    """버전 표기 정규화는 파서 한 곳(firewall.fortiperf)에 둔다 — 경로마다
    따로 자르면 이번처럼 한 경로만 어긋난다. import는 지연(순환 방지)."""
    from .firewall import fortiperf
    return fortiperf.norm_version(raw)


def norm_fgt_model(raw):
    """SNMP 모델 문자열 정규화 — 'FGT_1000D'/'FGT-1000D' → 'FortiGate-1000D'.

    sysDescr 폴백은 모델처럼 보일 때만 인정한다(잡다한 설명문 오인 방지).
    """
    s = (raw or "").strip()
    if not s:
        return ""
    m = re.match(r"(?i)^(fortigate|fortiwifi|fgt|fwf)[-_\s]*([\w-]+)", s)
    if not m:
        return ""
    fam = {"fgt": "FortiGate", "fwf": "FortiWiFi"}.get(
        m.group(1).lower(), m.group(1)[:1].upper() + m.group(1)[1:].lower())
    fam = {"Fortigate": "FortiGate", "Fortiwifi": "FortiWiFi"}.get(fam, fam)
    return ("%s-%s" % (fam, m.group(2).upper()))[:60]


def _scalars(sess):
    """스칼라 GET을 한 번에 — 지원하지 않는 OID는 값이 없거나 빠진다."""
    want = [_SYS_DESCR, _SYS_UPTIME, _SYS_NAME, _FG_VERSION, _FG_CPU, _FG_MEM,
            _FG_MEM_CAP, _FG_DISK_USED, _FG_DISK_CAP, _FG_SESSIONS,
            _FG_HA_MODE, _FG_HA_GROUP, _ENT_MODEL]
    got = {}
    # 한 PDU에 다 넣으면 하나만 없어도 장비에 따라 통째로 noSuchName이 온다.
    # 4개씩 나눠 부분 실패를 격리한다.
    for i in range(0, len(want), 4):
        chunk = want[i:i + 4]
        try:
            for oid, val in sess.get(chunk):
                got[oid] = val
        except SnmpError:
            raise                       # 무응답·차단은 호출부가 구분해야 한다
        except Exception:
            continue
    return got


def _ha_members(sess, max_rows=16):
    """HA 멤버별 상태. HA가 아니면 빈 목록."""
    def m(base):
        out = {}
        try:
            for oid, val in sess.walk(base, max_rows=max_rows):
                out[oid[len(base) + 1:]] = val
        except Exception:
            pass
        return out

    hosts = m(_HA_HOSTNAME)
    if not hosts:
        return []
    serials, cpus, mems, sess_counts, syncs = (m(_HA_SERIAL), m(_HA_CPU), m(_HA_MEM),
                                               m(_HA_SESSIONS), m(_HA_SYNC))
    rows = []
    for idx, host in sorted(hosts.items()):
        rows.append({"index": idx, "hostname": _text(host),
                     "serial": _text(serials.get(idx)),
                     "cpu_pct": _num(cpus.get(idx)),
                     "mem_pct": _num(mems.get(idx)),
                     "sessions": _num(sess_counts.get(idx)),
                     "sync_raw": _num(syncs.get(idx))})
    return rows


def collect_health(ip, community="public", timeout=2.0, budget=20.0):
    """FortiGate 상태 지표를 읽어 dict 반환.

    반환 키(없을 수 있음): version, uptime_sec, hostname, cpu_pct, mem_pct,
      mem_total_mb, disk_used_mb, disk_total_mb, disk_pct, sessions,
      ha_mode, ha_group, ha_members[], level
    무응답·차단은 SnmpSilent/SnmpClosed 예외.
    """
    sess = _Session(ip, community, timeout=timeout, budget=budget)
    g = _scalars(sess)
    out = {}

    # SSH·REST와 같은 표기로 맞춘다 — 예전엔 여기만 원문(빌드·날짜 포함)을 넣어
    # 같은 화면에 'v7.4.6'과 'v7.4.6,build2726,241210 (GA.M)'이 섞였다(사용자 신고).
    ver = _norm_version(_text(g.get(_FG_VERSION)))
    if ver:
        out["version"] = ver
    model = norm_fgt_model(_text(g.get(_ENT_MODEL)) or _text(g.get(_SYS_DESCR)))
    if model:
        out["model"] = model
    name = _text(g.get(_SYS_NAME))
    if name:
        out["hostname"] = name.split(".")[0][:100]
    up = _num(g.get(_SYS_UPTIME))
    if up is not None:
        out["uptime_sec"] = up // 100          # sysUpTime은 1/100초 단위

    cpu = _num(g.get(_FG_CPU))
    if cpu is None:
        # 폴백: 코어별 사용률 평균 — fgSysCpuUsage를 안 주는 펌웨어가 있다
        # (사용자 실장비에서 CPU만 비던 원인 후보).
        try:
            cores = [_num(v) for _o, v in sess.walk(_FG_PROC_USAGE, max_rows=128)]
            cores = [c for c in cores if c is not None]
            if cores:
                cpu = round(sum(cores) / len(cores))
        except Exception:
            pass
    if cpu is not None:
        out["cpu_pct"] = cpu
    mem = _num(g.get(_FG_MEM))
    if mem is not None:
        out["mem_pct"] = mem
    mem_cap = _num(g.get(_FG_MEM_CAP))
    if mem_cap:
        out["mem_total_mb"] = round(mem_cap / 1024.0)   # KB → MB

    d_used, d_cap = _num(g.get(_FG_DISK_USED)), _num(g.get(_FG_DISK_CAP))
    if d_used is not None:
        out["disk_used_mb"] = d_used
    if d_cap:
        out["disk_total_mb"] = d_cap
        if d_used is not None:
            out["disk_pct"] = round(d_used * 100.0 / d_cap)
    elif d_cap == 0:
        # 용량 0 = 로그 디스크가 없거나 비활성인 모델(흔하다). '수집 실패'가 아니라
        # '디스크 없음'이므로 화면이 구분해 표기할 수 있게 표시한다.
        out["disk_absent"] = True

    ses = _num(g.get(_FG_SESSIONS))
    if ses is not None:
        out["sessions"] = ses

    ha = _num(g.get(_FG_HA_MODE))
    if ha is not None:
        out["ha_mode"] = _HA_MODE_NAME.get(ha, str(ha))
    grp = _text(g.get(_FG_HA_GROUP))
    if grp:
        out["ha_group"] = grp
    if out.get("ha_mode") and out["ha_mode"] != "standalone":
        members = _ha_members(sess)
        if members:
            out["ha_members"] = members

    # 가장 나쁜 사용률로 전체 등급을 정한다(하나만 90%여도 눈에 띄어야 한다).
    worst = max([p for p in (out.get("cpu_pct"), out.get("mem_pct"),
                             out.get("disk_pct")) if p is not None], default=None)
    out["level"] = pct_level(worst)

    utils.log_event("info", "snmp_fortigate_health", ip=ip,
                    cpu=out.get("cpu_pct"), mem=out.get("mem_pct"),
                    sessions=out.get("sessions"))
    return out


def probe(ip, community="public", timeout=2.0, budget=25.0, max_rows=120):
    """장비가 실제로 무엇을 주는지 원문을 훑는다(파싱 확정 전 확인용).

    실장비 없이 작성한 OID가 맞는지 화면에서 눈으로 확인하기 위한 진단 경로다.
    반환: {"scalars": [{oid, value}], "subtree": [{oid, value}]}
    """
    sess = _Session(ip, community, timeout=timeout, budget=budget)
    scalars = []
    for oid in (_SYS_DESCR, _SYS_NAME, _SYS_UPTIME, _FG_VERSION, _FG_CPU,
                _FG_MEM, _FG_MEM_CAP, _FG_DISK_USED, _FG_DISK_CAP,
                _FG_SESSIONS, _FG_HA_MODE):
        got = None
        try:
            for o, v in sess.get([oid]):
                if o == oid:
                    got = _text(v)[:200]
        except SnmpError:
            raise
        except Exception:
            got = None
        # 응답이 '빈 목록'으로 오는 경우도 미지원이다. 예외만 처리하면 그 OID가
        # 결과에서 통째로 빠져, 정작 '무엇이 없는지'를 묻는 진단이 답을 못 한다.
        scalars.append({"oid": oid, "value": got if got is not None else "(응답 없음)"})
    subtree = []
    try:
        for o, v in sess.walk(_FG + ".4.1", max_rows=max_rows):
            subtree.append({"oid": o, "value": _text(v)[:200]})
    except Exception:
        pass
    try:
        for o, v in sess.walk(_FG_PROC_USAGE, max_rows=32):
            subtree.append({"oid": o, "value": _text(v)[:200]})
    except Exception:
        pass
    return {"scalars": scalars, "subtree": subtree}
