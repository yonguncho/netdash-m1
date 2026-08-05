# -*- coding: utf-8 -*-
"""상태 감시 폴러(기본 10분) — 포트 DOWN·설비 끊김을 수집 주기와 무관하게 감지.

배경(사용자 지적): 포트 상태는 하루 2회 자동 수집 때만, 설비 온라인은 하루 1회
스캔 때만 갱신됐다. 60초 `monitor_known_hosts`가 있지만 MAC 테이블 기반이라
MAC 테이블이 수집 때만 갱신되는 한 사실상 같은 주기에 묶여 있었다.

이 폴러는 두 가지를 주기적으로 직접 확인한다:
  ① 스위치 포트: SNMP IF-MIB(ifOperStatus) — up↔down 전이 시
     port_down/port_up 이벤트(알람 벨·이메일·관제 티커로 흐른다).
     상태는 port_state 테이블에 저장(재시작해도 기준 유지 — 재기동 오탐 방지).
  ② 설비: 이 PC에서 직접 ICMP ping(동시 40개).
     - 대역 전멸 가드: 온라인이던 대역이 한 번에 전부 무응답이면 그 대역은
       'PC에서 라우팅 불가'로 보고 건너뛴다(직접 ping이 안 되는 VLAN에서
       무더기 허위 '끊김' 알람을 내지 않기 위해 — 그런 대역은 기존 게이트웨이
       스캔이 담당한다).
     - 디바운스: 연속 2회(=2주기) 무응답이어야 끊김 확정. 복구는 즉시.

주기: ⚙설정 `status_poll_minutes` (기본 10, 0=끔). 데모 모드는 동작 안 함.
"""
import platform
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import db, utils

DEFAULT_MINUTES = 10
MISS_THRESHOLD = 2          # 설비: 연속 무응답 N회(=N주기)에 끊김 확정
_PING_WORKERS = 40

# IF-MIB
_IF_OPER = "1.3.6.1.2.1.2.2.1.8"      # 1=up 2=down
_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"   # ifName (짧은 이름)
_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"     # 폴백

# 물리 포트만 알람 대상(논리 인터페이스 down은 잡음)
_SKIP_PREFIX = ("vlan", "vl", "po", "port-channel", "lo", "loopback", "tu",
                "tunnel", "null", "ae", "irb", "mgmt0.", "cpu", "stack")

_thread = None
_stop = threading.Event()
_miss = {}                  # {ip: 연속 무응답 횟수} — 디바운스(메모리로 충분)


def poll_minutes(db_path):
    try:
        v = int(db.get_setting(db_path, "status_poll_minutes", str(DEFAULT_MINUTES)))
        return max(0, min(1440, v))
    except (TypeError, ValueError):
        return DEFAULT_MINUTES


def _is_physical(name):
    n = (name or "").strip().lower()
    return bool(n) and not n.startswith(_SKIP_PREFIX)


# ── ① 포트 상태(SNMP) ───────────────────────────────────────────

def _walk_oper_status(ip, community, budget=10.0):
    """{포트이름: 1|2}. 응답 없으면 예외(호출부가 장비 단위로 건너뜀)."""
    from .snmp_collect import _Session
    sess = _Session(ip, community, budget=budget)
    oper = {}
    for oid, val in sess.walk(_IF_OPER, max_rows=1024):
        try:
            oper[oid.rsplit(".", 1)[1]] = int(val)
        except (ValueError, IndexError, TypeError):
            continue
    names = {}
    for base in (_IF_NAME, _IF_DESCR):
        for oid, val in sess.walk(base, max_rows=1024):
            idx = oid.rsplit(".", 1)[1]
            if idx not in names and val:
                names[idx] = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
        if names:
            break
    out = {}
    for idx, st in oper.items():
        nm = (names.get(idx) or "").strip()
        if st in (1, 2) and _is_physical(nm):
            out[nm[:80]] = st
    return out


def check_ports(db_path, community):
    """전 스위치 포트 up/down 전이 감지. 반환: (down 이벤트 수, up 이벤트 수)."""
    downs = ups = 0
    for sw in db.get_switches(db_path):
        ip = sw.get("ip")
        if not ip:
            continue
        try:
            cur = _walk_oper_status(ip, community)
        except Exception:
            continue                      # SNMP 미지원/차단 장비 — 조용히 건너뜀
        if not cur:
            continue
        prev = db.get_port_state(db_path, sw["id"])
        for port, st in cur.items():
            old = prev.get(port)
            if old is None:
                continue                  # 첫 관측 — 기준만 저장(재기동 오탐 방지)
            if old == 1 and st == 2:
                downs += 1
                db.save_device_event(
                    db_path, "port_down", "warning", switch_id=sw["id"],
                    label=sw.get("name"),
                    message="포트 다운: %s %s" % (sw.get("name") or ip, port))
            elif old == 2 and st == 1:
                ups += 1
                db.save_device_event(
                    db_path, "port_up", "info", switch_id=sw["id"],
                    label=sw.get("name"),
                    message="포트 복구: %s %s" % (sw.get("name") or ip, port))
        db.save_port_state(db_path, sw["id"], cur)
    return downs, ups


# ── ② 설비 상태(직접 ping) ───────────────────────────────────────

def _ping(ip, timeout_ms=1000):
    if platform.system() == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 2)
        # Windows ping은 'Destination host unreachable'에도 rc=0을 주는 경우가 있어
        # TTL 문자열까지 본다(응답이 실제로 왔는지).
        return r.returncode == 0 and b"TTL=" in r.stdout.upper()
    except Exception:
        return False


def check_facility(db_path):
    """설비 직접 ping — 전이만 반영. 반환: (끊김 확정 수, 복구 수, 스킵 대역 수)."""
    hosts = [h for h in db.get_facility_hosts(db_path) if h.get("ip")]
    if not hosts:
        return 0, 0, 0
    ips = [h["ip"] for h in hosts]
    with ThreadPoolExecutor(max_workers=_PING_WORKERS) as ex:
        alive = dict(zip(ips, ex.map(_ping, ips)))

    # 대역 전멸 가드 — 온라인이던 대역이 통째로 무응답이면 라우팅 불가로 판단
    by_band = {}
    for h in hosts:
        by_band.setdefault(h.get("subnet") or "?", []).append(h)
    skipped = 0
    skip_bands = set()
    for band, hs in by_band.items():
        was_online = [h for h in hs if h.get("online")]
        if len(was_online) >= 3 and not any(alive.get(h["ip"]) for h in was_online):
            skip_bands.add(band)
            skipped += 1
            utils.log_event("info", "status_monitor_band_unreachable", subnet=band,
                            hosts=len(was_online))

    dropped = restored = 0
    for h in hosts:
        band = h.get("subnet") or "?"
        if band in skip_bands:
            _miss.pop(h["ip"], None)
            continue
        ip, was = h["ip"], bool(h.get("online"))
        ok = alive.get(ip, False)
        if ok:
            _miss.pop(ip, None)
            if not was:                   # 복구는 즉시
                restored += 1
                db.set_facility_online(db_path, band, ip, True)
                db.save_device_event(db_path, "device_online", "info", subnet=band,
                                     ip=ip, mac=h.get("mac"),
                                     message="설비 복구(ping 응답): " + ip)
            continue
        if not was:
            continue                      # 이미 끊김 상태 — 재알람 금지
        _miss[ip] = _miss.get(ip, 0) + 1
        if _miss[ip] < MISS_THRESHOLD:
            continue                      # 디바운스 — 다음 주기에 확정
        _miss.pop(ip, None)
        dropped += 1
        db.set_facility_online(db_path, band, ip, False)
        _loc = ""
        if h.get("switch_name") and h.get("port"):
            _loc = " (연결: %s %s)" % (h["switch_name"], h["port"])
        db.save_device_event(db_path, "device_offline", "warning", subnet=band,
                             ip=ip, mac=h.get("mac"), switch_id=h.get("switch_id"),
                             label=h.get("switch_name"),
                             message="설비 연결 끊김(ping 무응답 %d회): %s%s"
                                     % (MISS_THRESHOLD, ip, _loc))
    return dropped, restored, skipped


# ── 루프 ─────────────────────────────────────────────────────────

def poll_once(db_path):
    """한 주기 — (포트다운, 포트복구, 설비끊김, 설비복구, 스킵대역)."""
    community = None
    try:
        from . import collector
        community = collector._snmp_community_if_enabled(db_path)
    except Exception:
        pass
    pd = pu = 0
    if community:
        try:
            pd, pu = check_ports(db_path, community)
        except Exception as e:
            utils.log_event("warning", "status_monitor_ports_error", error=str(e)[:120])
    fd = fr = sk = 0
    try:
        fd, fr, sk = check_facility(db_path)
    except Exception as e:
        utils.log_event("warning", "status_monitor_facility_error", error=str(e)[:120])
    if pd or pu or fd or fr:
        utils.log_event("info", "status_monitor_tick", port_down=pd, port_up=pu,
                        fac_down=fd, fac_up=fr, skipped_bands=sk)
    return pd, pu, fd, fr, sk


def _loop(db_path):
    while not _stop.is_set():
        minutes = poll_minutes(db_path)
        if minutes <= 0:
            _stop.wait(60)
            continue
        started = time.monotonic()
        try:
            poll_once(db_path)
        except Exception as e:
            utils.log_event("warning", "status_monitor_tick_error", error=str(e)[:120])
        elapsed = time.monotonic() - started
        _stop.wait(max(30, minutes * 60 - elapsed))


def start(db_path):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(db_path,),
                               name="status-monitor", daemon=True)
    _thread.start()
    utils.log_event("info", "status_monitor_started", minutes=poll_minutes(db_path))


def stop():
    _stop.set()
