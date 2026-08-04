# -*- coding: utf-8 -*-
"""경량 지표 폴러 — 시계열 그래프의 데이터 공급원.

주기(기본 5분, ⚙설정에서 변경/끄기)마다:
  - FortiGate: SNMP로 CPU/메모리/세션(+온도) 한 점씩 기록
  - 스위치: SNMP 온도 한 점
  - 설비: 온라인/전체 수(DB 집계 — 네트워크 접근 없음)
  - 포트: 전체 Up/전체 수(DB 집계)

전체 수집(SSH/REST)과 완전히 별개다 — SNMP GET 몇 개 + SQL 두 개라 장비·서버
부하가 무시할 수준이고, 그래서 5분마다 돌려도 된다.

데모 모드에서는 SNMP를 시도하지 않는다(가짜 IP로 매 주기 타임아웃만 쌓인다) —
DB 집계 점(설비·포트)만 기록해 화면 데모는 되게 한다.
"""
import threading
import time

from . import db, utils

DEFAULT_MINUTES = 5
RETENTION_DAYS = 30

_thread = None
_stop = threading.Event()


def poll_minutes(db_path):
    """설정된 주기(분). 0 = 끔."""
    try:
        v = int(db.get_setting(db_path, "metrics_poll_minutes", str(DEFAULT_MINUTES)))
        return max(0, min(1440, v))
    except (TypeError, ValueError):
        return DEFAULT_MINUTES


def _snmp_community(db_path):
    try:
        from . import collector
        return collector._snmp_community_if_enabled(db_path)
    except Exception:
        return None


def poll_once(db_path, demo_mode=False):
    """한 주기 실행 — 기록한 점 수를 반환(테스트·진단용).

    장비 하나가 느리거나 죽어도 나머지는 계속한다. 예외는 점 하나 손실로 끝나야지
    폴러 스레드를 죽이면 안 된다.
    """
    points = 0

    # ① DB 집계 점 — 네트워크 접근 없음(데모 포함 항상)
    try:
        with db.get_db(db_path) as conn:
            r = conn.execute("SELECT COUNT(*) AS t, IFNULL(SUM(online),0) AS o "
                             "FROM facility_hosts").fetchone()
            if r and (r["t"] or 0) > 0:
                db.save_metrics_point(db_path, "facility", 0,
                                      online=r["o"], total=r["t"])
                points += 1
            r = conn.execute(
                "SELECT COUNT(*) AS t, "
                "SUM(CASE WHEN LOWER(IFNULL(status,'')) IN ('up','connected') "
                "THEN 1 ELSE 0 END) AS u FROM ports WHERE snapshot_id IN "
                "(SELECT MAX(snapshot_id) FROM ports GROUP BY switch_id)").fetchone()
            if r and (r["t"] or 0) > 0:
                db.save_metrics_point(db_path, "ports", 0,
                                      online=r["u"] or 0, total=r["t"])
                points += 1
    except Exception as e:
        utils.log_event("warning", "metrics_poll_db_error", error=str(e)[:120])

    if demo_mode:
        return points

    community = _snmp_community(db_path)
    if not community:
        return points

    # ② FortiGate — CPU/메모리/세션 + 온도. 주기 폴링이므로 짧은 예산.
    try:
        from . import snmp_fortigate, snmp_env
        for fw in db.list_firewalls(db_path):
            if fw.get("vendor") != "fortigate" or not fw.get("host"):
                continue
            cpu = mem = sess = temp = None
            try:
                h = snmp_fortigate.collect_health(fw["host"], community, budget=8.0)
                cpu, mem, sess = h.get("cpu_pct"), h.get("mem_pct"), h.get("sessions")
            except Exception:
                pass
            try:
                e = snmp_env.collect_env(fw["host"], community, budget=6.0)
                temp = e.get("max_temp_c")
            except Exception:
                pass
            if any(v is not None for v in (cpu, mem, sess, temp)):
                db.save_metrics_point(db_path, "firewall", fw["id"],
                                      cpu=cpu, mem=mem, sessions=sess, temp_c=temp)
                points += 1
    except Exception as e:
        utils.log_event("warning", "metrics_poll_fw_error", error=str(e)[:120])

    # ③ 스위치 — 온도만(범용으로 얻을 수 있는 것이 그것뿐)
    try:
        from . import snmp_env
        for sw in db.get_switches(db_path):
            if not sw.get("ip"):
                continue
            try:
                e = snmp_env.collect_env(sw["ip"], community, budget=6.0)
                if e.get("max_temp_c") is not None:
                    db.save_metrics_point(db_path, "switch", sw["id"],
                                          temp_c=e["max_temp_c"])
                    points += 1
            except Exception:
                continue
    except Exception as e:
        utils.log_event("warning", "metrics_poll_sw_error", error=str(e)[:120])

    return points


def _loop(db_path, demo_mode):
    last_prune = 0.0
    while not _stop.is_set():
        minutes = poll_minutes(db_path)
        if minutes <= 0:
            # 꺼짐 — 1분마다 설정 재확인(켜면 다음 분부터 동작)
            _stop.wait(60)
            continue
        started = time.monotonic()
        try:
            n = poll_once(db_path, demo_mode)
            utils.log_event("info", "metrics_poll_tick", points=n)
        except Exception as e:
            # 어떤 예외도 스레드를 죽이면 안 된다 — 다음 주기에 재시도.
            utils.log_event("warning", "metrics_poll_tick_error", error=str(e)[:120])
        # 보존기간 정리는 하루 한 번이면 충분
        if time.monotonic() - last_prune > 86400:
            try:
                removed = db.prune_metrics_history(db_path, RETENTION_DAYS)
                if removed:
                    utils.log_event("info", "metrics_history_pruned", removed=removed)
            except Exception:
                pass
            last_prune = time.monotonic()
        # 실행에 걸린 시간을 빼고 대기 — 장비가 많아도 주기가 밀리지 않게
        elapsed = time.monotonic() - started
        _stop.wait(max(30, minutes * 60 - elapsed))


def start(db_path, demo_mode=False):
    """폴러 스레드 시작(중복 시작 무시)."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(db_path, demo_mode),
                               name="metrics-poller", daemon=True)
    _thread.start()
    utils.log_event("info", "metrics_poller_started",
                    minutes=poll_minutes(db_path), demo=demo_mode)


def stop():
    _stop.set()
