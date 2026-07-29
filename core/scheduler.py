# -*- coding: utf-8 -*-
"""M14: 하루 N회 자동 수집 스케줄러.

설정(app_settings):
  auto_collect_enabled  "1"/"0"
  auto_collect_times    "HH:MM,HH:MM" (예: "06:00,18:00")

앱 실행 중에만 동작(폐쇄망 상주 exe 가정). 같은 분 중복 실행은 슬롯 키로 방지.
"""
import threading
import time
from datetime import datetime, timedelta

from . import collector, db, utils

_thread = None
_stop = False

# 앱이 이보다 오래 멈춰 있었으면(재시작·절전) 놓친 슬롯을 소급 실행하지 않는다.
# 몇 시간 전 예약을 지금 와서 돌리면 오히려 놀란다.
_CATCHUP_LIMIT_SEC = 300
_LOOP_SEC = 50


def start_scheduler(db_path):
    """백그라운드 스케줄러 시작(이미 실행 중이면 무시)."""
    global _thread, _stop
    if _thread is not None and _thread.is_alive():
        return
    _stop = False
    _thread = threading.Thread(target=_loop, args=(db_path,), daemon=True)
    _thread.start()
    utils.log_event("info", "scheduler_started")


def stop_scheduler():
    global _stop
    _stop = True


def _parse_times(raw):
    out = []
    for t in (raw or "").split(","):
        t = t.strip()
        if t and ":" in t:
            out.append(t)
    return out


def due_slots(times, last_check, now):
    """(last_check, now] 구간에 든 예약 시각을 [(원문, 실제시각)]으로 돌려준다.

    예전엔 '지금이 정확히 그 분(HH:MM)인가'로만 트리거하고 sleep(50)이 고정이라,
    루프 본문이 11초만 넘어도 주기가 60초를 넘겨 특정 분이 아예 관측되지 않았다.
    그날의 자동 수집·설비 스캔이 실행되지 않고 놓쳤다는 로그조차 없었다.
    (공유폴더 배포는 writer가 reader를 막아 get_setting이 실측 11초까지 걸린다)
    구간으로 판정하면 루프가 늦어도 슬롯을 놓치지 않는다.
    """
    if last_check is None or now <= last_check:
        return []
    if (now - last_check).total_seconds() > _CATCHUP_LIMIT_SEC:
        return []          # 재시작·절전 등으로 오래 끊김 — 소급 실행하지 않는다
    out = []
    for t in times:
        try:
            hh, mm = str(t).split(":")[:2]
            base = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
        except (ValueError, TypeError):
            continue
        # 자정 넘김 대비: 오늘 기준과 어제 기준을 모두 확인
        for cand in (base, base - timedelta(days=1)):
            if last_check < cand <= now:
                out.append((t, cand))
                break
    return out


def _fire(name, event, fn, db_path, t, when, now):
    late = (now - when).total_seconds()
    utils.log_event("info", event, time=t,
                    late_sec=int(late) if late >= 60 else 0)
    # 별도 스레드로 실행 — 수집이 수 분 걸려도 스케줄러 루프가 블로킹되지 않아
    # 같은 창의 설비 스캔·다른 슬롯을 놓치지 않는다.
    threading.Thread(target=fn, args=(db_path,), daemon=True, name=name).start()


def _loop(db_path):
    last_slot = None
    last_fac_slot = None
    last_purge_day = None
    last_check = datetime.now()      # 기동 직후 과거 슬롯을 소급 실행하지 않도록 현재로 시작
    while not _stop:
        t0 = time.monotonic()
        try:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")

            # 1) 장비 자동 수집(하루 N회)
            if db.get_setting(db_path, "auto_collect_enabled", "0") == "1":
                times = _parse_times(db.get_setting(db_path, "auto_collect_times", "06:00,18:00"))
                for t, when in due_slots(times, last_check, now):
                    slot = when.strftime("%Y-%m-%d %H:%M")
                    if slot == last_slot:
                        continue
                    last_slot = slot
                    _fire("auto-collect", "auto_collect_trigger",
                          collector.collect_all_registered, db_path, t, when, now)

            # 2) 설비 대역 자동 스캔(1일 1회, 대역별 순차 — 부하 분산)
            if db.get_setting(db_path, "facility_auto_enabled", "0") == "1":
                fac_time = (db.get_setting(db_path, "facility_auto_time", "07:00") or "07:00").strip()
                for t, when in due_slots([fac_time], last_check, now):
                    slot = when.strftime("%Y-%m-%d %H:%M")
                    if slot == last_fac_slot:
                        continue
                    last_fac_slot = slot
                    from . import facility
                    _fire("facility-auto", "facility_auto_trigger",
                          facility.run_auto_scan, db_path, t, when, now)

            # 3) 알람 이력 자동 정리(보존 기간 초과 삭제, 1일 1회)
            if today != last_purge_day:
                last_purge_day = today
                days = db.get_setting(db_path, "alert_retention_days", "90") or "90"
                n = db.purge_device_events(db_path, days)
                if n:
                    utils.log_event("info", "device_events_purged", count=n, retention_days=days)

            # 4) 만료된 세션 계정 정리(매 주기)
            # 만료가 '그 키를 다시 조회할 때'만 일어나서, 브라우저가 IP를 바꾸거나
            # 탭을 닫고 다시 오지 않으면 평문 비밀번호가 프로세스 수명 내내 메모리에
            # 남았다(TTL 30분이 무의미해진다). 주기적으로 직접 걷어낸다.
            try:
                from . import session_creds
                _p = session_creds.purge_expired()
                if _p:
                    utils.log_event("info", "session_creds_purged", count=_p)
            except Exception:
                pass
            last_check = now
        except Exception as e:
            utils.log_event("error", "scheduler_loop_error",
                            error=collector._sanitize_error_msg(str(e)))
        # 본문이 오래 걸린 만큼 빼서 잔다 — 주기가 60초를 넘지 않게(슬롯 누락 방지)
        time.sleep(max(5, _LOOP_SEC - (time.monotonic() - t0)))
