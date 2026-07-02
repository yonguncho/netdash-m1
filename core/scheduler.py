# -*- coding: utf-8 -*-
"""M14: 하루 N회 자동 수집 스케줄러.

설정(app_settings):
  auto_collect_enabled  "1"/"0"
  auto_collect_times    "HH:MM,HH:MM" (예: "06:00,18:00")

앱 실행 중에만 동작(폐쇄망 상주 exe 가정). 같은 분 중복 실행은 슬롯 키로 방지.
"""
import threading
import time
from datetime import datetime

from . import collector, db, utils

_thread = None
_stop = False


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


def _loop(db_path):
    last_slot = None
    last_fac_slot = None
    last_purge_day = None
    while not _stop:
        try:
            now = datetime.now()
            hhmm = now.strftime("%H:%M")
            today = now.strftime("%Y-%m-%d")

            # 1) 장비 자동 수집(하루 N회)
            if db.get_setting(db_path, "auto_collect_enabled", "0") == "1":
                times = _parse_times(db.get_setting(db_path, "auto_collect_times", "06:00,18:00"))
                slot = today + " " + hhmm
                if hhmm in times and slot != last_slot:
                    last_slot = slot
                    utils.log_event("info", "auto_collect_trigger", time=hhmm)
                    collector.collect_all_registered(db_path)

            # 2) 설비 대역 자동 스캔(1일 1회, 대역별 순차 — 부하 분산)
            if db.get_setting(db_path, "facility_auto_enabled", "0") == "1":
                fac_time = (db.get_setting(db_path, "facility_auto_time", "07:00") or "07:00").strip()
                fac_slot = today + " " + hhmm
                if hhmm == fac_time and fac_slot != last_fac_slot:
                    last_fac_slot = fac_slot
                    utils.log_event("info", "facility_auto_trigger", time=hhmm)
                    from . import facility
                    threading.Thread(target=facility.run_auto_scan,
                                     args=(db_path,), daemon=True).start()

            # 3) 알람 이력 자동 정리(보존 기간 초과 삭제, 1일 1회)
            if today != last_purge_day:
                last_purge_day = today
                days = db.get_setting(db_path, "alert_retention_days", "90") or "90"
                n = db.purge_device_events(db_path, days)
                if n:
                    utils.log_event("info", "device_events_purged", count=n, retention_days=days)
        except Exception as e:
            utils.log_event("error", "scheduler_loop_error", error=str(e))
        time.sleep(50)  # 분 단위 슬롯을 놓치지 않도록 1분 미만 주기
