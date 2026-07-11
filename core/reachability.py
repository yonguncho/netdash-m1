# -*- coding: utf-8 -*-
"""스위치 도달성 감시 — 수집과 무관하게 끊김을 1분 내 감지.

방식: PC에서 등록 스위치의 TCP-22 포트에 연결 시도(SYN 1개 수준, SSH 로그인 없음).
  - 장비 부하: 사실상 0 (커널이 SYN-ACK 응답, CPU 미사용)
  - PC 부하: 소켓 1개/수 ms. 100대 이상도 동시 10개 제한 + 순차 분산으로 안전.
전이 시에만 이벤트: 도달→불가 = switch_unreachable, 불가→도달 = switch_recovered.

설정(app_settings):
  reach_check_enabled   "1"/"0" (기본 1)
  reach_check_interval  초 (기본 60, 최소 30)
"""
import socket
import threading
import time

from . import db, utils

_thread = None
_stop = False
_lock = threading.Lock()
_state = {}          # {switch_id: True(도달)/False(불가)} — 미확인은 키 없음
_fw_state = {}       # {firewall_id: bool} — 방화벽은 관리 포트(443 등)로 확인

_CONCURRENCY = 10    # 동시 확인 상한(부하 분산)
_TCP_TIMEOUT = 3


def get_state():
    """{switch_id: bool} 스냅샷(미확인 스위치는 미포함)."""
    with _lock:
        return dict(_state)


def get_fw_state():
    """{firewall_id: bool} 스냅샷(미확인 방화벽은 미포함)."""
    with _lock:
        return dict(_fw_state)


def _check_tcp(ip, port=22, timeout=_TCP_TIMEOUT):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _sweep(db_path):
    """등록 스위치 전체를 동시 _CONCURRENCY개 제한으로 확인, 전이 시 이벤트."""
    switches = db.get_switches(db_path) or []
    sem = threading.Semaphore(_CONCURRENCY)
    threads = []

    def _one(sw):
        with sem:
            ok = _check_tcp(sw.get("ip"))
        sid = sw["id"]
        with _lock:
            prev = _state.get(sid)
            _state[sid] = ok
        if prev is None:
            return                       # 첫 관측은 이벤트 없이 기준만 설정
        # 알람에 이름+IP 함께 표기(어느 장비인지 즉시 특정)
        sw_disp = "%s (%s)" % (sw.get("name") or sid, sw.get("ip") or "-")
        if prev and not ok:
            db.save_device_event(db_path, "switch_unreachable", "warning",
                                 switch_id=sid, label=sw.get("name"),
                                 message="스위치 도달 불가(TCP-22): %s" % sw_disp)
        elif ok and not prev:
            db.save_device_event(db_path, "switch_recovered", "info",
                                 switch_id=sid, label=sw.get("name"),
                                 message="스위치 도달 복구: %s" % sw_disp)

    # 방화벽도 함께 감시 — 관리 포트(등록 포트, 기본 443)로 TCP 핸드셰이크만
    try:
        firewalls = db.list_firewalls(db_path)
    except Exception:
        firewalls = []

    def _one_fw(fw):
        with sem:
            ok = _check_tcp(fw.get("host"), fw.get("port") or 443)
        fid = fw["id"]
        with _lock:
            prev = _fw_state.get(fid)
            _fw_state[fid] = ok
        if prev is None:
            return
        fw_disp = "%s (%s)" % (fw.get("name") or fid, fw.get("host") or "-")
        if prev and not ok:
            db.save_device_event(db_path, "firewall_unreachable", "warning",
                                 label=fw.get("name"),
                                 message="방화벽 도달 불가(TCP-%s): %s" % (
                                     fw.get("port") or 443, fw_disp))
        elif ok and not prev:
            db.save_device_event(db_path, "firewall_recovered", "info",
                                 label=fw.get("name"),
                                 message="방화벽 도달 복구: %s" % fw_disp)

    for sw in switches:
        t = threading.Thread(target=_one, args=(sw,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.05)                 # 시작 시점 분산(버스트 방지)
    for fw in firewalls:
        t = threading.Thread(target=_one_fw, args=(fw,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.05)
    for t in threads:
        t.join(timeout=_TCP_TIMEOUT + 5)


def _loop(db_path):
    while not _stop:
        # BUGFIX: interval을 try 밖에서 먼저 바인딩. 이전엔 try 안에서 초기화해
        # 첫 get_setting 예외(기동 직후 DB lock 등) 시 interval 미정의 → 아래
        # range(interval)에서 NameError로 감시 스레드가 침묵 사망했다.
        interval = 60
        try:
            enabled = db.get_setting(db_path, "reach_check_enabled", "1") != "0"
            try:
                interval = max(30, int(db.get_setting(db_path, "reach_check_interval", "60") or 60))
            except (TypeError, ValueError):
                pass
            if enabled:
                _sweep(db_path)
        except Exception as e:
            utils.log_event("error", "reachability_loop_error", error=str(e))
        for _ in range(interval):
            if _stop:
                return
            time.sleep(1)


def start_monitor(db_path):
    """백그라운드 도달성 감시 시작(이미 실행 중이면 무시)."""
    global _thread, _stop
    if _thread is not None and _thread.is_alive():
        return
    _stop = False
    _thread = threading.Thread(target=_loop, args=(db_path,), daemon=True)
    _thread.start()
    utils.log_event("info", "reachability_monitor_started")


def stop_monitor():
    global _stop
    _stop = True
