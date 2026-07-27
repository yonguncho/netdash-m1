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
    """등록 스위치·방화벽을 확인, 전이 시 이벤트.

    HA/이중화 대응: 동일 (IP, 포트)를 공유하는 장비(FW_M/FW_B 등)는 '한 번만' 확인해
    같은 결과를 공유한다. 활성 장비가 응답하면 같은 IP의 대기 장비도 '도달'로 간주 →
    대기측이 도달 불가로 오탐되지 않는다. 확인 횟수도 줄어 부하가 낮아진다.
    """
    switches = db.get_switches(db_path) or []
    try:
        firewalls = db.list_firewalls(db_path)
    except Exception:
        firewalls = []

    # 1) 확인 대상 (IP, 포트) 유니크 집합 — 동일 키는 1회만 확인
    targets = {}   # (ip, port) -> None
    for sw in switches:
        ip = (sw.get("ip") or "").strip()
        if ip:
            targets.setdefault((ip, 22), None)
    for fw in firewalls:
        host = (fw.get("host") or "").strip()
        if host:
            targets.setdefault((host, int(fw.get("port") or 443)), None)

    # 2) 유니크 키를 동시 _CONCURRENCY개 제한으로 확인
    results = {}   # (ip, port) -> bool
    sem = threading.Semaphore(_CONCURRENCY)
    threads = []

    def _probe(key):
        ip, port = key
        with sem:
            results[key] = _check_tcp(ip, port)

    for key in targets:
        t = threading.Thread(target=_probe, args=(key,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.05)                 # 시작 시점 분산(버스트 방지)
    for t in threads:
        t.join(timeout=_TCP_TIMEOUT + 5)

    # 3) 스위치 상태 반영(전이 시 이벤트) — 결과는 IP 공유 그룹이 동일
    for sw in switches:
        ip = (sw.get("ip") or "").strip()
        ok = results.get((ip, 22))
        if ok is None:
            continue
        sid = sw["id"]
        with _lock:
            prev = _state.get(sid)
            _state[sid] = ok
        if prev is None:
            continue                     # 첫 관측은 이벤트 없이 기준만 설정
        sw_disp = "%s (%s)" % (sw.get("name") or sid, ip or "-")
        if prev and not ok:
            db.save_device_event(db_path, "switch_unreachable", "warning",
                                 switch_id=sid, label=sw.get("name"),
                                 message="스위치 도달 불가(TCP-22): %s" % sw_disp)
        elif ok and not prev:
            db.save_device_event(db_path, "switch_recovered", "info",
                                 switch_id=sid, label=sw.get("name"),
                                 message="스위치 도달 복구: %s" % sw_disp)

    # 4) 방화벽 상태 반영 — 동일 IP 공유(FW_M/FW_B)는 같은 결과를 따른다
    for fw in firewalls:
        host = (fw.get("host") or "").strip()
        port = int(fw.get("port") or 443)
        ok = results.get((host, port))
        if ok is None:
            continue
        fid = fw["id"]
        with _lock:
            prev = _fw_state.get(fid)
            _fw_state[fid] = ok
        if prev is None:
            continue
        fw_disp = "%s (%s)" % (fw.get("name") or fid, host or "-")
        if prev and not ok:
            db.save_device_event(db_path, "firewall_unreachable", "warning",
                                 label=fw.get("name"),
                                 message="방화벽 도달 불가(TCP-%s): %s" % (port, fw_disp))
        elif ok and not prev:
            db.save_device_event(db_path, "firewall_recovered", "info",
                                 label=fw.get("name"),
                                 message="방화벽 도달 복구: %s" % fw_disp)


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
                # 이미 수집된 설비를 자주(이 60초 주기) 재판정: 대역 재스캔 없이
                # 스위치 MAC 테이블만으로 online↔offline 양방향 갱신(끊김/복구 즉시 감지).
                try:
                    from . import facility
                    facility.monitor_known_hosts(db_path)
                except Exception:
                    pass
        except Exception as e:
            from .collector import _sanitize_error_msg
            utils.log_event("error", "reachability_loop_error",
                            error=_sanitize_error_msg(str(e)))
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
