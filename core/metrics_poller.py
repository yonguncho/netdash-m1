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
ERROR_RETENTION_DAYS = 7      # 포트 에러 증가분 — 오래된 것은 이미 조치했거나 무의미

# IF-MIB 64bit 트래픽 카운터(32bit ifIn/OutOctets는 1G에서 34초면 한 바퀴 돈다)
_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

# 포트 에러·폐기 카운터(IF-MIB, 32bit) + CRC(EtherLike-MIB dot3StatsFCSErrors).
# CRC는 IF-MIB에 없어서 따로 읽는다 — 물리 계층(케이블·SFP) 문제의 가장 직접적 신호다.
_IF_IN_DISC = "1.3.6.1.2.1.2.2.1.13"
_IF_IN_ERR = "1.3.6.1.2.1.2.2.1.14"
_IF_OUT_DISC = "1.3.6.1.2.1.2.2.1.19"
_IF_OUT_ERR = "1.3.6.1.2.1.2.2.1.20"
_DOT3_FCS_ERR = "1.3.6.1.2.1.10.7.2.1.3"

_ERR_KO = {"in_err": "수신오류", "out_err": "송신오류",
           "in_disc": "수신폐기", "out_disc": "송신폐기", "crc": "CRC"}

_thread = None
_stop = threading.Event()

# 직전 카운터 샘플 {(switch_id, port): (time.time(), in_octets, out_octets)}.
# 메모리로 충분 — 재시작하면 첫 주기는 기준선만 잡고 다음 주기부터 bps가 나온다.
_prev_traffic = {}

# 포트 에러 직전 샘플 {switch_id: {port: {키: 카운터}}} — 위와 같은 이유로 메모리.
_prev_errors = {}

# 임계값 상태 {(fw_id, metric): 초과 여부} — 같은 초과 상태에서 매 주기 재알람 금지.
# 메모리라 재시작 후 여전히 초과면 한 번 다시 알린다(지속 중인 이상은 알리는 게 맞다).
_over_state = {}


def poll_minutes(db_path):
    """설정된 주기(분). 0 = 끔."""
    try:
        v = int(db.get_setting(db_path, "metrics_poll_minutes", str(DEFAULT_MINUTES)))
        return max(0, min(1440, v))
    except (TypeError, ValueError):
        return DEFAULT_MINUTES


def bg_snmp_enabled(db_path):
    """백그라운드 주기 SNMP 폴링 허용 여부 — 기본 켜짐.

    사용자 확정 정책(2026-08-11): **스위치·방화벽은 주기 SNMP+ping 체크 허용,
    설비는 ping만.** 주기 SNMP의 대상은 원래부터 switches·firewalls 테이블뿐이고
    설비(facility_hosts)에는 SNMP를 보내지 않는다 — 설비는 status_monitor의
    ICMP ping이 전부다. 그래도 부하가 걱정되면 이 설정으로 끌 수 있다.
    """
    try:
        return db.get_setting(db_path, "snmp_bg_poll_enabled", "1") == "1"
    except Exception:
        return False


def _snmp_community(db_path):
    try:
        from . import collector
        return collector._snmp_community_if_enabled(db_path)
    except Exception:
        return None


# ── 트래픽(업링크 bps) ────────────────────────────────────────────

def _walk_traffic(ip, community, budget=8.0):
    """{포트이름: (in_octets, out_octets)} — 물리 포트만. 응답 없으면 예외."""
    from .snmp_collect import _Session
    from .status_monitor import _is_physical
    sess = _Session(ip, community, budget=budget)
    names = {}
    for oid, val in sess.walk(_IF_NAME, max_rows=1024):
        idx = oid.rsplit(".", 1)[1]
        names[idx] = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
    out = {}
    for base, pos in ((_IF_HC_IN, 0), (_IF_HC_OUT, 1)):
        for oid, val in sess.walk(base, max_rows=1024):
            idx = oid.rsplit(".", 1)[1]
            nm = (names.get(idx) or "").strip()
            if not _is_physical(nm):
                continue
            cur = out.setdefault(nm[:80], [None, None])
            try:
                cur[pos] = int(val)
            except (TypeError, ValueError):
                pass
    return {p: (v[0], v[1]) for p, v in out.items()
            if v[0] is not None and v[1] is not None}


def _walk_errors(ip, community, budget=10.0):
    """{포트이름: {in_err, out_err, in_disc, out_disc, crc}} — 물리 포트만.

    IF-MIB의 에러/폐기 카운터 넷 + EtherLike-MIB의 FCS(=CRC) 에러.
    CRC는 IF-MIB에 없어서 dot3StatsFCSErrors를 따로 읽는다. 이 MIB을 지원하지
    않는 장비가 있으므로 실패해도 나머지 넷은 그대로 쓴다.
    """
    from .snmp_collect import _Session
    from .status_monitor import _is_physical
    sess = _Session(ip, community, budget=budget)
    names = {}
    for oid, val in sess.walk(_IF_NAME, max_rows=1024):
        idx = oid.rsplit(".", 1)[1]
        names[idx] = val.decode("utf-8", "replace") if isinstance(val, bytes) else str(val)
    out = {}
    for base, key in ((_IF_IN_ERR, "in_err"), (_IF_OUT_ERR, "out_err"),
                      (_IF_IN_DISC, "in_disc"), (_IF_OUT_DISC, "out_disc")):
        for oid, val in sess.walk(base, max_rows=1024):
            idx = oid.rsplit(".", 1)[1]
            nm = (names.get(idx) or "").strip()
            if not _is_physical(nm):
                continue
            try:
                out.setdefault(nm[:80], {})[key] = int(val)
            except (TypeError, ValueError):
                pass
    try:
        for oid, val in sess.walk(_DOT3_FCS_ERR, max_rows=1024):
            idx = oid.rsplit(".", 1)[1]
            nm = (names.get(idx) or "").strip()
            if not _is_physical(nm) or nm[:80] not in out:
                continue
            try:
                out[nm[:80]]["crc"] = int(val)
            except (TypeError, ValueError):
                pass
    except Exception:
        pass                      # EtherLike-MIB 미지원 — CRC만 빠진다
    return out


def compute_error_delta(prev, cur, port_filter=None):
    """직전 샘플 대비 증가분 → {포트: {키: 증가량}}. prev를 제자리 갱신.

    카운터가 줄면(장비 재부팅·카운터 초기화) 그 항목은 버린다 — 32bit 카운터라
    랩어라운드도 있는데, 그걸 증가로 세면 멀쩡한 포트가 갑자기 40억 에러가 된다.
    첫 관측은 기준선만 잡고 넘어간다(툴을 켠 순간 과거 누적이 증가로 잡히면
    안 된다 — 그게 지금 ports 테이블 누적값이 쓸모없는 이유다).
    """
    KEYS = ("in_err", "out_err", "in_disc", "out_disc", "crc")
    delta = {}
    for port, vals in cur.items():
        if port_filter and port.lower() not in port_filter:
            continue
        old = prev.get(port)
        prev[port] = dict(vals)
        if not old:
            continue                      # 첫 관측 — 기준선만
        d = {}
        for k in KEYS:
            c, o = vals.get(k), old.get(k)
            if c is None or o is None:
                continue
            diff = c - o
            if diff > 0:
                d[k] = diff
        if d:
            delta[port] = d
    return delta


def error_alert_limit(db_path):
    """한 주기에 이만큼 이상 늘면 이벤트를 낸다. 0이면 알람 끔."""
    try:
        return max(0, int(db.get_setting(db_path, "alert_port_errors", "10") or 10))
    except (TypeError, ValueError):
        return 10


def collect_port_errors(db_path, community):
    """전 스위치 포트 에러 증가분 수집·기록. 반환: 기록한 행 수.

    증가한 포트만 저장한다. 임계를 넘으면 이벤트를 남겨 알람 벨·이메일·관제
    티커로 흘러가게 한다(포트 DOWN 이벤트와 같은 경로).
    """
    limit = error_alert_limit(db_path)
    rows = []
    for sw in db.get_switches(db_path):
        ip, sid = sw.get("ip"), sw["id"]
        if not ip:
            continue
        try:
            cur = _walk_errors(ip, community)
        except Exception:
            continue                      # SNMP 미지원/차단 — 조용히 건너뜀
        if not cur:
            continue
        prev = _prev_errors.setdefault(sid, {})
        delta = compute_error_delta(prev, cur)
        name = sw.get("name") or ip
        for port, d in delta.items():
            total = sum(d.values())
            rows.append((sid, port, d.get("in_err", 0), d.get("out_err", 0),
                         d.get("in_disc", 0), d.get("out_disc", 0), d.get("crc", 0)))
            if limit and total >= limit:
                try:
                    parts = ", ".join("%s %d" % (_ERR_KO.get(k, k), v)
                                      for k, v in sorted(d.items()))
                    db.save_device_event(
                        db_path, "port_errors", "warning", switch_id=sid,
                        label=sw.get("name"),
                        message="포트 에러 증가: %s %s (%s)" % (name, port, parts))
                except Exception:
                    pass
    db.save_port_error_points(db_path, rows)
    return len(rows)


def compute_bps(prev, cur, now):
    """직전 샘플과 비교해 {포트: (in_bps, out_bps)}를 계산하고 prev를 갱신한다.

    prev: {포트: (ts, in, out)} — 이 함수가 제자리 갱신.
    카운터가 줄었으면(장비 재부팅·카운터 초기화) 그 포트는 이번 점을 버린다 —
    음수 bps나 64bit 랩 계산으로 만든 거대한 가짜 스파이크보다 점 하나 빠지는 게 낫다.
    """
    bps = {}
    for port, (ci, co) in cur.items():
        old = prev.get(port)
        prev[port] = (now, ci, co)
        if not old:
            continue                      # 첫 관측 — 기준선만
        dt = now - old[0]
        if dt <= 0:
            continue
        di, do = ci - old[1], co - old[2]
        if di < 0 or do < 0:
            continue                      # 재부팅/초기화 — 이번 점 버림
        bps[port] = (int(di * 8 / dt), int(do * 8 / dt))
    return bps


def collect_traffic(db_path, community):
    """전 스위치 업링크 트래픽 한 점씩. 반환: 기록한 점 수.

    저장 대상은 업링크 포트(uplinks_for) — 전 포트를 저장하면 이력이 폭주한다.
    업링크가 하나도 안 잡힌 스위치(단독 구성)는 이번 주기 가장 바쁜 포트 3개를
    대신 저장해 화면이 비지 않게 한다.
    """
    try:
        uplinks = db.uplinks_for(db_path)
    except Exception:
        uplinks = frozenset()
    rows = []
    for sw in db.get_switches(db_path):
        ip, sid = sw.get("ip"), sw["id"]
        if not ip:
            continue
        try:
            cur = _walk_traffic(ip, community)
        except Exception:
            continue                      # SNMP 미지원/차단 — 조용히 건너뜀
        if not cur:
            continue
        prev = _prev_traffic.setdefault(sid, {})
        bps = compute_bps(prev, cur, time.time())
        picked = {p: v for p, v in bps.items() if (sid, p.lower()) in uplinks}
        if not picked and bps:
            top = sorted(bps.items(), key=lambda kv: kv[1][0] + kv[1][1],
                         reverse=True)[:3]
            picked = dict(top)
        for port, (ib, ob) in picked.items():
            rows.append((sid, port, ib, ob))
    db.save_traffic_points(db_path, rows)
    return len(rows)


# ── 임계값 알람 ───────────────────────────────────────────────────

def _alert_limit(db_path, key, default):
    try:
        v = int(db.get_setting(db_path, key, str(default)))
        return max(0, v)                  # 0 = 끔
    except (TypeError, ValueError):
        return default


def check_thresholds(db_path, fw_id, name, cpu, mem, sessions):
    """CPU/MEM/세션이 임계를 넘으면 threshold_over, 내려오면 threshold_clear.

    해제는 임계-5%p(세션은 95%)에서 — 임계 근처에서 오르내리며 알람이
    반복되는 것(플래핑)을 막는 히스테리시스. 반환: 발생 이벤트 수.
    """
    checks = [
        ("cpu", cpu, _alert_limit(db_path, "alert_cpu_pct", 80), "%", 5),
        ("mem", mem, _alert_limit(db_path, "alert_mem_pct", 80), "%", 5),
        ("sessions", sessions, _alert_limit(db_path, "alert_sessions", 0), "", None),
    ]
    label_ko = {"cpu": "CPU", "mem": "메모리", "sessions": "세션"}
    fired = 0
    for metric, val, limit, unit, margin in checks:
        if not limit or val is None:
            continue
        clear_at = limit - margin if margin is not None else int(limit * 0.95)
        key = (fw_id, metric)
        was = _over_state.get(key, False)
        if not was and val > limit:
            _over_state[key] = True
            fired += 1
            db.save_device_event(
                db_path, "threshold_over", "warning", label=name,
                message="%s %s 임계 초과: %s%s (임계 %s%s)"
                        % (name, label_ko[metric], val, unit, limit, unit))
        elif was and val <= clear_at:
            _over_state[key] = False
            fired += 1
            db.save_device_event(
                db_path, "threshold_clear", "info", label=name,
                message="%s %s 정상 복귀: %s%s (임계 %s%s)"
                        % (name, label_ko[metric], val, unit, limit, unit))
    return fired


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

    # 주기 SNMP는 명시적으로 켠 경우에만 — 툴을 켜두는 것만으로 장비에
    # 5분마다 쿼리가 나가면 안 된다(사용자 지시).
    if not bg_snmp_enabled(db_path):
        return points
    community = _snmp_community(db_path)
    if not community:
        return points

    # ② FortiGate — CPU/메모리/세션 + 온도. 주기 폴링이므로 짧은 예산.
    from .collector import temp_thresholds
    _warn_c, _crit_c = temp_thresholds(db_path)
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
                e = snmp_env.collect_env(fw["host"], community, budget=6.0,
                                         warn_c=_warn_c, crit_c=_crit_c)
                temp = e.get("max_temp_c")
            except Exception:
                pass
            if any(v is not None for v in (cpu, mem, sess, temp)):
                db.save_metrics_point(db_path, "firewall", fw["id"],
                                      cpu=cpu, mem=mem, sessions=sess, temp_c=temp)
                points += 1
            try:
                check_thresholds(db_path, fw["id"], fw.get("name") or fw["host"],
                                 cpu, mem, sess)
            except Exception:
                pass
    except Exception as e:
        utils.log_event("warning", "metrics_poll_fw_error", error=str(e)[:120])

    # ③ 스위치 — 온도만(범용으로 얻을 수 있는 것이 그것뿐)
    try:
        from . import snmp_env
        for sw in db.get_switches(db_path):
            if not sw.get("ip"):
                continue
            try:
                e = snmp_env.collect_env(sw["ip"], community, budget=6.0,
                                         warn_c=_warn_c, crit_c=_crit_c)
                if e.get("max_temp_c") is not None:
                    db.save_metrics_point(db_path, "switch", sw["id"],
                                          temp_c=e["max_temp_c"])
                    points += 1
            except Exception:
                continue
    except Exception as e:
        utils.log_event("warning", "metrics_poll_sw_error", error=str(e)[:120])

    # ④ 업링크 트래픽(bps) — 첫 주기는 카운터 기준선만, 다음 주기부터 점이 쌓인다
    try:
        points += collect_traffic(db_path, community)
    except Exception as e:
        utils.log_event("warning", "metrics_poll_traffic_error", error=str(e)[:120])

    # ⑤ 포트 에러 증가분 — 끊어진 뒤가 아니라 나빠지는 중에 알기 위한 것.
    #    ports 테이블의 누적값과 달리 '이번 주기에 늘어난 양'만 남긴다.
    try:
        points += collect_port_errors(db_path, community)
    except Exception as e:
        utils.log_event("warning", "metrics_poll_porterr_error", error=str(e)[:120])

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
                removed += db.prune_traffic_history(db_path, RETENTION_DAYS)
                # 에러 이력은 짧게 — '지금 늘고 있는가'가 관심사다
                removed += db.prune_port_error_history(db_path, ERROR_RETENTION_DAYS)
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
