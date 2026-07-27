# -*- coding: utf-8 -*-
"""알람 이메일 알림 — 폐쇄망 내부 SMTP 릴레이로 발송.

설정(app_settings):
  email_enabled   "1"/"0"
  smtp_host       내부 SMTP 서버 IP/호스트
  smtp_port       기본 25
  smtp_from       발신 주소
  email_to        수신 주소(쉼표 구분)
  smtp_auth_blob  (선택) DPAPI 암호화된 "user|pass" — 인증 필요한 릴레이용
  email_min_sev   "warning"(기본: warning+critical만) | "info"(전부)

동작: save_device_event가 notify()로 이벤트를 큐에 넣고, 백그라운드 스레드가
60초마다 모아 1통으로 발송(수집/스캔 중 수십 건 스팸 방지). 발송 실패는
로그만 남기고 수집·알람 저장에는 영향 없음.
"""
import logging
import queue
import smtplib
import threading
import time as _time
from email.mime.text import MIMEText
from email.header import Header

from . import db, utils

logger = logging.getLogger(__name__)

_queue = queue.Queue(maxsize=1000)
# 발송 실패 시 다음 주기에 재시도하려고 들고 있는 알람의 상한
# (메일 서버가 오래 죽어 있어도 메모리가 무한히 늘지 않게)
_PENDING_MAX = 500
_thread = None
_stop = False

_KIND_KO = {
    "new_device": "새 설비", "device_offline": "설비 연결 끊김", "device_online": "설비 복구",
    "device_moved": "설비 이동", "config_changed": "설정 변경",
    "switch_unreachable": "스위치 연결 실패", "switch_recovered": "스위치 복구",
    "firewall_unreachable": "방화벽 연결 실패", "firewall_recovered": "방화벽 복구",
    "flapping": "포트 flapping", "looping": "포트 looping",
}


_dropped = 0            # 큐 포화로 버린 알람 수(무증상 유실 방지용 집계)


def dropped_count():
    """큐 포화로 버려진 알람 누적 수 — 진단용."""
    return _dropped


def notify(event):
    """이벤트를 발송 큐에 추가(논블로킹, 가득 차면 버림).

    버릴 때는 반드시 흔적을 남긴다. 이전엔 조용히 pass해서 대량 장애 시
    알람이 사라져도 아무 로그가 없었다. 로그 자체가 폭주하지 않도록
    100건마다 1회만 기록한다.
    """
    global _dropped
    try:
        _queue.put_nowait(dict(event))
    except queue.Full:
        _dropped += 1
        if _dropped == 1 or _dropped % 100 == 0:
            try:
                utils.log_event("warning", "notifier_queue_full",
                                dropped=_dropped, kind=str(event.get("kind")))
            except Exception:
                pass


def _settings(db_path):
    return {
        "enabled": db.get_setting(db_path, "email_enabled", "0") == "1",
        "host": (db.get_setting(db_path, "smtp_host", "") or "").strip(),
        "port": int(db.get_setting(db_path, "smtp_port", "25") or 25),
        "from": (db.get_setting(db_path, "smtp_from", "netdash@localhost") or "").strip(),
        "to": [a.strip() for a in (db.get_setting(db_path, "email_to", "") or "").split(",") if a.strip()],
        "min_sev": db.get_setting(db_path, "email_min_sev", "warning") or "warning",
    }


def _auth(db_path):
    """(user, pass) 또는 None — DPAPI blob에서 복호화."""
    blob = db.get_setting(db_path, "smtp_auth_blob", "") or ""
    if not blob:
        return None
    try:
        from . import credentials
        dec = credentials.decrypt_credential(blob)
        if dec and "|" in dec:
            u, p = dec.split("|", 1)
            return (u, p)
    except Exception:
        pass
    return None


def _severity_ok(ev, min_sev):
    if min_sev == "info":
        return True
    return (ev.get("severity") or "info") in ("warning", "critical")


def _mx_hosts(domain):
    """수신 도메인의 메일 서버 후보. dnspython 있으면 MX 우선, 없으면 관례적 이름 추정.

    폐쇄망 내부 메일(예: user@company.local)은 대개 회사 메일 서버가
    company.local / mail.company.local 로 잡힌다. 우선순위대로 반환.
    """
    hosts = []
    try:                                  # MX 레코드(있으면 가장 정확)
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "MX")
        for r in sorted(answers, key=lambda x: x.preference):
            hosts.append(str(r.exchange).rstrip("."))
    except Exception:
        pass
    for cand in (domain, "mail." + domain, "smtp." + domain, "mx." + domain):
        if cand not in hosts:
            hosts.append(cand)
    return hosts


_DIRECT_CONNECT_TIMEOUT = 5     # 후보 1개당 접속 대기(초)
_DIRECT_DOMAIN_BUDGET = 20      # 도메인 하나에 쓸 총 시간 상한(초)


def _direct_send(from_addr, recipients, msg_str, port):
    """SMTP 릴레이 없이 수신자 도메인의 메일 서버로 직접 전달(무인증).

    도메인별로 후보 메일 서버에 순서대로 접속을 시도해 첫 성공 시 그 도메인 완료.
    반환: (성공한 수신자 수, 마지막 오류 메시지).

    후보가 4개(domain·mail.·smtp.·mx.)라 타임아웃이 15초면 도메인당 최대 60초,
    수신 도메인이 여럿이면 그 배수만큼 블로킹됐다(설정창의 '테스트 발송'이 그동안
    멈추고, 알림 루프도 그만큼 잡혀 큐가 찼다). 후보당 5초 + 도메인당 20초로 묶는다.
    """
    by_domain = {}
    for addr in recipients:
        if "@" in addr:
            by_domain.setdefault(addr.rsplit("@", 1)[1].lower(), []).append(addr)
    ok_count = 0
    last_err = ""
    for domain, addrs in by_domain.items():
        delivered = False
        _deadline = _time.monotonic() + _DIRECT_DOMAIN_BUDGET
        for host in _mx_hosts(domain):
            if _time.monotonic() >= _deadline:
                last_err = "%s: 시간 초과(%d초) — 남은 후보 건너뜀" % (domain, _DIRECT_DOMAIN_BUDGET)
                utils.log_event("warning", "email_direct_timeout", domain=domain)
                break
            try:
                with smtplib.SMTP(host, port, timeout=_DIRECT_CONNECT_TIMEOUT) as s:
                    try:
                        s.ehlo()
                        if s.has_extn("starttls"):
                            s.starttls()
                            s.ehlo()
                    except Exception:
                        pass              # TLS 미지원 서버는 평문으로 계속
                    s.sendmail(from_addr, addrs, msg_str)
                delivered = True
                ok_count += len(addrs)
                utils.log_event("info", "email_direct_delivered", domain=domain,
                                host=host, count=len(addrs))
                break
            except Exception as e:
                last_err = "%s: %s" % (host, str(e)[:120])
                continue
        if not delivered:
            utils.log_event("warning", "email_direct_failed", domain=domain, error=last_err)
    return ok_count, last_err


def send_email(db_path, subject, body):
    """이메일 1통 발송. 성공 True/실패 False.

    smtp_host가 있으면 그 릴레이로, 없으면 수신 도메인 메일 서버로 '직접 전달'.
    """
    cfg = _settings(db_path)
    if not cfg["to"]:
        return False
    from_addr = cfg["from"] or "netdash@localhost"
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = from_addr
    msg["To"] = ", ".join(cfg["to"])
    msg_str = msg.as_string()

    # 릴레이 미지정 → 수신 도메인으로 직접 전달(SMTP 서버 없이)
    if not cfg["host"]:
        ok_count, last_err = _direct_send(from_addr, cfg["to"], msg_str, cfg["port"] or 25)
        if ok_count:
            return True
        utils.log_event("warning", "email_send_failed",
                        error="direct delivery failed: " + (last_err or "no route"))
        return False

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            auth = _auth(db_path)
            if auth:
                try:
                    s.starttls()
                except Exception:
                    pass  # 내부 릴레이는 TLS 미지원 가능
                s.login(auth[0], auth[1])
            s.sendmail(from_addr, cfg["to"], msg_str)
        return True
    except Exception as e:
        utils.log_event("warning", "email_send_failed", error=str(e)[:200])
        return False


def _format_digest(events):
    lines = ["NetDash 알람 %d건" % len(events), ""]
    for ev in events[:50]:
        kind = _KIND_KO.get(ev.get("kind"), ev.get("kind") or "-")
        where = " ".join(x for x in (ev.get("label"), ev.get("ip"), ev.get("subnet")) if x)
        lines.append("[%s] %s — %s" % (ev.get("severity", "info"), kind, where))
        if ev.get("message"):
            lines.append("    " + ev["message"])
    if len(events) > 50:
        lines.append("... 외 %d건 (NetDash 알람 화면에서 확인)" % (len(events) - 50))
    return "\n".join(lines)


def _loop(db_path):
    pending = []
    last_flush = _time.monotonic()
    while not _stop:
        # BUGFIX: 이전 구현은 '60초 무이벤트 시 발송'(debounce)이라 이벤트가
        # 60초 미만 간격으로 계속 오면(설비 대역 스캔·flap 폭주) 이메일이 무기한
        # 지연됐다. 이제 마지막 발송 후 60초 경과 시 강제 flush(짧게 폴링).
        try:
            pending.append(_queue.get(timeout=5))
            while True:
                try:
                    pending.append(_queue.get_nowait())
                except queue.Empty:
                    break
        except queue.Empty:
            pass
        if pending and (_time.monotonic() - last_flush) >= 60:
            sent = False
            try:
                cfg = _settings(db_path)
                if not cfg["enabled"]:
                    sent = True                  # 발송 안 하기로 설정 → 쌓아둘 이유 없음
                else:
                    send_list = [e for e in pending if _severity_ok(e, cfg["min_sev"])]
                    if not send_list:
                        sent = True              # 보낼 만한 등급이 없음
                    else:
                        crit = sum(1 for e in send_list if e.get("severity") == "critical")
                        subject = "[NetDash] 알람 %d건%s" % (
                            len(send_list), (" (긴급 %d)" % crit) if crit else "")
                        if send_email(db_path, subject, _format_digest(send_list)):
                            utils.log_event("info", "email_alert_sent", count=len(send_list))
                            sent = True
            except Exception as e:
                utils.log_event("warning", "notifier_loop_error", error=str(e)[:200])
            if sent:
                pending = []
            else:
                # 릴레이가 잠깐 죽었다고 그 60초 묶음을 버리면 알람이 영영 안 간다.
                # 다음 주기에 다시 시도한다(무한 증식은 막게 최근 것 위주로 상한).
                if len(pending) > _PENDING_MAX:
                    dropped = len(pending) - _PENDING_MAX
                    pending = pending[-_PENDING_MAX:]
                    utils.log_event("warning", "email_pending_trimmed", dropped=dropped)
                utils.log_event("warning", "email_retry_pending", count=len(pending))
            last_flush = _time.monotonic()


def start_notifier(db_path):
    global _thread, _stop
    if _thread is not None and _thread.is_alive():
        return
    _stop = False
    _thread = threading.Thread(target=_loop, args=(db_path,), daemon=True)
    _thread.start()
    utils.log_event("info", "notifier_started")


def stop_notifier():
    global _stop
    _stop = True
