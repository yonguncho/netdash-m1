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
from email.mime.text import MIMEText
from email.header import Header

from . import db, utils

logger = logging.getLogger(__name__)

_queue = queue.Queue(maxsize=1000)
_thread = None
_stop = False

_KIND_KO = {
    "new_device": "새 설비", "device_offline": "설비 연결 끊김", "device_online": "설비 복구",
    "device_moved": "설비 이동", "config_changed": "설정 변경",
    "switch_unreachable": "스위치 연결 실패", "switch_recovered": "스위치 복구",
    "flapping": "포트 flapping", "looping": "포트 looping",
}


def notify(event):
    """이벤트를 발송 큐에 추가(논블로킹, 가득 차면 버림)."""
    try:
        _queue.put_nowait(dict(event))
    except queue.Full:
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


def send_email(db_path, subject, body):
    """설정된 SMTP로 즉시 1통 발송. 성공 True/실패 False."""
    cfg = _settings(db_path)
    if not (cfg["host"] and cfg["to"]):
        return False
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            auth = _auth(db_path)
            if auth:
                try:
                    s.starttls()
                except Exception:
                    pass  # 내부 릴레이는 TLS 미지원 가능
                s.login(auth[0], auth[1])
            s.sendmail(cfg["from"], cfg["to"], msg.as_string())
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
    while not _stop:
        # 60초 동안 이벤트 모으기
        try:
            ev = _queue.get(timeout=60)
            pending.append(ev)
            # 큐에 더 쌓인 것 즉시 흡수
            while True:
                try:
                    pending.append(_queue.get_nowait())
                except queue.Empty:
                    break
            continue  # 다음 60초 창에서 더 모아질 수 있음 → 아래 타임아웃 발송 경로로
        except queue.Empty:
            pass
        if not pending:
            continue
        try:
            cfg = _settings(db_path)
            if cfg["enabled"]:
                send_list = [e for e in pending if _severity_ok(e, cfg["min_sev"])]
                if send_list:
                    crit = sum(1 for e in send_list if e.get("severity") == "critical")
                    subject = "[NetDash] 알람 %d건%s" % (
                        len(send_list), (" (긴급 %d)" % crit) if crit else "")
                    if send_email(db_path, subject, _format_digest(send_list)):
                        utils.log_event("info", "email_alert_sent", count=len(send_list))
        except Exception as e:
            utils.log_event("warning", "notifier_loop_error", error=str(e)[:200])
        pending = []


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
