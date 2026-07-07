# -*- coding: utf-8 -*-
"""웹 SSH 터미널 — 브라우저 xterm.js ⟷ WebSocket ⟷ paramiko invoke_shell ⟷ 장비.

보안:
  - 등록된 스위치 IP만 접속(SSRF: 등록 시 RFC1918 검증됨 + 여기서 재확인).
  - 저장된 DPAPI 자격증명 사용(없으면 클라이언트가 전달한 계정, 미제공 시 거부).
  - 세션 open/close를 감사 로그에 기록.
  - 유휴 타임아웃(기본 600초)으로 방치 세션 정리.
"""
import threading
import time

from . import db, credentials, utils, ssh_compat
from .collector import _sanitize_error_msg

_IDLE_TIMEOUT = 600      # 초 — 입력 없이 방치되면 종료
_MAX_SESSION = 3600      # 초 — 세션 절대 상한


def _resolve_credentials(db_path, switch, username, password):
    """전달된 계정 우선 → 세션(방금 수집) → 영구 DPAPI 자격증명 순. (user, pass) 또는 (None, None)."""
    if username and password:
        return username, password
    # 세션(메모리) 자격증명 — 방금 수집한 경우
    try:
        cred = credentials.load_credential(switch["id"])
        if cred and cred.get("username") and cred.get("password"):
            return cred["username"], cred["password"]
    except Exception:
        pass
    # 영구 저장(DPAPI)
    try:
        blob = db.get_switch_credential(db_path, switch["id"])
        if blob:
            dec = credentials.decrypt_credential(blob)
            if dec and "|" in dec:
                u, p = dec.split("|", 1)
                return u, p
    except Exception:
        pass
    return None, None


def run_shell(ws, db_path, switch_id, username, password, source_ip, validate_ip=None,
              client_ip="unknown"):
    """WebSocket 연결에 대해 대화형 SSH 셸을 중계. 블로킹 호출(WS 핸들러 스레드에서).

    validate_ip: (ip)->검증(실패 시 예외) 콜백. app.py의 validate_ipv4를 주입.
    """
    import paramiko

    switch = db.get_switch(db_path, switch_id)
    if not switch:
        ws.send("\r\n[NetDash] 등록되지 않은 스위치입니다.\r\n")
        return
    # SSRF: 등록 IP 재검증(사설 대역만)
    if validate_ip:
        try:
            validate_ip(switch["ip"])
        except Exception as e:
            ws.send("\r\n[NetDash] 허용되지 않는 IP: %s\r\n" % _sanitize_error_msg(str(e)))
            return
    user, pw = _resolve_credentials(db_path, switch, username, password)
    if not (user and pw):
        ws.send("\r\n[NetDash] 계정 정보가 없습니다. 계정을 입력하거나 저장 후 다시 시도하세요.\r\n")
        return

    ssh_compat.enable_legacy_algorithms()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sock = None
    if source_ip:
        from . import netbind
        try:
            sock = netbind.bind_socket(switch["ip"], 22, source_ip, 15)
        except Exception:
            sock = None
    try:
        ws.send("\r\n[NetDash] %s (%s) 접속 중...\r\n" % (switch.get("name") or "", switch["ip"]))
        client.connect(switch["ip"], port=22, username=user, password=pw,
                       timeout=15, allow_agent=False, look_for_keys=False, sock=sock)
    except Exception as e:
        ws.send("\r\n[NetDash] 접속 실패: %s\r\n" % _sanitize_error_msg(str(e)))
        try:
            client.close()
        except Exception:
            pass
        return

    chan = client.invoke_shell(term="xterm", width=120, height=32)
    chan.settimeout(0.0)
    utils.log_event("info", "webshell_open", switch_id=switch_id, ip=client_ip,
                    name=switch.get("name"))
    try:
        db.save_audit(db_path, client_ip, "SSH 터미널 접속",
                      target=switch.get("name") or switch["ip"], method="WS",
                      path="/ws/shell/%d" % switch_id)
    except Exception:
        pass

    start = time.monotonic()
    last_activity = [time.monotonic()]
    stop = threading.Event()

    def _pump_device_to_ws():
        """장비 출력 → 브라우저."""
        while not stop.is_set():
            try:
                if chan.recv_ready():
                    data = chan.recv(4096)
                    if not data:
                        break
                    ws.send(data.decode("utf-8", errors="replace"))
                else:
                    if chan.closed or chan.exit_status_ready():
                        break
                    time.sleep(0.02)
            except Exception:
                break
        stop.set()

    reader = threading.Thread(target=_pump_device_to_ws, daemon=True)
    reader.start()

    try:
        while not stop.is_set():
            # 유휴/절대 타임아웃
            now = time.monotonic()
            if now - last_activity[0] > _IDLE_TIMEOUT:
                ws.send("\r\n[NetDash] 유휴 시간 초과로 세션을 종료합니다.\r\n")
                break
            if now - start > _MAX_SESSION:
                ws.send("\r\n[NetDash] 세션 최대 시간(1시간)에 도달해 종료합니다.\r\n")
                break
            try:
                msg = ws.receive(timeout=1)
            except Exception:
                break
            if msg is None:
                continue
            last_activity[0] = time.monotonic()
            # 리사이즈 제어 메시지: "\x00resize:cols,rows"
            if isinstance(msg, str) and msg.startswith("\x00resize:"):
                try:
                    cols, rows = msg[len("\x00resize:"):].split(",")
                    chan.resize_pty(width=int(cols), height=int(rows))
                except Exception:
                    pass
                continue
            try:
                chan.send(msg)
            except Exception:
                break
    finally:
        stop.set()
        try:
            chan.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass
        utils.log_event("info", "webshell_close", switch_id=switch_id, ip=client_ip)
