# -*- coding: utf-8 -*-
"""웹 SSH 터미널 — 브라우저 xterm.js ⟷ WebSocket ⟷ paramiko invoke_shell ⟷ 장비.

대상: 스위치 · 방화벽 · 서버(kind로 구분). 어느 쪽이든 등록된 장비만 접속한다.

보안:
  - 등록된 장비 IP만 접속(SSRF: 등록 시 RFC1918 검증됨 + 여기서 재확인).
  - 저장된 DPAPI 자격증명 사용(없으면 클라이언트가 전달한 계정, 미제공 시 거부).
  - 세션 open/close를 감사 로그에 기록.
  - 유휴 타임아웃(기본 600초)으로 방치 세션 정리.
"""
import json
import threading
import time

from . import db, credentials, utils, ssh_compat
from .collector import _sanitize_error_msg

_IDLE_TIMEOUT = 600      # 초 — 입력 없이 방치되면 종료
_MAX_SESSION = 3600      # 초 — 세션 절대 상한

KINDS = ("switch", "firewall", "server")


def _server_ssh_port(server):
    """서버의 SSH 포트 — 스캔에서 22가 안 열렸고 2222가 열렸으면 2222."""
    ports = set()
    for tok in str(server.get("open_ports") or "").split(","):
        tok = tok.strip()
        if tok.isdigit():
            ports.add(int(tok))
    if 22 not in ports and 2222 in ports:
        return 2222
    return 22


def resolve_target(db_path, kind, target_id):
    """접속 대상 조회 → {kind, id, label, host, port} 또는 None(미등록).

    방화벽의 `port` 컬럼은 관리/REST 포트(FortiGate 443 등)라 SSH 포트가 아니다.
    터미널은 항상 SSH(22)로 붙는다.
    """
    if kind == "firewall":
        fw = db.get_firewall(db_path, target_id)
        if not fw:
            return None
        return {"kind": kind, "id": target_id, "label": fw.get("name") or fw.get("host"),
                "host": fw.get("host"), "port": 22}
    if kind == "server":
        sv = db.get_server(db_path, target_id)
        if not sv:
            return None
        return {"kind": kind, "id": target_id, "label": sv.get("name") or sv.get("ip"),
                "host": sv.get("ip"), "port": _server_ssh_port(sv)}
    sw = db.get_switch(db_path, target_id)
    if not sw:
        return None
    return {"kind": "switch", "id": target_id, "label": sw.get("name") or sw.get("ip"),
            "host": sw.get("ip"), "port": 22}


def _resolve_credentials(db_path, kind, target_id, username, password):
    """전달된 계정 우선 → (스위치만) 세션 → 영구 DPAPI 순. (user, pass) 또는 (None, None).

    세션 자격증명 저장소는 스위치 id로만 키가 잡혀 있어 방화벽·서버 id와 겹칠 수 있다.
    엉뚱한 장비 계정으로 접속하지 않도록 스위치에서만 세션을 참조한다.
    """
    if username and password:
        return username, password
    if kind == "switch":
        try:
            cred = credentials.load_credential(target_id)
            if cred and cred.get("username") and cred.get("password"):
                return cred["username"], cred["password"]
        except Exception:
            pass
    try:
        if kind == "firewall":
            # 방화벽은 JSON(token/username/password)으로 저장된다. 토큰은 REST 전용이라
            # SSH에는 못 쓰므로 username/password가 있을 때만 접속할 수 있다.
            blob = db.get_firewall_credential(db_path, target_id)
            dec = credentials.decrypt_text(blob) if blob else None
            if dec:
                saved = json.loads(dec)
                u, p = saved.get("username", ""), saved.get("password", "")
                if u and p:
                    return u, p
            return None, None
        blob = (db.get_server_credential(db_path, target_id) if kind == "server"
                else db.get_switch_credential(db_path, target_id))
        if blob:
            dec = credentials.decrypt_credential(blob)
            if dec and "|" in dec:
                u, p = dec.split("|", 1)
                return u, p
    except Exception:
        pass
    return None, None


_KIND_LABEL = {"switch": "스위치", "firewall": "방화벽", "server": "서버"}


def run_shell(ws, db_path, switch_id, username, password, source_ip, validate_ip=None,
              client_ip="unknown", kind="switch"):
    """WebSocket 연결에 대해 대화형 SSH 셸을 중계. 블로킹 호출(WS 핸들러 스레드에서).

    kind: 'switch' | 'firewall' | 'server' — switch_id는 그 종류의 id다.
    validate_ip: (ip)->검증(실패 시 예외) 콜백. app.py의 validate_ipv4를 주입.
    """
    import paramiko

    kind = kind if kind in KINDS else "switch"
    target = resolve_target(db_path, kind, switch_id)
    if not target or not target.get("host"):
        ws.send("\r\n[NetDash] 등록되지 않은 %s입니다.\r\n" % _KIND_LABEL[kind])
        return
    host, port = target["host"], target["port"]
    # SSRF: 등록 IP 재검증(사설 대역만)
    if validate_ip:
        try:
            validate_ip(host)
        except Exception as e:
            ws.send("\r\n[NetDash] 허용되지 않는 IP: %s\r\n" % _sanitize_error_msg(str(e)))
            return
    user, pw = _resolve_credentials(db_path, kind, switch_id, username, password)
    if not (user and pw):
        if kind == "firewall":
            ws.send("\r\n[NetDash] SSH 계정이 없습니다. 방화벽에 API 토큰만 저장돼 있으면"
                    " 터미널에 쓸 수 없습니다 — 수집 팝업에서 계정/비밀번호를 저장하세요.\r\n")
        else:
            ws.send("\r\n[NetDash] 계정 정보가 없습니다. 계정을 입력하거나 저장 후 다시 시도하세요.\r\n")
        return

    ssh_compat.enable_legacy_algorithms()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sock = None
    if source_ip:
        from . import netbind
        try:
            sock = netbind.bind_socket(host, port, source_ip, 15)
        except Exception:
            sock = None
    try:
        ws.send("\r\n[NetDash] %s (%s:%d) 접속 중...\r\n" % (target["label"] or "", host, port))
        client.connect(host, port=port, username=user, password=pw,
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
    utils.log_event("info", "webshell_open", switch_id=switch_id, kind=kind,
                    ip=client_ip, name=target["label"])
    try:
        db.save_audit(db_path, client_ip, "SSH 터미널 접속(%s)" % _KIND_LABEL[kind],
                      target=target["label"] or host, method="WS",
                      path="/ws/shell/%s/%d" % (kind, switch_id))
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
        utils.log_event("info", "webshell_close", switch_id=switch_id, kind=kind,
                        ip=client_ip)
