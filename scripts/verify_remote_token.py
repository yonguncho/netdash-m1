# -*- coding: utf-8 -*-
"""B-26 실동작 검증 — 0.0.0.0 바인드 원격 접속이 실제로 쓸 수 있는가.

토큰 없는 원격 요청은 셸도 API도 막히고, 토큰을 준 원격 요청은 셸을 받고
그 셸에 실린 토큰으로 /api/* 를 호출할 수 있어야 한다.
"""
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

TOKEN = "Abcdefgh1234567890Abcdefgh1234567890"
REMOTE = {"REMOTE_ADDR": "192.168.10.77"}
fails = []


def check(label, cond, detail=""):
    print("  [%s] %s%s" % ("OK" if cond else "FAIL", label,
                           (" — " + str(detail)) if detail else ""))
    if not cond:
        fails.append(label)


def main():
    tmp = tempfile.mkdtemp(prefix="netdash_tok_")
    cfg = os.path.join(tmp, "config.yaml")
    Path(cfg).write_text(
        "app:\n  host: 0.0.0.0\n  port: 8099\n  demo_mode: false\n"
        "  data_dir: %s\napi_token: %s\n" % (tmp.replace("\\", "/"), TOKEN),
        encoding="utf-8")
    os.environ["NETDASH_CONFIG"] = cfg
    os.environ.pop("API_TOKEN", None)

    from config import reset_config
    import app as app_mod
    reset_config()
    application = app_mod.create_app()
    application.config["TESTING"] = True
    c = application.test_client()

    print("[1] 토큰 없는 원격 접속")
    r = c.get("/", environ_overrides=REMOTE)
    check("셸이 401로 막힘", r.status_code == 401, r.status_code)
    r = c.get("/api/state", environ_overrides=REMOTE)
    check("API도 401", r.status_code == 401, r.status_code)

    print("[2] 토큰 제출(POST /session) — 쿼리스트링을 쓰지 않는다")
    r = c.post("/session", data={"token": TOKEN, "next": "/"},
               environ_overrides=REMOTE)
    check("302 리다이렉트", r.status_code == 302, r.status_code)
    check("쿠키 발급", "netdash_token" in r.headers.get("Set-Cookie", ""),
          r.headers.get("Set-Cookie", "")[:40])
    r = c.get("/", environ_overrides=REMOTE)
    check("셸 200", r.status_code == 200, r.status_code)
    html = r.data.decode("utf-8", "replace")
    m = re.search(r'window\._API_TOKEN\s*=\s*"([^"]+)"', html)
    check("셸에 토큰이 실림", bool(m), m.group(1)[:8] + "…" if m else "없음")
    got = m.group(1) if m else ""
    check("실린 토큰이 설정값과 일치", got == TOKEN)

    print("[3] 셸에 실린 토큰으로 API 호출")
    r = c.get("/api/state", headers={"X-API-Token": got}, environ_overrides=REMOTE)
    check("API 200", r.status_code == 200, r.status_code)
    r = c.get("/api/wall", headers={"X-API-Token": got}, environ_overrides=REMOTE)
    check("관제 API 200", r.status_code == 200, r.status_code)

    print("[4] 쿠키 재사용 / 오답 토큰 / 오픈 리다이렉트")
    r = c.get("/", environ_overrides=REMOTE)          # 쿠키가 남아 있음
    check("쿠키로 셸 재접속 200", r.status_code == 200, r.status_code)
    c2 = application.test_client()
    r = c2.post("/session", data={"token": "wrong-token"}, environ_overrides=REMOTE)
    check("틀린 토큰은 401", r.status_code == 401, r.status_code)
    check("틀린 토큰에 쿠키를 주지 않음",
          "netdash_token" not in r.headers.get("Set-Cookie", ""))
    r = c2.post("/session", data={"token": TOKEN, "next": "https://evil.example.com/x"},
                environ_overrides=REMOTE)
    check("외부 URL 리다이렉트 차단",
          r.headers.get("Location", "").endswith("/") and "evil" not in r.headers.get("Location", ""),
          r.headers.get("Location"))

    print("[5-1] 쿼리 토큰(하위호환)은 즉시 쿠키로 옮기고 URL에서 지운다")
    c3 = application.test_client()
    r = c3.get("/?token=" + TOKEN, environ_overrides=REMOTE)
    check("302로 쿼리 제거", r.status_code == 302, r.status_code)
    check("리다이렉트 대상에 토큰 없음", "token" not in r.headers.get("Location", ""),
          r.headers.get("Location"))
    r = c3.get("/", environ_overrides=REMOTE)
    check("이후 쿠키로 접속 200", r.status_code == 200, r.status_code)

    print("[5] 0.0.0.0 바인드에서는 로컬 요청도 토큰이 필요하다(API 게이트와 동일 정책)")
    c4 = application.test_client()          # 쿠키 없는 새 클라이언트
    r = c4.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    check("토큰 없는 로컬 셸은 401", r.status_code == 401, r.status_code)
    check("API도 401(셸과 판정 일치)",
          c4.get("/api/state", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}).status_code == 401)
    r = c4.post("/session", data={"token": TOKEN},
                environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    check("토큰 제출 후 접속 가능", r.status_code == 302, r.status_code)
    r = c4.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    check("로컬 셸 200", r.status_code == 200, r.status_code)
    m2 = re.search(r'window\._API_TOKEN\s*=\s*"([^"]+)"',
                   r.data.decode("utf-8", "replace"))
    check("셸에 토큰이 실림", bool(m2) and m2.group(1) == TOKEN)

    print("[5-2] 루프백 전용 배포(127.0.0.1 바인드)는 종전대로 아무것도 묻지 않는다")
    reset_config()
    cfg2 = tmp + "/config_local.yaml"
    Path(cfg2).write_text(
        "app:\n  host: 127.0.0.1\n  port: 8098\n  demo_mode: false\n"
        "  data_dir: %s\napi_token: %s\n" % (tmp.replace("\\", "/"), TOKEN),
        encoding="utf-8")
    os.environ["NETDASH_CONFIG"] = cfg2
    reset_config()
    local_app = app_mod.create_app()
    local_app.config["TESTING"] = True
    c5 = local_app.test_client()
    r = c5.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    check("로컬 전용 배포 셸 200(입력 없음)", r.status_code == 200, r.status_code)
    check("로컬 전용 배포 API 200",
          c5.get("/api/state", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200)
    os.environ["NETDASH_CONFIG"] = cfg
    reset_config()

    print("[6] 접근 로그에 토큰이 남지 않아야 한다")
    import logging as _lg
    from app import _RedactTokenFilter
    rec = _lg.LogRecord("werkzeug", _lg.INFO, "", 0,
                        '%s - - [x] "%s" %s -',
                        ("192.168.10.77", "GET /?token=" + TOKEN + " HTTP/1.1", "302"), None)
    _RedactTokenFilter().filter(rec)
    line = rec.getMessage()
    check("요청 라인에서 토큰 마스킹", TOKEN not in line and "<redacted>" in line, line[:70])

    print()
    if fails:
        print("FAIL %d건: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("ALL PASS — 원격 접속 토큰 경로 정상")
    return 0


if __name__ == "__main__":
    sys.exit(main())
