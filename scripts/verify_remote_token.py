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

    print("[2] 토큰을 준 원격 접속")
    r = c.get("/?token=" + TOKEN, environ_overrides=REMOTE)
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

    print("[4] 쿠키 재사용 / 오답 토큰")
    r = c.get("/", environ_overrides=REMOTE)          # 쿠키가 남아 있음
    check("쿠키로 셸 재접속 200", r.status_code == 200, r.status_code)
    c2 = application.test_client()
    r = c2.get("/?token=wrong-token", environ_overrides=REMOTE)
    check("틀린 토큰은 401", r.status_code == 401, r.status_code)

    print("[5] 같은 PC(루프백)에서는 묻지 않고 바로 쓸 수 있어야 한다")
    r = c2.get("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    check("로컬 셸 200(토큰 입력 없음)", r.status_code == 200, r.status_code)
    m2 = re.search(r'window\._API_TOKEN\s*=\s*"([^"]+)"',
                   r.data.decode("utf-8", "replace"))
    check("로컬 셸에도 토큰이 실림", bool(m2) and m2.group(1) == TOKEN)
    r = c2.get("/api/state", headers={"X-API-Token": m2.group(1) if m2 else ""},
               environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
    check("로컬 API 200", r.status_code == 200, r.status_code)

    print()
    if fails:
        print("FAIL %d건: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("ALL PASS — 원격 접속 토큰 경로 정상")
    return 0


if __name__ == "__main__":
    sys.exit(main())
