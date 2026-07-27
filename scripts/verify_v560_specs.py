# -*- coding: utf-8 -*-
"""v5.6.0 서버 사양 수집 — 프로덕션 모드 런타임 검증(포트 바인딩 없이 test client).

레포 루트의 netdash.db/config.yaml을 건드리지 않도록 임시 작업 디렉터리에서 돈다.
실행: python scripts/verify_v560_specs.py   → 전부 통과 시 exit 0
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TOKEN = "verify_token_32_chars_long_secure_value_1"
FAILS = []


def check(name, cond, detail=""):
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (" — " + str(detail) if detail else ""))
    if not cond:
        FAILS.append(name)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="netdash_verify_"))
    shutil.copy(ROOT / "config.yaml", tmp / "config.yaml")
    os.chdir(tmp)
    os.environ["API_TOKEN"] = TOKEN
    os.environ.pop("DEMO_MODE", None)

    from config import reset_config
    reset_config()
    from app import create_app
    from core import db

    print("\n[1] 프로덕션 기동(배포 config.yaml 그대로)")
    app = create_app(demo_mode=False)
    app.config["TESTING"] = True
    c = app.test_client()
    hdr = {"X-API-Token": TOKEN}

    r = c.get("/")
    check("GET / → 200", r.status_code == 200, r.status_code)
    html = r.get_data(as_text=True)
    for th in (">CPU</th>", ">메모리</th>", ">디스크</th>"):
        check("서버 표 헤더 %s 렌더" % th, th in html)
    check("빈 목록 colspan=17", 'colspan="17"' in html)

    print("\n[2] 인증 (정책: 루프백 바인딩+루프백 출처는 면제, 외부 바인딩은 토큰 필수)")
    check("루프백 바인딩 → 토큰 없이 200(면제 정책)",
          c.get("/api/servers").status_code == 200, c.get("/api/servers").status_code)
    r = c.get("/api/servers", headers=hdr)
    check("토큰과 함께 /api/servers → 200", r.status_code == 200, r.status_code)

    print("\n[3] 서버 등록 → 사양 저장 → 조회")
    r = c.post("/api/servers", headers=hdr,
               json={"name": "VERIFY-SRV", "ip": "10.77.0.9", "os_type": "linux",
                     "location": "A09U27"})
    check("POST /api/servers → 2xx", 200 <= r.status_code < 300, (r.status_code, r.get_data(as_text=True)[:200]))

    db_path = Path(tmp) / "netdash.db"
    if not db_path.exists():
        db_path = Path(app.config.get("DB_PATH", db_path))
    servers = db.list_servers(db_path)
    check("DB에 서버 1건", len(servers) == 1, len(servers))
    sid = servers[0]["id"]

    # 수집 결과를 실제 수집기 파서로 만들어 저장(수집기→DB 경로 검증)
    from core import server_collector as sc
    spec = sc._specs_from_unix({
        "lscpu": "CPU(s):              8\nModel name:          Intel Xeon Silver 4210\n",
        "cat /proc/meminfo": "MemTotal:       32946200 kB\n",
        "df -Pk": ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                   "/dev/sda2 209715200 104857600 104857600 50% /\n"
                   "tmpfs 8151728 0 8151728 0% /dev/shm\n"),
    })
    db.update_server(db_path, sid, collected=True, status="done", **spec)

    r = c.get("/api/servers", headers=hdr)
    s = r.get_json()["servers"][0]
    check("cpu_model 노출", s.get("cpu_model") == "Intel Xeon Silver 4210", s.get("cpu_model"))
    check("cpu_cores 노출", s.get("cpu_cores") == 8, s.get("cpu_cores"))
    check("mem_total_mb 노출", s.get("mem_total_mb") == 32174, s.get("mem_total_mb"))
    check("disk_total_gb 노출", s.get("disk_total_gb") == 200.0, s.get("disk_total_gb"))
    check("disk_used_gb 노출", s.get("disk_used_gb") == 100.0, s.get("disk_used_gb"))
    check("cred_blob 미노출(자격증명 유출 없음)", "cred_blob" not in s, list(s.keys()))

    print("\n[4] 재수집 실패해도 사양 보존")
    db.update_server(db_path, sid, status="failed", last_error="도달 불가")
    s2 = db.get_server(db_path, sid)
    check("실패 갱신 후에도 cpu_cores 유지", s2["cpu_cores"] == 8, s2["cpu_cores"])
    check("실패 갱신 후에도 disk_total_gb 유지", s2["disk_total_gb"] == 200.0, s2["disk_total_gb"])

    print("\n[5] 다운로드(CSV/TXT)")
    for fmt in ("csv", "txt"):
        r = c.get("/api/export/servers?fmt=%s" % fmt, headers=hdr)
        check("GET /api/export/servers?fmt=%s → 200" % fmt, r.status_code == 200, r.status_code)
        body = r.get_data().decode("utf-8-sig", "replace")
        check("%s에 CPU 값 포함" % fmt, "Intel Xeon Silver 4210" in body)
        check("%s에 사양 컬럼 헤더 포함" % fmt, "메모리(GB)" in body and "디스크 전체(GB)" in body)

    print("\n[6] 수집 API 무결성(계정 없이 호출 — 크래시 없이 수락/거절)")
    r = c.post("/api/servers/%d/collect" % sid, headers=hdr, json={})
    check("POST /collect → 500 아님", r.status_code != 500, r.status_code)
    r = c.post("/api/servers/999999/collect", headers=hdr, json={})
    check("없는 id collect → 500 아님", r.status_code != 500, r.status_code)
    r = c.post("/api/servers", headers=hdr, data="{bad json", content_type="application/json")
    check("깨진 JSON 등록 → 400대", 400 <= r.status_code < 500, r.status_code)

    print("\n[7] 외부 바인딩(0.0.0.0)에서는 토큰 필수 — 사양 컬럼 추가가 인증을 우회하지 않음")
    ext = tempfile.mkdtemp(prefix="netdash_verify_ext_")
    ext_cfg = Path(ext) / "config.yaml"
    ext_cfg.write_text(
        "api_token: %s\napp:\n  debug: false\n  host: 0.0.0.0\n  port: 8083\n"
        "  demo_mode: false\ndatabase:\n  path: netdash.db\n" % TOKEN, encoding="utf-8")
    os.chdir(ext)
    os.environ["NETDASH_CONFIG"] = str(ext_cfg)   # 이걸 안 주면 레포 루트 config를 읽는다
    reset_config()
    import importlib
    import app as app_mod
    importlib.reload(app_mod)
    app2 = app_mod.create_app(demo_mode=False)
    app2.config["TESTING"] = True
    c2 = app2.test_client()
    check("외부 바인딩 + 토큰 없음 → 401",
          c2.get("/api/servers").status_code == 401, c2.get("/api/servers").status_code)
    check("외부 바인딩 + 유효 토큰 → 200",
          c2.get("/api/servers", headers=hdr).status_code == 200,
          c2.get("/api/servers", headers=hdr).status_code)
    check("외부 바인딩 + 틀린 토큰 → 401",
          c2.get("/api/servers", headers={"X-API-Token": "wrong"}).status_code == 401,
          c2.get("/api/servers", headers={"X-API-Token": "wrong"}).status_code)

    print("\n" + ("=" * 60))
    if FAILS:
        print("FAILED %d건: %s" % (len(FAILS), ", ".join(FAILS)))
        return 1
    print("ALL PASS — v5.6.0 서버 사양 수집 런타임 검증 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
