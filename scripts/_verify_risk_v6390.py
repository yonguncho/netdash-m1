# -*- coding: utf-8 -*-
"""v6.39.0 관제 위험도·이상치·SNMP 무응답 카드 + 스위치 SNMP 진단 — 실화면 검증."""
import os
import subprocess
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8")  # cp949 콘솔 크래시 방지
except Exception:
    pass
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "build", "risk_verify")
DBP = os.path.join(ROOT, "netdash.db")
URL = "http://127.0.0.1:8082"
HOT_IP = "192.0.2.231"      # TEST-NET-1
HOT = "ZZ-HOT-SW"
COLD_IP = "192.0.2.232"
COLD = "ZZ-NOSNMP-SW"


ANOM_FW = None


def cleanup():
    from core import db
    with db.get_db(DBP) as conn:
        try:
            conn.execute("DELETE FROM metrics_history WHERE sessions IN (1000, 3000)")
        except Exception:
            pass
        for ip, nm in ((HOT_IP, HOT), (COLD_IP, COLD)):
            r = conn.execute("SELECT id FROM switches WHERE ip=?", (ip,)).fetchone()
            if r:
                conn.execute("DELETE FROM device_env WHERE kind='switch' AND device_id=?",
                             (r["id"],))
            conn.execute("DELETE FROM switches WHERE ip=? OR name=?", (ip, nm))
        conn.commit()


def seed():
    from core import db
    db.init_db(DBP)
    cleanup()
    db.set_setting(DBP, "temp_warn_c", "55")
    db.set_setting(DBP, "temp_crit_c", "70")
    db.save_switch(DBP, HOT, HOT_IP, "cisco_ios")
    hot = [s for s in db.get_switches(DBP) if s["ip"] == HOT_IP][0]
    # 임계(70) 대비 97% — 위험도 순위 최상단에 와야 한다
    db.save_device_env(DBP, "switch", hot["id"], {
        "max_temp_c": 68.0, "level": "warning", "temp_count": 1, "fan_count": 0,
        "sensors": [{"name": "inlet", "type": "celsius", "value": 68.0,
                     "status": "ok", "level": "warning"}]})
    db.save_switch(DBP, COLD, COLD_IP, "cisco_ios")   # 환경정보 없음 = SNMP 무응답

    # 이상치용 세션 이력 — 지난 7일은 낮게, 최근 24시간은 3배로.
    # (이상치가 없으면 그 카드는 slimEmptyCards가 숨긴다 — v6.35.0 의도된 동작)
    fws = db.list_firewalls(DBP)
    global ANOM_FW
    ANOM_FW = None
    if fws:
        f = fws[0]
        ANOM_FW = f.get("name") or f.get("host")
        with db.get_db(DBP) as conn:
            conn.execute("DELETE FROM metrics_history WHERE kind='firewall' AND device_id=?",
                         (f["id"],))
            for h in range(30, 24, -1):          # 평소(7일 구간)
                conn.execute(
                    "INSERT INTO metrics_history (kind, device_id, ts, sessions) "
                    "VALUES ('firewall', ?, datetime('now','localtime', ?), 1000)",
                    (f["id"], "-%d hours" % h))
            for h in range(20, 0, -2):           # 최근 24시간 — 3배
                conn.execute(
                    "INSERT INTO metrics_history (kind, device_id, ts, sessions) "
                    "VALUES ('firewall', ?, datetime('now','localtime', ?), 3000)",
                    (f["id"], "-%d hours" % h))
            conn.commit()
    print("seeded: %s(68C) / %s(무응답) / 이상치=%s" % (HOT, COLD, ANOM_FW))


def main():
    os.makedirs(OUT, exist_ok=True)
    seed()
    proc = subprocess.Popen([sys.executable, "app.py"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            time.sleep(1)
            try:
                urllib.request.urlopen(URL + "/api/state", timeout=2).read()
                break
            except Exception:
                pass
        else:
            raise SystemExit("server did not start")

        from playwright.sync_api import sync_playwright
        errs, logs = [], []
        with sync_playwright() as p:
            br = p.chromium.launch()
            pg = br.new_page(viewport={"width": 1600, "height": 1100})
            pg.on("pageerror", lambda e: errs.append(str(e)))
            pg.on("console", lambda m: logs.append("%s: %s" % (m.type, m.text)))

            # ① 관제 요약 탭 — 위험도·이상치·무응답
            pg.goto(URL + "/wall", wait_until="networkidle")
            pg.wait_for_timeout(3000)
            assert not pg.query_selector("#wall-risk"), "관제에서 뺀 위험도 영역이 남아 있다"
            txt = pg.inner_text("#wtab-summary")
            print("--- 관제 요약 탭 ---")
            print(txt[:400])
            for gone in ("임계 근접 장비", "평소와 다른 장비", "SNMP 무응답 장비"):
                assert gone not in txt, "관제에서 빼기로 한 항목이 보인다: %s" % gone
            pg.screenshot(path=os.path.join(OUT, "wall_summary.png"), full_page=True)

            # 온도는 스위치 상세보기에서 — 본 화면으로
            pg.goto(URL + "/", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.click(".tab-nav__btn[data-tab='switch']")
            pg.wait_for_timeout(900)
            detail = pg.query_selector("#switch-table-body [data-action='detail-switch']")
            if detail:
                detail.click()
                pg.wait_for_timeout(2000)
                envbox = pg.query_selector("#detail-env")
                etxt = envbox.inner_text() if envbox else ""
                print("--- 상세보기 환경 정보 ---")
                print(etxt[:300])
                assert "환경 정보" in etxt, "상세보기에 환경 정보 영역이 없다"
                # 온도가 있으면 최고 온도, 없으면 사유가 보여야 한다
                assert ("현재 최고 온도" in etxt) or ("SNMP 허용 호스트" in etxt),                     "온도도 사유도 없다"
                pg.screenshot(path=os.path.join(OUT, "detail_env.png"), full_page=True)
            else:
                print("(상세보기 버튼 없음 — 스위치 목록이 비었을 수 있음)")

            # ② 본 화면 — 스위치 SNMP 진단 버튼
            pg.goto(URL + "/", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.click(".tab-nav__btn[data-tab='switch']")
            pg.wait_for_timeout(900)
            btn = pg.query_selector("[data-action='snmp-probe-switch']")
            assert btn, "스위치 표에 SNMP 진단 버튼이 없다"
            btn.click()
            # 가짜 IP라 무응답 타임아웃까지 기다려야 결과 문구가 나온다
            for _ in range(40):
                pg.wait_for_timeout(1000)
                if "조회 중" not in pg.inner_text("#diag-result"):
                    break
            res = pg.inner_text("#diag-result")
            print("--- 스위치 SNMP 진단 ---")
            print(res[:400])
            assert res.strip(), "진단 결과가 비었다"
            # 가짜 IP라 무응답이 정상 — 사유가 사람 말로 나와야 한다
            assert ("확인" in res or "응답" in res or "SNMP" in res)
            pg.screenshot(path=os.path.join(OUT, "sw_probe.png"), full_page=True)

            for bad in ("undefined", "NaN", "[object"):
                assert bad not in txt, "위험도 영역에 %s 노출" % bad
                assert bad not in res, "진단 결과에 %s 노출" % bad
            br.close()

        bad = [x for x in logs
               if x.startswith("error") and "Content Security Policy" not in x]
        print("pageerrors:", errs or "none")
        print("console errors:", bad or "none")
        assert not errs and not bad, "JS 오류 발생"
        print("OK — screenshots in", OUT)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        cleanup()
        print("seed cleaned")


if __name__ == "__main__":
    main()
