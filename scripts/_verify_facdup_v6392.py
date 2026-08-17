# -*- coding: utf-8 -*-
"""v6.39.2 설비 중복(같은 IP, 대역 표기만 다름) — 실화면 검증.

중복 2건을 심어두고 설비 현황에서 ↻ 새로고침(재매칭)을 눌러
① 목록에서 중복이 사라지는지 ② 정리 건수가 화면에 안내되는지 본다.
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "build", "facdup_verify")
DBP = os.path.join(ROOT, "netdash.db")
URL = "http://127.0.0.1:8082"
DUP_IP = "203.0.113.77"          # TEST-NET-3 — 실장비와 겹치지 않음
DUP_IP2 = "203.0.113.78"
SUBS = ("203.0.113.0/24", "203.0.113.0/22")


def cleanup():
    from core import db
    with db.get_db(DBP) as conn:
        conn.execute("DELETE FROM facility_hosts WHERE ip IN (?,?)", (DUP_IP, DUP_IP2))
        conn.commit()


def seed():
    from core import db
    db.init_db(DBP)
    cleanup()
    with db.get_db(DBP) as conn:
        for i, ip in enumerate((DUP_IP, DUP_IP2)):
            for j, sub in enumerate(SUBS):
                conn.execute(
                    "INSERT INTO facility_hosts (subnet, ip, mac, online, direct, "
                    " switch_name, port, updated) VALUES (?,?,?,1,1,?,?,?)",
                    (sub, ip, "aa:bb:cc:00:00:%02d" % i, "ZZ-SW", "Gi1/0/%d" % (i + 1),
                     "2026-08-0%d 10:00:00" % (j + 1)))
        conn.commit()
        n = conn.execute("SELECT COUNT(*) FROM facility_hosts WHERE ip IN (?,?)",
                         (DUP_IP, DUP_IP2)).fetchone()[0]
    print("seeded 중복 행 수: %d (IP 2개 x 대역 2개)" % n)


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
            pg = br.new_page(viewport={"width": 1600, "height": 1000})
            pg.on("pageerror", lambda e: errs.append(str(e)))
            pg.on("console", lambda m: logs.append("%s: %s" % (m.type, m.text)))
            pg.goto(URL + "/", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.click(".tab-nav__btn[data-tab='facility']")
            pg.wait_for_timeout(1500)

            def _count(ip):
                return pg.evaluate(
                    "(ip) => Array.from(document.querySelectorAll('#facility-table-body tr'))"
                    ".filter(tr => tr.innerText.includes(ip)).length", ip)

            before = _count(DUP_IP)
            print("재매칭 전 %s 행 수: %d" % (DUP_IP, before))
            assert before >= 2, "중복이 화면에 보이지 않는다(시드 실패?)"
            pg.screenshot(path=os.path.join(OUT, "before.png"), full_page=True)

            rf = pg.query_selector("#btn-fac-refresh")
            assert rf, "설비 새로고침(재매칭) 버튼이 없다"
            info = pg.evaluate(
                "() => { const b = document.getElementById('btn-fac-refresh');"
                " if (!b) return 'no button';"
                " const r = b.getBoundingClientRect();"
                " const top = document.elementFromPoint(r.x + r.width/2, r.y + r.height/2);"
                " return {text: b.innerText, disabled: b.disabled,"
                "   visible: !!(r.width && r.height), rect: [r.x, r.y, r.width, r.height],"
                "   topEl: top ? top.tagName + '#' + top.id : null}; }")
            print("버튼 상태:", info)
            rf.scroll_into_view_if_needed()
            pg.wait_for_timeout(200)
            rf.click()
            pg.wait_for_timeout(500)
            print("클릭 직후 문구:", repr(pg.inner_text("#fac-rematch-note")))
            for _ in range(40):
                pg.wait_for_timeout(1000)
                t = pg.inner_text("#fac-rematch-note")
                if "완료" in t or "실패" in t or "오류" in t:
                    break
            msg = pg.inner_text("#fac-rematch-note")
            print("재매칭 결과 문구:", msg)
            assert "재매칭 완료" in msg, msg
            assert "중복" in msg, "중복 정리 건수가 화면에 안내되지 않는다"

            pg.wait_for_timeout(1500)
            after = _count(DUP_IP)
            after2 = _count(DUP_IP2)
            print("재매칭 후 %s 행 수: %d / %s 행 수: %d" % (DUP_IP, after, DUP_IP2, after2))
            assert after == 1 and after2 == 1, "중복이 남아 있다"
            pg.screenshot(path=os.path.join(OUT, "after.png"), full_page=True)

            body = pg.inner_text("#tab-facility")
            for bad in ("undefined", "NaN", "[object"):
                assert bad not in body, "설비 화면에 %s 노출" % bad
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
