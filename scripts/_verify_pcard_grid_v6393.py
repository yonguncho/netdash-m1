# -*- coding: utf-8 -*-
"""v6.39.3 관제 장애 카드 격자 정렬 — 실화면 검증.

이름·IP·사유 길이가 제각각인 설비 실패를 심어두고,
카드 폭이 **모두 같은지**(격자) 확인한다. 예전에는 flex-wrap이라 내용 길이에
따라 폭이 달라 '긴 네모, 짧은 네모'가 섞였다(사용자 지적).
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "build", "pcard_verify")
DBP = os.path.join(ROOT, "netdash.db")
URL = "http://127.0.0.1:8082"
SUB = "198.51.100.0/24"          # TEST-NET-2
SW = "ZZ-GRID-SW"
SWIP = "198.51.100.250"


def cleanup():
    from core import db
    with db.get_db(DBP) as conn:
        conn.execute("DELETE FROM facility_hosts WHERE subnet=?", (SUB,))
        conn.execute("DELETE FROM switches WHERE ip=? OR name=?", (SWIP, SW))
        conn.commit()


def seed():
    from core import db
    db.init_db(DBP)
    cleanup()
    db.save_switch(DBP, SW, SWIP, "cisco_ios")
    # 이름·사유 길이를 일부러 크게 다르게 — 폭이 흔들리는지 보려고
    rows = []
    names = ["A", "설비-짧음",
             "매우-긴-설비-이름-현장표기-포함-라인3-충전기-컨트롤러-01",
             "중간길이설비", "B2",
             "또다른-아주-긴-이름의-설비-공정라인-우측-끝단-센서-게이트웨이"]
    for i, nm in enumerate(names):
        rows.append({"subnet": SUB, "ip": "198.51.100.%d" % (10 + i),
                     "mac": "aa:bb:cc:00:0%d:01" % i,
                     "switch_name": SW, "port": "Gi1/0/%d" % (i + 1),
                     "online": 0})
    db.save_facility_hosts(DBP, rows)
    print("seeded 실패 설비 %d건(이름 길이 제각각)" % len(rows))


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
            pg.goto(URL + "/wall", wait_until="networkidle")
            pg.wait_for_timeout(3000)

            cards = pg.query_selector_all("#wall-problems .pcard")
            assert cards, "장애 카드가 없다(시드 실패?)"
            widths = [round(c.bounding_box()["width"]) for c in cards]
            print("카드 %d개 / 폭 종류: %s" % (len(cards), sorted(set(widths))))
            # 폭은 전부 같아야 한다 — 사용자가 지적한 '긴 네모, 짧은 네모'의 정체.
            assert len(set(widths)) == 1, "카드 폭이 제각각이다: %s" % sorted(set(widths))

            # 높이는 **같은 격자(카테고리) 안에서** 같아야 한다.
            # 카테고리가 다르면(설비/도달 불가/수집 실패) 항목 구성이 달라 다를 수 있다.
            grids = pg.query_selector_all("#wall-problems .wall-cat__grid")
            for gi, g in enumerate(grids):
                hs = [round(c.bounding_box()["height"])
                      for c in g.query_selector_all(".pcard")]
                if not hs:
                    continue
                print("  격자%d: 카드 %d개, 높이 종류 %s" % (gi + 1, len(hs), sorted(set(hs))))
                assert len(set(hs)) == 1, \
                    "같은 카테고리 안에서 카드 높이가 다르다: %s" % sorted(set(hs))

            # 긴 이름이 잘리되 툴팁으로 전체를 볼 수 있어야 한다
            tip = cards[0].get_attribute("title")
            assert tip, "카드에 전체 값 툴팁이 없다"
            print("  툴팁 예:", tip[:60])
            pg.screenshot(path=os.path.join(OUT, "problems.png"), full_page=True)

            body = pg.inner_text("#wall-problems")
            for bad in ("undefined", "NaN", "[object"):
                assert bad not in body, "장애 목록에 %s 노출" % bad
            br.close()

        bad = [x for x in logs
               if x.startswith("error") and "Content Security Policy" not in x]
        print("pageerrors:", errs or "none")
        print("console errors:", bad or "none")
        assert not errs and not bad, "JS 오류 발생"
        print("OK — screenshot in", OUT)
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
