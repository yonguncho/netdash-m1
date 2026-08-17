# -*- coding: utf-8 -*-
"""v6.39.3 관제 '연결 실패 구역 (TPS)' 카드 — 실화면 검증."""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "build", "tpszone_verify")
DBP = os.path.join(ROOT, "netdash.db")
URL = "http://127.0.0.1:8082"
SWS = [("TPS-F1B02_1F01_FA_SW1", "203.0.113.11"),
       ("TPS-F1B02_1F01_FA_SW2", "203.0.113.12"),
       ("TPS-F2B1A_3F05_SW1", "203.0.113.13")]
SUB = "203.0.113.0/24"


def cleanup():
    from core import db
    with db.get_db(DBP) as conn:
        conn.execute("DELETE FROM facility_hosts WHERE subnet=?", (SUB,))
        for _, ip in SWS:
            r = conn.execute("SELECT id FROM switches WHERE ip=?", (ip,)).fetchone()
            if not r:
                continue
            sid = r["id"]
            # 자식 행부터 — FK 때문에 스위치를 먼저 지울 수 없다
            conn.execute("DELETE FROM mac_entries WHERE switch_id=?", (sid,))
            conn.execute("DELETE FROM ports WHERE switch_id=?", (sid,))
            conn.execute("DELETE FROM snapshots WHERE switch_id=?", (sid,))
            conn.execute("DELETE FROM switches WHERE id=?", (sid,))
        conn.commit()


def seed():
    from core import db
    db.init_db(DBP)
    cleanup()
    for name, ip in SWS:
        db.save_switch(DBP, name, ip, "cisco_ios")
        with db.get_db(DBP) as conn:
            conn.execute("UPDATE switches SET hostname=? WHERE ip=?", (name, ip))
            conn.commit()
    rows = []
    # 1공장 TPS01: 두 스위치 합쳐 실패 5 / 전체 9
    for i in range(5):
        rows.append({"subnet": SUB, "ip": "203.0.113.10%d" % i,
                     "switch_name": SWS[0][0], "online": 0 if i < 3 else 1})
    for i in range(4):
        rows.append({"subnet": SUB, "ip": "203.0.113.11%d" % i,
                     "switch_name": SWS[1][0], "online": 0 if i < 2 else 1})
    # 2공장 TPS05: 구역 전체(2/2) 끊김 — '구역 전체' 배지가 떠야 한다
    for i in range(2):
        rows.append({"subnet": SUB, "ip": "203.0.113.12%d" % i,
                     "switch_name": SWS[2][0], "online": 0})
    # 끊겨서 MAC이 사라진 설비 — switch_name이 비어 있어도 과거 이력으로
    # 구역을 찾아야 한다(사용자 지적: 죄다 '위치 미확인'으로 나왔다)
    sw0 = [s for s in db.get_switches(DBP) if s["ip"] == SWS[0][1]][0]
    with db.get_db(DBP) as conn:
        conn.execute("INSERT INTO snapshots (switch_id, collected_at) "
                     "VALUES (?, datetime('now','-1 day'))", (sw0["id"],))
        snap = conn.execute("SELECT MAX(id) FROM snapshots").fetchone()[0]
        conn.execute("INSERT INTO mac_entries (snapshot_id, switch_id, mac, port, vlan) "
                     "VALUES (?,?,?,?,10)", (snap, sw0["id"], "aabbcc001199", "Gi1/0/7"))
        conn.commit()
    rows.append({"subnet": SUB, "ip": "203.0.113.199", "mac": "aa:bb:cc:00:11:99",
                 "switch_name": "", "online": 0})
    db.save_facility_hosts(DBP, rows)
    print("seeded 설비 %d건 (1공장 실패5/9 + 끊겨서 스위치 미상 1건, 2공장 실패2/2)" % len(rows))


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
            pg.wait_for_timeout(2500)
            pg.click("[data-wtab='facility']")
            pg.wait_for_timeout(1800)

            card = pg.query_selector(".wcard:has-text('연결 실패 구역')")
            assert card, "관제 설비 탭에 '연결 실패 구역 (TPS)' 카드가 없다"
            txt = card.inner_text()
            print("--- 카드 ---")
            print(txt[:500])
            assert "1공장 Assembly(B02) 1층 TPS01" in txt, "TPS 구역 라벨이 없다"
            assert "2공장 Assembly(B1A) 3층 TPS05" in txt
            assert "구역 전체" in txt, "구역 전체 끊김 배지가 없다"
            # 끊겨서 switch_name이 빈 설비도 과거 MAC 이력으로 구역을 찾아야 한다.
            # → 1공장 실패가 5가 아니라 6이 되고, '위치 미확인'은 없어야 한다.
            row1 = card.query_selector_all("tbody tr")[0].inner_text()
            nums = [t for t in row1.replace("\t", " ").split() if t.isdigit()]
            assert nums and nums[0] == "6", (
                "끊긴 설비가 과거 이력으로 보강되지 않았다(위치 미확인으로 샜다): %r"
                % row1)
            rows = card.query_selector_all("tbody tr")
            assert rows and "TPS01" in rows[0].inner_text(), "실패 많은 순 정렬이 아니다"
            card.scroll_into_view_if_needed()
            pg.wait_for_timeout(300)
            pg.screenshot(path=os.path.join(OUT, "facility_tab.png"), full_page=True)

            for bad in ("undefined", "NaN", "[object"):
                assert bad not in txt, "카드에 %s 노출" % bad
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
