# -*- coding: utf-8 -*-
"""v6.40.0 설비 연결 이력 타임라인 — 관제·설비 현황 양쪽에서 실화면 검증.

연결→끊김→재연결→끊김 이벤트를 심어두고
① 설비 현황 [진단 결과] 팝업 위에 타임라인이 뜨는지
② 관제 구역 팝업에서 설비 행을 누르면 이력이 열리는지 본다.
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
OUT = os.path.join(ROOT, "build", "fachist_verify")
DBP = os.path.join(ROOT, "netdash.db")
URL = "http://127.0.0.1:8082"
SUB = "203.0.113.0/24"
IP = "203.0.113.55"
SW = "TPS-F1B02_1F01_FA_SW1"
SWIP = "203.0.113.201"


def cleanup():
    from core import db
    with db.get_db(DBP) as conn:
        conn.execute("DELETE FROM device_events WHERE ip=?", (IP,))
        conn.execute("DELETE FROM facility_hosts WHERE ip=?", (IP,))
        r = conn.execute("SELECT id FROM switches WHERE ip=?", (SWIP,)).fetchone()
        if r:
            conn.execute("DELETE FROM mac_entries WHERE switch_id=?", (r["id"],))
            conn.execute("DELETE FROM ports WHERE switch_id=?", (r["id"],))
            conn.execute("DELETE FROM snapshots WHERE switch_id=?", (r["id"],))
            conn.execute("DELETE FROM switches WHERE id=?", (r["id"],))
        conn.commit()


def seed():
    from core import db
    db.init_db(DBP)
    cleanup()
    db.save_switch(DBP, SW, SWIP, "cisco_ios")
    with db.get_db(DBP) as conn:
        conn.execute("UPDATE switches SET hostname=? WHERE ip=?", (SW, SWIP))
        conn.commit()
    db.save_facility_hosts(DBP, [{"subnet": SUB, "ip": IP, "mac": "aa:bb:cc:11:22:33",
                                  "switch_name": SW, "port": "Gi1/0/12", "online": 0}])
    # 연결 → 끊김 → 재연결 → 끊김
    with db.get_db(DBP) as conn:
        for days, kind in ((20, "device_online"), (12, "device_offline"),
                           (8, "device_online"), (3, "device_offline")):
            conn.execute(
                "INSERT INTO device_events (ts, kind, ip, subnet, severity) "
                "VALUES (datetime('now','localtime',?),?,?,?, 'info')",
                ("-%d days" % days, kind, IP, SUB))
        conn.commit()
    print("seeded: %s 연결→끊김→재연결→끊김 (현재 끊김)" % IP)


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

            # ① 설비 현황 → [진단 결과] 팝업에 타임라인
            pg.goto(URL + "/", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.click(".tab-nav__btn[data-tab='facility']")
            pg.wait_for_timeout(1500)
            btn = pg.query_selector(
                "#facility-table-body tr:has-text('%s') [data-action='explain-facility']" % IP)
            assert btn, "설비 %s 의 [진단 결과] 버튼을 찾지 못했다" % IP
            btn.click()
            for _ in range(20):
                pg.wait_for_timeout(500)
                hb = pg.query_selector("#diag-history")
                if hb and hb.is_visible() and "불러오는 중" not in hb.inner_text():
                    break
            hist = pg.query_selector("#diag-history")
            assert hist and hist.is_visible(), "진단 팝업에 연결 이력 영역이 없다"
            ht = hist.inner_text()
            print("--- 설비 현황 진단 팝업의 이력 ---")
            print(ht[:300])
            assert "연결 이력" in ht and "끊김" in ht
            assert "2회" in ht, "끊김 횟수(2회)가 안 맞는다: %r" % ht[:120]
            segs = pg.query_selector_all("#diag-history span[title]")
            assert len(segs) >= 4, "타임라인 구간이 부족하다: %d" % len(segs)
            pg.screenshot(path=os.path.join(OUT, "facility_diag.png"), full_page=True)
            pg.click("#modal-diagnose .modal__close")
            pg.wait_for_timeout(400)

            # ② 관제 구역 팝업 → 설비 행 클릭 → 이력
            pg.goto(URL + "/wall", wait_until="networkidle")
            pg.wait_for_timeout(2500)
            pg.click("[data-wtab='facility']")
            pg.wait_for_timeout(1500)
            # 시드 구역을 명시적으로 — 개발 DB의 다른 설비 때문에 1위가 아닐 수 있다
            # 설비 탭 '연결 실패 설비' 목록(v6.40.1) — 끊긴 시점·경과가 보여야 한다
            ohc = pg.query_selector(".wcard:has-text('연결 실패 설비')")
            assert ohc, "설비 탭에 '연결 실패 설비' 목록 카드가 없다"
            oht = ohc.inner_text()
            print("--- 연결 실패 설비 목록 ---")
            print(oht[:340])
            assert IP in oht, "시드 설비가 목록에 없다"
            assert "끊긴 시점" in oht and "경과" in oht
            ohrow = ohc.query_selector("tr[data-fachist='%s']" % IP)
            assert ohrow, "설비 행이 이력 클릭 대상이 아니다"
            rowtxt = ohrow.inner_text()
            assert "Gi1/0/12" in rowtxt, "연결 포트가 안 보인다: %r" % rowtxt
            assert "TPS-F1B02" in rowtxt, "연결 스위치가 안 보인다: %r" % rowtxt
            assert "일" in rowtxt or "시간" in rowtxt, "경과 시간이 안 보인다: %r" % rowtxt
            pg.screenshot(path=os.path.join(OUT, "offline_hosts.png"), full_page=True)

            zrow = pg.query_selector("tr[data-zone*='TPS01']")
            assert zrow, "시드 구역(TPS01) 행이 없다"
            zrow.click()
            pg.wait_for_timeout(1600)
            frow = pg.query_selector("#wsw-body tr[data-fachist='%s']" % IP)
            assert frow, "구역 팝업에서 %s 행을 찾지 못했다" % IP
            frow.click()
            pg.wait_for_timeout(1800)
            name = pg.inner_text("#wsw-name")
            sub = pg.inner_text("#wsw-sub")
            body = pg.inner_text("#wsw-body")
            print("--- 관제 이력 팝업 ---")
            print(name, "|", sub)
            print(body[:260])
            assert IP in name, name
            assert "끊김 2회" in sub, sub
            assert pg.query_selector("#wsw-body .hbar"), "타임라인 막대가 없다"
            assert pg.query_selector("#hist-back"), "구역으로 돌아가기 버튼이 없다"
            pg.screenshot(path=os.path.join(OUT, "wall_history.png"), full_page=True)

            # 돌아가기 동작
            pg.click("#hist-back")
            pg.wait_for_timeout(1500)
            assert pg.query_selector("#zone-recollect"), "구역 목록으로 안 돌아갔다"

            for bad in ("undefined", "NaN", "[object"):
                assert bad not in body, "이력 팝업에 %s 노출" % bad
                assert bad not in ht, "진단 팝업 이력에 %s 노출" % bad
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
