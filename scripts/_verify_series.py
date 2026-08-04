# -*- coding: utf-8 -*-
"""시계열 위젯 실화면 검증 — 24시간치 가짜 이력을 주입해 그래프 렌더 확인."""
import math
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
URL = "http://127.0.0.1:8082"


def seed_history(dbp):
    from core import db
    with db.get_db(dbp) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-HQ-01','fortigate','10.10.0.1','done')")
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-DR-01','fortigate','10.10.0.2','done')")
    fws = db.list_firewalls(dbp)
    sws = db.get_switches(dbp)
    # 5분 간격 × 24시간 = 288점. 파형: 업무시간 봉우리 + 노이즈 + 저녁 장애 계단.
    with db.get_db(dbp) as conn:
        for i in range(288):
            mins_ago = (287 - i) * 5
            ts = "datetime('now','localtime','-%d minutes')" % mins_ago
            frac = i / 288.0
            day = math.sin(frac * math.pi)          # 0→1→0 (하루 봉우리)
            for j, fw in enumerate(fws[:2]):
                cpu = int(20 + 45 * day + 8 * math.sin(i / 7.0 + j))
                sess = int(20000 + 60000 * day + 4000 * math.sin(i / 5.0 + j * 2))
                conn.execute(
                    "INSERT INTO metrics_history (kind, device_id, ts, cpu, mem, sessions, temp_c) "
                    "VALUES ('firewall', ?, %s, ?, ?, ?, ?)" % ts,
                    (fw["id"], cpu, min(95, cpu + 20), sess, 40 + 6 * day))
            for k, sw in enumerate(sws[:3]):
                conn.execute(
                    "INSERT INTO metrics_history (kind, device_id, ts, temp_c) "
                    "VALUES ('switch', ?, %s, ?)" % ts,
                    (sw["id"], 36 + 8 * day + k * 3))
            online = 1240 if i < 200 else (1180 if i < 230 else 1235)   # 장애 계단
            conn.execute(
                "INSERT INTO metrics_history (kind, device_id, ts, online, total) "
                "VALUES ('facility', 0, %s, ?, 1250)" % ts, (online,))
            conn.execute(
                "INSERT INTO metrics_history (kind, device_id, ts, online, total) "
                "VALUES ('ports', 0, %s, ?, 2304)" % ts,
                (int(1780 + 60 * day),))
    print("seeded 288 ticks")


def main():
    proc = subprocess.Popen([sys.executable, str(ROOT / "app.py"), "--demo"],
                            cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        end = time.time() + 60
        while time.time() < end:
            try:
                urllib.request.urlopen(URL + "/api/wall/stats", timeout=2)
                break
            except Exception:
                time.sleep(1)
        seed_history(ROOT / "netdash.db")
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            pg = b.new_page(viewport={"width": 1600, "height": 1000})
            errs = []
            pg.on("pageerror", lambda e: errs.append(str(e)))
            pg.goto(URL + "/wall")
            pg.wait_for_timeout(3000)
            for tab in ("firewall", "switch", "facility"):
                pg.click("[data-wtab='%s']" % tab)
                pg.wait_for_timeout(900)
                pg.add_style_tag(content="body{overflow:auto!important;height:auto!important}"
                                         ".wall-pane--on{overflow:visible!important;flex:none!important}")
                pg.wait_for_timeout(300)
                pg.screenshot(path=str(ROOT / "build" / "wall_verify" / ("series_%s.png" % tab)),
                              full_page=True)
                print("captured", tab)
            print("JS errors:", errs or "none")
            b.close()
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
