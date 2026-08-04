# -*- coding: utf-8 -*-
"""관제 통합 대시보드 검증 — 탭 4개를 실제 브라우저로 렌더해 스크린샷.

데모 DB에 방화벽 지표(VPN·정책·센서·부하)와 설비까지 주입해, 카드가 비어 있지
않은 '실사용 모양'으로 확인한다.
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
URL = "http://127.0.0.1:8082"
OUT = ROOT / "build" / "wall_verify"


def wait_health(timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(URL + "/api/wall/stats", timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def seed(db_path):
    from core import db
    # 방화벽 2대 + 지표(부하·VPN·정책·센서)
    with db.get_db(db_path) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status, location) "
                     "VALUES ('FW-HQ-01','fortigate','10.10.0.1','done','A09U20')")
        conn.execute("INSERT INTO firewalls (name, vendor, host, status, location) "
                     "VALUES ('FW-DR-01','fortigate','10.10.0.2','done','A10U20')")
        # 사용자가 신고한 상황 재현: 수집은 됐는데 지표가 없는 장비 + 수집 실패 장비
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-DMZ-01','fortigate','10.30.0.1','done')")
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-DMZ-02','fortigate','10.30.0.2','failed')")
    fws = db.list_firewalls(db_path)
    db.save_device_metrics(db_path, "firewall", fws[0]["id"], {
        "cpu_pct": 34, "mem_pct": 61, "disk_pct": 22, "sessions": 48210,
        "level": "normal", "ha_mode": "active-passive",
        "vpn": {"tunnel_total": 4, "tunnel_up": 3, "ssl_users": 23,
                "tunnels": [
                    {"name": "BR-SEOUL-01", "status": "up", "peer": "203.0.113.5"},
                    {"name": "BR-DAEGU-01", "status": "up", "peer": "203.0.113.17"},
                    {"name": "BR-JEJU-01", "status": "up", "peer": "203.0.113.30"},
                    {"name": "BR-BUSAN-02", "status": "down", "peer": "203.0.113.44"}]},
        "policy": {"total": 412, "proxy_total": 31, "unused": 37, "disabled": 9},
        "sensors": {"alarms": [], "psu_count": 2, "max_temp_c": 47},
    })
    db.save_device_metrics(db_path, "firewall", fws[1]["id"], {
        "cpu_pct": 87, "mem_pct": 92, "disk_pct": 41, "sessions": 91520,
        "level": "critical",
        "vpn": {"tunnel_total": 3, "tunnel_up": 2, "ssl_users": 4, "tunnels": [
            {"name": "DR-MAIN", "status": "up", "peer": "198.51.100.2"},
            {"name": "DR-BACKUP", "status": "up", "peer": "198.51.100.3"},
            {"name": "DR-LEGACY", "status": "down", "peer": "198.51.100.9"}]},
        "policy": {"total": 380, "proxy_total": 22, "unused": 51, "disabled": 2},
        "sensors": {"alarms": ["PS2 Status"], "psu_count": 2, "max_temp_c": 63},
    })
    db.save_device_env(db_path, "firewall", fws[0]["id"], {
        "sensors": [], "temp_count": 1, "fan_count": 2,
        "max_temp_c": 47.0, "level": "normal"})
    # 스위치 온도
    for i, s in enumerate(db.get_switches(db_path)):
        db.save_device_env(db_path, "switch", s["id"], {
            "sensors": [], "temp_count": 1, "fan_count": 2,
            "max_temp_c": 38.0 + i * 7, "level": "normal"})
    # 설비 2개 대역
    db.save_facility_hosts(db_path, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.%d" % i,
         "mac": "aa:bb:cc:00:01:%02x" % i, "online": 1 if i % 7 else 0,
         "direct": 1 if i % 5 else 0, "switch_name": "SW-CORE-01" if i % 2 else "SW-ACCESS-01",
         "port": "Gi1/0/%d" % i} for i in range(2, 40)
    ] + [
        {"subnet": "10.92.150.0/24", "ip": "10.92.150.%d" % i,
         "mac": "aa:bb:cc:00:02:%02x" % i, "online": 1 if i % 3 else 0,
         "direct": 1, "switch_name": "DIST-SW-01", "port": "Gi1/0/%d" % i}
        for i in range(2, 20)
    ])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen([sys.executable, str(ROOT / "app.py"), "--demo"],
                            cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        if not wait_health():
            print("SERVER FAILED TO START")
            return 1
        seed(ROOT / "netdash.db")
        stats = json.load(urllib.request.urlopen(URL + "/api/wall/stats", timeout=5))
        print("stats keys:", sorted(stats.keys()))
        print("firewall vpn:", stats["firewalls"]["vpn"], "policy:", stats["firewalls"]["policy"])
        print("facility:", stats["facility"]["total"], "online", stats["facility"]["online"])

        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            page = b.new_page(viewport={"width": 1600, "height": 1000})
            page.goto(URL + "/wall")
            page.wait_for_timeout(2500)
            for tab in ("summary", "switch", "firewall", "facility"):
                if tab != "summary":
                    page.click("[data-wtab='%s']" % tab)
                    page.wait_for_timeout(600)
                page.screenshot(path=str(OUT / ("wall_%s.png" % tab)), full_page=True)
                print("captured", tab)
            b.close()
    finally:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
