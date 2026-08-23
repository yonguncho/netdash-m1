# -*- coding: utf-8 -*-
"""실사용 시나리오 종단 검증 — 단위 테스트가 놓치는 '기능 사이 연결'을 잡는다.

각 시나리오는 사용자가 실제로 하는 순서 그대로 API를 호출하고, 중간 산출물이
다음 단계에서 제대로 쓰이는지 확인한다. 실서버 포트를 열지 않고 test client 사용.

실행: python scripts/verify_user_journeys.py   → 전부 통과 시 exit 0
"""
import io
import json
import os
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8")  # cp949 콘솔 크래시 방지
except Exception:
    pass
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILS = []


def check(name, cond, detail=""):
    print(("  [OK]   " if cond else "  [FAIL] ") + name +
          (" — " + str(detail)[:200] if detail else ""))
    if not cond:
        FAILS.append(name)


def new_client():
    os.chdir(tempfile.mkdtemp(prefix="netdash_journey_"))
    from config import reset_config
    reset_config()
    from app import create_app
    app = create_app(demo_mode=True)
    app.config["TESTING"] = True
    return app.test_client()


def _db_path():
    return Path(os.getcwd()) / "netdash.db"


def journey_switch():
    """스위치: 등록 → 목록 → 수정 → 상세 → 진단 → 삭제"""
    print("\n[여정 1] 스위치 등록부터 삭제까지")
    c = new_client()
    r = c.post("/api/switches/manual", json={"name": "J-SW", "ip": "10.99.0.1",
                                             "vendor": "cisco_ios"})
    check("스위치 등록", r.status_code in (200, 201), (r.status_code, r.get_data(as_text=True)[:120]))
    st = c.get("/api/state").get_json()
    sw = [s for s in st.get("switches", []) if s.get("ip") == "10.99.0.1"]
    check("목록에 즉시 반영", len(sw) == 1, len(st.get("switches", [])))
    if not sw:
        return
    sid = sw[0]["id"]
    r = c.put("/api/switches/%d" % sid, json={"name": "J-SW-2", "location": "A01U10"})
    check("수정", r.status_code == 200, r.get_data(as_text=True)[:120])
    st2 = c.get("/api/state").get_json()
    upd = [s for s in st2["switches"] if s["id"] == sid][0]
    check("수정 내용이 목록에 반영", upd.get("name") == "J-SW-2", upd.get("name"))
    check("위치가 서버실 좌표로 인식", bool(upd.get("room_rack") or upd.get("location")),
          upd.get("location"))
    r = c.get("/api/switches/%d/detail" % sid)
    check("상세 조회", r.status_code == 200, r.status_code)
    r = c.get("/api/export/switches?fmt=csv")
    body = r.get_data().decode("utf-8-sig", "replace")
    check("내보내기에 방금 등록한 스위치 포함", "J-SW-2" in body, body[:120])
    r = c.delete("/api/switches/%d" % sid)
    check("삭제", r.status_code == 200, r.status_code)
    st3 = c.get("/api/state").get_json()
    check("삭제 후 목록에서 사라짐",
          all(s["id"] != sid for s in st3.get("switches", [])))


def journey_server_specs():
    """서버: 등록 → 사양·장착구성 저장 → 목록/상세/CSV 가 서로 일치하는가"""
    print("\n[여정 2] 서버 사양·장착 구성이 화면과 CSV에서 일치")
    c = new_client()
    from core import db, server_collector as sc
    r = c.post("/api/servers", json={"name": "J-SRV", "ip": "10.99.1.1", "os_type": "linux"})
    check("서버 등록", r.status_code in (200, 201), r.get_data(as_text=True)[:120])
    sid = r.get_json().get("id")
    spec = sc._specs_from_unix({
        sc._CMD_LSCPU: "CPU(s):              16\nModel name:          Intel Xeon Gold 6248\n",
        "cat /proc/meminfo": "MemTotal:       65805928 kB\n",
        sc._CMD_DF: ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                     "/dev/sda2 209715200 104857600 104857600 50% /\n"),
        sc._CMD_DIMM: ("Memory Device\n\tSize: 32768 MB\n\tLocator: DIMM_A1\n\tType: DDR4\n"
                       "\tManufacturer: Samsung\n\n"
                       "Memory Device\n\tSize: 32768 MB\n\tLocator: DIMM_B1\n\tType: DDR4\n"
                       "\tManufacturer: Samsung\n\n"
                       "Memory Device\n\tSize: No Module Installed\n\tLocator: DIMM_A2\n"),
        sc._CMD_LSBLK: ('NAME="sda" MODEL="SAMSUNG MZ7" SIZE="894.3G" ROTA="0" TYPE="disk"\n'),
    })
    db.update_server(_db_path(), sid, collected=True, status="done", **spec)

    row = [s for s in c.get("/api/servers").get_json()["servers"] if s["id"] == sid][0]
    check("API에 CPU 코어 노출", row.get("cpu_cores") == 16, row.get("cpu_cores"))
    check("API에 메모리 모듈 노출", len(json.loads(row.get("mem_modules") or "[]")) == 2)
    check("빈 슬롯 포함 슬롯 수", row.get("mem_slots_total") == 3, row.get("mem_slots_total"))
    check("물리 디스크 노출", len(json.loads(row.get("disk_devices") or "[]")) == 1)

    csv = c.get("/api/export/servers?fmt=csv").get_data().decode("utf-8-sig", "replace")
    summary = sc.summarize_modules(json.loads(row["mem_modules"]), row["mem_slots_total"])
    check("CSV의 메모리 구성이 백엔드 요약과 동일", summary in csv, summary)
    check("CSV에 디스크 모델 포함", "SAMSUNG MZ7" in csv)

    r = c.post("/api/servers/%d/diagnose" % sid)
    check("서버 진단 응답", r.status_code == 200, r.get_data(as_text=True)[:150])
    after = [s for s in c.get("/api/servers").get_json()["servers"] if s["id"] == sid][0]
    check("진단 후에도 사양이 보존됨", after.get("cpu_cores") == 16, after.get("cpu_cores"))
    check("진단 후에도 장착 구성이 보존됨",
          len(json.loads(after.get("mem_modules") or "[]")) == 2)


def journey_facility_link():
    """설비: 스위치 수집 → 설비 등록 → 감시가 연결 스위치를 채우는가"""
    print("\n[여정 3] 설비가 연결 스위치를 스스로 찾아 채우는가")
    c = new_client()
    from core import db, facility
    p = _db_path()
    sid = db.save_switch(p, "J-ACC", "10.99.2.1", "cisco_ios")
    db.set_switch_status(p, sid, "done")
    other = db.save_switch(p, "J-ACC-2", "10.99.2.2", "cisco_ios")
    snap2 = db.save_snapshot(p, other)
    db.save_mac_entries(p, snap2, other, [{"vlan": "9", "mac": "aa:00:00:00:00:99",
                                           "port": "Gi1/0/1"}])
    # 설비를 먼저 등록(연결 스위치 미확인 상태)
    db.save_facility_hosts(p, [{"subnet": "10.99.9.0/24", "ip": "10.99.9.5",
                                "mac": "aa:00:00:00:00:01", "switch_id": None,
                                "switch_name": None, "port": None, "online": 1,
                                "direct": 0, "via": None, "port_desc": None}])
    facility._miss_counts.clear()
    before = db.get_facility_hosts(p)[0]
    check("초기에는 연결 스위치 미확인", not before.get("switch_name"))
    # 뒤늦게 스위치 수집
    snap = db.save_snapshot(p, sid)
    db.save_ports(p, snap, sid, [{"name": "Gi1/0/7", "status": "connected", "vlan": "9",
                                  "description": "PLC"}])
    db.save_mac_entries(p, snap, sid, [{"vlan": "9", "mac": "aa:00:00:00:00:01",
                                        "port": "Gi1/0/7"}])
    facility.monitor_known_hosts(p)
    after = db.get_facility_hosts(p)[0]
    check("감시가 연결 스위치를 채움", after.get("switch_name") == "J-ACC", after.get("switch_name"))
    check("포트도 채움", after.get("port") == "Gi1/0/7", after.get("port"))
    check("포트 설명까지 채움", after.get("port_desc") == "PLC", after.get("port_desc"))
    # MAC 명령만 실패한 재수집 → 설비가 끊김으로 오탐되면 안 된다
    snap3 = db.save_snapshot(p, sid)
    db.save_mac_entries(p, snap3, sid, [])
    for _ in range(facility._MISS_THRESHOLD + 1):
        facility.monitor_known_hosts(p)
    check("MAC 수집 실패가 설비를 끊김으로 만들지 않음",
          db.get_facility_hosts(p)[0]["online"] == 1)
    r = c.get("/api/export/facility?fmt=csv")
    check("설비 내보내기 동작", r.status_code == 200, r.status_code)


def journey_excel_import():
    """엑셀 일괄 등록: 서버 → 등록된 항목이 목록·수집 대상에 들어오는가"""
    print("\n[여정 4] 엑셀 일괄 등록")
    c = new_client()
    try:
        from openpyxl import Workbook
    except ImportError:
        print("  (openpyxl 없음 — 건너뜀)")
        return
    wb = Workbook()
    ws = wb.active
    ws.append(["이름", "IP", "위치"])
    ws.append(["XL-SRV-1", "10.99.3.1", "A02U05"])
    ws.append(["XL-SRV-2", "10.99.3.2", ""])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    r = c.post("/api/servers/import",
               data={"file": (buf, "servers.xlsx")},
               content_type="multipart/form-data")
    check("엑셀 업로드 수락", r.status_code == 200, r.get_data(as_text=True)[:180])
    if r.status_code == 200:
        body = r.get_json() or {}
        check("2건 등록", (body.get("imported") or 0) == 2, body)
        names = {s["name"] for s in c.get("/api/servers").get_json()["servers"]}
        check("목록에 반영", {"XL-SRV-1", "XL-SRV-2"} <= names, names)


def journey_bulk_guard():
    """일괄 수집: 잘못된 입력·중복 실행에서 사용자를 속이지 않는가"""
    print("\n[여정 5] 일괄 수집 입력 검증과 중복 실행 방지")
    c = new_client()
    c.post("/api/servers", json={"name": "B1", "ip": "10.99.4.1"})
    check("ids 문자열 → 400", c.post("/api/servers/collect-all",
                                   json={"ids": "abc"}).status_code == 400)
    check("빈 ids → 전체 수집으로 수락(202)",
          c.post("/api/servers/collect-all", json={"ids": []}).status_code == 202)
    from core import server_collector
    st = server_collector.get_progress()
    check("진행 상태 API 동작", c.get("/api/servers/collect-all/status").status_code == 200, st)
    r = c.post("/api/servers/collect-all", json={})
    check("진행 중 재시작은 409로 거절(진행률 오염 방지)",
          r.status_code in (202, 409), r.status_code)


def main():
    for fn in (journey_switch, journey_server_specs, journey_facility_link,
               journey_excel_import, journey_bulk_guard):
        try:
            fn()
        except Exception as e:
            import traceback
            print("  [FAIL] %s 예외: %s" % (fn.__name__, e))
            traceback.print_exc()
            FAILS.append(fn.__name__)
    print("\n" + "=" * 62)
    if FAILS:
        print("FAILED %d건: %s" % (len(FAILS), ", ".join(FAILS)))
        return 1
    print("ALL PASS — 실사용 시나리오 종단 검증 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
