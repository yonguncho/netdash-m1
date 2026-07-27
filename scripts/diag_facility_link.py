# -*- coding: utf-8 -*-
"""진단 — '설비 연결 끊김인데 연결된 스위치 없음'의 원인을 실제 DB로 추적한다.

실행: python scripts/diag_facility_link.py [db경로]
읽기 전용. 아무것도 고치지 않는다.
"""
import sqlite3
import sys
from collections import Counter
from pathlib import Path

DB = Path(sys.argv[1] if len(sys.argv) > 1 else "netdash.db")
if not DB.exists():
    print("DB 없음:", DB)
    sys.exit(1)
conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row
q = conn.execute


def n(sql, *a):
    return q(sql, a).fetchone()[0]


print("DB:", DB.resolve())
print("\n=== 1. 설비(facility_hosts) 현황 ===")
total = n("SELECT COUNT(*) FROM facility_hosts")
print("전체:", total)
if not total:
    print("  (설비 데이터 없음 — 대역 수집을 한 적이 없는 DB)")
print("온라인:", n("SELECT COUNT(*) FROM facility_hosts WHERE online=1"))
print("오프라인:", n("SELECT COUNT(*) FROM facility_hosts WHERE online=0"))
print("스위치 미지정:", n("SELECT COUNT(*) FROM facility_hosts "
                     "WHERE switch_name IS NULL OR switch_name=''"))
print("오프라인 + 스위치 미지정(문제 증상):",
      n("SELECT COUNT(*) FROM facility_hosts WHERE online=0 "
        "AND (switch_name IS NULL OR switch_name='')"))
print("MAC 없음:", n("SELECT COUNT(*) FROM facility_hosts WHERE mac IS NULL OR mac=''"))

print("\n=== 2. 증상에 해당하는 설비 표본 ===")
rows = q("SELECT * FROM facility_hosts WHERE online=0 "
         "AND (switch_name IS NULL OR switch_name='') LIMIT 10").fetchall()
for r in rows:
    d = dict(r)
    print("  ip=%-16s mac=%-18s subnet=%-18s direct=%s via=%s switch_id=%s" % (
        d.get("ip"), d.get("mac") or "(없음)", d.get("subnet"),
        d.get("direct"), d.get("via"), d.get("switch_id")))

print("\n=== 3. 스위치 수집 상태 ===")
print("스위치 수:", n("SELECT COUNT(*) FROM switches"))
for r in q("SELECT status, COUNT(*) c FROM switches GROUP BY status").fetchall():
    print("  status=%s: %d" % (r["status"], r["c"]))
print("스냅샷 수:", n("SELECT COUNT(*) FROM snapshots"))
print("MAC 엔트리(전체 스냅샷):", n("SELECT COUNT(*) FROM mac_entries"))

print("\n=== 4. 최신 스냅샷 기준 MAC 테이블 ===")
latest = {}
for r in q("SELECT switch_id, MAX(id) mid FROM snapshots GROUP BY switch_id").fetchall():
    latest[r["switch_id"]] = r["mid"]
print("스위치별 최신 스냅샷:", len(latest), "개")
mac_owner = {}
for sid, snap in latest.items():
    cnt = n("SELECT COUNT(*) FROM mac_entries WHERE snapshot_id=?", snap)
    name = q("SELECT name FROM switches WHERE id=?", (sid,)).fetchone()
    print("  switch_id=%s(%s) snapshot=%s mac=%d건" % (
        sid, name["name"] if name else "?", snap, cnt))
    for m in q("SELECT mac, port FROM mac_entries WHERE snapshot_id=?", (snap,)).fetchall():
        mac_owner.setdefault((m["mac"] or "").upper().replace("-", ":"), []).append(
            (sid, name["name"] if name else "?", m["port"]))
print("최신 스냅샷 MAC 총 개수(정규화):", len(mac_owner))

print("\n=== 5. 핵심 확인 — 설비 MAC이 스위치 MAC 테이블에 있는가 ===")
hosts = q("SELECT * FROM facility_hosts").fetchall()
stat = Counter()
examples = {"mac있고_스위치테이블에도_있는데_설비엔_미지정": [],
            "mac있는데_스위치테이블에_없음": [],
            "mac자체가_없음": []}
for h in hosts:
    d = dict(h)
    mac = (d.get("mac") or "").upper().replace("-", ":")
    has_sw = bool(d.get("switch_name"))
    if not mac:
        stat["mac자체가_없음"] += 1
        if len(examples["mac자체가_없음"]) < 5:
            examples["mac자체가_없음"].append(d)
        continue
    if mac in mac_owner:
        if has_sw:
            stat["정상(MAC매칭+스위치지정)"] += 1
        else:
            stat["mac있고_스위치테이블에도_있는데_설비엔_미지정"] += 1
            if len(examples["mac있고_스위치테이블에도_있는데_설비엔_미지정"]) < 8:
                d["_owner"] = mac_owner[mac]
                examples["mac있고_스위치테이블에도_있는데_설비엔_미지정"].append(d)
    else:
        stat["mac있는데_스위치테이블에_없음"] += 1
        if len(examples["mac있는데_스위치테이블에_없음"]) < 5:
            examples["mac있는데_스위치테이블에_없음"].append(d)
for k, v in stat.most_common():
    print("  %-45s %d" % (k, v))

for k, lst in examples.items():
    if not lst:
        continue
    print("\n  -- %s 표본 --" % k)
    for d in lst:
        print("     ip=%-16s mac=%-18s online=%s switch_name=%r via=%r owner=%s" % (
            d.get("ip"), d.get("mac"), d.get("online"), d.get("switch_name"),
            d.get("via"), d.get("_owner", "")))

print("\n=== 6. MAC 표기 정규화 점검(대소문자·구분자 불일치 여부) ===")
raw_fac = [r["mac"] for r in q("SELECT DISTINCT mac FROM facility_hosts "
                               "WHERE mac IS NOT NULL AND mac<>''").fetchall()][:10]
raw_mac = [r["mac"] for r in q("SELECT DISTINCT mac FROM mac_entries LIMIT 10").fetchall()]
print("  facility_hosts.mac 표본:", raw_fac)
print("  mac_entries.mac   표본:", raw_mac)

print("\n=== 7. 최근 설비 이벤트 ===")
try:
    for r in q("SELECT * FROM device_events ORDER BY id DESC LIMIT 12").fetchall():
        d = dict(r)
        print("  %s %-16s %-14s label=%r %s" % (
            d.get("created_at", "")[:19], d.get("ip"), d.get("event_type"),
            d.get("label"), (d.get("message") or "")[:70]))
except Exception as e:
    print("  (device_events 조회 실패:", e, ")")
conn.close()
