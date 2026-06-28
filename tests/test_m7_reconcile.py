"""M7: 장부 대조(Reconcile) 테스트.

검증 목표:
- reconcile 6판정(match/port_mismatch/switch_mismatch/ledger_only/measured_only/no_data).
- 비교용 normalize_port (인터페이스 타입 접두사 제거, 콜론 유지).
- save_hosts / save_ledger_hosts 양방향 UPSERT가 서로의 컬럼을 보존 (적재 순서 무관).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import correlator, db


# ── 비교용 포트 정규화 ─────────────────────────────────────────────

# 1. 인터페이스 타입 접두사 제거 + 콜론 유지 + None
def test_normalize_port_equivalence():
    assert correlator.normalize_port("GigabitEthernet1/0/5") == correlator.normalize_port("Gi1/0/5")
    assert correlator.normalize_port("Gi1/0/5") == "1/0/5"
    assert correlator.normalize_port("  TenGigE 0/1 ") == "0/1"
    assert correlator.normalize_port("1:12") == "1:12"  # Extreme 콜론 포맷
    assert correlator.normalize_port(None) == ""


# ── reconcile 판정 ─────────────────────────────────────────────────

def _setup(db_path, ledger=None, measured=None, sw_name="ACC-SW01"):
    sid = db.save_switch(db_path, sw_name, "10.0.0.20", "cisco_ios")
    if ledger is not None:
        db.save_ledger_hosts(db_path, [{"ip": "10.0.1.10", "hostname": "WEB-01", **ledger}])
    if measured is not None:
        db.save_hosts(db_path, {"10.0.1.10": {
            "mac": "aa",
            "switch_id": sid if measured.get("on_switch") else None,
            "port": measured.get("port"),
            "located": measured.get("located", False),
        }})
    return sid


# 2. match
def test_reconcile_match(temp_db):
    _setup(temp_db, ledger={"ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"},
           measured={"on_switch": True, "port": "Gi1/0/5", "located": True})
    res = correlator.reconcile(temp_db)
    assert res["summary"].get("match") == 1
    assert res["hosts"][0]["verdict"] == "match"


# 3. port_mismatch
def test_reconcile_port_mismatch(temp_db):
    _setup(temp_db, ledger={"ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"},
           measured={"on_switch": True, "port": "Gi1/0/9", "located": True})
    res = correlator.reconcile(temp_db)
    assert res["hosts"][0]["verdict"] == "port_mismatch"


# 4. switch_mismatch
def test_reconcile_switch_mismatch(temp_db):
    sid_other = db.save_switch(temp_db, "CORE-SW", "10.0.0.99", "cisco_ios")
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "hostname": "WEB-01",
                                    "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"}])
    db.save_hosts(temp_db, {"10.0.1.10": {"mac": "aa", "switch_id": sid_other,
                                          "port": "Gi1/0/5", "located": True}})
    res = correlator.reconcile(temp_db)
    assert res["hosts"][0]["verdict"] == "switch_mismatch"


# 5. ledger_only
def test_reconcile_ledger_only(temp_db):
    _setup(temp_db, ledger={"ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"})
    res = correlator.reconcile(temp_db)
    assert res["hosts"][0]["verdict"] == "ledger_only"


# 6. measured_only
def test_reconcile_measured_only(temp_db):
    _setup(temp_db, measured={"on_switch": True, "port": "Gi1/0/5", "located": True})
    res = correlator.reconcile(temp_db)
    assert res["hosts"][0]["verdict"] == "measured_only"


# 7. no_data (장부 위치 없음 + 실측 안 됨)
def test_reconcile_no_data(temp_db):
    db.save_switch(temp_db, "ACC-SW01", "10.0.0.20", "cisco_ios")
    # 장부에 스위치 위치 없이 등록 + 미측정
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "hostname": "WEB-01",
                                    "ledger_switch": "", "ledger_port": ""}])
    res = correlator.reconcile(temp_db)
    assert res["hosts"][0]["verdict"] == "no_data"


# 8. summary 카운트
def test_reconcile_summary_counts(temp_db):
    sid = db.save_switch(temp_db, "ACC-SW01", "10.0.0.20", "cisco_ios")
    db.save_ledger_hosts(temp_db, [
        {"ip": "10.0.1.10", "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"},
        {"ip": "10.0.1.11", "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/6"},
    ])
    db.save_hosts(temp_db, {
        "10.0.1.10": {"mac": "aa", "switch_id": sid, "port": "Gi1/0/5", "located": True},   # match
        "10.0.1.11": {"mac": "bb", "switch_id": sid, "port": "Gi1/0/99", "located": True},  # port_mismatch
    })
    res = correlator.reconcile(temp_db)
    assert res["summary"]["match"] == 1
    assert res["summary"]["port_mismatch"] == 1


# ── UPSERT 컬럼 보존 (핵심 통합) ───────────────────────────────────

# 9. 장부 적재 후 save_hosts(측정)가 ledger 컬럼을 보존
def test_save_hosts_preserves_ledger(temp_db):
    sid = db.save_switch(temp_db, "ACC-SW01", "10.0.0.20", "cisco_ios")
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "hostname": "WEB-01",
                                    "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"}])
    # 측정값이 나중에 들어와도 ledger가 살아있어야 match
    db.save_hosts(temp_db, {"10.0.1.10": {"mac": "aa", "switch_id": sid,
                                          "port": "Gi1/0/5", "located": True}})
    rows = {h["ip"]: h for h in db.list_hosts(temp_db)}
    assert rows["10.0.1.10"]["ledger_switch"] == "ACC-SW01"
    assert rows["10.0.1.10"]["ledger_port"] == "Gi1/0/5"
    assert rows["10.0.1.10"]["located"] == 1


# 10. 실측 적재 후 save_ledger_hosts가 측정 컬럼을 보존
def test_save_ledger_preserves_measured(temp_db):
    sid = db.save_switch(temp_db, "ACC-SW01", "10.0.0.20", "cisco_ios")
    db.save_hosts(temp_db, {"10.0.1.10": {"mac": "aa", "switch_id": sid,
                                          "port": "Gi1/0/5", "located": True}})
    # 장부가 나중에 들어와도 측정값 보존
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "hostname": "WEB-01",
                                    "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"}])
    rows = {h["ip"]: h for h in db.list_hosts(temp_db)}
    assert rows["10.0.1.10"]["switch_id"] == sid
    assert rows["10.0.1.10"]["port"] == "Gi1/0/5"
    assert rows["10.0.1.10"]["located"] == 1
    assert rows["10.0.1.10"]["hostname"] == "WEB-01"


# ── normalize_port edge cases (Opus R1 C3/C4 회귀) ─────────────────

# 11. 서브인터페이스는 전체 보존 (1/0/5.100 → 100 으로 축소되면 안 됨)
def test_normalize_port_subinterface_preserved():
    assert correlator.normalize_port("GigabitEthernet1/0/5.100") == "1/0/5.100"
    assert correlator.normalize_port("Gi1/0/5.100") == "1/0/5.100"
    # 서로 다른 서브인터페이스는 다르게 정규화
    assert correlator.normalize_port("Gi1/0/5.100") != correlator.normalize_port("Gi1/0/5.200")


# 12. 논리/특수 포트는 물리 포트와 충돌하지 않음
def test_normalize_port_logical_ports_no_collision():
    # Po1(port-channel)·Mgmt0·Vlan10 은 물리 1·0·10 과 달라야 함
    assert correlator.normalize_port("Po1") != correlator.normalize_port("1")
    assert correlator.normalize_port("Mgmt0") != correlator.normalize_port("0")
    assert correlator.normalize_port("Vlan10") != correlator.normalize_port("10")
    # 물리 이더넷 타입은 여전히 동등
    assert correlator.normalize_port("Eth1/1") == correlator.normalize_port("Ethernet1/1")


# 13. 스위치명 FQDN suffix 차이는 match (장부 단축명 vs 실측 FQDN)
def test_reconcile_switch_fqdn_match(temp_db):
    sid = db.save_switch(temp_db, "acc-sw01.corp.local", "10.0.0.20", "cisco_ios")
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "ledger_switch": "ACC-SW01",
                                    "ledger_port": "Gi1/0/5"}])
    db.save_hosts(temp_db, {"10.0.1.10": {"mac": "aa", "switch_id": sid,
                                          "port": "Gi1/0/5", "located": True}})
    res = correlator.reconcile(temp_db)
    assert res["hosts"][0]["verdict"] == "match"


# ── ledger Excel 적재 경로 (Opus R1 C1 회귀) ───────────────────────

# 14. excel_loader가 연결스위치/연결포트를 ledger 컬럼으로 파싱
def test_excel_loader_parses_ledger_columns(tmp_path):
    from openpyxl import Workbook
    from core import excel_loader

    wb = Workbook(); ws = wb.active
    ws.append(["ip", "사용서버명", "연결스위치", "연결포트"])
    ws.append(["10.0.1.10", "WEB-01", "ACC-SW01", "Gi1/0/5"])
    path = tmp_path / "ledger.xlsx"
    wb.save(str(path))

    result = excel_loader.load_workbook(str(path))
    assert len(result["hosts"]) == 1
    h = result["hosts"][0]
    # _norm으로 소문자화/공백제거됨
    assert h["ledger_switch"] == "acc-sw01"
    assert h["ledger_port"] == "gi1/0/5"
    assert h["hostname"] == "web-01"


# 15. [Opus R2 W1 회귀] 재적재 시 빈값이 기존 장부값을 지우지 않음
def test_save_ledger_preserves_existing_on_empty(temp_db):
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "hostname": "WEB-01",
                                    "ledger_switch": "ACC-SW01", "ledger_port": "Gi1/0/5"}])
    # hostname/ledger 컬럼이 없는 시트 재업로드 (빈값) → 기존값 보존
    db.save_ledger_hosts(temp_db, [{"ip": "10.0.1.10", "mac": "aa:bb"}])
    rows = {h["ip"]: h for h in db.list_hosts(temp_db)}
    assert rows["10.0.1.10"]["hostname"] == "WEB-01"
    assert rows["10.0.1.10"]["ledger_switch"] == "ACC-SW01"
    assert rows["10.0.1.10"]["ledger_port"] == "Gi1/0/5"
    assert rows["10.0.1.10"]["mac"] == "aa:bb"  # 새 mac은 갱신


# 16. [Opus R2 W3 회귀] Juniper xe-/ge- 접두사도 물리 포트로 정규화
def test_normalize_port_juniper_prefixes():
    assert correlator.normalize_port("xe-0/0/1") == "0/0/1"
    assert correlator.normalize_port("ge-0/0/1") == "0/0/1"
    # 장부 단축 표기와 실측 풀 표기가 동등 비교됨
    assert correlator.normalize_port("xe-0/0/1") == correlator.normalize_port("0/0/1")
