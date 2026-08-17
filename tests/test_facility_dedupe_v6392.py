# -*- coding: utf-8 -*-
"""v6.39.2 — 같은 IP가 대역 표기만 다르게 중복 저장되던 문제 (사용자 신고).

설비 현황에 동일한 IP·MAC이 두 줄로 보였다. 유일 제약이 (subnet, ip)라서
같은 구간을 10.92.140.0/24로 수집한 뒤 10.92.140.0/22로 다시 수집하면
같은 설비가 별도 행이 된다. IP는 망에서 유일하므로 한 IP당 한 행만 남긴다.
"""
import os
import tempfile

import pytest

from core import db


@pytest.fixture()
def dbf():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db.init_db(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


def _rows(dbf, ip):
    with db.get_db(dbf) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT subnet, ip, mac, updated FROM facility_hosts WHERE ip=?", (ip,))]


def _raw_insert(dbf, subnet, ip, mac="aa:bb", updated="2026-01-01 00:00:00"):
    """중복 상황을 만들기 위해 저장 필터를 우회해 직접 넣는다."""
    with db.get_db(dbf) as conn:
        conn.execute(
            "INSERT INTO facility_hosts (subnet, ip, mac, online, updated) "
            "VALUES (?,?,?,1,?)", (subnet, ip, mac, updated))
        conn.commit()


# ── 저장 시점 차단 ────────────────────────────────────────────────

def test_save_replaces_row_with_other_subnet(dbf):
    """/24로 수집한 뒤 /22로 재수집해도 한 줄이어야 한다(사용자가 본 증상)."""
    db.save_facility_hosts(dbf, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.5", "mac": "aa:01", "online": 1}])
    db.save_facility_hosts(dbf, [
        {"subnet": "10.92.140.0/22", "ip": "10.92.140.5", "mac": "aa:01", "online": 1}])
    rows = _rows(dbf, "10.92.140.5")
    assert len(rows) == 1
    assert rows[0]["subnet"] == "10.92.140.0/22"      # 마지막 수집이 남는다


def test_replace_subnet_also_drops_other_subnet_rows(dbf):
    """대역 교체 경로도 같은 규칙 — 한쪽만 고치면 반드시 뚫린다."""
    db.save_facility_hosts(dbf, [
        {"subnet": "10.50.0.0/24", "ip": "10.50.0.9", "mac": "bb:02", "online": 1}])
    db.replace_facility_subnet(dbf, "10.50.0.0/16", [
        {"subnet": "10.50.0.0/16", "ip": "10.50.0.9", "mac": "bb:02", "online": 1}])
    rows = _rows(dbf, "10.50.0.9")
    assert len(rows) == 1 and rows[0]["subnet"] == "10.50.0.0/16"


def test_save_keeps_different_ips(dbf):
    """다른 IP는 당연히 각자 남아야 한다(과도한 삭제 방지)."""
    db.save_facility_hosts(dbf, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.1", "mac": "a", "online": 1},
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.2", "mac": "b", "online": 1}])
    with db.get_db(dbf) as conn:
        assert conn.execute("SELECT COUNT(*) FROM facility_hosts").fetchone()[0] == 2


def test_save_same_subnet_updates_in_place(dbf):
    """같은 대역·같은 IP 재수집은 갱신(행이 늘지 않는다)."""
    for on in (1, 0):
        db.save_facility_hosts(dbf, [
            {"subnet": "10.2.0.0/24", "ip": "10.2.0.3", "mac": "c", "online": on}])
    rows = _rows(dbf, "10.2.0.3")
    assert len(rows) == 1


# ── 이미 쌓인 중복 정리 ───────────────────────────────────────────

def test_dedupe_keeps_most_recent(dbf):
    """남길 행은 **가장 최근 갱신** — 사용자가 마지막에 수집한 현재 상태."""
    _raw_insert(dbf, "10.99.0.0/24", "10.99.0.7", updated="2026-08-01 10:00:00")
    _raw_insert(dbf, "10.99.0.0/22", "10.99.0.7", updated="2026-08-05 10:00:00")
    _raw_insert(dbf, "10.99.0.0/16", "10.99.0.7", updated="2026-08-09 10:00:00")
    assert db.dedupe_facility_by_ip(dbf) == 2
    rows = _rows(dbf, "10.99.0.7")
    assert len(rows) == 1 and rows[0]["subnet"] == "10.99.0.0/16"


def test_dedupe_is_idempotent(dbf):
    """두 번 눌러도 더 지울 게 없어야 한다(재매칭은 여러 번 눌린다)."""
    _raw_insert(dbf, "10.3.0.0/24", "10.3.0.1")
    _raw_insert(dbf, "10.3.0.0/22", "10.3.0.1")
    assert db.dedupe_facility_by_ip(dbf) == 1
    assert db.dedupe_facility_by_ip(dbf) == 0


def test_dedupe_does_not_touch_unique_ips(dbf):
    _raw_insert(dbf, "10.4.0.0/24", "10.4.0.1")
    _raw_insert(dbf, "10.4.0.0/24", "10.4.0.2")
    assert db.dedupe_facility_by_ip(dbf) == 0
    with db.get_db(dbf) as conn:
        assert conn.execute("SELECT COUNT(*) FROM facility_hosts").fetchone()[0] == 2


def test_dedupe_on_empty_table(dbf):
    assert db.dedupe_facility_by_ip(dbf) == 0


def test_rematch_cleans_existing_duplicates(dbf):
    """사용자 동선: 설비 현황 ↻ 새로고침(재매칭)을 누르면 정리된다."""
    from core import facility
    _raw_insert(dbf, "10.5.0.0/24", "10.5.0.1", updated="2026-08-01 10:00:00")
    _raw_insert(dbf, "10.5.0.0/22", "10.5.0.1", updated="2026-08-09 10:00:00")
    facility.rematch(dbf)
    assert len(_rows(dbf, "10.5.0.1")) == 1


def test_rematch_reports_dedupe_count():
    """조용히 지우면 '왜 줄었지?'가 된다 — 화면에 개수를 알려야 한다."""
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod)
    assert "dedupe_facility_by_ip(db_path)" in src
    assert '"deduped": deduped' in src
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "web", "static", "app.js")
    with open(p, encoding="utf-8") as f:
        js = f.read()
    assert "res.deduped" in js and "중복" in js


def test_rematch_result_not_wiped_by_polling():
    """결과를 #fac-progress 에 쓰면 설비 상태 폴링이 곧바로 innerHTML을 비워
    사용자가 볼 수 없다(실제로 등록 장비 제외 안내도 그렇게 묻혔다).
    전용 영역에 써야 한다."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "web", "static", "app.js"), encoding="utf-8") as f:
        js = f.read()
    with open(os.path.join(root, "web", "templates", "index.html"), encoding="utf-8") as f:
        html = f.read()
    assert 'id="fac-rematch-note"' in html
    i = js.index('document.getElementById("btn-fac-refresh")')
    blk = js[i:js.index("rf.disabled = false;", i)]      # 재매칭 핸들러 구간만
    assert "_facNote(" in blk
    # 주석에서 이유를 설명하며 이름을 언급할 수는 있다 — **실제 조회**만 금지.
    assert 'getElementById("fac-progress")' not in blk, \
        "재매칭 결과를 폴링이 지우는 영역에 쓰고 있다"
