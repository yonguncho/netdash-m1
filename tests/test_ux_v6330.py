# -*- coding: utf-8 -*-
"""v6.33.0 — UX 정리 6건(사용자 지적).

① 라이선스 표기 영어 통일 ② 추이 미표시 장비 사유 표시 ③ TV 모드 즉각 피드백
④ 수명주기 배지 → 상세 하단 ⑤ 설비 선택 삭제 ⑥ 비고→결과(설명은 팝업)
+ 관제 빈 카드 슬림화.
"""
from pathlib import Path

from core import db
from core.firewall import fortigate as fgw

ROOT = Path(__file__).parent.parent


# ── ① 라이선스 영어 통일 ─────────────────────────────────────────

def test_license_names_english():
    """FortiGate GUI와 같은 영어 표기 — 장비 화면과 대조 가능해야 한다."""
    lic = fgw.parse_license_status({
        "antivirus": {"status": "licensed", "expires": 1790000000},
        "web_filtering": {"status": "licensed", "expires": 1790000000},
        "appctrl": {"status": "licensed", "expires": 1790000000}})
    names = {x["name"] for x in lic}
    assert names == {"AntiVirus", "Web Filtering", "Application Control"}
    for n in names:
        assert not any("가" <= ch <= "힣" for ch in n), "한글 금지: " + n


# ── ④ 수명주기 배지 → 상세 하단 ──────────────────────────────────

def test_lifecycle_moved_to_detail():
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    # 목록 셀에서는 배지 호출 제거
    model_fn = js[js.index("function fwModelCell"):js.index("function fwVersionCell")]
    ver_fn = js[js.index("function fwVersionCell"):js.index("function tempCell")]
    assert "lifeBadge" not in model_fn and "lifeBadge" not in ver_fn
    # 상세 하단에 수명주기 섹션
    assert "지원 수명주기 (EOS/EoES)" in js


def test_detail_endpoint_attaches_lifecycle(client):
    """상세 API가 모델·버전·수명주기를 실어야 상세 하단에 그릴 수 있다."""
    import app as app_module  # noqa: F401 — client 픽스처의 앱 사용
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    with db.get_db(dbp) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW-LC','fortigate','10.77.0.1','done')")
    fid = db.list_firewalls(dbp)[-1]["id"]
    db.save_device_metrics(dbp, "firewall", fid, {
        "cpu_pct": 5, "model": "FortiGate-1500D", "version": "v7.2.5"})
    d = client.get("/api/firewalls/%d" % fid).get_json()
    fw = d["firewall"]
    assert fw["fw_model"] == "FortiGate-1500D"
    assert fw["lifecycle"]["hw"]["status"], "수명주기 판정이 실려야 한다"


# ── ⑤ 설비 선택 삭제 ────────────────────────────────────────────

def test_delete_facility_hosts_roundtrip(temp_db):
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.%d" % i, "mac": "aa:%02x" % i,
         "online": 1, "direct": 1, "switch_name": "SW", "port": "Gi1/0/%d" % i}
        for i in range(2, 6)])
    n = db.delete_facility_hosts(temp_db, [("10.1.0.0/24", "10.1.0.2"),
                                           ("", "10.1.0.3")])
    assert n == 2
    left = {h["ip"] for h in db.get_facility_hosts(temp_db)}
    assert left == {"10.1.0.4", "10.1.0.5"}
    assert db.delete_facility_hosts(temp_db, []) == 0


def test_delete_hosts_endpoint(client):
    r = client.post("/api/facility/delete-hosts", json={"items": "bad"})
    assert r.status_code == 400
    r = client.post("/api/facility/delete-hosts", json={"items": [{"ip": ""}]})
    assert r.status_code == 400
    r = client.post("/api/facility/delete-hosts",
                    json={"items": [{"subnet": "10.9.0.0/24", "ip": "10.9.0.9"}]})
    assert r.status_code == 200 and r.get_json()["ok"] is True


def test_facility_ui_select_delete_markers():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="btn-fac-delete-sel"' in html and 'id="fac-check-all"' in html
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "/api/facility/delete-hosts" in js and "fac-check" in js


# ── ⑥ 비고 → 결과(설명은 진단 결과 팝업으로) ─────────────────────

def test_facility_result_column_and_popup():
    html = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert ">결과</th>" in html and "<th>비고</th>" not in html
    js = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert ">진단 결과</button>" in js and "data-remarks" in js
    # 설명을 표에 직접 늘어놓던 코드 제거 — 팝업(explainFacility)이 담당
    rows_fn = js[js.index("function _renderFacilityRows"):]
    rows_fn = rows_fn[:rows_fn.index("\nfunction ")]
    assert 'remarks.join(" · ")' not in rows_fn
    assert "explainFacility(ip, remarks)" in js


# ── ②③⑦ 관제 — 미표시 사유·TV 피드백·빈 카드 슬림 ────────────────

def test_wall_series_missing_note():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    assert "fw-series-note" in js and "추이 미표시" in js
    assert "SNMP" in js.split("추이 미표시")[1][:200], "사유(SNMP 무응답)를 함께"


def test_wall_tv_instant_feedback():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    html = (ROOT / "web" / "templates" / "wall.html").read_text(encoding="utf-8")
    assert "wall-tv-ind" in js and "wall-tv-ind" in html
    # 켜는 순간 다음 탭으로 전환(화면상 즉각 변화)
    tv = js[js.index("tv-instant") if "tv-instant" in js else js.index("_tvOn = !_tvOn"):]
    assert "wallShowTab(_TAB_ORDER[(_TAB_ORDER.indexOf(_wtab) + 1)" in tv


def test_wall_empty_card_slim():
    js = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
    css = (ROOT / "web" / "static" / "wall.css").read_text(encoding="utf-8")
    assert "wcard--empty" in js and ".wcard--empty" in css
    assert ".wnote" in css
