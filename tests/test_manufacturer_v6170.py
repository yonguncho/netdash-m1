# -*- coding: utf-8 -*-
"""제품 정보 → 제조사(벤더사) 판별 (v6.17.0).

사용자 지적: 방화벽 현황의 '벤더'가 fortigate로 나오는데 FortiGate는 제품이고
벤더사는 Fortinet이다. 스위치의 cisco_ios도 마찬가지로 드라이버 키다.
"""
from core import manufacturer as mf


def test_firewall_product_keys_map_to_company():
    """신고된 그 건 — fortigate는 제품, 제조사는 Fortinet."""
    assert mf.resolve(vendor="fortigate") == "Fortinet"
    assert mf.resolve(vendor="paloalto") == "Palo Alto Networks"


def test_switch_driver_keys_map_to_company():
    assert mf.resolve(vendor="cisco_nxos") == "Cisco"
    assert mf.resolve(vendor="cisco_ios") == "Cisco"
    assert mf.resolve(vendor="arista_eos") == "Arista"
    assert mf.resolve(vendor="juniper_junos") == "Juniper"
    assert mf.resolve(vendor="extreme_exos") == "Extreme Networks"
    assert mf.resolve(vendor="alteon") == "Radware"
    assert mf.resolve(vendor="aruba_os") == "HPE Aruba"


def test_case_and_whitespace_tolerant():
    assert mf.resolve(vendor="  FortiGate  ") == "Fortinet"
    assert mf.resolve(vendor="CISCO_NXOS") == "Cisco"


# --- "앞으로 제품정보를 보고 벤더사를 판단" — 모델명 추론 --------------------

def test_model_infers_company_when_driver_unknown():
    """드라이버를 모를 때 수집된 모델명으로 제조사를 알아낸다."""
    cases = [
        ("N9K-C9508", "Cisco"),
        ("WS-C2960X-48TS-L", "Cisco"),
        ("C9300-48P", "Cisco"),
        ("PA-3220", "Palo Alto Networks"),
        ("FG-100F", "Fortinet"),
        ("FortiGate-601E", "Fortinet"),
        ("DCS-7050SX3-48YC8", "Arista"),
        ("EX4300-48T", "Juniper"),
        ("SRX345", "Juniper"),
        ("X460-48t", "Extreme Networks"),
        ("JL256A", "HPE Aruba"),
    ]
    for model, maker in cases:
        assert mf.resolve(vendor="unknown", model=model) == maker, model


def test_driver_key_wins_over_model():
    """드라이버 키가 가장 확실한 근거 — 모델 추론보다 앞선다."""
    assert mf.resolve(vendor="cisco_nxos", model="JL256A") == "Cisco"


def test_os_string_used_as_last_resort():
    assert mf.resolve(model="", os_info="NX-OS version 9.3(8)") == "Cisco"
    assert mf.resolve(os_info="FortiOS v7.2.5") == "Fortinet"
    assert mf.resolve(os_info="ExtremeXOS 30.7") == "Extreme Networks"


def test_unknown_returns_empty_not_a_guess():
    """모르면서 아무 제조사나 적으면 자산 목록이 조용히 틀린다."""
    assert mf.resolve() == ""
    assert mf.resolve(vendor="unknown") == ""
    assert mf.resolve(vendor="", model="ZZ-9000", os_info="") == ""


def test_product_label_is_not_the_company():
    """'제품' 컬럼은 제품 계열을 보여준다(드라이버 키 노출 금지)."""
    assert mf.product_label("fortigate") == "FortiGate"
    assert mf.product_label("cisco_nxos") == "Cisco NX-OS"
    assert mf.product_label("paloalto") == "PAN-OS"
    # 모르는 값은 원래 값 그대로 — 빈칸으로 만들어 정보를 잃지 않는다
    assert mf.product_label("weird_thing") == "weird_thing"


def test_annotate_adds_both_fields():
    rows = [{"vendor": "fortigate"}, {"vendor": "unknown", "model": "N9K-C9508"}]
    mf.annotate(rows)
    assert rows[0]["manufacturer"] == "Fortinet" and rows[0]["product"] == "FortiGate"
    assert rows[1]["manufacturer"] == "Cisco"


def test_annotate_survives_bad_rows():
    """한 행이 이상해도 목록 전체가 죽으면 안 된다."""
    rows = [{"vendor": "fortigate"}, None]
    try:
        mf.annotate([r for r in rows if r is not None])
    except Exception as e:
        raise AssertionError("annotate가 예외를 올리면 안 된다: %s" % e)


# --- API·화면 연동 -----------------------------------------------------------

def test_firewall_api_returns_manufacturer(tmp_path, monkeypatch):
    """방화벽 목록이 제조사와 제품을 나눠서 준다 — 신고된 그 화면."""
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import db, collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    with db.get_db(dbp) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                     ("FW-01", "fortigate", "10.0.0.1"))
    fws = application.test_client().get("/api/firewalls").get_json()["firewalls"]
    row = [f for f in fws if f["name"] == "FW-01"][0]
    assert row["manufacturer"] == "Fortinet"
    assert row["product"] == "FortiGate"
    assert row["vendor"] == "fortigate", "원래 드라이버 키는 그대로 유지(수집에 쓰인다)"


def test_switch_api_returns_manufacturer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import app as app_module
    from core import db, collector
    application = app_module.create_app(demo_mode=True)
    collector.shutdown_workers()
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_switch(dbp, "BB", "10.9.9.9", "cisco_nxos")
    sws = application.test_client().get("/api/switches").get_json()["switches"]
    row = [s for s in sws if s["name"] == "BB"][0]
    assert row["manufacturer"] == "Cisco" and row["product"] == "Cisco NX-OS"


def test_ui_shows_manufacturer_column():
    from pathlib import Path
    root = Path(__file__).parent.parent
    js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")
    html = (root / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert ">제조사</th>" in html and ">제품</th>" in html
    assert "f.manufacturer" in js
    # 스위치 표도 서버 판별을 우선해야 한다(판별 규칙이 둘로 갈라지지 않게)
    assert "sw.manufacturer || _vendorLabel(sw.vendor)" in js


def test_export_uses_same_resolution(temp_db):
    """엑셀 내보내기도 같은 판별을 써야 한다 — 세 번째 경로(표·API·엑셀)."""
    from core import db, exporter
    db.save_switch(temp_db, "BB", "10.9.9.9", "cisco_nxos")
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                     ("FW-01", "fortigate", "10.0.0.1"))
    sw = exporter.switches_rows(temp_db)[0]
    assert sw["벤더"] == "Cisco" and sw["제품"] == "Cisco NX-OS"
    fw = exporter.firewalls_rows(temp_db)[0]
    assert fw["벤더"] == "Fortinet" and fw["제품"] == "FortiGate"
    assert "제품" in exporter.SWITCH_COLS and "제품" in exporter.FIREWALL_COLS
