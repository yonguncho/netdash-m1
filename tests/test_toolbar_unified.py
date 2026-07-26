# -*- coding: utf-8 -*-
"""현황 페이지 툴바 통일 + 공통 계정 입력칸 제거(보안) 가드."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

ROOT = Path(__file__).parent.parent
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
APP_JS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


def _toolbar(tab):
    m = re.search(r'<div id="tab-%s".*?<div class="pane-toolbar__actions">(.*?)</div>\s*</div>'
                  % tab, HTML, re.S)
    assert m, "%s 툴바를 찾지 못함" % tab
    return m.group(1)


def test_all_pages_have_search():
    """모든 현황 페이지에 검색 입력이 있다."""
    for tab, sid in [("dashboard", "loc-filter-dash"), ("room", "loc-filter-room"),
                     ("firewall", "fw-search"), ("switch", "loc-filter-sw"),
                     ("server", "server-search"), ("facility", "fac-search")]:
        assert 'id="%s"' % sid in _toolbar(tab), "%s 검색 없음" % tab


def test_all_pages_have_download():
    """모든 현황 페이지에 다운로드(CSV/TXT 선택) 버튼이 있다."""
    for tab, kind in [("room", "serverroom"), ("firewall", "firewalls"),
                      ("switch", "switches"), ("server", "servers"), ("facility", "facility")]:
        assert 'data-export="%s"' % kind in _toolbar(tab), "%s 다운로드 없음" % tab


def test_collect_and_diagnose_buttons():
    """정보 수집·전체 진단이 주요 페이지에 공통으로 있다."""
    assert 'id="btn-sw-collect"' in _toolbar("switch")
    assert 'id="btn-diagnose-all"' in _toolbar("switch")
    assert 'id="btn-firewall-collect-all"' in _toolbar("firewall")
    assert 'id="btn-fw-diagnose-all"' in _toolbar("firewall")
    assert 'id="btn-server-collect-all"' in _toolbar("server")
    assert 'id="btn-server-diagnose"' in _toolbar("server")
    assert 'id="btn-room-collect"' in _toolbar("room")
    assert 'id="btn-room-diagnose"' in _toolbar("room")


def test_bulk_delete_buttons():
    assert 'id="btn-sw-bulk-delete"' in _toolbar("switch")
    assert 'id="btn-fw-bulk-delete"' in _toolbar("firewall")
    assert 'id="btn-server-bulk-delete"' in _toolbar("server")
    assert 'id="btn-dash-bulk-delete"' in _toolbar("dashboard")


def test_excel_import_buttons():
    """엑셀 등록: 스위치·서버·방화벽(현황판 포함)."""
    assert 'id="btn-sw-import"' in _toolbar("switch")
    assert 'id="btn-server-import"' in _toolbar("server")
    assert 'id="btn-firewall-import"' in _toolbar("firewall")
    assert 'id="btn-import-excel"' in _toolbar("dashboard")


def test_switch_page_specific():
    """스위치: 설정(config) 다운로드 + 단건 추가."""
    tb = _toolbar("switch")
    assert 'id="btn-configs-export"' in tb and "설정 다운로드" in tb
    assert 'id="btn-sw-add"' in tb


def test_room_page_specific():
    """서버실: 카드뷰·랙뷰 + '다운로드' 명칭."""
    tb = _toolbar("room")
    assert 'id="btn-room-card"' in tb and 'id="btn-room-rack"' in tb
    assert "⬇ 다운로드" in tb


def test_firewall_table_has_checkbox():
    assert 'id="fw-check-all"' in HTML
    assert "fw-check" in APP_JS and "_fwSel" in APP_JS


def test_common_credential_inputs_removed():
    """보안: 툴바의 공통 계정/비밀번호 평문 입력칸이 노출되지 않는다."""
    for tab in ("dashboard", "server"):
        tb = _toolbar(tab)
        assert 'placeholder="공통 계정"' not in tb
        assert 'placeholder="공통 SSH 계정"' not in tb
        assert 'placeholder="비밀번호"' not in tb
    # 기존 JS 호환용 hidden 필드는 유지(값은 비어 있음)
    assert 'type="hidden" id="dash-cred-user"' in HTML
    assert 'type="hidden" id="server-common-user"' in HTML
    # 수집은 팝업(모달)에서 계정을 받는다
    assert 'id="modal-bulk-collect"' in HTML and 'id="modal-server-collect"' in HTML


def test_firewall_collect_supports_ids(client):
    """방화벽 정보 수집이 선택 항목(ids)만 대상으로 동작."""
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    a = db.save_firewall(dbp, "FW-A", "fortigate", "10.20.0.1", 443)
    db.save_firewall(dbp, "FW-B", "fortigate", "10.20.0.2", 443)
    r = client.post("/api/firewalls/collect-all", json={"ids": [a]})
    assert r.status_code in (202, 409)
    if r.status_code == 202:
        assert r.get_json()["total"] == 1      # 선택 1대만 대상
