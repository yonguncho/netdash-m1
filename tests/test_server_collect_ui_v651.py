# -*- coding: utf-8 -*-
"""사용자 보고 2건 (v6.5.1).

① 서버 현황에서 수집해도 상태가 'collecting'으로 바뀌지 않는다
   → 일괄 수집 경로가 진행바만 갱신하고 표는 완료 시점에 1회만 새로고침했다.
     (스위치 표는 5초 전역 폴러가 있어 증상이 없었다)
② 장착 구성 팝업의 디스크 줄에 `<span style='color:#64748b'> (76%)</span>` 가
   글자로 보인다 → HTML을 돌려주는 fmtDisk()를 escHtml()로 감쌌다.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db  # noqa: E402

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


# ── ① 수집 중 표 갱신 ────────────────────────────────────────────
def test_poll_progress_supports_on_tick():
    """수집 중에도 표를 갱신할 훅이 있어야 한다."""
    i = APPJS.index("function pollProgress(")
    sig = APPJS[i:i + 120]
    assert "onTick" in sig, "완료 콜백만 있으면 수집 중 상태 변화를 볼 수 없다"
    body = APPJS[i:i + 900]
    assert "if (st.running && typeof onTick === \"function\") onTick(st);" in body


def test_server_bulk_collect_refreshes_table_during_run():
    for anchor in ('pollProgress("/api/servers/collect-all/status", "server-progress"',):
        idx = 0
        found = 0
        while True:
            j = APPJS.find(anchor, idx)
            if j < 0:
                break
            found += 1
            tail = APPJS[j:j + 300]
            assert "loadServers);" in tail, "수집 중 표 갱신 훅이 없다: %s" % tail[:120]
            idx = j + 1
        assert found >= 1, "서버 일괄 수집 폴러를 찾지 못했다"


def test_firewall_bulk_collect_refreshes_table_during_run():
    j = APPJS.index('pollProgress("/api/firewalls/collect-all/status", "firewall-progress"')
    assert "loadFirewalls);" in APPJS[j:j + 300]


def test_backend_sets_collecting_status_promptly(temp_db, monkeypatch):
    """백엔드는 수집 시작 직후 상태를 collecting으로 기록한다(전제 확인)."""
    from core import server_collector
    sid = db.save_server(temp_db, "SRV-1", "10.77.77.77")
    seen = []

    orig = server_collector.scan_ports

    def slow_scan(ip, *a, **k):
        seen.append(db.get_server(temp_db, sid)["status"])
        return []

    monkeypatch.setattr(server_collector, "scan_ports", slow_scan)
    monkeypatch.setattr(server_collector, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(server_collector, "netbios_name", lambda ip: None)
    server_collector.collect_server(temp_db, sid, None, None)
    assert seen and seen[0] == "collecting", \
        "포트 스캔 시점에 이미 collecting이어야 한다(실제 관측: %s)" % seen
    assert orig is not None


# ── ② 장착 구성 팝업 HTML 누출 ───────────────────────────────────
def test_disk_text_helper_exists_and_is_plain():
    """escHtml()로 감싸는 자리용 순수 텍스트 함수가 있어야 한다."""
    assert "function fmtDiskText(" in APPJS
    i = APPJS.index("function fmtDiskText(")
    body = APPJS[i:i + 400]
    assert "<span" not in body, "텍스트 전용 함수가 HTML을 만들면 같은 문제가 반복된다"
    assert "%)" in body


def test_hw_detail_popup_uses_text_variant():
    i = APPJS.index("html += \"<h4 style='margin:0 0 6px;font-size:13px'>디스크 \"")
    line = APPJS[i:i + 200]
    assert "fmtDiskText(s)" in line, "HTML을 돌려주는 fmtDisk를 escHtml로 감싸면 태그가 글자로 보인다"
    assert "escHtml(fmtDisk(s))" not in APPJS


def test_table_cell_still_shows_colored_usage():
    """표 셀은 색상 표시를 유지해야 한다(과잉 수정 방지)."""
    i = APPJS.index("function diskCell(")
    body = APPJS[i:i + 500]
    assert "fmtDisk(s)" in body and "fmtDiskText" not in body


def test_fmtdisk_html_contract_is_documented():
    """다음 사람이 같은 실수를 하지 않도록 계약을 주석으로 남긴다."""
    i = APPJS.index("function fmtDisk(s)")
    head = APPJS[max(0, i - 400):i]
    assert "HTML" in head and "escHtml" in head
