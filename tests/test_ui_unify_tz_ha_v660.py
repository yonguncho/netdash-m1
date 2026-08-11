# -*- coding: utf-8 -*-
"""사용자 요청 묶음 (v6.6.0) — 표기 통일 · 시간대 · 방화벽 HA · SSH 포트 탐색.

① 4개 현황(스위치·서버·방화벽·설비) 상태 표기 통일
② 위치 값의 아이콘·색 강조 제거(글씨체 통일)
③ 이름 컬럼 제거 + 호스트네임 맨 좌측(스위치·서버)
④ 서버 CPU·메모리·디스크 → '사양' 1컬럼(내용 잘림 해소)
⑤ 상태별 필터
⑥ 표시 시간대 설정(기본 미국 동부) — 저장값을 UTC로 오해해 4시간 이르게 표시되던 것
⑦ 방화벽 이중화(동일 VIP) 대기 장비가 '수집 실패'로 뜨던 것
⑧ SSH 포트를 22/2222로만 찾던 것 → 배너로 실측 탐색
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import server_collector as sc  # noqa: E402

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "web" / "static" / "style.css").read_text(encoding="utf-8")


# ── ① 상태 표기 통일 ─────────────────────────────────────────────
def test_shared_status_helpers_exist():
    for fn in ("function statusBadge(", "function reachBadge(",
               "function alertBadge(", "function locationCell(",
               "function hostnameCell("):
        assert fn in APPJS, fn


def test_all_four_screens_use_shared_status_badge():
    """화면마다 다른 배지·이모지를 쓰던 것을 하나로 모았다."""
    # 스위치·서버·방화벽 표 + 설비(연결 상태)
    assert APPJS.count("statusBadge(") >= 4, "일부 화면이 여전히 자체 표기를 쓴다"
    # v6.35: 설비 상태는 3단계(연결됨/확인 필요/끊김) — facStateBadge가
    # 내부에서 reachBadge를 재사용한다(표기 통일 유지).
    assert "facStateBadge(h)" in APPJS, "설비 표에 상태 배지가 없다"
    assert "reachBadge(true)" in APPJS and "reachBadge(false)" in APPJS


def test_no_emoji_in_status_cells():
    """🟢/🔴 같은 이모지를 상태 표기에서 제거(글씨체 통일)."""
    assert "🟢 연결됨" not in APPJS and "🔴 끊김" not in APPJS


def test_status_badge_uses_existing_css_classes():
    """CSS에 없는 클래스(--done)를 쓰면 배지가 무색으로 나온다."""
    assert "status-badge--done" not in APPJS
    i = APPJS.index("function _statusCls(")
    body = APPJS[i:i + 400]
    for cls in re.findall(r'"(critical|ok|collecting|new)"', body):
        assert ".status-badge--%s" % cls in CSS, cls


# ── ② 위치 표기 ─────────────────────────────────────────────────
def test_location_cell_has_no_icon_or_color_emphasis():
    i = APPJS.index("function locationCell(")
    body = APPJS[i:i + 500]
    assert "📍" not in body and "#2563eb" not in body
    assert "cell-sub" in body, "원문 위치는 공용 보조 서식으로"


def test_cell_classes_defined_in_css():
    for cls in (".cell-sub", ".cell-none", ".cell-spec"):
        assert cls in CSS, cls


# ── ③ 이름 컬럼 제거 · 호스트네임 좌측 ───────────────────────────
def test_switch_table_hostname_first_no_name_column():
    head = HTML[HTML.index('id="sw-check-all"'):HTML.index('id="switch-table-body"')]
    assert ">호스트네임</th>" in head
    assert ">이름</th>" not in head
    # 구분이 맨 좌측, 그다음 호스트네임
    assert head.index("구분") < head.index("호스트네임") < head.index("IP")


def test_kind_column_is_leftmost_in_both_tables():
    """구분 컬럼이 있는 현황은 구분을 맨 좌측에 둔다(사용자 요청)."""
    sw = HTML[HTML.index('id="sw-check-all"'):HTML.index('id="switch-table-body"')]
    sv = HTML[HTML.index('id="srv-check-all"'):HTML.index('id="server-table-body"')]
    for head in (sw, sv):
        assert head.index("구분") < head.index("호스트네임"), head[:120]


def test_row_cell_order_matches_header_order():
    """헤더만 바꾸고 행을 안 바꾸면 값이 엉뚱한 컬럼에 들어간다."""
    i = APPJS.index("tbody.innerHTML = switches.map(")
    body = APPJS[i:i + 1600]
    assert body.index("kindLabel") < body.index("hostnameCell(sw)")
    j = APPJS.index('"<td style=\'text-align:center\'><input type=\'checkbox\' class=\'srv-check\'')
    sbody = APPJS[j:j + 1200]
    assert sbody.index('"<td>" + kind + "</td>"') < sbody.index("hostnameCell(s)")


def test_server_table_hostname_first_no_name_column():
    head = HTML[HTML.index('id="srv-check-all"'):HTML.index('id="server-table-body"')]
    assert ">호스트네임</th>" in head and ">이름</th>" not in head


def test_uncollected_device_falls_back_to_registered_name():
    """hostname은 수집 성공 후에만 채워진다 — 그대로 두면 IP로만 구분해야 한다."""
    i = APPJS.index("function hostnameCell(")
    body = APPJS[i:i + 400]
    assert "dev.name" in body and "등록 이름" in body


# ── ④ 사양 컬럼 ─────────────────────────────────────────────────
def test_server_spec_column_merged():
    head = HTML[HTML.index('id="srv-check-all"'):HTML.index('id="server-table-body"')]
    assert ">사양</th>" in head
    for gone in (">CPU</th>", ">메모리</th>", ">디스크</th>"):
        assert gone not in head, gone
    assert head.count("</th>") == 13
    assert 'colspan="13"' in HTML and "colspan='13'" in APPJS


def test_spec_cell_keeps_hw_detail_link():
    i = APPJS.index("function specCell(")
    body = APPJS[i:i + 1500]
    assert "data-action='hw-detail'" in body, "장착 구성 팝업 진입이 사라졌다"
    assert "CPU" in body and "MEM" in body and "DISK" in body


# ── ⑤ 상태 필터 ─────────────────────────────────────────────────
def test_status_filter_selects_exist():
    for sid in ("status-filter-sw", "status-filter-srv",
                "status-filter-fw", "status-filter-fac"):
        assert 'id="%s"' % sid in HTML, sid


def test_status_filter_applied_in_renderers():
    assert '_byStatusSel(switches, "status-filter-sw")' in APPJS
    assert '_byStatusSel(_servers, "status-filter-srv")' in APPJS
    assert '_byStatusSel(firewalls, "status-filter-fw"' in APPJS
    assert '_statusFilterValue("status-filter-fac")' in APPJS


def test_firewall_filter_uses_display_status():
    """이중화 대기 장비는 '정상'으로 보이므로 필터도 같은 기준이어야 한다."""
    i = APPJS.index('_byStatusSel(firewalls, "status-filter-fw"')
    assert "status_display" in APPJS[i:i + 200]


# ── ⑥ 표시 시간대 ───────────────────────────────────────────────
def test_fmt_time_no_longer_assumes_utc():
    """DB는 서버 로컬 시각을 저장한다 — UTC로 가정하면 오프셋만큼 어긋난다."""
    i = APPJS.index("function fmtTime(")
    body = APPJS[i:i + 1600]
    assert 's += "Z"' not in body, "저장값에 Z를 붙이면 UTC로 오해한다"
    assert "srvOffsetMin" in body


def test_timezone_setting_ui_and_choices():
    assert 'id="ac-timezone"' in HTML
    for zone in ("America/New_York", "Asia/Seoul", "UTC", "local"):
        assert 'value="%s"' % zone in HTML, zone
    # 기본값(첫 옵션)이 미국 동부여야 한다
    i = HTML.index('id="ac-timezone"')
    assert HTML.index('value="America/New_York"', i) < HTML.index('value="Asia/Seoul"', i)


def test_timezone_saved_and_returned_by_api():
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    assert '"display_timezone"' in src
    assert "ALLOWED_TIMEZONES" in src
    assert "server_tz_offset_min" in src


def test_server_tz_offset_is_signed_minutes():
    import app as app_mod
    off = app_mod._server_tz_offset_min()
    assert isinstance(off, int) and -12 * 60 <= off <= 14 * 60


def test_default_timezone_is_us_eastern():
    import app as app_mod
    assert app_mod.DEFAULT_TIMEZONE == "America/New_York"


# ── ⑦ 방화벽 이중화 ─────────────────────────────────────────────
def test_ha_standby_shown_as_normal():
    from app import annotate_fw_ha
    rows = [{"id": 1, "name": "FW_M", "host": "10.2.2.100", "status": "done"},
            {"id": 2, "name": "FW_B", "host": "10.2.2.100", "status": "failed"}]
    annotate_fw_ha(rows)
    b = rows[1]
    assert b["status_display"] == "done", "정상 이중화가 '수집 실패'로 보인다"
    assert b["ha_via"] == "FW_M"
    assert b["status"] == "failed", "저장된 실제 결과는 보존해야 한다"


def test_standalone_failure_still_failure():
    from app import annotate_fw_ha
    rows = [{"id": 3, "name": "FW-단독", "host": "10.2.2.200", "status": "failed"}]
    annotate_fw_ha(rows)
    assert rows[0]["status_display"] == "failed", "단독 장비 장애를 감춰선 안 된다"


def test_ha_pair_both_failed_stays_failed():
    from app import annotate_fw_ha
    rows = [{"id": 1, "name": "FW_M", "host": "10.9.9.9", "status": "failed"},
            {"id": 2, "name": "FW_B", "host": "10.9.9.9", "status": "failed"}]
    annotate_fw_ha(rows)
    assert all(r["status_display"] == "failed" for r in rows), \
        "짝이 둘 다 죽었는데 정상으로 보이면 장애를 놓친다"


def test_wall_excludes_ha_standby_from_failures():
    import inspect
    import app as app_mod
    src = inspect.getsource(app_mod.create_app)
    i = src.index("fw_failed = [f for f in firewalls")
    assert "status_display" in src[i:i + 120]


def test_firewall_host_column_renamed_to_ip():
    head = HTML[HTML.index('id="firewall-table-body"') - 900:HTML.index('id="firewall-table-body"')]
    assert "<th>IP</th>" in head and "<th>호스트</th>" not in head


# ── ⑧ SSH 포트 탐색 ─────────────────────────────────────────────
def test_ssh_port_discovery_probes_banner():
    assert "def looks_like_ssh" in (ROOT / "core" / "server_collector.py").read_text(encoding="utf-8")
    assert sc.SSH_PORT_CANDIDATES[0] == 22
    assert 2200 in sc.SSH_PORT_CANDIDATES and 22222 in sc.SSH_PORT_CANDIDATES


def test_find_ssh_port_falls_back_to_conventional_when_no_banner(monkeypatch):
    """배너가 안 와도 22가 열려 있으면 기존처럼 시도해야 한다(회귀 방지)."""
    monkeypatch.setattr(sc, "looks_like_ssh", lambda ip, p, timeout=None: False)
    assert sc.find_ssh_port("10.0.0.1", [22, 443]) == 22


def test_find_ssh_port_discovers_nonstandard(monkeypatch):
    monkeypatch.setattr(sc, "looks_like_ssh",
                        lambda ip, p, timeout=None: p == 9022)
    assert sc.find_ssh_port("10.0.0.1", [443, 8081, 9022]) == 9022


def test_find_ssh_port_skips_web_ports(monkeypatch):
    seen = []

    def probe(ip, p, timeout=None):
        seen.append(p)
        return False

    monkeypatch.setattr(sc, "looks_like_ssh", probe)
    sc.find_ssh_port("10.0.0.1", [80, 443, 3389])
    assert not (set(seen) & {80, 443, 3389}), "웹·RDP 포트에 불필요한 연결을 시도한다"


def test_no_ports_means_no_ssh():
    assert sc.find_ssh_port("10.0.0.1", []) is None


def test_collect_uses_find_ssh_port():
    src = (ROOT / "core" / "server_collector.py").read_text(encoding="utf-8")
    assert "ssh_port = find_ssh_port(ip, open_ports)" in src
    assert "SSH 포트(22/2222) 미개방" not in src, "안내 문구가 옛 동작을 설명한다"
