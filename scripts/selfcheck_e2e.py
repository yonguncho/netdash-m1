# -*- coding: utf-8 -*-
"""릴리스 전 셀프체크 — 사용자가 하듯 실제로 눌러보고 살펴본다.

배경: pytest는 함수를, 스크린샷은 '그려졌는가'를 검증하지만, 사용자가 보고한
버그의 다수는 그 사이에 있었다 — 버튼을 눌렀을 때의 동작(.then 중복), 사용자
눈에 무의미한 표기(0/0, 이유 없는 누락). 이 스크립트는 그 간극을 메운다:

  ① 흐름 클릭: 탭 전환·상세보기·일괄 수집 모달→실행·관제 탭/팝업/기간 전환
  ② 오류 수집: pageerror + console(.catch에 잡힌 것 포함, CSP 잡음 제외)
  ③ 표기 검사: 화면 텍스트의 undefined/NaN/[object Object]
  ④ 스크린샷: build/selfcheck/*.png — 릴리스 전에 직접 눈으로 훑는다

실행: python scripts/selfcheck_e2e.py   (exit 0 = 통과)
릴리스 게이트: 전체 pytest PASS + 이 스크립트 PASS + 스크린샷 육안 검토.
"""
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
URL = "http://127.0.0.1:8082"
OUT = ROOT / "build" / "selfcheck"

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("  FAIL:", msg)


def ok(msg):
    print("  ok:", msg)


def wait_health(timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(URL + "/api/state", timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def seed(dbp):
    """부분 수집 상태를 만든다 — 빈 화면·전부 정상 화면만 보면 결함이 숨는다.

    멱등: 이전 실행이 중간에 죽어 시드가 남아 있어도 지우고 다시 심는다
    (실제로 검증 스크립트 잔재 때문에 UNIQUE 충돌로 죽은 적 있음)."""
    from core import db
    with db.get_db(dbp) as conn:
        conn.execute("DELETE FROM firewalls WHERE name LIKE 'SC-FW-%'")
        conn.execute("DELETE FROM servers WHERE name = 'SC-SRV'")
        conn.execute("DELETE FROM traffic_history WHERE port = 'Gi1/0/48'")
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('SC-FW-OK','fortigate','10.99.0.1','done')")
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('SC-FW-NEW','fortigate','10.99.0.2','new')")
    fid = db.list_firewalls(dbp)[-2]["id"]
    db.save_device_metrics(dbp, "firewall", fid, {
        "cpu_pct": 41, "mem_pct": 63, "sessions": 12000, "level": "normal",
        "model": "FortiGate-1100E", "version": "v7.2.5",
        "vpn": {"tunnel_total": 2, "tunnel_up": 1, "tunnels": [
            {"name": "SC-T-UP", "status": "up", "peer": "203.0.113.1"},
            {"name": "SC-T-DN", "status": "down", "peer": "203.0.113.2"}]},
        "policy": {"total": 99, "proxy_total": 4, "unused": 7, "disabled": 1},
        "license": [{"key": "ips", "name": "IPS", "status": "licensed",
                     "expires": "2027-01-01"}],
        "objects": {"address": 10, "total": 10}})
    # 업링크 트래픽 시계열(v6.29) — 차트가 실데이터로 그려지는지 확인
    sws = db.get_switches(dbp)
    if sws:
        sid = sws[0]["id"]
        with db.get_db(dbp) as conn:
            for i in range(24):
                conn.execute(
                    "INSERT INTO traffic_history (switch_id, port, ts, in_bps, out_bps) "
                    "VALUES (?, 'Gi1/0/48', datetime('now','localtime', ?), ?, ?)",
                    (sid, "-%d minutes" % (i * 5),
                     40_000_000 + i * 1_000_000, 8_000_000 + i * 300_000))
    # 토폴로지 자동 연결(v6.32) — 데모 스위치 1↔2 인접 시드(스위치별 교체라 멱등)
    sws2 = db.get_switches(dbp)
    if len(sws2) >= 2:
        db.save_neighbors(dbp, sws2[0]["id"], [
            {"local_port": "Te1/1/1", "remote_name": sws2[1]["name"],
             "remote_port": "Te2/1/1", "remote_ip": sws2[1]["ip"]}])
    # 설비 + 서버(랙) — 서버실·설비 흐름용
    db.save_facility_hosts(dbp, [
        {"subnet": "10.99.1.0/24", "ip": "10.99.1.%d" % i, "mac": "sc:%02x" % i,
         "online": 1 if i % 3 else 0, "direct": 1,
         "switch_name": "SW-CORE-01", "port": "Gi1/0/%d" % i} for i in range(2, 12)])
    with db.get_db(dbp) as conn:
        conn.execute("INSERT INTO servers (name, ip, location) "
                     "VALUES ('SC-SRV','10.99.2.1','A09U27')")


def text_problems(page, where):
    """화면 텍스트에서 코드가 새어 나온 표기를 찾는다."""
    body = page.evaluate("() => document.body.innerText") or ""
    for bad in ("undefined", "[object Object]"):
        if bad in body:
            fail("%s: 화면에 '%s' 노출" % (where, bad))
    # NaN은 단어 경계로(한글 조합 오탐 방지)
    if re.search(r"\bNaN\b", body):
        fail("%s: 화면에 'NaN' 노출" % where)


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

        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            pg = b.new_page(viewport={"width": 1600, "height": 1000})
            errors = []
            pg.on("pageerror", lambda e: errors.append("pageerror: " + str(e)))
            pg.on("console", lambda m: errors.append("console: " + m.text)
                  if ("Error" in m.text or "error" in m.text)
                  and "Content Security Policy" not in m.text else None)
            dialogs = []

            def _dlg(d):
                dialogs.append(d.message)
                d.accept()
            pg.on("dialog", _dlg)      # alert/confirm 자동 진행 + 내용 기록

            # ── 본 화면: 모든 탭 전환 ──
            print("[1] 본 화면 탭 전환")
            pg.goto(URL + "/")
            pg.wait_for_timeout(2500)
            tab_names = pg.eval_on_selector_all(
                ".tab-nav__btn", "els => els.map(e => e.getAttribute('data-tab'))")
            for name in tab_names:
                pg.click(".tab-nav__btn[data-tab='%s']" % name)
                pg.wait_for_timeout(500)
            text_problems(pg, "본 화면 전체 탭")
            ok("탭 %d개 전환" % len(tab_names))

            # ── 스위치 현황: 상세보기 클릭 ──
            print("[2] 스위치 상세보기")
            pg.click(".tab-nav__btn[data-tab='switch']")
            pg.wait_for_timeout(600)
            btn = pg.query_selector("#switch-table-body [data-action='detail-switch']")
            if btn:
                btn.click()
                pg.wait_for_timeout(900)
                panel = pg.query_selector("#detail-panel:not(.hidden)")
                if panel:
                    ok("상세 패널 열림")
                else:
                    fail("상세보기 클릭 후 패널이 열리지 않음")
                # 닫기는 JS로 — 오버레이는 겹침 때문에 클릭이 불안정하다
                pg.evaluate("() => closeDetailPanel()")
                pg.wait_for_timeout(300)
            else:
                fail("스위치 표에 상세보기 버튼 없음")

            # ── 방화벽: 일괄 수집 흐름(v6.24 .then 중복 버그가 있던 경로) ──
            print("[3] 방화벽 일괄 수집 흐름")
            pg.click(".tab-nav__btn[data-tab='firewall']")
            pg.wait_for_timeout(600)
            pg.click("#btn-firewall-collect-all")
            pg.wait_for_timeout(500)
            modal = pg.query_selector("#modal-fw-collect:not(.hidden)")
            if not modal:
                fail("일괄 수집 모달이 열리지 않음")
            else:
                ok("일괄 수집 모달 열림")
                pg.click("#btn-fw-collect")
                pg.wait_for_timeout(1500)
                prog = pg.evaluate(
                    "() => (document.getElementById('firewall-progress')||{}).innerText || ''")
                if "오류" in prog:
                    fail("일괄 수집이 오류 표기: %r" % prog[:60])
                elif prog.strip():
                    ok("일괄 수집 진행률 연결: %r" % prog[:40])
                else:
                    # 데모라 즉시 완료될 수 있음 — 콘솔 오류만 없으면 통과
                    ok("일괄 수집 시작(진행률 즉시 종료)")
            pg.screenshot(path=str(OUT / "main_firewall.png"))

            # ── 서버실: 배치 저장/업데이트 버튼 ──
            print("[4] 서버실 저장/업데이트")
            pg.click(".tab-nav__btn[data-tab='room']")
            pg.wait_for_timeout(700)
            for bid in ("btn-room-save-layout", "btn-room-update-layout"):
                el = pg.query_selector("#" + bid)
                if not el:
                    fail("서버실 버튼 없음: " + bid)
                    continue
                el.click()
                pg.wait_for_timeout(900)
            ok("배치 저장/업데이트 클릭")
            text_problems(pg, "서버실")

            # ── 랙 직접 입력(v6.37): 빈 U 클릭 → 입력 → 랙에 표시 → 삭제 ──
            print("[4.1] 랙 직접 입력(기타 장비·예약 자리)")
            rackbtn = pg.query_selector("#btn-room-rack")
            if not rackbtn:
                fail("랙뷰 전환 버튼 없음")
            else:
                rackbtn.click()
                pg.wait_for_timeout(1100)
                empty = pg.query_selector("#room-rack-view .ru--empty[data-action='add-rack-item']")
                if not empty:
                    fail("랙뷰 빈 칸이 클릭 대상이 아님(직접 입력 불가)")
                else:
                    rk = empty.get_attribute("data-rack")
                    un = empty.get_attribute("data-unit")
                    empty.click()
                    pg.wait_for_timeout(700)
                    modal = pg.query_selector("#rack-item-modal")
                    if not (modal and modal.is_visible()):
                        fail("빈 U를 눌렀는데 입력 창이 안 열림")
                    else:
                        pg.select_option("#rack-item-type", "reserved")
                        pg.fill("#rack-item-name", "SC 예약칸")
                        pg.fill("#rack-item-height", "1")
                        pg.click("#btn-rack-item-save")
                        pg.wait_for_timeout(1400)
                        sel = ("#room-rack-view .ru--item-reserved[data-rack='%s']"
                               "[data-unit='%s']" % (rk, un))
                        made = pg.query_selector(sel)
                        if not made:
                            fail("저장한 예약 자리가 랙에 안 그려짐")
                        else:
                            ok("랙 직접 입력: %s U%s 예약 자리 표시" % (rk, un))
                            # 원상복구 — 셀프체크가 DB에 잔재를 남기면 안 된다.
                            # 삭제 confirm은 위의 전역 _dlg 핸들러가 받는다.
                            made.click()
                            pg.wait_for_timeout(700)
                            dl = pg.query_selector("#btn-rack-item-delete")
                            if dl and dl.is_visible():
                                dl.click()
                                pg.wait_for_timeout(1200)
                                if pg.query_selector(
                                        "#room-rack-view .ru--empty[data-rack='%s']"
                                        "[data-unit='%s']" % (rk, un)):
                                    ok("랙 항목 삭제 → 빈 칸 복귀")
                                else:
                                    fail("랙 항목 삭제 후에도 칸이 비지 않음")
                            else:
                                fail("수정 창에 삭제 버튼이 없음")
                    text_problems(pg, "랙뷰")
                pg.screenshot(path=str(OUT / "room_rack.png"))
                cardbtn = pg.query_selector("#btn-room-card")
                if cardbtn:
                    cardbtn.click()
                    pg.wait_for_timeout(500)

            # ── 설비: 선택 체크 → 삭제 버튼 활성 + 진단 결과 팝업(v6.33) ──
            print("[4.2] 설비 선택·진단 결과")
            pg.click(".tab-nav__btn[data-tab='facility']")
            pg.wait_for_timeout(900)
            chk = pg.query_selector(".fac-check")
            if chk:
                chk.click()
                pg.wait_for_timeout(300)
                btn = pg.query_selector("#btn-fac-delete-sel:not([disabled])")
                if btn and "1" in (btn.inner_text() or ""):
                    ok("설비 선택 → 삭제 버튼 활성(1)")
                else:
                    fail("설비 체크 후 선택 삭제 버튼이 활성화되지 않음")
                chk.click()               # 해제(실삭제는 하지 않는다)
                pg.wait_for_timeout(200)
            else:
                fail("설비 선택 체크박스 없음")
            diag = pg.query_selector("[data-action='explain-facility']")
            if diag:
                if "진단 결과" not in (diag.inner_text() or ""):
                    fail("설비 결과 컬럼 버튼 문구가 '진단 결과'가 아님")
                diag.click()
                pg.wait_for_timeout(900)
                if pg.query_selector("#modal-diagnose:not(.hidden)"):
                    ok("진단 결과 팝업 열림")
                    pg.evaluate("() => closeModal && closeModal('modal-diagnose')")
                else:
                    fail("진단 결과 팝업이 열리지 않음")
            else:
                fail("진단 결과 버튼 없음")

            # ── 토폴로지: 자동 연결·자동 정렬·검색(v6.32) ──
            print("[4.5] 토폴로지 자동 연결·정렬·검색")
            pg.click(".tab-nav__btn[data-tab='topology']")
            pg.wait_for_timeout(1000)
            # 시드된 인접 쌍(데모 스위치 1↔2)을 캔버스에 올린다
            ips = pg.evaluate("""() =>
                fetch('/api/switches').then(r => r.json()).then(d =>
                    (d.switches || d || []).slice(0, 2).map(s => [s.ip, s.name]))""")
            if ips and len(ips) >= 2:
                pg.evaluate("""(pair) => {
                    _tdiag = { nodes: [
                      {id:'sca', kind:'backbone', ip:pair[0][0], name:pair[0][1], x:300, y:400, subnets:[]},
                      {id:'scb', kind:'l3', ip:pair[1][0], name:pair[1][1], x:700, y:150, subnets:[]},
                    ], edges: [] }; _tLoaded = true; _renderEditor();
                }""", ips)
                if not pg.evaluate("() => _tEditMode"):
                    pg.click("#btn-topo-edit")
                    pg.wait_for_timeout(400)
                pg.click("#btn-topo-autolink")
                pg.wait_for_timeout(1200)
                ecount = pg.evaluate("() => _tdiag.edges.length")
                if ecount >= 1:
                    ok("토폴로지 자동 연결(%d건)" % ecount)
                else:
                    fail("자동 연결이 시드된 인접을 잇지 못함")
                pg.click("#btn-topo-arrange")
                pg.wait_for_timeout(500)
                rows = pg.evaluate("() => new Set(_tdiag.nodes.map(n => n.y)).size")
                if rows >= 2:
                    ok("토폴로지 자동 정렬(행 %d개)" % rows)
                else:
                    fail("자동 정렬 후 행 분리가 안 됨")
                pg.fill("#topo-search", ips[1][1][:5])
                pg.press("#topo-search", "Enter")
                pg.wait_for_timeout(400)
                if pg.evaluate("() => _tSelId"):
                    ok("토폴로지 검색 포커스")
                else:
                    fail("검색이 장비를 선택하지 못함")
                pg.click("#btn-topo-edit")   # 편집 종료(자동 저장 방지)
                pg.wait_for_timeout(300)
            else:
                fail("토폴로지 검증용 스위치 목록을 얻지 못함")
            pg.screenshot(path=str(OUT / "topology.png"), full_page=True)

            # ── 관제: 4탭 + 기간 전환 + Top10 팝업 ──
            print("[5] 관제 탭·차트·팝업")
            pg.goto(URL + "/wall")
            pg.wait_for_timeout(2500)
            for tab in ("switch", "firewall", "facility", "summary"):
                pg.click("[data-wtab='%s']" % tab)
                pg.wait_for_timeout(600)
            text_problems(pg, "관제 전체 탭")
            # 대역별 IP 사용 현황(v6.36) — 행 클릭 → 그 대역의 IP 목록 팝업
            pg.click("[data-wtab='facility']")
            pg.wait_for_timeout(700)
            subrow = pg.query_selector(".wsub__row")
            if not subrow:
                fail("설비 탭에 대역별 IP 사용 현황이 없음")
            else:
                subrow.click()
                pg.wait_for_timeout(1500)
                modal = pg.query_selector("#wsw-modal")
                iprows = pg.query_selector_all("#wsw-body .wtable tbody tr")
                sub = pg.inner_text("#wsw-sub")
                if not (modal and modal.is_visible()) or not iprows:
                    fail("대역 클릭 → IP 목록이 안 열림")
                elif "불러오는 중" in sub:
                    fail("대역 IP 목록이 로딩에서 멈춤")
                else:
                    ok("대역 IP 리스트업: %d행 (%s)" % (len(iprows), sub[:40]))
                text_problems(pg, "대역 IP 목록")
                # 목록이 길어도 헤더의 ×가 화면 안에 남아야 한다 — 팝업에 높이
                # 제한이 없으면 뷰포트 밖으로 밀려 닫을 수 없다.
                vh = pg.evaluate("() => window.innerHeight")
                xbox = pg.eval_on_selector(
                    "#wsw-modal .wswm__x",
                    "el => { const r = el.getBoundingClientRect();"
                    "        return {top: r.top, bottom: r.bottom}; }")
                if xbox["top"] < 0 or xbox["bottom"] > vh:
                    fail("대역 팝업의 닫기 버튼이 화면 밖(top=%.0f, vh=%d)"
                         % (xbox["top"], vh))
                else:
                    ok("대역 팝업 닫기 버튼이 화면 안")
                # [data-close] 첫 매치는 배경 오버레이라 박스에 가려 클릭 불가 —
                # 사용자가 실제로 누르는 × 버튼을 집는다.
                close = pg.query_selector("#wsw-modal .wswm__x")
                if close:
                    close.click()
                    pg.wait_for_timeout(400)
                    m2 = pg.query_selector("#wsw-modal")
                    if m2 and m2.is_visible():
                        fail("× 를 눌렀는데 대역 팝업이 안 닫힘")
                    else:
                        ok("대역 팝업 닫기")
            pg.click("[data-wtab='switch']")
            pg.wait_for_timeout(700)
            # 포트 에러 증가 카드(v6.38) — 데이터가 없어도 사유 문구가 떠야 한다
            pec = pg.query_selector(".wcard:has-text('포트 에러 증가')")
            if not pec:
                fail("관제 스위치 탭에 '포트 에러 증가' 카드가 없음")
            else:
                t = pec.inner_text()
                if "늘어난 포트가 없습니다" in t or pec.query_selector("tbody tr"):
                    ok("포트 에러 증가 카드")
                else:
                    fail("포트 에러 카드가 비어 있는데 사유 문구도 없음")
            rb = pg.query_selector("[data-hours='168']")
            if rb:
                rb.click()
                pg.wait_for_timeout(900)
                ok("기간 전환(7일)")
            else:
                fail("기간 전환 버튼 없음")
            # 위젯 편집(v6.28): 토글 → 크기 변경 → 숨김 → 표시 복원
            pg.click("[data-wtab='firewall']")
            pg.wait_for_timeout(500)
            pg.click("#wall-edit-btn")
            pg.wait_for_timeout(600)
            tool = pg.query_selector("#wtab-firewall .wtool[data-wact='size']")
            if not tool:
                fail("편집 모드에서 크기 버튼이 안 보임")
            else:
                key = tool.get_attribute("data-wkey")
                tool.click()
                pg.wait_for_timeout(600)
                ok("위젯 크기 변경: " + (key or ""))
                hide = pg.query_selector("#wtab-firewall .wtool[data-wact='hide']")
                if hide:
                    hide.click()
                    pg.wait_for_timeout(600)
                    shown = pg.query_selector("#wtab-firewall .wtool[data-wact='hide']")
                    if shown and "표시" in (shown.inner_text() or ""):
                        shown.click()          # 복원
                        pg.wait_for_timeout(400)
                        ok("위젯 숨김/복원")
                    else:
                        fail("숨김 후 '표시' 버튼이 없음")
            # 드래그 순서(v6.29): 편집 모드에서 카드 두 장을 맞바꾸고 order 저장 확인
            # (Playwright 마우스 드래그는 headless HTML5 DnD가 불안정 —
            #  DragEvent를 직접 디스패치해 핸들러 경로를 검증한다)
            dragged = pg.evaluate("""() => {
                const grid = document.querySelector('#wtab-firewall .wgrid');
                if (!grid) return 'no-grid';
                const cards = grid.querySelectorAll(':scope > .wcard');
                if (cards.length < 2) return 'few-cards';
                const dt = new DataTransfer();
                const ev = (type, el) => el.dispatchEvent(new DragEvent(type,
                    {bubbles: true, cancelable: true, dataTransfer: dt}));
                ev('dragstart', cards[0]);
                ev('dragover', cards[1]);
                ev('dragend', cards[0]);
                return localStorage.getItem('wall_layout_v1') || '';
            }""")
            if '"order"' in (dragged or ""):
                ok("위젯 드래그 순서 저장")
            else:
                fail("드래그 후 order가 저장되지 않음: %r" % str(dragged)[:60])
            pg.click("#wall-edit-btn")         # 편집 종료
            pg.wait_for_timeout(400)
            # TV 모드(v6.29): 토글 켬 → 상태 클래스 확인 → 끔(로테이션까진 안 기다림)
            tab_before = pg.evaluate("() => _wtab")
            pg.click("#wall-tv-btn")
            pg.wait_for_timeout(300)
            tv = pg.query_selector("#wall-tv-btn.wall-tab--editing")
            ind = pg.query_selector("#wall-tv-ind:not([style*='display: none'])")
            tab_after = pg.evaluate("() => _wtab")
            if tv and ind and tab_after != tab_before:
                ok("TV 모드 토글(즉시 탭 전환 %s→%s + 표시등)" % (tab_before, tab_after))
            else:
                fail("TV 모드 즉각 피드백 없음(btn=%s ind=%s tab %s→%s)"
                     % (bool(tv), bool(ind), tab_before, tab_after))
            pg.click("#wall-tv-btn")           # 끔(다음 검사에 로테이션 간섭 방지)
            pg.wait_for_timeout(300)
            # 트래픽 위젯(v6.29): 스위치 탭에 카드가 있고 자리표시 or 차트가 있다
            pg.click("[data-wtab='switch']")
            pg.wait_for_timeout(400)
            if pg.query_selector("#ch-sw-traffic"):
                ok("업링크 트래픽 위젯 표시")
            else:
                fail("업링크 트래픽 위젯 없음")
            pg.click("[data-wtab='firewall']")
            pg.wait_for_timeout(400)
            # 장비 칩 토글(전체 ↔ 개별)
            chip = pg.query_selector("[data-fwdev]:not([data-fwdev='all'])")
            if chip:
                chip.click()
                pg.wait_for_timeout(600)
                pg.click("[data-fwdev='all']")
                pg.wait_for_timeout(400)
                ok("장비 선택 칩 토글")
            pg.click("[data-wtab='switch']")
            pg.wait_for_timeout(400)
            row = pg.query_selector("[data-swid]")
            if row:
                row.click()
                pg.wait_for_timeout(1200)
                if pg.query_selector("#wsw-modal:not([style*='display: none'])"):
                    ok("Top10 팝업 열림")
                    pg.click("#wsw-modal .wswm__x")
                else:
                    fail("Top10 클릭 후 팝업이 열리지 않음")
            else:
                fail("Top10 행 없음(데이터 시드 확인)")
            pg.screenshot(path=str(OUT / "wall_firewall.png"), full_page=True)

            # ── 오류 종합 ──
            # 오류성 alert — 자동 승인 탓에 화면에서 안 보이고 지나갈 수 있다.
            # (.then 중복 버그의 "수집 오류"가 정확히 이 유형이었다)
            for msg in dialogs:
                if ("오류" in msg or "실패" in msg) and "삭제하시겠" not in msg:
                    fail("오류 알림 발생: %r" % msg[:80])
            real = [e for e in errors if "favicon" not in e]
            for e in real[:10]:
                fail("스크립트 오류: " + e[:160])
            b.close()
    finally:
        proc.terminate()

    print()
    if FAILS:
        print("SELF-CHECK FAILED (%d건)" % len(FAILS))
        for f in FAILS:
            print(" -", f)
        return 1
    print("SELF-CHECK PASSED — 스크린샷 육안 검토: build/selfcheck/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
