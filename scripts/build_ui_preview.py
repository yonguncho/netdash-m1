# -*- coding: utf-8 -*-
"""NetDash UI 프리뷰 생성 — 실제 style.css를 그대로 인라인한 자체 완결 HTML 1개.

목적: 앱을 띄우지 않고도(원격에서도) 화면 디자인을 확인·검토하기 위한 샘플.
데이터는 전부 가상값이다. 실제 장비 이름·IP·MAC은 한 글자도 들어가지 않는다.

실행: python scripts/build_ui_preview.py
출력: docs/index.html  (GitHub Pages 루트 + 릴리스 첨부용)
"""
import re
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8")  # cp949 콘솔 크래시 방지
except Exception:
    pass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = ROOT / "web" / "static" / "style.css"
OUT_DIR = ROOT / "docs"
OUT = OUT_DIR / "index.html"

# ── 가상 데이터(실제 환경 정보 아님) ──────────────────────────────
SWITCHES = [
    ("TPS-CORE-01", "10.10.0.11", "cisco_ios", "코어", "1공장 B동 1층", "done", "-"),
    ("TPS-ACC-02", "10.10.0.21", "cisco_nxos", "액세스", "1공장 B동 2층", "done", "-"),
    ("TPS-ACC-03", "10.10.0.22", "arista_eos", "액세스", "1공장 B동 2층", "done", "warning"),
    ("TPS-EDGE-07", "10.10.0.37", "extreme_exos", "엣지", "2공장 A동 1층", "failed", "critical"),
]
SERVERS = [
    dict(name="APP-SRV-01", ip="10.20.1.10", host="app01", mac="AA:BB:CC:11:22:01",
         os="Linux 5.15.0 (Ubuntu 22.04)", cpu="Intel Xeon Silver 4210", cores=20,
         mem="64 GB", mem_sum="32GB×2 (DDR4) · 2/8 슬롯",
         disk="1.2 TB / 2.7 TB", pct=44, pct_color="#64748b",
         disk_sum="SSD 1 · HDD 1", kind="물리", ports="22,80,443",
         sw="TPS-ACC-02", port="Eth1/14", loc="A09U27", st="done"),
    dict(name="DB-SRV-02", ip="10.20.1.11", host="db02", mac="AA:BB:CC:11:22:02",
         os="Microsoft Windows [10.0.20348]", cpu="Intel Xeon Gold 6248", cores=40,
         mem="128 GB", mem_sum="32GB×4 (DDR4) · 4/8 슬롯",
         disk="3.1 TB / 3.4 TB", pct=91, pct_color="#dc2626",
         disk_sum="NVMe 2 · SSD 2", kind="물리", ports="445,1433,3389",
         sw="TPS-ACC-02", port="Eth1/15", loc="A09U29", st="done"),
    dict(name="WEB-VM-11", ip="10.20.1.51", host="web11", mac="00:50:56:AA:01:11",
         os="Linux 5.4.0", cpu="", cores=0, mem="8 GB", mem_sum="",
         disk="42 GB / 120 GB", pct=35, pct_color="#64748b", disk_sum="",
         kind="VM", ports="22,443", sw="TPS-CORE-01", port="Po10", loc="",
         st="done"),
]
DIMMS = [("DIMM_A1", "32 GB", "DDR4", "3200 MT/s", "Samsung", "M393A4K40DB3-CWE"),
         ("DIMM_A2", "32 GB", "DDR4", "3200 MT/s", "Samsung", "M393A4K40DB3-CWE"),
         ("DIMM_B1", "(비어 있음)", "-", "-", "-", "-"),
         ("DIMM_B2", "(비어 있음)", "-", "-", "-", "-")]
DISKS = [("sda", "SAMSUNG MZ7LH960HAJR-00005", "894.3 GB", "SSD", "SATA"),
         ("sdb", "ST2000NM0055-1V4104", "1.8 TB", "HDD", "SATA")]

_VENDOR_LABEL = {"cisco_ios": "Cisco IOS", "cisco_nxos": "Cisco NX-OS",
                 "arista_eos": "Arista EOS", "extreme_exos": "Extreme EXOS"}


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def switch_rows():
    out = []
    for name, ip, vendor, kind, loc, st, alert in SWITCHES:
        sc = "critical" if st == "failed" else "done"
        alert_html = ("<span class='status-badge status-badge--%s'>%s</span>" % (alert, alert)
                      if alert != "-" else "<span style='color:#94a3b8'>-</span>")
        out.append(
            "<tr>"
            "<td style='text-align:center'><input type='checkbox' checked></td>"
            "<td><strong>%s</strong></td><td><code>%s</code></td><td>%s</td><td>%s</td>"
            "<td>%s</td>"
            "<td><span class='status-badge status-badge--%s'>%s</span></td>"
            "<td>%s</td>"
            "<td style='white-space:nowrap'>"
            "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px'>수집</button> "
            "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px'>수정</button> "
            "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px'>진단</button> "
            "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px'>💻</button> "
            "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px'>삭제</button>"
            "</td></tr>"
            % (esc(name), esc(ip), esc(_VENDOR_LABEL.get(vendor, vendor)), esc(kind),
               esc(loc), sc, esc(st), alert_html))
    return "".join(out)


def server_rows():
    out = []
    for s in SERVERS:
        cpu = (esc(s["cpu"]) + " <span style='color:#64748b'>(%dC)</span>" % s["cores"]
               if s["cpu"] else "-")
        mem = esc(s["mem"])
        if s["mem_sum"]:
            mem = ("<a href='#' data-open='m-hw' style='color:inherit;text-decoration:none'>"
                   + mem + "<div style='color:#2563eb'>" + esc(s["mem_sum"]) + " ▸</div></a>")
        disk = "%s <span style='color:%s'>(%d%%)</span>" % (esc(s["disk"]), s["pct_color"], s["pct"])
        if s["disk_sum"]:
            disk = ("<a href='#' data-open='m-hw' style='color:inherit;text-decoration:none'>"
                    + disk + "<div style='color:#2563eb'>" + esc(s["disk_sum"]) + " ▸</div></a>")
        kind = ("<span style='color:#8b5cf6'>VM</span>" if s["kind"] == "VM"
                else "<span style='color:#2563eb'>물리</span>")
        out.append(
            "<tr><td style='text-align:center'><input type='checkbox'></td>"
            "<td><strong>%s</strong></td><td><code>%s</code></td><td>%s</td>"
            "<td><code style='font-size:11px'>%s</code></td><td>%s</td>"
            "<td style='font-size:11px;max-width:200px'>%s</td>"
            "<td style='font-size:11px;white-space:nowrap'>%s</td>"
            "<td style='font-size:11px;white-space:nowrap'>%s</td>"
            "<td>%s</td><td style='font-size:11px'>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td><span class='status-badge status-badge--done'>%s</span></td>"
            "<td style='white-space:nowrap'>"
            "<button class='btn btn--primary' style='font-size:11px;padding:2px 8px'>수집</button> "
            "<button class='btn btn--secondary' style='font-size:11px;padding:2px 8px'>수정</button> "
            "<button class='btn btn--secondary' style='font-size:11px;padding:2px 8px'>진단</button> "
            "<button class='btn btn--secondary' style='font-size:11px;padding:2px 8px'>💻</button> "
            "<button class='btn btn--ghost' style='font-size:11px;padding:2px 8px'>삭제</button>"
            "</td></tr>"
            % (esc(s["name"]), esc(s["ip"]), esc(s["host"]), esc(s["mac"]), esc(s["os"]),
               cpu, mem, disk, kind, esc(s["ports"]), esc(s["sw"]), esc(s["port"]),
               esc(s["loc"] or "-"), esc(s["st"])))
    return "".join(out)


def dimm_rows():
    return "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % tuple(esc(x) for x in row) for row in DIMMS)


def disk_rows():
    return "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % tuple(esc(x) for x in row) for row in DISKS)


def bulk_target_list():
    """일괄 수집 팝업의 '300대 선택' 상태 — 요약 + 접힌 전체 목록."""
    names = ["TPS-SW-%03d (10.10.%d.%d)" % (i, i // 250, i % 250) for i in range(1, 301)]
    preview = ", ".join(esc(n) for n in names[:5])
    full = "<br>".join(esc(n) for n in names)
    return (
        "<strong>300대</strong> 선택됨"
        "<div style='margin-top:4px;color:var(--text-2)'>" + preview +
        " <span style='color:var(--text-faint)'>외 295대</span></div>"
        "<details class='target-list' style='margin-top:6px'>"
        "<summary>대상 300대 전체 보기</summary>"
        "<div class='target-list__items'>" + full + "</div></details>")


NAV = [("현황판", 1), ("서버실 현황", 0), ("방화벽 현황", 0), ("스위치 현황", 0),
       ("서버 현황", 0), ("설비 현황", 0), ("VLAN", 0), ("토폴로지", 0)]


def build():
    if not CSS.exists():
        print("style.css 없음:", CSS)
        return 1
    css = CSS.read_text(encoding="utf-8")
    # 앱에서만 의미 있는 외부 참조(폰트 등)는 없지만, 방어적으로 상대 URL 제거
    css = re.sub(r"url\((['\"]?)/static/", r"url(\1", css)

    nav = "".join(
        "<button class='tab-nav__btn%s'><span class='nav-label'>%s</span></button>"
        % (" active" if act else "", esc(label)) for label, act in NAV)

    html = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetDash UI 프리뷰</title>
<style>
%(css)s
/* 프리뷰 전용(실제 앱에는 없음) */
.pv-note {
  background: var(--warning-soft); border: 1px solid #fde68a; color: #92400e;
  border-radius: var(--radius); padding: 10px 14px; font-size: 12.5px;
  margin-bottom: 16px; line-height: 1.6;
}
.pv-sec { margin: 26px 0 10px; font-size: 15px; font-weight: 700; color: var(--text); }
.pv-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 10px; }
.pv-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 10px; }
.pv-card { background: var(--surface); border: 1px solid var(--border);
           border-radius: var(--radius); padding: 16px; box-shadow: var(--shadow); }
</style>
</head>
<body class="app-shell">
<aside class="sidebar">
  <div class="sidebar__brand">
    <span class="sidebar__mark">ND</span>
    <span><div class="sidebar__title">NetDash</div>
    <div class="sidebar__sub">NETWORK OPERATIONS</div></span>
  </div>
  <div class="sidebar__section">모니터링</div>
  <nav class="tab-nav">%(nav)s</nav>
  <div class="sidebar__footer">
    <a href="#" class="sidebar__link"><span>관제 화면</span></a>
  </div>
</aside>

<header class="header">
  <div class="header__left">
    <span class="header__logo">네트워크 현황</span>
    <span class="badge badge--demo">UI 샘플</span>
  </div>
  <div class="header__search">
    <input type="text" placeholder="IP·이름·MAC 검색 (스위치·설비·ARP)">
    <button>검색</button>
  </div>
  <div class="header__right">
    <button class="alert-bell">⚙</button>
    <button class="alert-bell">🔑</button>
    <button class="alert-bell">📒</button>
    <button class="alert-bell">🔔</button>
  </div>
</header>

<main class="main">
  <div class="pv-note">
    <strong>UI 샘플입니다.</strong> 실제 앱을 띄우지 않고 화면 디자인만 확인하는 정적 페이지입니다.
    표에 보이는 장비 이름·IP·MAC은 <strong>전부 가상값</strong>이며 실제 환경 정보가 아닙니다.
    버튼과 팝업은 눌러볼 수 있습니다(데이터는 바뀌지 않습니다).
  </div>

  <div class="pane-toolbar">
    <div class="pane-toolbar__title">스위치 현황</div>
    <div class="pane-toolbar__actions">
      <input type="text" placeholder="이름·IP 검색">
      <button class="btn btn--primary">+ 스위치 추가</button>
      <button class="btn btn--primary">📥 엑셀 등록</button>
      <button class="btn btn--secondary" data-open="m-bulk">정보 수집 (300)</button>
      <button class="btn btn--secondary">전체 진단</button>
      <button class="btn btn--secondary">⬇ 다운로드</button>
      <button class="btn btn--ghost">선택 삭제 (4)</button>
    </div>
  </div>

  <div class="kpi-row">
    <div class="kpi kpi--total active"><div class="kpi__ico">▦</div>
      <div class="kpi__body"><div class="kpi__val">312</div><div class="kpi__label">전체 스위치</div></div></div>
    <div class="kpi kpi--ok"><div class="kpi__ico">✓</div>
      <div class="kpi__body"><div class="kpi__val">298</div><div class="kpi__label">정상</div></div></div>
    <div class="kpi kpi--warn"><div class="kpi__ico">!</div>
      <div class="kpi__body"><div class="kpi__val">9</div><div class="kpi__label">경고</div></div></div>
    <div class="kpi kpi--bad"><div class="kpi__ico">×</div>
      <div class="kpi__body"><div class="kpi__val">5</div><div class="kpi__label">수집 실패</div></div></div>
    <div class="kpi kpi--info"><div class="kpi__ico">◈</div>
      <div class="kpi__body"><div class="kpi__val">1,204</div><div class="kpi__label">설비</div></div></div>
  </div>

  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th style="width:34px;text-align:center"><input type="checkbox" checked></th>
        <th>이름</th><th>IP</th><th>벤더</th><th>구분</th><th>위치</th><th>상태</th><th>경보</th>
        <th>작업</th></tr></thead>
      <tbody>%(swrows)s</tbody>
    </table>
  </div>

  <div class="pv-sec">서버 현황 — CPU·메모리·디스크 사양</div>
  <div class="pv-sub">메모리·디스크 칸의 파란 요약을 클릭하면 장착 구성 상세가 열립니다.</div>
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th style="width:34px;text-align:center"><input type="checkbox"></th>
        <th>이름</th><th>IP</th><th>hostname</th><th>MAC</th><th>OS</th>
        <th>CPU</th><th>메모리</th><th>디스크</th><th>구분</th><th>열린 포트</th>
        <th>연결 스위치</th><th>포트</th><th>위치</th><th>상태</th><th>작업</th></tr></thead>
      <tbody>%(svrows)s</tbody>
    </table>
  </div>

  <div class="pv-sec">팝업</div>
  <div class="pv-sub">가장 많이 쓰는 세 가지입니다. 특히 첫 번째는 300대를 선택한 상태입니다.</div>
  <div class="pv-row">
    <button class="btn btn--primary" data-open="m-bulk">일괄 정보 수집 (300대 선택)</button>
    <button class="btn btn--secondary" data-open="m-hw">장착 구성 상세</button>
    <button class="btn btn--secondary" data-open="m-diag">장비 진단</button>
  </div>

  <div class="pv-sec">버튼</div>
  <div class="pv-sub">역할별 계층 — 주요 동작 / 보조 / 부가 / 위험. 누르면 살짝 눌리고, Tab으로 이동하면 포커스가 보입니다.</div>
  <div class="pv-card">
    <div class="pv-row">
      <button class="btn btn--primary">주요 동작</button>
      <button class="btn btn--secondary">보조 동작</button>
      <button class="btn btn--ghost">부가 동작</button>
      <button class="btn btn--danger">삭제</button>
      <button class="btn btn--primary" disabled>비활성</button>
    </div>
    <div class="pv-row">
      <button class="btn btn--primary" style="font-size:12px;padding:4px 10px">작은 주요</button>
      <button class="btn btn--secondary" style="font-size:12px;padding:4px 10px">작은 보조</button>
      <button class="btn btn--secondary" style="font-size:12px;padding:4px 10px">💻</button>
      <button class="btn btn--ghost" style="font-size:12px;padding:4px 10px">삭제</button>
    </div>
    <div class="pv-row">
      <span class="status-badge status-badge--done">done</span>
      <span class="status-badge status-badge--new">new</span>
      <span class="status-badge status-badge--warning">warning</span>
      <span class="status-badge status-badge--critical">critical</span>
      <span class="status-badge status-badge--ok">🟢 연결됨</span>
    </div>
  </div>
</main>

<!-- 일괄 정보 수집: 300대를 골라도 입력칸과 하단 버튼이 항상 보인다 -->
<div id="m-bulk" class="modal hidden">
  <div class="modal__backdrop" data-close></div>
  <div class="modal__box">
    <div class="modal__header"><span>일괄 정보 수집 (공통 계정)</span>
      <button class="modal__close" data-close>&times;</button></div>
    <div class="modal__body">
      <div class="switch-info-box">%(bulk)s</div>
      <label>아이디</label><input type="text" placeholder="admin">
      <label>패스워드</label><input type="password" placeholder="••••••••">
      <label>Enable Secret <span style="font-weight:400;color:#64748b">(선택)</span></label>
      <input type="password" placeholder="비워두면 패스워드를 사용">
      <label style="display:flex;align-items:center;gap:6px;margin-top:10px;font-size:13px;cursor:pointer">
        <input type="checkbox" checked> 이 계정을 저장해 자동 수집에 사용 (암호화 저장)</label>
      <label style="display:flex;align-items:center;gap:6px;margin-top:6px;font-size:13px;cursor:pointer">
        <input type="checkbox"> 이 세션 동안 기억 (30분, 서버 메모리에만)</label>
      <p style="margin-top:8px;font-size:12px;color:#64748b">선택한 장비를 동시에(백그라운드) 수집합니다.</p>
    </div>
    <div class="modal__footer">
      <button class="btn btn--primary">수집 시작</button>
      <button class="btn btn--ghost" data-close>취소</button>
    </div>
  </div>
</div>

<div id="m-hw" class="modal hidden">
  <div class="modal__backdrop" data-close></div>
  <div class="modal__box" style="max-width:820px;width:820px">
    <div class="modal__header"><span>장착 구성 — APP-SRV-01 (10.20.1.10)</span>
      <button class="modal__close" data-close>&times;</button></div>
    <div class="modal__body">
      <h4 style="margin:0 0 6px;font-size:13px">메모리 64 GB · 2/4 슬롯 사용</h4>
      <table class="data-table" style="font-size:12px;margin-bottom:14px">
        <thead><tr><th>슬롯</th><th>용량</th><th>규격</th><th>속도</th><th>제조사</th><th>파트번호</th></tr></thead>
        <tbody>%(dimms)s</tbody>
      </table>
      <h4 style="margin:0 0 6px;font-size:13px">디스크 1.2 TB / 2.7 TB (44%%) · 2개 장착</h4>
      <table class="data-table" style="font-size:12px">
        <thead><tr><th>장치</th><th>모델</th><th>용량</th><th>종류</th><th>인터페이스</th></tr></thead>
        <tbody>%(disks)s</tbody>
      </table>
      <p style="font-size:11px;color:#64748b;margin-top:10px">
        장착 구성은 SSH 계정으로 수집할 때만 채워집니다.
        리눅스 메모리 슬롯 정보(<code>dmidecode</code>)는 root 권한이 필요합니다.</p>
    </div>
  </div>
</div>

<div id="m-diag" class="modal hidden">
  <div class="modal__backdrop" data-close></div>
  <div class="modal__box" style="max-width:720px;width:720px">
    <div class="modal__header"><span>장비 진단 (실제 응답 원문)</span>
      <button class="modal__close" data-close>&times;</button></div>
    <div class="modal__body">
      <pre style="white-space:pre-wrap;word-break:break-all;font-size:12px;background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;max-height:420px;overflow:auto;user-select:text">TPS-EDGE-07 (10.10.0.37)

TCP-22 도달: 성공
SSH 로그인: 실패
감지 결과(guess): 인식 못 함
오류: 인증 실패 — 아이디/비밀번호를 확인하세요.

── 프롬프트(마지막 줄) ──
login:

── 로그인 배너(끝부분) ──
Unauthorized access is prohibited.</pre>
    </div>
  </div>
</div>

<script>
document.addEventListener("click", function (e) {
  var o = e.target.closest("[data-open]");
  if (o) { e.preventDefault();
    document.getElementById(o.getAttribute("data-open")).classList.remove("hidden"); return; }
  if (e.target.closest("[data-close]")) {
    var m = e.target.closest(".modal"); if (m) m.classList.add("hidden");
  }
});
document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") {
    document.querySelectorAll(".modal:not(.hidden)").forEach(function (m) { m.classList.add("hidden"); });
  }
});
</script>
</body>
</html>
""" % {"css": css, "nav": nav, "swrows": switch_rows(), "svrows": server_rows(),
       "bulk": bulk_target_list(), "dimms": dimm_rows(), "disks": disk_rows()}

    OUT_DIR.mkdir(exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    print("생성:", OUT, "(%.1f KB)" % (OUT.stat().st_size / 1024))
    # 실제 환경 정보가 섞이지 않았는지 자체 점검
    leaked = [w for w in ("SKBA", "DETROIT", "netdash.db", "api_token") if w in html]
    if leaked:
        print("경고 — 실제 환경 문자열이 포함됨:", leaked)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(build())
