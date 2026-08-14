/* NetDash 관제(월보드) — 10초 자동 새로고침, 읽기 전용 */
"use strict";

// 원격 접속(0.0.0.0 바인드)이면 /api 호출에 토큰 헤더가 필요하다.
// 서버가 페이지 셸에 심어 준 window._API_TOKEN 을 쓴다(로컬 배포는 빈 값).
(function () {
  var tok = window._API_TOKEN || "";
  if (!tok) return;
  var orig = window.fetch;
  window.fetch = function (input, init) {
    if (typeof input === "string" &&
        (input.indexOf("/api/") === 0 || input.indexOf(location.origin + "/api/") === 0)) {
      init = init || {};
      var h = new Headers(init.headers || {});
      h.set("X-API-Token", tok);
      init.headers = h;
    }
    return orig.call(this, input, init);
  };
})();

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
  });
}

/* 벤더 NMS 톤의 라인 아이콘(stroke=currentColor, 1em 크기) — 이모지는 OS·폰트마다
   다르게 그려져 관제 화면 톤을 깬다(사용자 지적: "이런 아이콘 말고 세련되게"). */
var _ICO = {
  check: "<polyline points='20 6 9 17 4 12'/>",
  refresh: "<polyline points='23 4 23 10 17 10'/><path d='M20.49 15a9 9 0 1 1-2.12-9.36L23 10'/>",
  x: "<line x1='18' y1='6' x2='6' y2='18'/><line x1='6' y1='6' x2='18' y2='18'/>",
  port: "<rect x='2' y='7' width='20' height='10' rx='2'/><line x1='7' y1='11' x2='7' y2='13'/>" +
        "<line x1='12' y1='11' x2='12' y2='13'/><line x1='17' y1='11' x2='17' y2='13'/>",
  sliders: "<line x1='4' y1='21' x2='4' y2='14'/><line x1='4' y1='10' x2='4' y2='3'/>" +
           "<line x1='12' y1='21' x2='12' y2='12'/><line x1='12' y1='8' x2='12' y2='3'/>" +
           "<line x1='20' y1='21' x2='20' y2='16'/><line x1='20' y1='12' x2='20' y2='3'/>" +
           "<line x1='1' y1='14' x2='7' y2='14'/><line x1='9' y1='8' x2='15' y2='8'/>" +
           "<line x1='17' y1='16' x2='23' y2='16'/>",
  monitor: "<rect x='2' y='3' width='20' height='14' rx='2'/>" +
           "<line x1='8' y1='21' x2='16' y2='21'/><line x1='12' y1='17' x2='12' y2='21'/>",
  expand: "<polyline points='15 3 21 3 21 9'/><polyline points='9 21 3 21 3 15'/>" +
          "<line x1='21' y1='3' x2='14' y2='10'/><line x1='3' y1='21' x2='10' y2='14'/>",
  eye: "<path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/>",
  eyeoff: "<path d='M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 " +
          "5.06-5.94'/><path d='M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1 " +
          "-2.16 3.19'/><line x1='1' y1='1' x2='23' y2='23'/>",
};
function ico(name) {
  return "<svg class='ico' viewBox='0 0 24 24' fill='none' stroke='currentColor' " +
    "stroke-width='2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>" +
    (_ICO[name] || "") + "</svg>";
}

var KIND_KO = {
  new_device: "새 설비", device_offline: "설비 연결 끊김", device_online: "설비 복구",
  port_down: "포트 다운", port_up: "포트 복구", port_errors: "포트 에러 증가",
  threshold_over: "임계 초과", threshold_clear: "임계 해제",
  device_moved: "설비 이동", config_changed: "설정 변경",
  switch_unreachable: "스위치 연결 실패", switch_recovered: "스위치 복구",
  firewall_unreachable: "방화벽 연결 실패", firewall_recovered: "방화벽 복구",
  flapping: "포트 flapping", looping: "포트 looping",
};

function setTile(id, val, tileOnWhenPositive) {
  var el = document.getElementById(id);
  if (!el) return;
  el.textContent = val;
  if (tileOnWhenPositive) {
    el.parentElement.classList.toggle("tile--on", Number(val) > 0);
  }
}

var _lastWall = null;
var wallFacFilter = null;   // 설비 카테고리에서 선택된 스위치(칩 클릭) — null=전체

// 문제 카테고리 섹션 렌더(칩 필터 적용). refresh와 칩 클릭에서 공용 호출.
function renderProblems() {
  var d = _lastWall;
  var host = document.getElementById("wall-problems");
  if (!host || !d) return;
  var cats = (d.categories || []).filter(function (c) { return (c.items || []).length > 0; });
  if (!cats.length) {
    host.innerHTML = "<div class='wall-ok'>" + ico("check") + " 이상 없음<small>모든 장비 정상 · " +
      (d.total_switches || 0) + "대 감시 중</small></div>";
    return;
  }
  host.innerHTML = cats.map(function (c) {
    var isFac = c.key === "facility";
    var count = (c.total != null) ? c.total : c.items.length;
    // 스위치별 요약 칩 — 설비 카테고리는 클릭 시 그 스위치 설비만 필터
    var summaryHtml = (c.summary && c.summary.length)
      ? "<div class='wall-cat__summary'>" + c.summary.map(function (s) {
          var sw = s.switch || "미확인";
          var active = (isFac && wallFacFilter === sw) ? " wall-sumchip--active" : "";
          var attr = isFac ? " data-fswitch='" + esc(sw) + "'" : "";
          return "<span class='wall-sumchip" + (isFac ? " wall-sumchip--click" : "") + active + "'" + attr + ">" + ico("port") + " " +
            esc(sw) + (s.location ? " <i>(" + esc(s.location) + ")</i>" : "") +
            " <b>" + s.count + "</b></span>";
        }).join("") + "</div>"
      : "";
    // 칩 필터 적용(설비 카테고리 한정)
    var items = c.items;
    var filterBar = "";
    if (isFac && wallFacFilter) {
      items = items.filter(function (p) { return (p.switch || "미확인") === wallFacFilter; });
      filterBar = "<div class='wall-cat__filter'>필터: " + ico("port") + " " + esc(wallFacFilter) +
        " (" + items.length + ") <button class='wall-filter-clear'>전체 보기</button></div>";
    }
    // '외 N건' 안내: 서버가 잘라 보낸 경우 항상 표시(설비 필터 중에도 유지),
    // 다른 카테고리(도달 불가/수집 실패)도 total이 있으면 동일하게 안내.
    var moreHtml = (c.total != null && c.total > c.items.length)
      ? "<div class='wall-cat__more'>외 " + (c.total - c.items.length) + "건 — 설비 현황에서 전체 확인</div>"
      : "";
    // 이 세 카테고리는 개별 재수집 말고 '전체 한 번에'도 필요하다(사용자 요청).
    // 설비는 칩 필터가 걸려 있으면 그 스위치 몫만 일괄 재수집한다.
    var bulkHtml = "";
    if (count > 0 && (c.key === "unreach" || c.key === "failed")) {
      bulkHtml = "<button class='wall-cat__bulk' data-bulk-cat='" + c.key + "'>" + ico("refresh") + " 전체 재수집 (" +
        count + ")</button>";
    } else if (isFac && items.length > 0) {
      bulkHtml = "<button class='wall-cat__bulk' data-bulk-cat='facility'" +
        (wallFacFilter ? " data-bulk-switch='" + esc(wallFacFilter) + "'" : "") +
        ">" + ico("refresh") + " 전체 재수집 (" + items.length + (wallFacFilter ? "" : "/" + count) + ")</button>";
    }
    return "<div class='wall-cat wall-cat--" + esc(c.severity || "warn") + "'>" +
      "<div class='wall-cat__title'>" + esc(c.title) +
      " <span class='wall-cat__count'>" + count + "</span>" + bulkHtml + "</div>" +
      summaryHtml + filterBar +
      "<div class='wall-cat__grid'>" +
      items.map(function (p) {
        var rc = p.recollect
          ? "<button class='pcard__recollect' data-ip='" + esc(p.fip || "") +
            "' data-subnet='" + esc(p.subnet || "") + "' title='이 설비 대역을 연결 게이트웨이에서 재수집'>재수집</button>"
          : "";
        return "<div class='pcard'><div class='pcard__name'>" + esc(p.name || "-") + "</div>" +
          (p.ip ? "<div class='pcard__ip'>" + esc(p.ip) + "</div>" : "") +
          (p.detail ? "<div class='pcard__why'>" + esc(p.detail) + "</div>" : "") +
          rc + "</div>";
      }).join("") +
      "</div>" + moreHtml + "</div>";
  }).join("");
}

function refresh() {
  fetch("/api/wall").then(function (r) { return r.json(); }).then(function (d) {
    setTile("t-total", d.total_switches || 0, false);
    setTile("t-unreach", d.unreachable || 0, true);
    setTile("t-failed", d.failed || 0, true);
    setTile("t-alert", d.alert_switches || 0, true);
    setTile("t-fwdown", d.firewalls_down || 0, true);
    setTile("t-facoff", d.facility_offline || 0, true);
    setTile("t-unack", d.unacked_alerts || 0, true);

    _lastWall = d;
    renderProblems();

    var tick = document.getElementById("wall-events");
    tick.innerHTML = (d.recent_events || []).map(function (ev) {
      var kind = KIND_KO[ev.kind] || ev.kind || "-";
      var where = [ev.label, ev.ip].filter(Boolean).join(" ");
      // 이벤트 상세(message)에 포트 등 핵심 정보가 있으므로 함께 표시
      var msg = (ev.message || "").slice(0, 90);
      return "<span>" + esc((ev.ts || "").replace("T", " ").slice(5, 16)) +
        " <b>" + esc(kind) + "</b> " + esc(where) +
        (msg ? " — " + esc(msg) : "") + "</span>";
    }).join("");

    // TV 모드: 새 알람성 이벤트면 관련 탭으로 자동 전환
    if (typeof tvMaybeJump === "function") tvMaybeJump(d.recent_events || []);
  }).catch(function (e) { console.error(e); });
}

function clock() {
  var el = document.getElementById("wall-clock");
  if (el) el.textContent = new Date().toLocaleString("ko-KR");
}

// 설비 '재수집' 버튼(위임) — 카드가 매 새로고침 재생성돼도 컨테이너 리스너는 유지
(function () {
  var host = document.getElementById("wall-problems");
  if (!host) return;
  host.addEventListener("click", function (e) {
    // 설비 요약 칩 클릭 → 그 스위치 설비만 필터(재클릭 시 해제)
    var chip = e.target.closest(".wall-sumchip--click");
    if (chip) {
      var sw = chip.getAttribute("data-fswitch");
      wallFacFilter = (wallFacFilter === sw) ? null : sw;
      renderProblems();
      return;
    }
    if (e.target.closest(".wall-filter-clear")) {
      wallFacFilter = null; renderProblems(); return;
    }
    var bulk = e.target.closest(".wall-cat__bulk");
    if (bulk) { startBulk(bulk); return; }
    var btn = e.target.closest(".pcard__recollect");
    if (!btn) return;
    var ip = btn.getAttribute("data-ip"), subnet = btn.getAttribute("data-subnet");
    startRecollect(btn, ip, subnet);
  });

  function reset(btn) { btn.disabled = false; btn.textContent = "재수집"; }

  // 카테고리 전체를 한 번에 재수집한다(사용자 요청) — 개별 재수집 버튼과 원리는
  // 같되, 스위치 카테고리는 비동기 큐잉(백그라운드 여러 대 동시 수집), 설비는
  // 대역별로 세션을 재사용하는 동기 일괄 확인이다. 계정을 새로 묻지 않는다 —
  // 이미 저장된 계정이 없는 장비는 건너뛰고 그 사실을 그대로 알려준다.
  function startBulk(btn) {
    var cat = btn.getAttribute("data-bulk-cat");
    var label = btn.textContent;
    btn.disabled = true; btn.textContent = "처리 중…";
    var req = (cat === "facility")
      ? fetch("/api/facility/recollect-offline", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({switch: btn.getAttribute("data-bulk-switch") || undefined}),
        })
      : fetch("/api/wall/recollect-switches", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({category: cat}),
        });
    req.then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        var b = res.b || {};
        if (!res.ok || !b.ok) { alert(b.error || "일괄 재수집 실패"); return; }
        var msg;
        if (cat === "facility") {
          msg = "확인 " + b.checked + "대 · 온라인 " + b.online +
            " · 여전히 끊김 " + b.still_offline;
          if (b.no_gateway && b.no_gateway.length)
            msg += "\n게이트웨이 미기억 대역 " + b.no_gateway.length + "건(설비 현황에서 '대역 수집' 먼저 필요)";
          if (b.no_cred && b.no_cred.length)
            msg += "\n계정 없는 대역 " + b.no_cred.length + "건(스위치에 계정 저장 필요)";
        } else {
          msg = "큐잉 " + b.queued + "대(백그라운드로 수집)";
          if (b.skipped_no_cred) msg += "\n계정 없음 " + b.skipped_no_cred + "대(스위치에 계정 저장 필요)";
          if (b.skipped_busy) msg += "\n이미 수집 중 " + b.skipped_busy + "대";
        }
        alert(msg);
        if (typeof refresh === "function") refresh();
      })
      .catch(function (e) { alert("일괄 재수집 오류: " + e); })
      .then(function () { btn.disabled = false; btn.textContent = label; });
  }

  // 이 설비 하나만 게이트웨이 스위치에서 다시 확인한다(대역 전체 재스캔이 아니다
  // — 예전엔 대역이 /23이면 15분+ 걸렸다). 몇 초 안에 끝나는 동기 요청이라
  // '대역 수집'처럼 다른 작업과 충돌해 409가 날 일이 없다.
  function startRecollect(btn, ip, subnet) {
    btn.disabled = true; btn.textContent = "확인 중…";
    fetch("/api/facility/recollect", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ip: ip, subnet: subnet}),
    }).then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        var b = res.b || {};
        if (!res.ok) { alert(b.error || "재수집 실패"); reset(btn); return; }
        if (typeof refresh === "function") refresh();   // 목록을 새 상태로 다시 그린다
        reset(btn);
      }).catch(function (e) { alert("재수집 오류: " + e); reset(btn); });
  }
})();

refresh();
clock();
setInterval(refresh, 10000);
setInterval(clock, 1000);

/* ── 통합 대시보드 v2 (스위치 / 방화벽 / 설비 탭) ─────────────────────
   목업(build/wall_mockup.html) 승인본. 외부 차트 라이브러리 없이
   SVG 도넛(그라데이션+글로우) + CSS 막대. 폐쇄망 = CDN 불가. */

var _WSTAT = null;
var _wtab = "summary";
var _gid = 0;   // SVG 그라데이션 id 충돌 방지(도넛마다 고유 defs)

// 시리즈 색상 팔레트 — 랭킹 막대·시계열 차트 공용.
// (이전 블록 교체 때 정의가 유실돼 차트가 조용히 안 그려졌었다 — 오류가 .catch에
//  잡혀 pageerror에도 안 걸림. 콘솔 로그까지 봐야 잡히는 유형.)
var PALETTE = ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24", "#fb7185",
               "#60a5fa", "#f97316", "#2dd4bf"];

function lvlColor(l) {
  return l === "critical" ? "#fb7185" : l === "warning" ? "#fbbf24" : "#34d399";
}
function pctLv(p) {
  if (p === null || p === undefined) return null;
  return p >= 90 ? "critical" : p >= 80 ? "warning" : "normal";
}
function _n(v) { return (v === null || v === undefined) ? "-" : Number(v).toLocaleString(); }

/* KPI 카드 — {num, label, detail, color} */
function kpiRow(cards) {
  return "<div class='wkpi'>" + cards.map(function (c) {
    return "<div class='wkpi__c' style='--ac:" + (c.color || "#60a5fa") + "'>" +
      "<div class='wkpi__n'>" + c.num + "</div>" +
      "<div class='wkpi__l'>" + esc(c.label) + "</div>" +
      (c.detail ? "<div class='wkpi__d'>" + esc(c.detail) + "</div>" : "") +
      "</div>";
  }).join("") + "</div>";
}

/* 도넛 — segs=[{label, value, c0, c1}] (그라데이션 양끝색) */
function donut(segs, centerTop, centerBottom) {
  segs = (segs || []).filter(function (s) { return s.value > 0; });
  var total = segs.reduce(function (a, s) { return a + s.value; }, 0);
  var R = 54, C = 2 * Math.PI * R, off = 0, gbase = "wg" + (++_gid) + "_";
  var defs = "", arcs = "";
  if (!total) {
    arcs = "<circle cx='70' cy='70' r='" + R + "' fill='none' stroke='rgba(148,163,184,.12)' stroke-width='14'/>";
  } else {
    arcs = "<circle cx='70' cy='70' r='" + R + "' fill='none' stroke='rgba(148,163,184,.1)' stroke-width='14'/>";
    segs.forEach(function (s, i) {
      var gid = gbase + i;
      defs += "<linearGradient id='" + gid + "' x1='0' y1='0' x2='1' y2='1'>" +
        "<stop offset='0' stop-color='" + s.c0 + "'/><stop offset='1' stop-color='" + s.c1 + "'/></linearGradient>";
      var len = C * (s.value / total);
      // 아주 작은 조각도 보이게 최소 길이 확보(단, 100% 단독이면 그대로)
      arcs += "<circle cx='70' cy='70' r='" + R + "' fill='none' stroke='url(#" + gid + ")' " +
        "stroke-width='14'" + (segs.length > 1 ? " stroke-linecap='round'" : "") +
        " stroke-dasharray='" + Math.max(len, 3).toFixed(2) + " " + C.toFixed(2) + "' " +
        "stroke-dashoffset='" + (-off).toFixed(2) + "' transform='rotate(-90 70 70)'/>";
      off += len;
    });
  }
  var legend = segs.map(function (s) {
    return "<span class='wl-item'><i style='background:" + s.c1 + "'></i>" +
      esc(s.label) + " <b>" + _n(s.value) + "</b></span>";
  }).join("");
  return "<div class='wchart'><svg class='dsvg' viewBox='0 0 140 140'><defs>" + defs + "</defs>" + arcs +
    "<text x='70' y='66' text-anchor='middle' class='dnum'>" + esc(String(centerTop)) + "</text>" +
    "<text x='70' y='86' text-anchor='middle' class='dlbl'>" + esc(centerBottom || "") + "</text></svg>" +
    "<div class='wlegend'>" + legend + "</div></div>";
}

/* Top N 랭킹 — items=[{name, id?, v(막대 기준값), d(표시값)}] */
function rankList(items, opts) {
  opts = opts || {};
  items = items || [];
  if (!items.length) return "<p class='wnone'>데이터 없음</p>";
  var max = opts.max || Math.max.apply(null, items.map(function (i) { return i.v || 0; })) || 1;
  return "<div class='wrank'>" + items.map(function (i, idx) {
    var pct = Math.max(2, Math.round((i.v || 0) * 100 / max));
    var click = (opts.link && i.id)
      ? " data-swid='" + i.id + "' title='클릭 → 스위치 상세'" : "";
    return "<div class='wrank__row" + (opts.link && i.id ? " wrank__row--link" : "") + "'" + click + ">" +
      "<span class='wrank__no'>" + (idx + 1) + "</span>" +
      "<span class='wrank__name' title='" + esc(i.name) + "'>" + esc(i.name) + "</span>" +
      "<span class='wrank__bar'><span class='wrank__fill' style='--f0:" + (opts.c0 || "#0891b2") +
      ";--f1:" + (opts.c1 || "#22d3ee") + ";width:" + pct + "%'></span></span>" +
      "<span class='wrank__val'>" + (i.d || _n(i.v)) + "</span></div>";
  }).join("") + "</div>";
}

function wcard(title, hint, body, cls) {
  return "<div class='wcard " + (cls || "") + "'><h3>" + esc(title) +
    (hint ? "<span class='hint'>" + esc(hint) + "</span>" : "") + "</h3>" + body + "</div>";
}

var STATUS_KO = { done: "정상", failed: "수집 실패", collecting: "수집 중", new: "미수집" };
function statusSegs(by) {
  var C = { done: ["#059669", "#34d399"], failed: ["#e11d48", "#fb7185"],
            collecting: ["#d97706", "#fbbf24"], new: ["#334155", "#64748b"] };
  return Object.keys(by || {}).map(function (k) {
    var c = C[k] || ["#334155", "#64748b"];
    return { label: STATUS_KO[k] || k, value: by[k], c0: c[0], c1: c[1] };
  });
}

/* 사용률 미터 한 줄(방화벽 카드) */
function meter(label, pct, disp) {
  if (pct === null || pct === undefined) {
    return "<div class='wmeter'><b>" + esc(label) + "</b><span class='wmeter__t'></span>" +
      "<span class='wmeter__v wdim'>-</span></div>";
  }
  var lv = pctLv(pct) || "normal";
  var cls = lv === "critical" ? "mf-crit" : lv === "warning" ? "mf-warn" : "mf-ok";
  return "<div class='wmeter'><b>" + esc(label) + "</b>" +
    "<span class='wmeter__t'><span class='wmeter__f " + cls + "' style='width:" +
    Math.min(100, pct) + "%'></span></span>" +
    "<span class='wmeter__v'>" + esc(disp || (pct + "%")) + "</span></div>";
}

/* 포트 에러 '증가' 카드 — 누적 카운터가 아니라 최근 24시간에 늘어난 양.
   포트 DOWN은 이미 끊어진 뒤의 신호다. 여기 뜨는 포트는 아직 붙어 있지만
   물리 계층(케이블·SFP·광 레벨)이 나빠지는 중일 가능성이 높다. */
function portErrCard(rows) {
  if (!rows.length) {
    return wcard("포트 에러 증가",
      "최근 24시간 · 증가한 포트만 · 지표 폴러가 SNMP로 주기 수집",
      "<p class='wnone'>최근 24시간 에러가 늘어난 포트가 없습니다.</p>", "wcard--6");
  }
  var body =
    "<table class='wtable'><thead><tr><th>스위치</th><th>포트</th>" +
    "<th>합계</th><th>내역</th><th>최근</th></tr></thead><tbody>" +
    rows.map(function (r) {
      var parts = [];
      if (r.crc) parts.push("CRC " + _n(r.crc));
      if (r.in_err) parts.push("수신오류 " + _n(r.in_err));
      if (r.out_err) parts.push("송신오류 " + _n(r.out_err));
      if (r.in_disc) parts.push("수신폐기 " + _n(r.in_disc));
      if (r.out_disc) parts.push("송신폐기 " + _n(r.out_disc));
      var click = r.id ? " class='wsub__row' data-swid='" + r.id + "'" : "";
      return "<tr" + click + "><td><b>" + esc(r.name) + "</b></td>" +
        "<td><code>" + esc(r.port) + "</code></td>" +
        "<td class='wsub__bad'><b>" + _n(r.total) + "</b></td>" +
        "<td><small>" + esc(parts.join(" · ")) + "</small></td>" +
        "<td><small>" + esc(String(r.last_ts || "").slice(5)) + "</small></td></tr>";
    }).join("") + "</tbody></table>";
  return wcard("포트 에러 증가",
    "최근 24시간 늘어난 양(누적값 아님) · CRC·수신오류는 케이블/SFP 의심 · " +
    "행 클릭 → 스위치 상세",
    body, "wcard--6" + (rows.length > 8 ? " wcard--tall" : ""));
}

/* ── 스위치 탭 ── */
function renderSwitchTab(s) {
  var el = document.getElementById("wtab-switch");
  if (!el) return;
  if (!s || !s.total) { el.innerHTML = "<p class='wnone'>등록된 스위치가 없습니다.</p>"; return; }
  var p = s.ports || {}, a = s.alerts || {}, r = s.reach || {};
  var kinds = (s.by_kind || []).filter(function (k) { return k.name !== "미지정"; })
    .map(function (k) { return k.name.replace(" Switch", "") + " " + k.count; }).join(" · ");
  var maxT = (s.temps || [])[0];
  el.innerHTML =
    kpiRow([
      { num: _n(s.total), label: "등록 스위치", detail: kinds, color: "#60a5fa" },
      { num: _n((s.by_status || {}).done || 0), label: "정상 수집", color: "#34d399" },
      { num: _n(r.down || 0), label: "도달 불가", color: r.down ? "#fb7185" : "#34d399" },
      { num: _n((a.flapping || 0) + (a.looping || 0)), label: "경보 FLAP/LOOP",
        color: (a.flapping || a.looping) ? "#fbbf24" : "#34d399" },
      { num: _n(p.up) + "<small>/" + _n(p.total) + "</small>",
        label: "포트 사용 (" + (p.pct || 0) + "%)",
        detail: "여유 " + _n(p.down) + "포트",
        color: p.pct >= 90 ? "#fb7185" : p.pct >= 80 ? "#fbbf24" : "#22d3ee" },
      maxT ? { num: maxT.temp_c + "°C", label: "최고 온도", detail: maxT.name, color: "#a78bfa" }
           : { num: "-", label: "최고 온도", detail: "SNMP 환경정보 없음", color: "#64748b" }
    ]) +
    "<div class='wgrid'>" +
    wcard("포트 사용률 TOP 10", "클릭 → 스위치 상세보기",
      rankList((s.top_ports || []).map(function (t) {
        return { id: t.id, name: t.name, v: t.pct,
                 d: t.pct + "% <small>(" + t.up + "/" + t.total + ")</small>" };
      }), { link: true, max: 100, c0: "#0891b2", c1: "#22d3ee" }), "wcard--8") +
    "<div class='wcard wcard--4'><h3>수집 상태</h3>" +
      donut(statusSegs(s.by_status),
            Math.round(((s.by_status || {}).done || 0) * 100 / s.total) + "%", "정상 수집률") +
      "<h3 style='margin-top:16px'>제조사</h3>" +
      rankList((s.by_vendor || []).map(function (v) {
        return { name: v.name, v: v.count, d: _n(v.count) + " <small>대</small>" };
      }), { c0: "#2563eb", c1: "#60a5fa" }) + "</div>" +
    ((s.temps || []).length
      ? wcard("온도 상위", "SNMP ENTITY-SENSOR-MIB",
          rankList(s.temps.map(function (t) {
            return { name: t.name, v: t.temp_c, d: t.temp_c + "°C" };
          }), { c0: "#c2410c", c1: "#fb923c" }), "wcard--6")
      : "") +
    portErrCard(s.port_errors || []) +
    "<div class='wcard wcard--6'><h3>포트 사용 추이" + rangeBtns() +
      "</h3><div id='ch-ports' class='wchartbox'></div></div>" +
    "<div class='wcard wcard--6'><h3>온도 추이<span class='hint'>스위치별</span></h3>" +
      "<div id='ch-sw-temp' class='wchartbox'></div></div>" +
    "<div class='wcard wcard--12'><h3>업링크 트래픽" +
      "<span class='hint'>SNMP 64bit 카운터 · 지표 폴러 주기로 갱신 (실선 수신 · 점선 송신)</span></h3>" +
      "<div id='ch-sw-traffic' class='wchartbox'></div></div>" +
    "</div>";
}

/* ── 방화벽 탭 v3 ──
   원칙(사용자 지적 반영):
   ① 터널은 '연결'도 모니터링이다 — 끊김이 있을 때만 보여주지 않는다.
     방화벽별로 모든 터널의 상태(연결/끊김)를 항상 나열한다(끊김 우선).
   ② 표에서 장비를 말없이 빼지 않는다 — 지표가 없으면 없는 이유("미수집",
     "실패", "지표 없음")를 그 줄에 적는다. "왜 2대만 나오지?"가 화면에서
     답이 되게 한다.
   ③ 도표는 반드시 실제 목록과 짝으로 — 도넛만 있으면 '어느 장비인지'를 모른다. */
function renderFirewallTab(f) {
  var el = document.getElementById("wtab-firewall");
  if (!el) return;
  if (!f || !f.total) { el.innerHTML = "<p class='wnone'>등록된 방화벽이 없습니다.</p>"; return; }
  var v = f.vpn || {}, pol = f.policy || {}, st = f.by_status || {};
  var devsAll = f.devices || [], stList = f.fw_status_list || [];
  // 장비 선택(사용자 커스터마이즈) — 칩으로 고른 장비만 카드·추이에 표시.
  var sel = _fwDevSel();
  var devs = sel ? devsAll.filter(function (d) { return sel.has(String(d.id)); }) : devsAll;
  var devById = {};
  devs.forEach(function (d) { devById[d.id] = d; });
  var sess = devs.reduce(function (a, d) { return a + (d.sessions || 0); }, 0);
  var failedNames = stList.filter(function (x) { return x.status === "failed"; })
    .map(function (x) { return x.name; });

  /* 지표가 왜 없는지 — 줄마다 설명할 사유 */
  function whyEmpty(x) {
    if (x.status === "failed") return "수집 실패" + (x.last_error ? " — " + x.last_error.slice(0, 30) : "");
    if (x.status === "new") return "미수집 — '수집'을 눌러 첫 수집을 하세요";
    if (x.status === "collecting") return "수집 중...";
    return "지표 없음 — SNMP 커뮤니티(설정 메뉴) 또는 SSH 계정 지정 후 재수집";
  }

  /* 장비별 카드 — 지표가 수집된 방화벽만.
     FortiGate 대시보드의 System Information 위젯처럼 라벨:값 표로 정리한다.
     터널 목록은 여기 두지 않는다 — 'VPN 터널 모니터링' 카드가 전담(중복 제거). */
  var cards = devs.map(function (d) {
    var lv = d.level || (d.alarms.length ? "critical" : "normal");
    function frow(k, val, cls) {
      return (val === null || val === undefined || val === "") ? "" :
        "<tr><td class='fwc__k'>" + esc(k) + "</td><td" +
        (cls ? " class='" + cls + "'" : "") + ">" + val + "</td></tr>";
    }
    var lc = d.lifecycle || {};
    function lcTxt(e) {
      if (!e || !e.status || e.status === "unknown") return "";
      var cls = e.status === "expired" ? "wbad" : (e.status === "ok" ? "" : "wam");
      return " <span class='" + cls + "'>· " + esc(e.message || "") + "</span>";
    }
    var facts =
      frow("모델", d.model ? esc(d.model) + lcTxt(lc.hw) : null) +
      frow("펌웨어", d.version
        ? esc("v" + String(d.version).replace(/^v/, "")) + lcTxt(lc.os) : null) +
      frow("가동 시간", d.uptime_sec ? Math.floor(d.uptime_sec / 86400) + "일" : null) +
      frow("HA", d.ha ? esc(d.ha) : null) +
      frow("온도", d.temp_c !== null && d.temp_c !== undefined
        ? "<span" + (d.temp_c >= 60 ? " class='wam'" : "") + ">" + d.temp_c + "°C</span>" : null) +
      frow("PSU", d.psu_count
        ? (d.alarms.length ? "<span class='wbad'>" + d.psu_count + "개 — 알람</span>"
                           : d.psu_count + "개 정상") : null) +
      (d.alarms.length
        ? frow("센서 알람", "<span class='wbad'>" + d.alarms.map(esc).join(", ") + "</span>") : "") +
      frow("정책", d.policy_total !== null && d.policy_total !== undefined
        ? _n(d.policy_total) + (d.proxy_total ? " <span class='wdim'>(Proxy " + _n(d.proxy_total) + ")</span>" : "")
        : null) +
      // 라이선스 — 별도 카드 대신 장비 카드에 통합(사용자 지적: 한 박스에서).
      // 문제(만료·임박)만 강조하고 정상은 개수로 요약해 카드 비대화를 막는다.
      (function () {
        var lic = d.license || [];
        if (!lic.length) return "";
        var bad = lic.filter(function (l) { return l.level !== "ok"; });
        var txt = bad.length
          ? bad.map(function (l) {
              var cls = l.level === "expired" ? "wbad" : "wam";
              var word = l.level === "expired" ? "만료" : "임박";
              return "<span class='" + cls + "'>" + esc(l.name) + " " + word +
                (l.expires ? "(" + esc(String(l.expires).slice(5)) + ")" : "") + "</span>";
            }).join(" · ") +
            (lic.length > bad.length
              ? " <span class='wdim'>· 정상 " + (lic.length - bad.length) + "</span>" : "")
          : "정상 " + lic.length + "건";
        return frow("라이선스", txt);
      })() +
      // VPN을 안 쓰는 방화벽이 많다 — 설정된(터널>0) 장비에만 표기
      (d.vpn_total
        ? frow("VPN 터널", (d.vpn_up < d.vpn_total
            ? "<span class='wbad'>" + d.vpn_up + "/" + d.vpn_total + " 연결 — 끊김 " +
              (d.vpn_total - d.vpn_up) + "</span>"
            : d.vpn_up + "/" + d.vpn_total + " 연결")) : "");
    var sub = d.host || "";
    return "<div class='fwc fwc--" + (lv === "critical" ? "crit" : lv === "warning" ? "warn" : "ok") + "'>" +
      "<div class='fwc__hd'><div><div class='fwc__nm'>" + esc(d.name || "-") + "</div>" +
      "<div class='fwc__ip'>" + esc(sub) + "</div></div>" +
      "<span class='pulse pulse--" + (lv === "critical" ? "bad" : "ok") + "'></span></div>" +
      "<div class='fwc__bd'>" +
      meter("CPU", d.cpu) + meter("MEM", d.mem) +
      (d.disk === null || d.disk === undefined
        ? "" : meter("DISK", d.disk)) +
      meter("세션", d.sessions !== null && d.sessions !== undefined
        ? Math.min(100, Math.round((d.sessions || 0) / 2000)) : null, _n(d.sessions)) +
      (facts ? "<table class='fwc__tb'>" + facts + "</table>" : "") +
      "</div></div>";
  }).join("");

  /* VPN 터널 모니터링 — 도넛 + 방화벽별 전체 터널 목록(도표·목록 한 카드) */
  var vpnRows = f.vpn_rows || [];
  var vpnList = vpnRows.length
    ? vpnRows.map(function (r) {
        return "<div class='vgrp'><div class='vgrp__fw'>" + esc(r.name) +
          " <span class='wdim'>(" + ((r.up || []).length) + "/" +
          (((r.up || []).length) + ((r.down || []).length)) + " 연결)</span></div>" +
          (r.down || []).map(function (t) {
            return "<div class='tun tun--dn'><i></i>" + esc(t.name || "-") +
              " <span class='tst tst--dn'>끊김</span><span class='peer'>" + esc(t.peer || "") + "</span></div>";
          }).join("") +
          (r.up || []).map(function (nm) {
            return "<div class='tun tun--up'><i></i>" + esc(nm) +
              " <span class='tst tst--up'>연결</span></div>";
          }).join("") + "</div>";
      }).join("")
    : "<p class='wnone'>VPN 터널이 수집된 방화벽이 없습니다. REST 토큰/계정을 지정하고 수집하면 채워집니다.</p>";
  var vpnCard = "<div class='wcard wcard--6'><h3>VPN 터널 모니터링" +
    "<span class='hint'>방화벽별 전체 터널 — 끊김 우선</span></h3>" +
    ((v.tunnels || 0) > 0
      ? donut([{ label: "연결", value: v.up || 0, c0: "#059669", c1: "#34d399" },
               { label: "끊김", value: v.down || 0, c0: "#e11d48", c1: "#fb7185" }],
              _n(v.tunnels), "터널") : "") +
    "<div class='vlist'>" + vpnList + "</div></div>";

  /* 수집 상태 — 도넛 + 전 장비 표 */
  var stTable = "<table class='wtable'><thead><tr><th>방화벽</th><th>IP</th><th>상태</th><th>마지막 수집</th></tr></thead><tbody>" +
    stList.map(function (x) {
      var badge = x.status === "done" ? "<span class='wst wst--ok'>정상</span>"
        : x.status === "failed" ? "<span class='wst wst--bad'>실패" +
            (x.last_error ? " — " + esc(x.last_error.slice(0, 40)) : "") + "</span>"
        : x.status === "collecting" ? "<span class='wst'>수집 중</span>"
        : "<span class='wst'>미수집</span>";
      return "<tr><td><b>" + esc(x.name || "-") + "</b></td><td>" + esc(x.host || "-") +
        "</td><td>" + badge + "</td><td>" +
        esc((x.last_collected || "-").toString().slice(5, 16)) + "</td></tr>";
    }).join("") + "</tbody></table>";
  var stCard = "<div class='wcard wcard--6'><h3>수집 상태" +
    "<span class='hint'>어떤 장비가 왜 실패했는지</span></h3>" +
    donut(statusSegs(st), _n(f.total), "대") + stTable + "</div>";

  /* 정책 구성 — 도넛 + 전 장비 표(지표 없는 장비도 사유와 함께) */
  var polById = {};
  (f.policy_rows || []).forEach(function (r) { polById[r.name] = r; });
  /* 객체 수 — 방화벽별 주소/서비스/VIP 등(수집된 장비만).
     polTable이 참조하므로 반드시 그보다 먼저 정의(정의를 뒤에 뒀다가
     '오류 없음+빈 표'가 아니라 렌더 전체가 죽는 걸 실화면 검증에서 잡았다). */
  var objByFw = {};
  (f.objects_rows || []).forEach(function (o) { objByFw[o.fw] = o; });
  var polTable = "<table class='wtable'><thead><tr><th>방화벽</th><th>Firewall 정책</th><th>Proxy 정책</th><th>히트 0건</th><th>비활성</th><th title='주소·주소그룹·서비스·VIP·IP풀 객체 합계'>객체</th></tr></thead><tbody>" +
    stList.map(function (x) {
      var r = polById[x.name];
      var ob = objByFw[x.name];
      var objCell = ob
        ? "<td title='주소 " + _n(ob.address) + " · 그룹 " + _n(ob.addrgrp) +
          " · 서비스 " + _n(ob.service) + " · VIP " + _n(ob.vip) + "'>" +
          _n(ob.total) + "</td>"
        : "<td class='wdim'>-</td>";
      if (!r) {
        return "<tr><td><b>" + esc(x.name || "-") + "</b></td>" +
          "<td colspan='5' class='wdim'>" + esc(whyEmpty(x)) + "</td></tr>";
      }
      return "<tr><td><b>" + esc(r.name) + "</b></td><td><b>" + _n(r.total) + "</b></td><td>" +
        _n(r.proxy_total) + "</td><td class='wam'>" + _n(r.unused) + "</td><td>" +
        _n(r.disabled) + "</td>" + objCell + "</tr>";
    }).join("") +
    ((f.policy_rows || []).length > 1
      ? "<tr class='wsum'><td>합계</td><td><b>" + _n(pol.total) + "</b></td><td><b>" +
        _n(pol.proxy_total) + "</b></td><td>" + _n(pol.unused) + "</td><td>" +
        _n(pol.disabled) + "</td><td>" +
        _n((f.objects_rows || []).reduce(function (a, o) { return a + (o.total || 0); }, 0)) +
        "</td></tr>" : "") + "</tbody></table>";
  var polCard = "<div class='wcard wcard--6'><h3>정책 구성" +
    "<span class='hint'>방화벽별 Firewall / Proxy 정책 수</span></h3>" +
    ((pol.total || 0) > 0
      ? donut([{ label: "사용 중",
                 value: Math.max(0, (pol.total || 0) - (pol.unused || 0) - (pol.disabled || 0)),
                 c0: "#2563eb", c1: "#60a5fa" },
               { label: "히트 0건", value: pol.unused || 0, c0: "#d97706", c1: "#fbbf24" },
               { label: "비활성", value: pol.disabled || 0, c0: "#334155", c1: "#64748b" }],
              _n(pol.total), "정책") : "") + polTable + "</div>";

  /* 장비별 부하 — 전 장비 표(지표 없는 장비는 사유) */
  var loadTable = "<table class='wtable'><thead><tr><th>방화벽</th><th>CPU</th><th>MEM</th><th>DISK</th><th>세션</th></tr></thead><tbody>" +
    stList.map(function (x) {
      var d = devById[x.id];
      if (!d || (d.cpu === null || d.cpu === undefined) &&
                (d.mem === null || d.mem === undefined) &&
                (d.sessions === null || d.sessions === undefined)) {
        return "<tr><td><b>" + esc(x.name || "-") + "</b><div class='wdim'>" + esc(x.host || "") +
          "</div></td><td colspan='4' class='wdim'>" + esc(whyEmpty(x)) + "</td></tr>";
      }
      function cell(pv) {
        if (pv === null || pv === undefined) return "<td class='wdim'>-</td>";
        var lv2 = pctLv(pv) || "normal";
        var cls = lv2 === "critical" ? "mf-crit" : lv2 === "warning" ? "mf-warn" : "mf-ok";
        return "<td><span class='wmini'><span class='wmini__f " + cls + "' style='width:" +
          Math.min(100, pv) + "%'></span></span> " + pv + "%</td>";
      }
      return "<tr><td><b>" + esc(d.name) + "</b><div class='wdim'>" + esc(d.host || "") +
        "</div></td>" + cell(d.cpu) + cell(d.mem) + cell(d.disk) +
        "<td>" + _n(d.sessions) + "</td></tr>";
    }).join("") + "</tbody></table>";
  var loadCard = "<div class='wcard wcard--6'><h3>장비별 부하" +
    "<span class='hint'>SNMP 또는 SSH(get sys perf status)로 수집</span></h3>" + loadTable + "</div>";

  el.innerHTML =
    kpiRow([
      { num: _n(f.total), label: "등록 방화벽", color: "#60a5fa" },
      { num: _n(st.done || 0), label: "수집 정상", color: "#34d399" },
      { num: _n(st.failed || 0), label: "수집 실패",
        detail: failedNames.slice(0, 2).join(", "),
        color: st.failed ? "#fb7185" : "#34d399" },
      { num: _n(v.up) + "<small>/" + _n(v.tunnels) + "</small>", label: "VPN 터널 연결",
        detail: v.down ? "끊김 " + v.down + " ⚠" : "",
        color: v.down ? "#fbbf24" : "#34d399" },
      { num: _n(pol.total), label: "총 방화벽 정책",
        detail: pol.proxy_total ? "Proxy 정책 " + _n(pol.proxy_total) : "", color: "#a78bfa" },
      { num: _n(sess), label: "동시 세션 합계", color: "#fbbf24" },
      { num: _n(f.license_bad || 0), label: "라이선스 만료·임박",
        color: f.license_bad ? "#fb7185" : "#34d399" }
    ]) +
    "<div class='wchips' id='fw-dev-chips'>" +
      "<span class='wchip" + (!sel ? " wchip--on" : "") + "' data-fwdev='all'>전체</span>" +
      devsAll.map(function (d) {
        var on = !sel || sel.has(String(d.id));
        return "<span class='wchip" + (on ? " wchip--on" : "") + "' data-fwdev='" +
          d.id + "'>" + esc(d.name || d.host || ("#" + d.id)) + "</span>";
      }).join("") + "</div>" +
    "<div class='wgrid'>" +
    "<div class='wcard wcard--4'><h3>세션 추이" + rangeBtns() +
      "</h3><div id='ch-fw-sess' class='wchartbox'></div></div>" +
    "<div class='wcard wcard--4'><h3>CPU 추이" +
      "<span class='hint'>" + (_seriesHours >= 168 ? "7일" : _seriesHours + "시간") +
      "</span></h3><div id='ch-fw-cpu' class='wchartbox'></div></div>" +
    "<div class='wcard wcard--4'><h3>MEM 추이" +
      "<span class='hint'>" + (_seriesHours >= 168 ? "7일" : _seriesHours + "시간") +
      "</span></h3><div id='ch-fw-mem' class='wchartbox'></div></div>" +
    "<div id='fw-series-note' class='wnote' style='display:none'></div>" +
    "</div>" +
    (cards ? "<div class='fwrow'>" + cards + "</div>" : "") +
    "<div class='wgrid'>" + vpnCard + loadCard + stCard + polCard + "</div>";
}

/* 대역별 IP 사용 현황 — 대역이 몇 개든 전부 싣는다. 예전엔 상위 12개만 보내
   13번째 대역이 화면에서 조용히 사라졌고, 그러면 '수집이 안 된 대역'과 구분되지
   않는다. 행을 클릭하면 그 대역의 IP 목록이 열린다. */
function subnetTable(rows) {
  return "<table class='wtable'><thead><tr>" +
    "<th>대역</th><th>사용 IP</th><th>사용률</th>" +
    "<th>온라인</th><th>연결 실패</th><th>연결 지점 확인</th>" +
    "</tr></thead><tbody>" +
    rows.map(function (x) {
      /* 사용률은 대역 크기를 알 때만 그린다. 모르는 걸 0%로 그리면 텅 빈
         대역처럼 보인다 — 그래서 막대 대신 '-'. */
      var pct = (x.usage_pct === null || x.usage_pct === undefined) ? null : x.usage_pct;
      var mf = pct === null ? "mf-ok"
        : (pct >= 90 ? "mf-crit" : pct >= 75 ? "mf-warn" : "mf-ok");
      var bar = pct === null ? "<span class='wsub__na'>-</span>"
        : "<span class='wsub__bar'><span class='wmeter__t'><span class='wmeter__f " + mf +
          "' style='width:" + Math.max(2, Math.min(100, pct)) + "%'></span></span>" +
          "<b>" + pct + "%</b></span>";
      return "<tr class='wsub__row' data-subnet='" + esc(x.name) + "'>" +
        "<td><b>" + esc(x.name) + "</b></td>" +
        "<td>" + _n(x.count) +
          (x.capacity ? " <small class='wsub__cap'>/ " + _n(x.capacity) + "</small>" : "") +
          "</td>" +
        "<td>" + bar + "</td>" +
        "<td>" + _n(x.online) + "</td>" +
        "<td" + (x.offline ? " class='wsub__bad'" : "") + ">" + _n(x.offline) + "</td>" +
        "<td>" + _n(x.direct) + "</td></tr>";
    }).join("") + "</tbody></table>";
}

function subnetCard(rows) {
  var body = rows.length ? subnetTable(rows)
    : "<p class='wnone'>수집된 대역이 없습니다.</p>";
  var total = rows.reduce(function (a, x) { return a + (x.count || 0); }, 0);
  return wcard("대역별 IP 사용 현황",
    "대역 " + rows.length + "개 · 수집 IP 합계 " + _n(total) +
    " · 행을 클릭하면 그 대역의 IP 목록이 열립니다. 사용률 = 수집 IP / 대역 용량",
    body, "wcard--6" + (rows.length > 8 ? " wcard--tall" : ""));
}

/* 대역 클릭 → 그 대역이 실제로 쓰는 IP 목록. 관제 안 팝업으로 연다. */
function openSubnetModal(subnet) {
  var modal = document.getElementById("wsw-modal");
  var body = document.getElementById("wsw-body");
  if (!modal || !body) return;
  modal.style.display = "";
  var box = modal.querySelector(".wswm__box");
  if (box) box.classList.add("wswm__box--wide");   /* 목록은 컬럼이 6개라 넓게 */
  document.getElementById("wsw-name").textContent = subnet;
  document.getElementById("wsw-sub").textContent = "불러오는 중...";
  body.innerHTML = "<p class='wnone'>불러오는 중...</p>";
  fetch("/api/wall/facility-subnet?subnet=" + encodeURIComponent(subnet))
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var hosts = d.hosts || [];
      /* 잘렸을 때는 표시 개수가 아니라 실제 사용 개수를 보여준다 —
         '사용 2000개'는 진짜 2000개인지 잘린 건지 구분이 안 된다. */
      var used = (d.total === null || d.total === undefined) ? hosts.length : d.total;
      document.getElementById("wsw-sub").textContent =
        "사용 " + used + "개" +
        (d.capacity ? " / 대역 용량 " + d.capacity + "개" : "") +
        " · 온라인 " + d.online + " · 연결 실패 " + d.offline;
      if (!hosts.length) {
        body.innerHTML = "<p class='wnone'>이 대역에 수집된 설비가 없습니다.</p>";
        return;
      }
      body.innerHTML =
        "<table class='wtable'><thead><tr><th>IP</th><th>상태</th>" +
        "<th>연결 스위치</th><th>포트</th><th>MAC</th><th>갱신</th></tr></thead><tbody>" +
        hosts.map(function (h) {
          var st = h.online
            ? "<span class='wst wst--ok'>온라인</span>"
            : "<span class='wst wst--bad'>연결 실패</span>";
          /* 접속 지점이 확인 안 된 것을 스위치 이름 없이 비워두면 '수집 실패'로
             오해한다 — 사유를 한 줄로 밝힌다(v6.35.0 설비 상태 3단계와 같은 취지). */
          var sw = h.switch_name
            ? esc(h.switch_name) + (h.direct ? "" : " <small class='wsub__na'>(경유 관측)</small>")
            : "<small class='wsub__na'>미확인</small>";
          return "<tr><td><b>" + esc(h.ip) + "</b></td><td>" + st + "</td><td>" + sw +
            "</td><td>" + esc(h.port || "-") + "</td><td>" + esc(h.mac || "-") +
            /* 연도는 뺀다(월-일 시:분) — 좁은 칸에서 두 줄로 접혀 읽기 나빴다.
               수집 상태 표도 같은 형식(slice(5,16))이다. */
            "</td><td>" + esc((h.updated || "-").slice(5)) + "</td></tr>";
        }).join("") + "</tbody></table>" +
        (d.truncated
          ? "<p class='wswm__foot'>" + used + "개 중 앞 " + hosts.length +
            "개만 표시했습니다(IP 순).</p>"
          : "");
    })
    .catch(function () {
      body.innerHTML = "<p class='wnone'>대역 정보를 불러오지 못했습니다.</p>";
    });
}

/* ── 설비 탭 ── */
function renderFacilityTab(c) {
  var el = document.getElementById("wtab-facility");
  if (!el) return;
  if (!c || !c.total) { el.innerHTML = "<p class='wnone'>수집된 설비가 없습니다.</p>"; return; }
  var onlinePct = c.total ? Math.round(c.online * 1000 / c.total) / 10 : 0;
  el.innerHTML =
    kpiRow([
      { num: _n(c.total), label: "전체 설비",
        detail: "대역 " + (c.by_subnet || []).length + "개", color: "#60a5fa" },
      { num: _n(c.online), label: "온라인 (" + onlinePct + "%)", color: "#34d399" },
      { num: _n(c.offline), label: "연결 실패",
        detail: c.offline_24h ? "24시간 내 +" + c.offline_24h : "",
        color: c.offline ? "#fb7185" : "#34d399" },
      { num: _n(c.direct), label: "연결 지점 확인", color: "#22d3ee" },
      { num: _n(c.indirect), label: "미확인", detail: "액세스 스위치 미수집",
        color: c.indirect ? "#fbbf24" : "#34d399" }
    ]) +
    "<div class='wgrid'>" +
    wcard("설비 최다 연결 스위치 TOP 10", "클릭 → 스위치 상세",
      rankList((c.by_switch || []).map(function (x) {
        return { id: x.id, name: x.name, v: x.count, d: _n(x.count) + " <small>대</small>" };
      }), { link: true, c0: "#7c3aed", c1: "#a78bfa" }), "wcard--6") +
    "<div class='wcard wcard--6'>" +
      "<h3>최근 7일 연결 실패 다발 스위치<span class='hint'>이 스위치 아래 설비가 자주 끊긴다 — 스위치·포트·전원 의심</span></h3>" +
      ((c.offline_by_switch || []).length
        ? rankList(c.offline_by_switch.map(function (x) {
            return { id: x.id, name: x.name, v: x.count, d: _n(x.count) + " <small>건</small>" };
          }), { link: true, c0: "#e11d48", c1: "#fb7185" })
        : "<p class='wnone'>최근 7일 연결 실패 이벤트 없음</p>") +
    "</div>" +
    subnetCard(c.by_subnet || []) +
    "<div class='wcard wcard--12'><h3>온라인 설비 추이" + rangeBtns() +
      "<span class='hint'>계단이 꺾인 시각 = 설비가 무더기로 끊긴 시각 — 그 시각의 스위치·전원 이벤트와 대조</span></h3>" +
      "<div id='ch-fac' class='wchartbox'></div></div>" +
    "</div>";
}

/* 위험도 통합 순위 + 평소 대비 이상치 (요약 탭 상단).

   CPU·메모리·온도를 각각 다른 카드에서 보면 '지금 제일 먼저 봐야 할 것'이
   무엇인지 알 수 없다. 단위가 다른 지표를 '임계까지 얼마나 왔나'(%)로 환산해
   한 줄에 세운다. */
function renderRisk(r) {
  var el = document.getElementById("wall-risk");
  if (!el) return;
  r = r || {};
  var top = r.top || [], ano = r.anomalies || [];
  var riskBody = top.length
    ? "<table class='wtable'><thead><tr><th>장비</th><th>지표</th><th>현재</th>" +
      "<th>임계</th><th>임계 대비</th></tr></thead><tbody>" +
      top.map(function (x) {
        var pct = x.pct_of_limit;
        var mf = pct >= 100 ? "mf-crit" : (pct >= 85 ? "mf-warn" : "mf-ok");
        var click = (x.id && x.kind === "switch")
          ? " class='wsub__row' data-swid='" + x.id + "'" : "";
        return "<tr" + click + "><td><b>" + esc(x.name) + "</b></td>" +
          "<td>" + esc(x.metric) + "</td>" +
          "<td><b>" + esc(String(x.value)) + esc(x.unit || "") + "</b></td>" +
          "<td><small>" + esc(String(x.limit)) + esc(x.unit || "") + "</small></td>" +
          "<td><span class='wsub__bar'><span class='wmeter__t'>" +
            "<span class='wmeter__f " + mf + "' style='width:" +
            Math.max(2, Math.min(100, pct)) + "%'></span></span>" +
            "<b>" + pct + "%</b></span></td></tr>";
      }).join("") + "</tbody></table>"
    : "<p class='wnone'>임계에 근접한 장비가 없습니다.</p>";

  var anoBody = ano.length
    ? "<table class='wtable'><thead><tr><th>장비</th><th>지표</th>" +
      "<th>최근 24시간</th><th>평소</th><th>변화</th></tr></thead><tbody>" +
      ano.map(function (a) {
        var up = a.direction === "급증";
        return "<tr><td><b>" + esc(a.name) + "</b></td><td>" + esc(a.metric) + "</td>" +
          "<td><b>" + _n(a.recent) + "</b></td><td><small>" + _n(a.baseline) + "</small></td>" +
          "<td" + (up ? " class='wsub__bad'" : "") + ">" + esc(a.direction) +
          " <small>(" + esc(String(a.ratio)) + "배)</small></td></tr>";
      }).join("") + "</tbody></table>"
    : "<p class='wnone'>평소와 크게 다른 장비가 없습니다.</p>";

  /* SNMP로 아무것도 못 받은 장비 — '지표 없음'만 뜨면 커뮤니티가 틀린 건지
     장비가 SNMP를 안 켠 건지 알 수 없다. 목록으로 드러내 확인하게 한다. */
  var ns = r.no_snmp || [];
  var nsCard = ns.length
    ? wcard("SNMP 무응답 장비 (" + (r.no_snmp_total || ns.length) + ")",
        "온도·부하가 하나도 안 들어온 장비 — 본 화면의 [SNMP] 버튼으로 원인을 확인하세요",
        "<table class='wtable'><thead><tr><th>장비</th><th>IP</th><th>종류</th>" +
        "</tr></thead><tbody>" +
        ns.map(function (x) {
          return "<tr><td><b>" + esc(x.name) + "</b></td><td><code>" + esc(x.ip) +
            "</code></td><td>" + (x.kind === "firewall" ? "방화벽" : "스위치") +
            "</td></tr>";
        }).join("") + "</tbody></table>" +
        ((r.no_snmp_total || 0) > ns.length
          ? "<p class='wswm__foot'>외 " + ((r.no_snmp_total) - ns.length) + "대</p>" : ""),
        "wcard--12" + (ns.length > 8 ? " wcard--tall" : ""))
    : "";

  el.innerHTML = "<div class='wgrid'>" +
    wcard("임계 근접 장비" + (r.critical ? " (임계 초과 " + r.critical + ")" : ""),
      "CPU·메모리·온도를 임계 대비 비율로 환산해 한 줄로 — 70% 이상만 표시",
      riskBody, "wcard--6" + (top.length > 8 ? " wcard--tall" : "")) +
    wcard("평소와 다른 장비",
      "최근 24시간을 지난 7일 평균과 비교 — 절대 임계보다 오탐이 적습니다",
      anoBody, "wcard--6") +
    nsCard +
    "</div>";
}

function renderStats() {
  if (!_WSTAT) return;
  renderRisk(_WSTAT.risk);
  renderSwitchTab(_WSTAT.switches);
  renderFirewallTab(_WSTAT.firewalls);
  renderFacilityTab(_WSTAT.facility);
  tidyHints();
  // 탭 HTML을 다시 그리면 차트 컨테이너도 비워진다 — 통계 갱신(30초)마다
  // 차트를 다시 그리지 않으면 처음 1분 안에 그래프가 사라진다(실화면에서 재현).
  if (typeof applyLayout === "function") applyLayout();   // 차트보다 먼저(숨김 반영)
  if (typeof renderSeriesCharts === "function" && _SERIES) renderSeriesCharts();
}

function refreshStats() {
  fetch("/api/wall/stats").then(function (r) { return r.json(); })
    .then(function (d) { _WSTAT = d; renderStats(); })
    .catch(function (e) { console.error("wall stats:", e); });
}

/* Top10 클릭 → 관제 화면 안 요약 팝업(리디렉션하지 않는다 — 관제는 관제에 머문다) */
function openWallSwitchModal(id) {
  var modal = document.getElementById("wsw-modal");
  var body = document.getElementById("wsw-body");
  if (!modal || !body) return;
  modal.style.display = "";
  /* 대역 목록 팝업이 넓게 켜뒀을 수 있다 — 스위치 요약은 좁은 기본 폭으로 */
  var box = modal.querySelector(".wswm__box");
  if (box) box.classList.remove("wswm__box--wide");
  document.getElementById("wsw-name").textContent = "불러오는 중...";
  document.getElementById("wsw-sub").textContent = "";
  body.innerHTML = "<p class='wnone'>불러오는 중...</p>";
  fetch("/api/switches/" + id + "/detail")
    .then(function (r) { return r.json(); })
    .then(function (d) {
      var sw = d.switch || {};
      document.getElementById("wsw-name").textContent = sw.name || "-";
      document.getElementById("wsw-sub").textContent =
        (sw.ip || "") + (sw.hostname ? " · " + sw.hostname : "");
      var ports = d.ports || [];
      var up = ports.filter(function (p) {
        var st = (p.status || "").toLowerCase();
        return st === "up" || st === "connected";
      }).length;
      var pct = ports.length ? Math.round(up * 100 / ports.length) : 0;
      var env = d.env || {};
      function row(k, v) {
        return (v === null || v === undefined || v === "") ? "" :
          "<tr><td class='wswm__k'>" + esc(k) + "</td><td>" + esc(String(v)) + "</td></tr>";
      }
      /* FortiGate System Information 위젯처럼 — 라벨:값 표 하나로 정리 */
      body.innerHTML =
        "<table class='wswm__tb'>" +
        row("호스트네임", sw.hostname) +
        row("제조사 / 모델", [sw.manufacturer, sw.model].filter(Boolean).join(" / ")) +
        row("펌웨어", sw.os_version) +
        row("시리얼", sw.serial) +
        row("위치", sw.tps_location || sw.location) +
        row("상태", sw.status === "done" ? "정상 수집" : sw.status) +
        row("온도", env.max_temp_c !== null && env.max_temp_c !== undefined
              ? env.max_temp_c + "°C" : null) +
        row("마지막 수집", (sw.last_collected || "").toString().slice(0, 16)) +
        "</table>" +
        "<h4 class='wswm__h4'>포트 사용</h4>" +
        "<div class='wmeter'><b style='width:70px'>" + up + "/" + ports.length + "</b>" +
        "<span class='wmeter__t'><span class='wmeter__f " +
        (pct >= 90 ? "mf-crit" : pct >= 80 ? "mf-warn" : "mf-ok") +
        "' style='width:" + pct + "%'></span></span>" +
        "<span class='wmeter__v'>" + pct + "%</span></div>" +
        "<p class='wswm__foot'>세부 포트·MAC·ARP는 본 화면(스위치 현황 → 상세보기)에서 확인하세요.</p>";
    })
    .catch(function () { body.innerHTML = "<p class='wnone'>정보를 불러오지 못했습니다.</p>"; });
}
document.addEventListener("click", function (e) {
  var row = e.target.closest && e.target.closest("[data-swid]");
  if (row) { openWallSwitchModal(row.getAttribute("data-swid")); return; }
  var sub = e.target.closest && e.target.closest("[data-subnet]");
  if (sub) { openSubnetModal(sub.getAttribute("data-subnet")); return; }
  var x = e.target.closest && e.target.closest("[data-close]");
  if (x) {
    var m = document.getElementById("wsw-modal");
    if (m) m.style.display = "none";
  }
});

var _TAB_ORDER = ["summary", "switch", "firewall", "facility"];

/* 탭 전환 — 버튼 클릭과 TV 로테이션이 공용으로 쓴다 */
function wallShowTab(key) {
  if (_TAB_ORDER.indexOf(key) < 0) return;
  _wtab = key;
  var nav = document.getElementById("wall-tabs");
  if (nav) {
    Array.prototype.forEach.call(nav.querySelectorAll("[data-wtab]"), function (x) {
      x.classList.toggle("wall-tab--on", x.getAttribute("data-wtab") === key);
    });
  }
  _TAB_ORDER.forEach(function (k) {
    var p = document.getElementById("wtab-" + k);
    if (p) p.classList.toggle("wall-pane--on", k === key);
  });
  // 숨긴 탭에서 그려진 차트는 clientWidth=0이라 500px 폴백으로 좁게 그려져
  // 있다 — 탭이 보이게 된 지금 실제 폭으로 다시 그린다.
  if (typeof renderSeriesCharts === "function" && _SERIES) renderSeriesCharts();
}

(function initWallTabs() {
  var nav = document.getElementById("wall-tabs");
  if (!nav) return;
  nav.addEventListener("click", function (e) {
    var b = e.target.closest("[data-wtab]");
    if (!b) return;
    wallShowTab(b.getAttribute("data-wtab"));
  });
})();

refreshStats();
// 통계는 집계 쿼리라 문제 목록(10초)보다 느슨하게 돈다 — 관제 화면 부하를 줄인다.
setInterval(refreshStats, 30000);

/* ── 시계열 차트 (uPlot 번들) ─────────────────────────────────────
   폴러가 5분마다 쌓는 metrics_history를 그린다. 데이터가 없으면(방금 켠 경우)
   "기록 수집 중" 안내를 보여준다 — 몇 시간 지나면 채워진다. */

var _SERIES = null;
var _seriesHours = 24;
var _plots = [];          // 리사이즈·재렌더 시 파괴할 uPlot 인스턴스들

function _tsToUnix(ts) {  // "2026-08-04 18:00:00" → epoch초
  return Math.floor(new Date(String(ts).replace(" ", "T")).getTime() / 1000);
}

var _UP_AXIS = { stroke: "#5b6f8c", grid: { stroke: "rgba(148,163,184,.08)" },
                 ticks: { stroke: "rgba(148,163,184,.15)" } };

/* 여러 장비 시리즈를 한 차트에 — devs={id:{name,points[[ts,cpu,mem,sess,temp]]}}
   pick: 점 배열에서 값 하나를 고르는 함수 */
function chartMulti(elId, devs, pick, unit) {
  var el = document.getElementById(elId);
  if (!el || typeof uPlot === "undefined") return;
  // 시간축 통합: 장비별 점을 시각 키로 합친다(5분 격자라 대부분 일치)
  var byTs = {};
  var names = [];
  var ids = Object.keys(devs || {});
  ids.forEach(function (id, di) {
    names.push(devs[id].name || ("#" + id));
    (devs[id].points || []).forEach(function (pt) {
      var t = _tsToUnix(pt[0]);
      (byTs[t] = byTs[t] || {})[di] = pick(pt);
    });
  });
  var xs = Object.keys(byTs).map(Number).sort(function (a, b) { return a - b; });
  var hasData = xs.length >= 2 && ids.length;
  if (!hasData) {
    el.innerHTML = "<p class='wnone'>기록 수집 중 — 지표 폴러(기본 5분)가 점을 쌓으면 그래프가 나타납니다.</p>";
    return;
  }
  var data = [xs];
  ids.forEach(function (_id, di) {
    data.push(xs.map(function (t) {
      var v = byTs[t][di];
      return (v === undefined || v === null) ? null : v;
    }));
  });
  var series = [{}];
  ids.forEach(function (_id, di) {
    series.push({ label: names[di], stroke: PALETTE[di % PALETTE.length],
                  width: 2, points: { show: false }, spanGaps: true });
  });
  el.innerHTML = "";
  var w = el.clientWidth || 500;
  _plots.push(new uPlot({
    width: w, height: 190,
    legend: { show: ids.length <= 6 },
    cursor: { points: { size: 6 } },
    scales: { x: { time: true } },
    axes: [Object.assign({}, _UP_AXIS),
           Object.assign({}, _UP_AXIS, {
             values: function (u, vals) {
               return vals.map(function (v) { return v + (unit || ""); });
             } })],
    series: series,
  }, data, el));
}

/* 단일 합계 시리즈(설비 온라인 수 / 포트 사용) — rows=[[ts, val, total]] */
function chartTotal(elId, rows, label, color) {
  var el = document.getElementById(elId);
  if (!el || typeof uPlot === "undefined") return;
  rows = rows || [];
  if (rows.length < 2) {
    el.innerHTML = "<p class='wnone'>기록 수집 중 — 지표 폴러(기본 5분)가 점을 쌓으면 그래프가 나타납니다.</p>";
    return;
  }
  var xs = rows.map(function (r) { return _tsToUnix(r[0]); });
  var ys = rows.map(function (r) { return r[1]; });
  var tot = rows.map(function (r) { return r[2]; });
  el.innerHTML = "";
  _plots.push(new uPlot({
    width: el.clientWidth || 500, height: 190,
    legend: { show: true },
    scales: { x: { time: true } },
    axes: [Object.assign({}, _UP_AXIS), Object.assign({}, _UP_AXIS)],
    series: [{},
      { label: label, stroke: color, width: 2, fill: color + "22",
        points: { show: false }, spanGaps: true },
      { label: "전체", stroke: "#475569", width: 1, dash: [4, 4],
        points: { show: false }, spanGaps: true }],
  }, [xs, ys, tot], el));
}

function _fmtBps(v) {
  if (v == null) return "";
  if (v >= 1e9) return (v / 1e9).toFixed(1) + "G";
  if (v >= 1e6) return (v / 1e6).toFixed(1) + "M";
  if (v >= 1e3) return Math.round(v / 1e3) + "K";
  return String(Math.round(v));
}

/* 업링크 트래픽 — 포트마다 수신(실선)/송신(점선) 두 시리즈, 같은 색.
   traffic={key:{name,points[[ts,in_bps,out_bps]]}} — 많으면 바쁜 순 8개만. */
function chartTraffic(elId, traffic) {
  var el = document.getElementById(elId);
  if (!el || typeof uPlot === "undefined") return;
  var keys = Object.keys(traffic || {});
  // 평균 (in+out) 큰 순 — 조용한 포트 수십 개가 범례를 덮지 않게
  keys.sort(function (a, b) {
    function avg(k) {
      var pts = traffic[k].points || [];
      var s = 0;
      pts.forEach(function (p) { s += (p[1] || 0) + (p[2] || 0); });
      return pts.length ? s / pts.length : 0;
    }
    return avg(b) - avg(a);
  });
  var dropped = keys.length - 8;
  keys = keys.slice(0, 8);
  var byTs = {};
  keys.forEach(function (k, ki) {
    (traffic[k].points || []).forEach(function (pt) {
      var t = _tsToUnix(pt[0]);
      (byTs[t] = byTs[t] || {})[ki] = pt;
    });
  });
  var xs = Object.keys(byTs).map(Number).sort(function (a, b) { return a - b; });
  if (xs.length < 2 || !keys.length) {
    el.innerHTML = "<p class='wnone'>기록 수집 중 — SNMP 커뮤니티가 설정된 스위치에서 " +
      "지표 폴러(기본 5분)가 두 주기를 돌면 그래프가 나타납니다.</p>";
    return;
  }
  var data = [xs];
  var series = [{}];
  keys.forEach(function (k, ki) {
    var color = PALETTE[ki % PALETTE.length];
    [1, 2].forEach(function (pos) {
      data.push(xs.map(function (t) {
        var pt = byTs[t][ki];
        return pt ? pt[pos] : null;
      }));
      series.push({
        label: traffic[k].name + (pos === 1 ? " ↓" : " ↑"),
        stroke: color, width: pos === 1 ? 2 : 1,
        dash: pos === 1 ? undefined : [5, 5],
        points: { show: false }, spanGaps: true });
    });
  });
  el.innerHTML = dropped > 0
    ? "<p class='wnone' style='margin:0 0 4px'>바쁜 포트 8개 표시 (외 " + dropped + "개 생략)</p>"
    : "";
  var box = document.createElement("div");
  el.appendChild(box);
  _plots.push(new uPlot({
    width: el.clientWidth || 500, height: 210,
    legend: { show: keys.length <= 4 },
    cursor: { points: { size: 6 } },
    scales: { x: { time: true } },
    axes: [Object.assign({}, _UP_AXIS),
           Object.assign({}, _UP_AXIS, {
             size: 56,
             values: function (u, vals) { return vals.map(_fmtBps); } })],
    series: series,
  }, data, box));
}

/* 기간 전환 버튼 줄 */
function rangeBtns() {
  var opts = [["1", "1시간"], ["24", "24시간"], ["168", "7일"]];
  return "<span class='wrange'>" + opts.map(function (o) {
    return "<button class='wrange__b" + (Number(o[0]) === _seriesHours ? " wrange__b--on" : "") +
      "' data-hours='" + o[0] + "'>" + o[1] + "</button>";
  }).join("") + "</span>";
}

document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest("[data-hours]");
  if (!b) return;
  _seriesHours = parseInt(b.getAttribute("data-hours"), 10) || 24;
  refreshSeries();
});

function _destroyPlots() {
  _plots.forEach(function (p) { try { p.destroy(); } catch (err) {} });
  _plots = [];
}

function _fwSeriesFiltered() {
  var sel = _fwDevSel();
  if (!sel) return _SERIES.firewalls || {};
  var out = {};
  Object.keys(_SERIES.firewalls || {}).forEach(function (id) {
    if (sel.has(String(id))) out[id] = _SERIES.firewalls[id];
  });
  return out;
}

/* 빈 카드 슬림화(v6.33) — 수집 전이라 안내문만 있는 카드가 큰 상자로 자리를
   차지하면 여백만 늘어난다(사용자 지적). 차트 placeholder는 renderSeriesCharts가
   렌더 후에 넣으므로, 차트까지 그린 뒤 다시 판정해야 한다. */
function slimEmptyCards() {
  ["summary", "switch", "firewall", "facility"].forEach(function (tab) {
    var pane = document.getElementById("wtab-" + tab);
    if (!pane) return;
    var hiddenN = 0;
    pane.querySelectorAll(".wcard").forEach(function (card) {
      var hasData = card.querySelector(
        "canvas, table, .wrank__row, .wmeter, .dsvg, .uplot");
      var empty = !hasData && !!card.querySelector(".wnone");
      card.classList.toggle("wcard--empty", empty);
      if (empty) {
        // 수집 전 카드는 아예 숨긴다(NOC 원칙: 안 쓰는 패널은 치운다).
        // 편집 모드에서는 흐리게 보여 존재를 알 수 있다.
        if (_editMode) { card.style.display = ""; }
        else { card.style.display = "none"; hiddenN++; }
      }
      // 목록이 긴 카드는 표준 높이로 눌러 행 정렬 유지(내부 스크롤)
      card.classList.toggle("wcard--tall", !empty && card.scrollHeight > 470);
    });
    var note = pane.querySelector(".wempty-note");
    if (hiddenN && !_editMode) {
      if (!note) {
        note = document.createElement("div");
        note.className = "wempty-note";
        pane.appendChild(note);
      }
      note.textContent = "수집 전 위젯 " + hiddenN +
        "개 숨김 — 수집·SNMP 연동 후 자동 표시됩니다";
      note.style.display = "";
    } else if (note) {
      note.style.display = "none";
    }
  });
}

/* 카드 제목의 긴 설명(.hint)을 ⓘ 툴팁으로 접는다 — 화면 텍스트 최소화
   (패널당 질문 하나 원칙). 마우스를 올리면 원문 설명이 그대로 보인다. */
function tidyHints() {
  document.querySelectorAll(".wall-pane h3 .hint").forEach(function (h) {
    var i = document.createElement("span");
    i.className = "winfo";
    i.title = h.textContent || "";
    i.textContent = "?";
    h.replaceWith(i);
  });
}

function renderSeriesCharts() {
  if (!_SERIES) return;
  _destroyPlots();
  var fwS = _fwSeriesFiltered();
  chartMulti("ch-fw-sess", fwS, function (pt) { return pt[3]; }, "");
  chartMulti("ch-fw-cpu", fwS, function (pt) { return pt[1]; }, "%");
  chartMulti("ch-fw-mem", fwS, function (pt) { return pt[2]; }, "%");
  var note = document.getElementById("fw-series-note");
  if (note) {
    var have = {};
    Object.keys(_SERIES.firewalls || {}).forEach(function (k) { have[k] = true; });
    var sel = _fwDevSel();
    var miss = ((_WSTAT && _WSTAT.firewalls && _WSTAT.firewalls.devices) || [])
      .filter(function (d) { return !have[String(d.id)] &&
                                    (!sel || sel.has(String(d.id))); })
      .map(function (d) { return d.name; });
    if (_SERIES.bg_snmp === false) {
      // 폴링 자체가 꺼져 있으면 '무응답'이 아니다 — 정확한 사유와 켜는 곳 안내
      note.style.display = "";
      note.innerHTML = "백그라운드 SNMP 폴링이 꺼져 있어 추이가 쌓이지 않습니다 " +
        "(기본 꺼짐 — 본 화면 설정 &gt; SNMP &gt; 백그라운드 자동 폴링에서 켤 수 있습니다)";
    } else {
      note.style.display = miss.length ? "" : "none";
      note.innerHTML = miss.length
        ? "추이 미표시 " + miss.length + "대 — SNMP 응답이 없어 지표가 안 쌓입니다: <b>" +
          esc(miss.join(", ")) + "</b> (설정의 SNMP 커뮤니티 · 장비의 허용 호스트 확인)"
        : "";
    }
  }
  slimEmptyCards();
  chartMulti("ch-sw-temp", _SERIES.switches,
             function (pt) { return pt[4]; }, "°C");
  chartTraffic("ch-sw-traffic", _SERIES.traffic);
  chartTotal("ch-ports", _SERIES.ports, "사용 중 포트", "#22d3ee");
  chartTotal("ch-fac", _SERIES.facility, "온라인 설비", "#34d399");
}

function refreshSeries() {
  fetch("/api/wall/series?hours=" + _seriesHours)
    .then(function (r) { return r.json(); })
    .then(function (d) { _SERIES = d; renderStats(); })
    .catch(function (e) { console.error("wall series:", e); });
}

/* ── 대시보드 커스터마이즈 ─────────────────────────────────────
   사용자가 직접 꾸민다: ① 장비 칩으로 보일 방화벽 선택 ② 위젯 편집에서
   카드 숨기기/크기(S·M·L·XL). 브라우저 localStorage에 저장(관제 PC별). */

function _fwDevSel() {
  try {
    var raw = localStorage.getItem("wall_fw_devsel");
    if (!raw) return null;                 // null = 전체
    var arr = JSON.parse(raw);
    return (arr && arr.length) ? new Set(arr.map(String)) : null;
  } catch (e) { return null; }
}

document.addEventListener("click", function (e) {
  var chip = e.target.closest && e.target.closest("[data-fwdev]");
  if (!chip) return;
  var id = chip.getAttribute("data-fwdev");
  var sel = _fwDevSel();
  var all = Array.prototype.map.call(
    document.querySelectorAll("[data-fwdev]:not([data-fwdev='all'])"),
    function (c) { return c.getAttribute("data-fwdev"); });
  if (id === "all") {
    localStorage.removeItem("wall_fw_devsel");
  } else {
    var cur = sel ? Array.from(sel) : all.slice();
    var i2 = cur.indexOf(id);
    if (i2 >= 0) cur.splice(i2, 1); else cur.push(id);
    if (!cur.length || cur.length === all.length) localStorage.removeItem("wall_fw_devsel");
    else localStorage.setItem("wall_fw_devsel", JSON.stringify(cur));
  }
  renderStats();
});

var _editMode = false;
function _wl() {
  try { return JSON.parse(localStorage.getItem("wall_layout_v1") || "{}"); }
  catch (e) { return {}; }
}
function _wlSave(m) { localStorage.setItem("wall_layout_v1", JSON.stringify(m)); }

var _SIZES = ["wcard--4", "wcard--6", "wcard--8", "wcard--12"];
function _cardKey(tab, card) {
  var h = card.querySelector("h3");
  var t = h ? (h.childNodes[0] ? String(h.childNodes[0].textContent || "").trim() : "") : "";
  return tab + ":" + t;
}

/* 렌더 후처리 — 카드 제목을 키로 저장된 크기/숨김을 적용하고,
   편집 모드면 카드마다 조절 버튼을 붙인다(렌더러 수정 없이 후처리로 통일). */
function applyLayout() {
  var layout = _wl();
  ["switch", "firewall", "facility"].forEach(function (tab) {
    var pane = document.getElementById("wtab-" + tab);
    if (!pane) return;
    pane.querySelectorAll(".wcard").forEach(function (card) {
      var key = _cardKey(tab, card);
      var st = layout[key] || {};
      if (st.size && _SIZES.indexOf(st.size) >= 0) {
        _SIZES.forEach(function (c) { card.classList.remove(c); });
        card.classList.add(st.size);
      }
      // 드래그로 정한 순서 — grid의 CSS order로 적용(DOM은 렌더 순서 유지)
      card.style.order = (st.order != null) ? st.order : "";
      card.setAttribute("draggable", _editMode ? "true" : "false");
      if (st.hidden && !_editMode) { card.style.display = "none"; return; }
      card.style.display = "";
      card.classList.toggle("wcard--dim", !!st.hidden && _editMode);
      var h = card.querySelector("h3");
      if (!h) return;
      var old = h.querySelector(".wtools");
      if (old) old.remove();
      if (_editMode) {
        var span = document.createElement("span");
        span.className = "wtools";
        span.innerHTML =
          "<button class='wtool' data-wact='size' data-wkey='" + esc(key) +
          "' title='크기 변경(S→M→L→XL)'>" + ico("expand") + "</button>" +
          "<button class='wtool' data-wact='hide' data-wkey='" + esc(key) + "'>" +
          (st.hidden ? ico("eye") + " 표시" : ico("eyeoff") + " 숨김") + "</button>";
        h.appendChild(span);
      }
    });
  });
}

document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest("[data-wact]");
  if (!b) return;
  var key = b.getAttribute("data-wkey");
  var layout = _wl();
  var st = layout[key] || {};
  if (b.getAttribute("data-wact") === "hide") {
    st.hidden = !st.hidden;
  } else {
    var card = b.closest(".wcard");
    var cur = _SIZES.filter(function (c) { return card.classList.contains(c); })[0] || "wcard--6";
    st.size = _SIZES[(_SIZES.indexOf(cur) + 1) % _SIZES.length];
  }
  layout[key] = st;
  _wlSave(layout);
  renderStats();
});

(function initEditBtn() {
  var nav = document.getElementById("wall-tabs");
  if (!nav) return;
  var b = document.createElement("button");
  b.id = "wall-edit-btn";
  b.className = "wall-tab wall-tab--edit";
  b.innerHTML = ico("sliders") + " 위젯 편집";
  b.title = "카드 드래그 순서·숨기기·크기 조절 — 이 PC 브라우저에 저장됩니다";
  b.addEventListener("click", function () {
    _editMode = !_editMode;
    b.classList.toggle("wall-tab--editing", _editMode);
    renderStats();
  });
  nav.appendChild(b);
})();

/* ── 위젯 드래그 순서(편집 모드) ─────────────────────────────────
   DOM은 렌더 순서 그대로 두고 CSS order만 바꾼다 — 30초 재렌더가 DOM을
   다시 만들어도 applyLayout이 저장된 order를 도로 입히므로 순서가 유지된다. */

var _dragCard = null;

function _gridSeq(grid) {
  return Array.prototype.slice.call(grid.querySelectorAll(":scope > .wcard"))
    .sort(function (a, b) {
      return (parseInt(a.style.order, 10) || 0) - (parseInt(b.style.order, 10) || 0);
    });
}

document.addEventListener("dragstart", function (e) {
  if (!_editMode) { if (e.preventDefault) e.preventDefault(); return; }
  var card = e.target.closest && e.target.closest(".wcard");
  if (!card) return;
  _dragCard = card;
  card.classList.add("wcard--drag");
  try {
    e.dataTransfer.setData("text/plain", "wcard");
    e.dataTransfer.effectAllowed = "move";
  } catch (err) {}
});

document.addEventListener("dragover", function (e) {
  if (!_dragCard) return;
  var over = e.target.closest && e.target.closest(".wcard");
  if (!over || over === _dragCard) return;
  if (over.parentElement !== _dragCard.parentElement) return;
  e.preventDefault();
  // 미리보기: 드래그 카드를 대상 앞/뒤로 끼운 순서를 즉시 order로 반영
  var seq = _gridSeq(over.parentElement);
  var di = seq.indexOf(_dragCard), oi = seq.indexOf(over);
  if (di < 0 || oi < 0 || di === oi) return;
  seq.splice(di, 1);
  seq.splice(oi, 0, _dragCard);
  seq.forEach(function (c, i) { c.style.order = i; });
});

document.addEventListener("dragend", function () {
  if (!_dragCard) return;
  _dragCard.classList.remove("wcard--drag");
  var grid = _dragCard.parentElement;
  var pane = _dragCard.closest("[id^='wtab-']");
  var tab = pane ? pane.id.replace("wtab-", "") : "";
  var layout = _wl();
  _gridSeq(grid).forEach(function (c, i) {
    var key = _cardKey(tab, c);
    (layout[key] = layout[key] || {}).order = i;
  });
  _wlSave(layout);
  _dragCard = null;
});

/* ── TV 관제 모드 ────────────────────────────────────────────────
   대형 모니터 상시 표출용: 30초마다 탭 자동 로테이션. 알람성 이벤트가 새로
   오면 관련 탭으로 즉시 전환 후 60초 머문다. 사용자가 조작하면 60초 정지. */

var _TV_ROTATE_MS = 30000;
var _TV_HOLD_MS = 60000;
var _tvOn = false;
var _tvHoldUntil = 0;
var _tvNextAt = 0;
var _tvLastEvtSig = null;

// 알람성 이벤트 종류 → 보여줄 탭
var _TV_JUMP = {
  port_down: "switch", port_errors: "switch", switch_unreachable: "switch",
  flapping: "switch", looping: "switch",
  firewall_unreachable: "firewall", threshold_over: "firewall",
  device_offline: "facility",
};

function tvMaybeJump(events) {
  if (!_tvOn || !events || !events.length) return;
  var top = events[0];
  var sig = (top.ts || "") + "|" + (top.kind || "") + "|" + (top.message || "");
  if (_tvLastEvtSig === null) { _tvLastEvtSig = sig; return; }   // 첫 로딩은 기준만
  if (sig === _tvLastEvtSig) return;
  _tvLastEvtSig = sig;
  var tab = _TV_JUMP[top.kind];
  if (!tab) return;
  wallShowTab(tab);
  _tvHoldUntil = Date.now() + _TV_HOLD_MS;
  _tvNextAt = _tvHoldUntil + _TV_ROTATE_MS;
}

setInterval(function () {
  if (!_tvOn || _editMode) return;
  var now = Date.now();
  if (now < _tvHoldUntil || now < _tvNextAt) return;
  _tvNextAt = now + _TV_ROTATE_MS;
  var i = _TAB_ORDER.indexOf(_wtab);
  wallShowTab(_TAB_ORDER[(i + 1) % _TAB_ORDER.length]);
}, 3000);

// 사용자가 화면을 만지면 로테이션을 잠시 멈춘다(보던 화면이 넘어가면 불편)
document.addEventListener("click", function (e) {
  if (!_tvOn) return;
  if (e.target.closest && e.target.closest("#wall-tv-btn")) return;
  _tvHoldUntil = Date.now() + _TV_HOLD_MS;
});

(function initTvBtn() {
  var nav = document.getElementById("wall-tabs");
  if (!nav) return;
  var b = document.createElement("button");
  b.id = "wall-tv-btn";
  b.className = "wall-tab wall-tab--edit";
  b.innerHTML = ico("monitor") + " TV 모드";
  b.title = "탭 자동 로테이션(30초) + 알람 발생 시 해당 탭 자동 전환";
  function apply() {
    b.classList.toggle("wall-tab--editing", _tvOn);
    var ind = document.getElementById("wall-tv-ind");
    if (ind) ind.style.display = _tvOn ? "" : "none";
  }
  b.addEventListener("click", function () {
    _tvOn = !_tvOn;
    localStorage.setItem("wall_tv_mode", _tvOn ? "1" : "0");
    _tvNextAt = Date.now() + _TV_ROTATE_MS;
    _tvHoldUntil = 0;
    apply();
    // 즉각 피드백(사용자: "화면상 달라지는 게 없다") — 켜는 순간 다음 탭으로
    if (_tvOn) wallShowTab(_TAB_ORDER[(_TAB_ORDER.indexOf(_wtab) + 1) % _TAB_ORDER.length]);
  });
  nav.appendChild(b);
  _tvOn = localStorage.getItem("wall_tv_mode") === "1";
  if (_tvOn) _tvNextAt = Date.now() + _TV_ROTATE_MS;
  apply();
})();

refreshSeries();
// 5분 격자 데이터라 1분 갱신이면 충분(가장 최근 점 반영)
setInterval(refreshSeries, 60000);
