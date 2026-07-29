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

var KIND_KO = {
  new_device: "새 설비", device_offline: "설비 연결 끊김", device_online: "설비 복구",
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
    host.innerHTML = "<div class='wall-ok'>✓ 이상 없음<small>모든 장비 정상 · " +
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
          return "<span class='wall-sumchip" + (isFac ? " wall-sumchip--click" : "") + active + "'" + attr + ">🔌 " +
            esc(sw) + (s.location ? " <i>(" + esc(s.location) + ")</i>" : "") +
            " <b>" + s.count + "</b></span>";
        }).join("") + "</div>"
      : "";
    // 칩 필터 적용(설비 카테고리 한정)
    var items = c.items;
    var filterBar = "";
    if (isFac && wallFacFilter) {
      items = items.filter(function (p) { return (p.switch || "미확인") === wallFacFilter; });
      filterBar = "<div class='wall-cat__filter'>필터: 🔌 " + esc(wallFacFilter) +
        " (" + items.length + ") <button class='wall-filter-clear'>✕ 전체 보기</button></div>";
    }
    // '외 N건' 안내: 서버가 잘라 보낸 경우 항상 표시(설비 필터 중에도 유지),
    // 다른 카테고리(도달 불가/수집 실패)도 total이 있으면 동일하게 안내.
    var moreHtml = (c.total != null && c.total > c.items.length)
      ? "<div class='wall-cat__more'>외 " + (c.total - c.items.length) + "건 — 설비 현황에서 전체 확인</div>"
      : "";
    return "<div class='wall-cat wall-cat--" + esc(c.severity || "warn") + "'>" +
      "<div class='wall-cat__title'>" + esc(c.title) +
      " <span class='wall-cat__count'>" + count + "</span></div>" +
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
    var btn = e.target.closest(".pcard__recollect");
    if (!btn) return;
    var ip = btn.getAttribute("data-ip"), subnet = btn.getAttribute("data-subnet");
    startRecollect(btn, ip, subnet);
  });

  function reset(btn) { btn.disabled = false; btn.textContent = "재수집"; }

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
