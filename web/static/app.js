/* NetDash — 메인 UI 스크립트 */

"use strict";

// ─── 전역 상태 ────────────────────────────────────────────────────
let _switches = [];
let _firewalls = [];
let _servers = [];
let _currentSwitchId = null;
let _pollTimer = null;

// ─── 읽기 전용 모드 (다른 PC의 주 서버가 DB 사용 중) ──────────────
// 서버가 쓰기 요청에 423을 반환하면 어느 화면에서든 안내를 띄운다.
// (개별 fetch 핸들러를 전부 고치지 않도록 전역 래퍼로 처리)
(function () {
  var origFetch = window.fetch;
  var lastAlert = 0;
  window.fetch = function () {
    return origFetch.apply(this, arguments).then(function (r) {
      if (r.status === 423) {
        var now = Date.now();
        if (now - lastAlert > 3000) {  // 연타 시 알림 폭주 방지
          lastAlert = now;
          r.clone().json().then(function (d) {
            alert(d.error || "다른 사용자가 DB를 사용 중입니다. 조회만 가능합니다.");
          }).catch(function () {
            alert("다른 사용자가 DB를 사용 중입니다. 조회만 가능합니다.");
          });
        }
      }
      return r;
    });
  };
})();

function showReadonlyBanner(primaryHost) {
  var el = document.getElementById("readonly-banner");
  if (!el) {
    el = document.createElement("div");
    el.id = "readonly-banner";
    el.style.cssText = "position:sticky;top:0;z-index:9999;background:#b45309;" +
      "color:#fff;text-align:center;padding:6px 12px;font-size:13px;font-weight:600";
    document.body.insertBefore(el, document.body.firstChild);
  }
  el.textContent = "읽기 전용 모드 — 주 서버(" + (primaryHost || "다른 PC") +
    ")가 DB를 사용 중입니다. 조회는 가능하며, 주 서버 종료 시 자동으로 전환됩니다.";
}

function clearReadonlyBanner() {
  // 승격(주 서버 전환) 감지: 배너를 초록으로 바꿔 8초간 알린 뒤 제거
  var el = document.getElementById("readonly-banner");
  if (!el || el.dataset.promoted) return;
  el.dataset.promoted = "1";
  el.style.background = "#15803d";
  el.textContent = "주 서버로 전환되었습니다 — 수집·수정 기능이 활성화되었습니다.";
  setTimeout(function () { el.remove(); }, 8000);
}

// ─── DB 오류 상세 배너(원인·힌트·경로) ──────────────────────────
function showDbErrorBanner(info) {
  info = info || {};
  var el = document.getElementById("dberr-banner");
  if (!el) {
    el = document.createElement("div");
    el.id = "dberr-banner";
    el.style.cssText = "position:sticky;top:0;z-index:10000;background:#991b1b;" +
      "color:#fff;padding:10px 16px;font-size:13px;line-height:1.6;border-bottom:2px solid #fca5a5";
    document.body.insertBefore(el, document.body.firstChild);
  }
  el.innerHTML =
    "<b>⚠ DB 오류: " + escHtml(info.reason || "알 수 없음") + "</b>" +
    (info.path_kind ? " <span style='opacity:.85'>[" + escHtml(info.path_kind) + "]</span>" : "") +
    (info.hint ? "<div style='font-weight:400;margin-top:2px'>" + escHtml(info.hint) + "</div>" : "") +
    (info.detail ? "<div style='font-weight:400;opacity:.8;font-size:11px;margin-top:2px'>상세: " +
      escHtml(info.detail) + (info.path ? " · 경로: " + escHtml(info.path) : "") + "</div>" : "");
}
function clearDbErrorBanner() {
  var el = document.getElementById("dberr-banner");
  if (el) el.remove();
}

// ─── 이벤트 위임 (CSP 'self' 호환: inline onclick 금지) ──────────────
// 동적 생성 버튼은 data-action/data-payload/data-id로 위임 처리한다.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-action]");
  if (!btn) return;
  var action = btn.getAttribute("data-action");
  var payload = btn.getAttribute("data-payload");
  var obj = payload ? JSON.parse(decodeURIComponent(payload)) : null;
  var id = btn.getAttribute("data-id");
  var nid = id != null ? parseInt(id, 10) : null;
  switch (action) {
    case "detail-switch": e.stopPropagation(); openDetailPanel(obj); break;
    case "collect-switch": e.stopPropagation(); openCredentialModal(obj); break;
    case "edit-switch": editSwitch(obj); break;
    case "diagnose-switch": diagnoseSwitch(nid); break;
    case "terminal-switch": openTerminal(nid); break;
    case "delete-switch": deleteSwitch(nid); break;
    case "collect-fw":
      // 저장된 자격증명이 있으면 모달 없이 바로 수집(매번 토큰 재입력 방지)
      if (obj && obj.has_credential) collectFirewallDirect(obj.id);
      else openFwCollect(obj);
      break;
    case "detail-fw": showFirewallDetail(nid); break;
    case "edit-fw": editFirewall(obj); break;
    case "delete-fw": deleteFirewall(nid); break;
    case "vlan-toggle": toggleVlanGroup(btn); break;
  }
});

// ─── 테이블 검색 위임 (.tbl-search → data-target tbody 행 필터) ──────
document.addEventListener("input", function (e) {
  var inp = e.target;
  if (!inp.classList) return;
  // 위치 필터(현황판/스위치 현황) → 카드/표 재렌더
  if (inp.classList.contains("loc-filter")) {
    // 필터로 숨겨진 장비가 수집/삭제 대상에 잔류하지 않도록 선택 해제
    // (상태 필터와 동일 정책 — '다른 리스트 오수집/오삭제 방지').
    _bulkSel = {};
    _tblSel = {};
    if (inp.id === "loc-filter-room") { renderRoom(_switches); return; }
    renderSwitchGrid(_switches);
    renderSwitchTable(_switches);
    if (_viewMode === "rack") renderRackView(_switches);
    return;
  }
  if (!inp.classList.contains("tbl-search")) return;
  var tbody = document.getElementById(inp.getAttribute("data-target"));
  if (!tbody) return;
  var q = inp.value.trim().toLowerCase();
  tbody.querySelectorAll("tr").forEach(function (tr) {
    tr.style.display = (!q || tr.textContent.toLowerCase().indexOf(q) >= 0) ? "" : "none";
  });
});

// 위치 필터 적용 헬퍼(현황판=loc-filter-dash, 스위치현황=loc-filter-sw)
function _applyLocFilter(list, inputId) {
  var el = document.getElementById(inputId);
  var q = el ? el.value.trim().toLowerCase() : "";
  if (!q) return list;
  // 위치·TPS 라벨·hostname뿐 아니라 IP·이름·모델로도 검색
  return list.filter(function (s) {
    var hay = [s.location, s.tps_location, s.hostname, s.ip, s.host, s.name, s.model]
      .map(function (x) { return x || ""; }).join(" ").toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

// ─── 설정(상단 ⚙): 자동 수집·상태 감시·알람·이메일 ───────────────
(function () {
  // 트리거는 상단 헤더의 '⚙ 설정' 버튼(구 현황판 '자동 수집' 버튼 대체)
  var btn = document.getElementById("btn-settings") || document.getElementById("btn-auto-collect");
  function _setVal(id, v) { var el = document.getElementById(id); if (el) el.value = v; }
  function _setChk(id, v) { var el = document.getElementById(id); if (el) el.checked = !!v; }
  function _val(id, dflt) { var el = document.getElementById(id); return el ? el.value : dflt; }
  function _chk(id) { var el = document.getElementById(id); return el ? el.checked : false; }
  if (btn) btn.addEventListener("click", function () {
    fetch("/api/settings/auto_collect").then(function (r) { return r.json(); }).then(function (d) {
      _setChk("ac-enabled", d.enabled);
      _setVal("ac-times", d.times || "06:00,18:00");
      _setChk("ac-fac-enabled", d.facility_enabled);
      _setVal("ac-fac-time", d.facility_time || "07:00");
      _setChk("ac-reach-enabled", d.reach_enabled !== false);
      _setVal("ac-retention", d.retention_days || "90");
      var info = document.getElementById("ac-fac-info");
      if (info) info.textContent = (d.facility_bands || 0) + "개 대역이 자동 스캔 대상으로 기억되어 있습니다. " +
        "(설비 탭에서 '대역 수집'을 한 번 실행한 대역이 자동 등록. 스위치에 저장된 계정 필요)";
      // 이메일 설정 로드
      fetch("/api/settings/email").then(function (r) { return r.json(); }).then(function (e) {
        _setChk("em-enabled", e.enabled);
        _setVal("em-host", e.smtp_host || "");
        _setVal("em-port", e.smtp_port || "25");
        _setVal("em-from", e.smtp_from || "");
        _setVal("em-to", e.email_to || "");
        _setVal("em-sev", e.min_sev || "warning");
        _setVal("em-user", ""); _setVal("em-pass", "");
        var tr = document.getElementById("em-test-result");
        if (tr) tr.textContent = e.has_auth ? "SMTP 인증정보 저장됨(변경 시에만 재입력)" : "";
      }).catch(function () {});
      openModal("modal-auto-collect");
    }).catch(function (e) { console.error(e); });
  });
  var emTest = document.getElementById("btn-em-test");
  if (emTest) emTest.addEventListener("click", function () {
    var tr = document.getElementById("em-test-result");
    if (tr) tr.textContent = "설정 저장 후 테스트 중...";
    // 현재 입력값을 먼저 저장한 뒤 테스트(저장 안 된 값으로 테스트되는 혼동 방지)
    fetch("/api/settings/email", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        enabled: _chk("em-enabled"), smtp_host: _val("em-host", ""), smtp_port: _val("em-port", "25"),
        smtp_from: _val("em-from", ""), email_to: _val("em-to", ""), min_sev: _val("em-sev", "warning"),
        smtp_user: _val("em-user", ""), smtp_pass: _val("em-pass", ""),
      }),
    }).then(function () {
      return fetch("/api/settings/email/test", { method: "POST", headers: {"Content-Type": "application/json"}, body: "{}" });
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (tr) { tr.textContent = res.detail || (res.ok ? "발송 성공" : "발송 실패"); tr.style.color = res.ok ? "#15803d" : "#991b1b"; }
    }).catch(function () { if (tr) tr.textContent = "테스트 오류"; });
  });
  var save = document.getElementById("btn-ac-save");
  if (save) save.addEventListener("click", function () {
    var body = {
      enabled: _chk("ac-enabled"),
      times: _val("ac-times", "06:00,18:00"),
      facility_enabled: _chk("ac-fac-enabled"),
      facility_time: _val("ac-fac-time", "07:00"),
      reach_enabled: _chk("ac-reach-enabled"),
      retention_days: _val("ac-retention", "90"),
    };
    var emailBody = {
      enabled: _chk("em-enabled"), smtp_host: _val("em-host", ""), smtp_port: _val("em-port", "25"),
      smtp_from: _val("em-from", ""), email_to: _val("em-to", ""), min_sev: _val("em-sev", "warning"),
      smtp_user: _val("em-user", ""), smtp_pass: _val("em-pass", ""),
    };
    fetch("/api/settings/auto_collect", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (!res.ok) { alert(res.error || "저장 실패"); return null; }
      return fetch("/api/settings/email", {
        method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(emailBody),
      });
    }).then(function (r) {
      if (r) { closeModal("modal-auto-collect"); alert("자동화 설정이 저장되었습니다."); }
    }).catch(function (e) { console.error(e); alert("서버 오류"); });
  });
})();

// ─── 장비 일괄 등록(IP/SUBNET/HOSTNAME 엑셀) ─────────────────────
(function () {
  var btn = document.getElementById("btn-import-inventory");
  var inp = document.getElementById("inventory-file-input");
  if (!btn || !inp) return;
  btn.addEventListener("click", function () { inp.click(); });
  inp.addEventListener("change", function () {
    if (!inp.files.length) return;
    var fd = new FormData();
    fd.append("file", inp.files[0]);
    fetch("/api/switches/import-inventory", {method: "POST", body: fd})
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (res.ok) {
          alert("장비 일괄 등록 완료: " + res.imported + "건 등록" +
            (res.skipped ? " (허용 대역 밖 " + res.skipped + "건 제외)" : "") + " / 전체 " + res.total + "행");
          pollState();
        } else alert(res.error || "등록 실패");
        inp.value = "";
      }).catch(function (e) { console.error(e); alert("서버 오류"); inp.value = ""; });
  });
})();

// ─── 서버/방화벽 엑셀 일괄 등록(공통 바인더) ─────────────────────
function _bindExcelImport(btnId, inputId, url, label, reload) {
  var btn = document.getElementById(btnId);
  var inp = document.getElementById(inputId);
  if (!btn || !inp) return;
  btn.addEventListener("click", function () { inp.click(); });
  inp.addEventListener("change", function () {
    if (!inp.files.length) return;
    var fd = new FormData();
    fd.append("file", inp.files[0]);
    fetch(url, { method: "POST", body: fd })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (res.ok) {
          alert(label + " 완료: " + res.imported + "건 등록" +
            (res.skipped ? " (제외 " + res.skipped + "건)" : "") + " / 전체 " + res.total + "행");
          if (typeof reload === "function") reload();
        } else alert(res.error || "등록 실패");
        inp.value = "";
      }).catch(function (e) { console.error(e); alert("서버 오류"); inp.value = ""; });
  });
}
_bindExcelImport("btn-server-import", "server-import-file", "/api/servers/import",
  "서버 엑셀 등록", function () { if (typeof loadServers === "function") loadServers(); });
_bindExcelImport("btn-firewall-import", "firewall-import-file", "/api/firewalls/import",
  "방화벽 엑셀 등록", function () { if (typeof loadFirewalls === "function") loadFirewalls(); });

// 테이블 검색창 HTML 생성 헬퍼
function _searchBox(targetId, placeholder) {
  return "<input class='tbl-search' data-target='" + targetId + "' placeholder='" +
    placeholder + "' style='margin-bottom:8px;padding:5px 9px;width:240px;" +
    "border:1px solid #cbd5e1;border-radius:4px;font-size:13px'>";
}

// ─── 현황 페이지 CSV/TXT 다운로드(공통 위임) ─────────────────────
document.addEventListener("click", function (e) {
  var b = e.target.closest(".nd-export");
  if (!b) return;
  var kind = b.getAttribute("data-export");
  var fmt = b.getAttribute("data-fmt") || "csv";
  if (!kind) return;
  window.location = "/api/export/" + encodeURIComponent(kind) + "?format=" + encodeURIComponent(fmt);
});

// ─── IP 컬럼 정렬(모든 .data-table 공통) ─────────────────────────
// 헤더에 'IP'가 있으면 클릭 시 IP 숫자 기준 오름/내림 정렬. 표 재렌더 후에도 재적용.
(function () {
  function ipToInt(s) {
    var m = String(s || "").match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (!m) return -1;                       // IP 없는 행은 뒤로
    return ((+m[1]) * 16777216) + ((+m[2]) * 65536) + ((+m[3]) * 256) + (+m[4]);
  }
  function sortByCol(tbl, idx, dir) {
    var tb = tbl.tBodies[0];
    if (!tb) return;
    var rows = Array.prototype.slice.call(tb.rows).filter(function (r) {
      return r.cells.length > idx && !r.querySelector("td[colspan]");
    });
    if (rows.length < 2) return;
    rows.sort(function (a, b) {
      return dir * (ipToInt(a.cells[idx].textContent) - ipToInt(b.cells[idx].textContent));
    });
    rows.forEach(function (r) { tb.appendChild(r); });
  }
  function setup(tbl) {
    if (tbl.dataset.ipSort === "1") return;
    var ths = Array.prototype.slice.call(tbl.querySelectorAll("thead th"));
    var idx = -1;
    ths.forEach(function (th, i) {
      var t = (th.textContent || "").trim().toUpperCase();
      if (idx < 0 && (t === "IP" || t === "호스트" || t.indexOf("IP") === 0)) idx = i;
    });
    if (idx < 0) return;
    tbl.dataset.ipSort = "1";
    var th = ths[idx];
    if (th.id === "fac-sort-ip") return;      // 설비 표는 자체 정렬 사용(중복 방지)
    th.style.cursor = "pointer";
    th.title = "클릭: IP 오름/내림차순 정렬";
    var arrow = document.createElement("span");
    arrow.className = "ip-sort-arrow";
    arrow.textContent = " ↕";
    th.appendChild(arrow);
    var dir = 0;
    th.addEventListener("click", function (e) {
      if (e.target.closest(".col-resizer")) return;   // 폭 조절 핸들 클릭은 제외
      dir = dir === 1 ? -1 : 1;
      arrow.textContent = dir === 1 ? " ▲" : " ▼";
      sortByCol(tbl, idx, dir);
      tbl._ipSortDir = dir;
      tbl._ipSortIdx = idx;
    });
    // 표가 다시 그려지면(수집·폴링) 마지막 정렬을 재적용
    var tb = tbl.tBodies[0];
    if (tb && window.MutationObserver) {
      var mo = new MutationObserver(function () {
        if (tbl._ipSortDir) {
          mo.disconnect();
          sortByCol(tbl, tbl._ipSortIdx, tbl._ipSortDir);
          mo.observe(tb, { childList: true });
        }
      });
      mo.observe(tb, { childList: true });
    }
  }
  function setupAll() { document.querySelectorAll("table.data-table").forEach(setup); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", setupAll);
  else setupAll();
  document.addEventListener("click", function () { setTimeout(setupAll, 60); });
})();

// ─── 표 컬럼 너비 조정(헤더 경계 드래그, 너비는 로컬 저장) ───────
// 모든 .data-table에 적용. 헤더 우측 경계를 끌어 폭 조절, 더블클릭이면 그 컬럼 초기화.
(function () {
  var MIN_W = 44;

  function tableKey(tbl) {
    // 표 식별: tbody id > 표가 속한 탭 id > 문서 내 순번
    var tb = tbl.querySelector("tbody");
    if (tb && tb.id) return tb.id;
    var pane = tbl.closest(".tab-pane");
    var idx = Array.prototype.indexOf.call(document.querySelectorAll("table.data-table"), tbl);
    return (pane ? pane.id : "tbl") + ":" + idx;
  }
  function loadWidths(key) {
    try { return JSON.parse(localStorage.getItem("nd_colw:" + key) || "{}"); }
    catch (e) { return {}; }
  }
  function saveWidths(key, map) {
    try { localStorage.setItem("nd_colw:" + key, JSON.stringify(map)); } catch (e) {}
  }
  // 현재 렌더된 폭을 모두 인라인으로 고정 → table-layout:fixed 전환(레이아웃 튐 방지)
  function freeze(tbl, ths) {
    if (tbl.classList.contains("col-sized")) return;
    ths.forEach(function (th) { th.style.width = th.getBoundingClientRect().width + "px"; });
    tbl.classList.add("col-sized");
  }

  function setup(tbl) {
    if (tbl.dataset.colResize === "1") return;
    var ths = Array.prototype.slice.call(tbl.querySelectorAll("thead th"));
    if (ths.length < 2) return;
    tbl.dataset.colResize = "1";
    var key = tableKey(tbl);
    var saved = loadWidths(key);

    // 저장된 폭 복원
    var hasSaved = false;
    ths.forEach(function (th, i) {
      if (saved[i]) { th.style.width = saved[i] + "px"; hasSaved = true; }
    });
    if (hasSaved) tbl.classList.add("col-sized");

    ths.forEach(function (th, i) {
      if (i === ths.length - 1) return;          // 마지막 컬럼은 잔여 폭
      th.classList.add("col-resizable");
      var grip = document.createElement("span");
      grip.className = "col-resizer";
      grip.title = "드래그: 폭 조절 · 더블클릭: 이 컬럼 폭 초기화";
      th.appendChild(grip);

      var startX = 0, startW = 0;
      function onMove(e) {
        var w = Math.max(MIN_W, startW + (e.clientX - startX));
        th.style.width = w + "px";
      }
      function onUp() {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        document.body.classList.remove("col-resizing");
        grip.classList.remove("dragging");
        var map = loadWidths(key);
        map[i] = Math.round(parseFloat(th.style.width) || th.getBoundingClientRect().width);
        saveWidths(key, map);
      }
      grip.addEventListener("mousedown", function (e) {
        e.preventDefault(); e.stopPropagation();
        freeze(tbl, ths);
        startX = e.clientX;
        startW = th.getBoundingClientRect().width;
        document.body.classList.add("col-resizing");
        grip.classList.add("dragging");
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      });
      // 더블클릭 = 이 컬럼만 저장 폭 삭제 후 자동 폭으로
      grip.addEventListener("dblclick", function (e) {
        e.preventDefault(); e.stopPropagation();
        var map = loadWidths(key);
        delete map[i];
        saveWidths(key, map);
        th.style.width = "";
        if (!Object.keys(map).length) {
          ths.forEach(function (t) { t.style.width = ""; });
          tbl.classList.remove("col-sized");
        }
      });
    });
  }

  function setupAll() {
    document.querySelectorAll("table.data-table").forEach(setup);
  }
  // 최초 + 탭 전환/동적 생성(상세 패널 표 등) 이후에도 적용
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupAll);
  } else {
    setupAll();
  }
  document.addEventListener("click", function () { setTimeout(setupAll, 60); });
  window._ndSetupColumnResize = setupAll;   // 필요 시 수동 호출
})();

// ─── 사이드바 접기/펼치기(선택 상태는 로컬 저장) ─────────────────
(function () {
  var btn = document.getElementById("btn-nav-toggle");
  if (!btn) return;
  function apply(collapsed) {
    document.body.classList.toggle("nav-collapsed", collapsed);
    btn.textContent = collapsed ? "▶" : "◀ 메뉴 접기";
    try { localStorage.setItem("nd_nav_collapsed", collapsed ? "1" : "0"); } catch (e) {}
  }
  var saved = "0";
  try { saved = localStorage.getItem("nd_nav_collapsed") || "0"; } catch (e) {}
  apply(saved === "1");
  btn.addEventListener("click", function () {
    apply(!document.body.classList.contains("nav-collapsed"));
  });
})();

// ─── 탭 전환 ─────────────────────────────────────────────────────
document.querySelectorAll(".tab-nav__btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-nav__btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "vlan") loadVlans();
    if (btn.dataset.tab === "switch") renderSwitchTable(_switches);
    if (btn.dataset.tab === "firewall") loadFirewalls();
    if (btn.dataset.tab === "facility") loadFacility();
    if (btn.dataset.tab === "server") loadServers();
    if (btn.dataset.tab === "room") { loadFirewalls(); loadServers(); renderRoom(_switches); }
    if (btn.dataset.tab === "topology") loadTopology();
  });
});

// ─── 상세 패널 탭 ────────────────────────────────────────────────
document.querySelectorAll(".detail-tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".detail-tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".dtab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("dtab-" + btn.dataset.dtab).classList.add("active");
    if (btn.dataset.dtab === "config" && _currentSwitchId) loadConfigTab(_currentSwitchId);
    if (btn.dataset.dtab === "history" && _currentSwitchId) loadPortHistory(_currentSwitchId);
  });
});

// ─── 모달 닫기 ───────────────────────────────────────────────────
document.querySelectorAll("[data-close]").forEach(btn => {
  btn.addEventListener("click", () => closeModal(btn.dataset.close));
});
document.querySelectorAll(".modal__backdrop").forEach(bd => {
  bd.addEventListener("click", () => {
    document.querySelectorAll(".modal:not(.hidden)").forEach(m => {
      // 터미널 모달은 closeTerminal로 닫아 SSH WebSocket 세션·resize 리스너를
      // 정리한다(백드롭 클릭 시 closeModal만 하면 _termWs 세션이 방치됐다).
      if (m.id === "modal-terminal") closeTerminal();
      else closeModal(m.id);
    });
  });
});

function openModal(id) { document.getElementById(id).classList.remove("hidden"); }
function closeModal(id) { document.getElementById(id).classList.add("hidden"); }

// ─── 상세 패널 ───────────────────────────────────────────────────
document.getElementById("detail-close").addEventListener("click", closeDetailPanel);
document.getElementById("detail-overlay").addEventListener("click", closeDetailPanel);

// ─── 웹 SSH 터미널 (xterm.js + WebSocket) ────────────────────────
var _term = null, _termFit = null, _termWs = null;
(function () {
  var btn = document.getElementById("detail-terminal");
  if (btn) btn.addEventListener("click", function () {
    if (_currentSwitchId != null) openTerminal(_currentSwitchId);
  });
  var closeBtn = document.getElementById("term-close-btn");
  if (closeBtn) closeBtn.addEventListener("click", closeTerminal);
})();

function openTerminal(switchId) {
  var sw = (_switches || []).find(function (s) { return s.id === switchId; });
  var title = document.getElementById("term-title");
  if (title) title.textContent = "💻 SSH 터미널 — " + (sw ? (sw.name + " (" + sw.ip + ")") : ("#" + switchId));
  var statusEl = document.getElementById("term-status");
  openModal("modal-terminal");

  if (typeof Terminal === "undefined") {
    if (statusEl) statusEl.textContent = "터미널 라이브러리를 불러오지 못했습니다.";
    return;
  }
  // 이전 세션 정리
  closeTerminal(true);

  _term = new Terminal({ cursorBlink: true, fontSize: 13, theme: { background: "#000000" },
                         fontFamily: "Consolas, 'Courier New', monospace" });
  try { _termFit = new FitAddon.FitAddon(); _term.loadAddon(_termFit); } catch (e) { _termFit = null; }
  _term.open(document.getElementById("terminal"));
  try { if (_termFit) _termFit.fit(); } catch (e) {}

  // 토큰(원격 접속 시 필요) — 로컬은 서버가 면제
  var token = (window._API_TOKEN || "");
  var proto = location.protocol === "https:" ? "wss" : "ws";
  var url = proto + "://" + location.host + "/ws/shell/" + switchId +
    (token ? "?token=" + encodeURIComponent(token) : "");
  if (statusEl) statusEl.textContent = "연결 중...";
  try {
    _termWs = new WebSocket(url);
  } catch (e) {
    if (statusEl) statusEl.textContent = "WebSocket 연결 실패: " + e;
    return;
  }
  _termWs.onopen = function () {
    if (statusEl) statusEl.textContent = "연결됨 · 세션은 감사 로그에 기록됩니다.";
    _sendResize();
  };
  _termWs.onmessage = function (ev) { _term.write(ev.data); };
  _termWs.onclose = function () {
    if (statusEl) statusEl.textContent = "연결 종료됨.";
    if (_term) _term.write("\r\n\x1b[33m[연결이 종료되었습니다]\x1b[0m\r\n");
  };
  _termWs.onerror = function () {
    if (statusEl) statusEl.textContent = "연결 오류.";
  };
  // 입력 → 서버
  _term.onData(function (d) {
    if (_termWs && _termWs.readyState === 1) _termWs.send(d);
  });
  // 리사이즈 반영
  window.addEventListener("resize", _termResizeHandler);
}

function _sendResize() {
  try {
    if (_termFit) _termFit.fit();
    if (_term && _termWs && _termWs.readyState === 1) {
      _termWs.send("\x00resize:" + _term.cols + "," + _term.rows);
    }
  } catch (e) {}
}
function _termResizeHandler() { _sendResize(); }

function closeTerminal(silent) {
  window.removeEventListener("resize", _termResizeHandler);
  if (_termWs) { try { _termWs.close(); } catch (e) {} _termWs = null; }
  if (_term) { try { _term.dispose(); } catch (e) {} _term = null; }
  _termFit = null;
  if (!silent) closeModal("modal-terminal");
}

function openDetailPanel(sw) {
  _currentSwitchId = sw.id;
  document.getElementById("detail-title").textContent = sw.name;
  document.getElementById("detail-subtitle").textContent =
    sw.ip + (sw.hostname ? " · " + sw.hostname : "") +
    (sw.tps_location ? "  📍 " + sw.tps_location : "");
  document.getElementById("detail-panel").classList.remove("hidden");
  document.getElementById("detail-overlay").classList.remove("hidden");

  document.querySelectorAll(".detail-tab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".dtab-pane").forEach(p => p.classList.remove("active"));
  document.querySelector('[data-dtab="ports"]').classList.add("active");
  document.getElementById("dtab-ports").classList.add("active");

  loadDetailData(sw.id);
}

function closeDetailPanel() {
  document.getElementById("detail-panel").classList.add("hidden");
  document.getElementById("detail-overlay").classList.add("hidden");
  _currentSwitchId = null;
}

function loadDetailData(switchId) {
  fetch("/api/switches/" + switchId + "/detail")
    .then(function(r) { return r.json(); })
    .then(function(detail) {
      var ports = detail.ports || [], macs = detail.macs || [], arps = detail.arps || [];
      renderDetailSummary(ports, macs, arps);
      renderPortsTab(ports);
      renderMacsTab(macs);
      renderArpsTab(arps);
      renderSyslogTab(detail.logs);
    }).catch(function(e) { console.error("detail load error:", e); });
}

function renderSyslogTab(logs) {
  var el = document.getElementById("dtab-syslog");
  if (!el) return;
  if (!logs) {
    el.innerHTML = "<p style='color:#64748b'>수집된 시스템 로그가 없습니다. (show logging / show log)</p>";
    return;
  }
  var html = "";
  var events = logs.events || [];
  if (events.length) {
    var alertColor = logs.alert === "critical" ? "#b91c1c" : (logs.alert === "warning" ? "#b45309" : "#64748b");
    html += "<div style='margin-bottom:10px'><strong style='color:" + alertColor + "'>⚠ 탐지된 이벤트 " +
      events.length + "건</strong></div>";
    html += "<table class='data-table'><thead><tr><th>유형</th><th>내용</th></tr></thead><tbody>";
    html += events.map(function(e) {
      var typeLabel = e.type === "looping" ? "🔁 루프" : (e.type === "flapping" ? "📶 플래핑" : "⚠ 오류");
      return "<tr><td>" + typeLabel + "</td><td><code style='font-size:12px'>" + escHtml(e.detail || "") + "</code></td></tr>";
    }).join("");
    html += "</tbody></table>";
  } else {
    html += "<p style='color:#15803d;margin-bottom:10px'>✓ 특이 이벤트(플래핑/루프/오류) 미탐지</p>";
  }
  // 최근 로그 원문
  html += "<h4 style='margin:14px 0 6px'>최근 로그</h4>" +
    "<pre style='background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;font-size:12px;" +
    "overflow:auto;max-height:320px;white-space:pre-wrap'>" +
    escHtml((logs.recent || []).join("\n") || "(없음)") + "</pre>";
  if (logs.updated) html += "<p style='font-size:11px;color:#64748b;margin-top:6px'>수집: " + escHtml(logs.updated) + "</p>";
  el.innerHTML = html;
}

function renderDetailSummary(ports, macs, arps) {
  var el = document.getElementById("detail-summary");
  if (!el) return;
  var up = ports.filter(function(p) { return p.status === "up"; }).length;
  var down = ports.length - up;
  var vlanSet = {};
  ports.forEach(function(p) { if (p.vlan != null) vlanSet[p.vlan] = 1; });
  macs.forEach(function(m) { if (m.vlan != null) vlanSet[m.vlan] = 1; });
  function stat(num, label, cls) {
    return "<div class='stat " + (cls || "") + "'><div class='stat__num'>" + num +
      "</div><div class='stat__label'>" + label + "</div></div>";
  }
  el.innerHTML =
    stat(ports.length, "전체 포트") +
    stat(up, "Up", "stat--up") +
    stat(down, "Down", "stat--down") +
    stat(macs.length, "MAC") +
    stat(arps.length, "ARP") +
    stat(Object.keys(vlanSet).length, "VLAN");
}

function renderPortsTab(ports) {
  var el = document.getElementById("dtab-ports");
  if (!ports.length) { el.innerHTML = "<p style='color:#64748b'>포트 정보 없음</p>"; return; }
  el.innerHTML = _searchBox("ports-tbody", "포트/상태/VLAN/설명 검색...") +
    "<table class='data-table'><thead><tr><th>포트</th><th>상태</th><th>VLAN</th><th>속도</th>" +
    "<th>CRC</th><th>In/Out 오류</th><th>설명</th></tr></thead><tbody id='ports-tbody'>" +
    ports.map(function(p) {
      // up=초록, err-disabled=빨강, notconnect/disabled/down=회색(구분 텍스트 유지)
      var pcls = p.status === "up" ? "ok" : (p.status === "err-disabled" ? "critical" : "new");
      var crc = p.crc_errors || 0, ie = p.in_errors || 0, oe = p.out_errors || 0;
      var errStyle = (crc > 0 || ie > 0 || oe > 0) ? " style='color:#b91c1c;font-weight:600'" : "";
      return "<tr><td>" + escHtml(p.name) + "</td><td><span class='status-badge status-badge--" +
        pcls + "'>" + escHtml(p.status || "-") + "</span></td><td>" +
        (p.vlan != null ? p.vlan : "-") + "</td><td>" + escHtml(p.speed || "-") + "</td>" +
        "<td" + errStyle + ">" + crc + "</td><td" + errStyle + ">" + ie + " / " + oe + "</td><td>" +
        escHtml(p.description || "-") + "</td></tr>";
    }).join("") + "</tbody></table>";
}

function renderMacsTab(macs) {
  var el = document.getElementById("dtab-macs");
  if (!macs.length) { el.innerHTML = "<p style='color:#64748b'>MAC 정보 없음</p>"; return; }
  el.innerHTML = _searchBox("macs-tbody", "VLAN/MAC/포트 검색...") +
    "<table class='data-table'><thead><tr><th>VLAN</th><th>MAC 주소</th><th>포트</th><th>타입</th></tr></thead><tbody id='macs-tbody'>" +
    macs.map(function(m) {
      return "<tr><td>" + (m.vlan != null ? m.vlan : "-") + "</td><td><code>" + escHtml(m.mac) + "</code></td><td>" + escHtml(m.port) + "</td><td>" + escHtml(m.entry_type || "-") + "</td></tr>";
    }).join("") + "</tbody></table>";
}

function renderArpsTab(arps) {
  var el = document.getElementById("dtab-arps");
  if (!arps.length) { el.innerHTML = "<p style='color:#64748b'>ARP 정보 없음</p>"; return; }
  el.innerHTML = _searchBox("arps-tbody", "IP/MAC/인터페이스 검색...") +
    "<table class='data-table'><thead><tr><th>IP</th><th>MAC 주소</th><th>인터페이스</th></tr></thead><tbody id='arps-tbody'>" +
    arps.map(function(a) {
      return "<tr><td>" + escHtml(a.ip) + "</td><td><code>" + escHtml(a.mac) + "</code></td><td>" + escHtml(a.interface || "-") + "</td></tr>";
    }).join("") + "</tbody></table>";
}


// ─── 스위치 카드 렌더링 ──────────────────────────────────────────
var _viewMode = "card";  // card | rack
var _bulkSel = {};        // 일괄 수집 선택 집합 {switch_id: true} — 재렌더에도 유지
var _tblSel = {};         // 스위치 표 선택 집합(선택 삭제/구분변경용) — 5초 재렌더에도 유지
var _dashStatusFilter = "all";  // all | ok | failed | new — 현황판 상태 필터 탭

// 상태 분류: 오류 = 수집 실패 또는 도달 불가, 미수집 = 아직 한 번도 수집 안 됨
function _swStatusBucket(sw) {
  if (sw.status === "failed" || sw.reachable === false) return "failed";
  if (sw.status === "done") return "ok";
  if (sw.status === "collecting") return "ok";  // 진행 중은 정상 취급
  return "new";
}

function _applyStatusFilter(list) {
  if (_dashStatusFilter === "all") return list;
  return (list || []).filter(function (s) { return _swStatusBucket(s) === _dashStatusFilter; });
}

function _updateStatusCounts(list) {
  var c = { all: (list || []).length, ok: 0, failed: 0, "new": 0 };
  (list || []).forEach(function (s) { c[_swStatusBucket(s)]++; });
  ["all", "ok", "failed", "new"].forEach(function (k) {
    var el = document.getElementById("sf-cnt-" + k);
    if (el) el.textContent = c[k];
  });
}

(function () {
  document.querySelectorAll(".dash-sfilter").forEach(function (btn) {
    btn.addEventListener("click", function () {
      _dashStatusFilter = btn.getAttribute("data-sfilter");
      // KPI 카드 선택 표시(.active) — 클래스 통째 교체하지 않아 카드 스타일 유지
      document.querySelectorAll(".dash-sfilter").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      _bulkSel = {};  // 필터 전환 시 이전 선택 해제(다른 리스트 오수집 방지)
      var allc = document.getElementById("dash-check-all");
      if (allc) allc.checked = false;
      renderSwitchGrid(_switches);
      if (_viewMode === "rack") renderRackView(_switches);
    });
  });
})();

(function () {
  var bc = document.getElementById("btn-view-card");
  var br = document.getElementById("btn-view-rack");
  if (!bc || !br) return;
  function setMode(m) {
    _viewMode = m;
    document.getElementById("switch-grid").style.display = (m === "card") ? "" : "none";
    document.getElementById("rack-view").style.display = (m === "rack") ? "" : "none";
    bc.className = "btn " + (m === "card" ? "btn--primary" : "btn--secondary");
    br.className = "btn " + (m === "rack" ? "btn--primary" : "btn--secondary");
    bc.style.fontSize = br.style.fontSize = "12px";
    if (m === "rack") renderRackView(_switches);
  }
  bc.addEventListener("click", function () { setMode("card"); });
  br.addEventListener("click", function () { setMode("rack"); });
})();

// hostname에서 구역(zone) 추출 — 사이트코드_<구역>_SW<n> 형식.
//  SKBA_RC_4F_SW1 → "RC_4F", SKBA_DETROIT_SW1 → "DETROIT", SKBA_F1_DMZ_SW_1 → "F1_DMZ".
// TPS·서버실이 아닌 스위치를 '위치 미상' 대신 구역으로 묶기 위함.
function _hostnameZone(hostname) {
  if (!hostname) return "";
  var m = String(hostname).toUpperCase().match(/^[A-Z0-9]+_(.+?)_SW(?:ITCH)?[\d_-]*$/);
  return m ? m[1].replace(/_+$/, "") : "";
}

// 장비(스위치/방화벽)의 랙뷰 그룹/랙 키 결정.
// TPS 호스트네임 → 공장/건물/층. 아니면 서버실 랙(A09U27). 아니면 위치 텍스트.
// 그 다음 hostname 구역(RC_4F/DETROIT 등). 없으면 미지정.
function _deviceRackKeys(dev) {
  if (dev.tps_group) return { group: dev.tps_group, rack: dev.tps_num || "기타" };
  if (dev.room_rack) return { group: "서버실", rack: dev.room_rack + " 랙" };
  if (dev.location) return { group: dev.location, rack: "기타" };
  var z = _hostnameZone(dev.hostname || dev.name);
  if (z) return { group: z, rack: "기타" };
  return { group: "위치 미상(미지정)", rack: "기타" };
}

// 현황판 = 현장 TPS(액세스) 스위치 전용 뷰.
// 서버실 소속(room_rack)·서버·방화벽 구분은 각자 전용 탭(서버실/서버/방화벽 현황)에만 노출.
function _isDashSwitch(sw) {
  if (!sw) return false;
  if (sw.room_rack) return false;                     // 서버실 위치 → 서버실 현황
  var dt = (sw.device_type || "");
  if (dt === "Server" || dt === "Firewall") return false;  // 서버/방화벽 → 전용 탭
  return true;
}
function _dashSwitches(list) { return (list || []).filter(_isDashSwitch); }

function renderRackView(switches) {
  var host = document.getElementById("rack-view");
  if (!host) return;
  switches = _applyStatusFilter(_applyLocFilter(_dashSwitches(switches), "loc-filter-dash"));
  // 현황판은 TPS 스위치 전용 — 방화벽은 방화벽 현황 탭에만 표시(여기선 제외)
  var devices = switches.map(function (s) { return { k: "sw", o: s }; });
  var groups = {};
  devices.forEach(function (d) {
    var keys = _deviceRackKeys(d.o);
    (groups[keys.group] = groups[keys.group] || {});
    (groups[keys.group][keys.rack] = groups[keys.group][keys.rack] || []).push(d);
  });
  var gkeys = Object.keys(groups).sort();
  if (!gkeys.length) { host.innerHTML = "<p class='placeholder'>표시할 장비가 없습니다.</p>"; return; }
  host.innerHTML = gkeys.map(function (g) {
    var racks = groups[g];
    var rkeys = Object.keys(racks).sort();
    // 구역 내 스위치 id 목록(방화벽 제외) — 구역 전체 선택→'정보 수집(N)'용
    var gIds = [];
    var zoneDown = false;   // 구역 전원다운 의심(백엔드 zone_outage 플래그)
    rkeys.forEach(function (t) {
      racks[t].forEach(function (d) {
        if (d.k !== "fw") gIds.push(d.o.id);
        if (d.o.zone_outage) zoneDown = true;
      });
    });
    var allSel = gIds.length > 0 && gIds.every(function (id) { return _bulkSel[id]; });
    var selBtn = gIds.length
      ? " <button class='btn " + (allSel ? "btn--primary" : "btn--secondary") +
        " rack-group-sel' data-ids='" + gIds.join(",") + "' style='font-size:11px;padding:2px 8px'>" +
        (allSel ? "구역 선택 해제" : "구역 전체 선택(" + gIds.length + ")") + "</button>"
      : "";
    var racksHtml = rkeys.map(function (t) {
      var units = racks[t].map(function (d) {
        if (d.k === "fw") {
          var f = d.o, fsc = f.reachable === false ? "critical" : (_fwStatusMeta[f.status] || "new");
          return "<div class='rack-unit rack-unit--" + fsc + "' data-action='detail-fw' data-id='" + f.id + "'>" +
            "<span class='rack-unit__name'>🛡 " + escHtml(f.name) + "</span>" +
            "<span class='rack-unit__ip'>" + escHtml(f.host) + "</span></div>";
        }
        var sw = d.o, cls = swStatusClass(sw);
        var sel = _bulkSel[sw.id] ? " style='outline:2px solid #38bdf8'" : "";
        return "<div class='rack-unit rack-unit--" + cls + "'" + sel +
          " data-action='detail-switch' data-payload='" + payloadAttr((sw)) + "'>" +
          "<span class='rack-unit__name'>" + escHtml(sw.name) + "</span>" +
          "<span class='rack-unit__ip'>" + escHtml(sw.ip) + "</span></div>";
      }).join("");
      return "<div class='rack'><div class='rack__label'>" + escHtml(t) + "</div>" +
        "<div class='rack__units'>" + units + "</div></div>";
    }).join("");
    var titleCls = zoneDown ? " rack-group__title--outage" : "";
    var outageBadge = zoneDown
      ? " <span class='zone-outage-badge'>⚡ 구역 전원 다운 의심</span>" : "";
    return "<div class='rack-group" + (zoneDown ? " rack-group--outage" : "") + "'>" +
      "<div class='rack-group__title" + titleCls + "'>📍 " + escHtml(g) + outageBadge + selBtn + "</div>" +
      "<div class='rack-row'>" + racksHtml + "</div></div>";
  }).join("");

  // 구역 전체 선택/해제 토글 → 상단 '정보 수집(N)'로 그 구역만 일괄 수집
  host.querySelectorAll(".rack-group-sel").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      var ids = (btn.getAttribute("data-ids") || "").split(",").filter(Boolean);
      var all = ids.every(function (id) { return _bulkSel[id]; });
      ids.forEach(function (id) {
        if (all) delete _bulkSel[id]; else _bulkSel[id] = true;
      });
      _updateBulkCollectBtn();
      renderRackView(_switches);  // 버튼 라벨/유닛 하이라이트 갱신
    });
  });
}

// ─── 서버실 현황 (location "A09U27" 랙/유닛) ─────────────────────
var _roomViewMode = "card";  // card | rack

(function () {
  var bc = document.getElementById("btn-room-card");
  var br = document.getElementById("btn-room-rack");
  if (!bc || !br) return;
  function setMode(m) {
    _roomViewMode = m;
    document.getElementById("room-grid").style.display = (m === "card") ? "" : "none";
    document.getElementById("room-rack-view").style.display = (m === "rack") ? "" : "none";
    bc.className = "btn " + (m === "card" ? "btn--primary" : "btn--secondary");
    br.className = "btn " + (m === "rack" ? "btn--primary" : "btn--secondary");
    bc.style.fontSize = br.style.fontSize = "12px";
    renderRoom(_switches);
  }
  bc.addEventListener("click", function () { setMode("card"); });
  br.addEventListener("click", function () { setMode("rack"); });
  var ex = document.getElementById("btn-room-export");
  if (ex) ex.addEventListener("click", function () { window.location = "/api/serverroom/export"; });
})();

function renderRoom(switches) {
  // 서버실 소속 = location이 "A09U27" 형식(room_rack 주입됨).
  // 스위치 + 방화벽 + 물리 서버(VM 제외 — API에서 물리만 room_* 주입).
  var roomSw = (switches || _switches || []).filter(function (sw) { return sw.room_rack; });
  var roomFw = (_firewalls || []).filter(function (f) { return f.room_rack; });
  var roomSrv = (_servers || []).filter(function (s) { return s.room_rack; });
  if (_roomViewMode === "rack") renderRoomRackView(roomSw, roomFw, roomSrv);
  else renderRoomGrid(roomSw, roomFw, roomSrv);
}

var _ROOM_EMPTY = "서버실 위치(A09U27 형식)가 지정된 장비가 없습니다. 스위치/방화벽 수정 → 위치에 A09U27처럼 입력하세요.";

// 방화벽 카드 — 스위치 카드(swCardHTML)와 동일한 골격으로 통일(현황판·서버실 공용).
function _fwCardHTML(f) {
  // 도달성 감시에서 끊김이면 카드 전체를 위험 상태로 표시(현황판/서버실 공통)
  var sc = f.reachable === false ? "critical" : (_fwStatusMeta[f.status] || "new");
  var reachBadge = f.reachable === false
    ? "<span class='sw-card__alert-badge badge--critical reach-down' title='도달성 감시: 관리 포트 TCP 응답 없음'><span class='reach-dot'></span> 연결 끊김</span>"
    : "";
  var locLine = f.tps_location ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>📍 " + escHtml(f.tps_location) + "</span>"
    : f.room_label ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>🗄 " + escHtml(f.room_label) + "</span>"
    : f.location ? "<span style='font-size:10px'>" + escHtml(f.location) + "</span>" : "";
  return "<div id='fwcard-" + f.id + "' class='sw-card sw-card--" + sc + "' title='클릭하면 이 방화벽 재수집'>" + reachBadge +
    "<div class='sw-card__icon'><div class='sw-icon'><div class='sw-icon__ports'>" +
    renderMiniPorts({ status: f.status }) +
    "</div></div></div>" +
    "<div class='sw-card__name'>🛡 " + escHtml(f.name) + "</div>" +
    "<div class='sw-card__meta'>" +
      "<span>" + escHtml(f.host) + "</span>" + locLine +
      "<span style='font-size:10px'>" + escHtml(f.vendor || "") + " · 방화벽</span>" +
    "</div>" +
    "<div class='sw-card__status'><span class='dot dot--" + sc + "'></span>" +
      "<span>방화벽 · " + escHtml(f.status || "new") + "</span></div>" +
    "<div class='sw-card__actions'>" +
      "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' data-action='detail-fw' data-id='" + f.id + "'>상세</button> " +
      "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' data-action='delete-fw' data-id='" + f.id + "'>삭제</button>" +
    "</div></div>";
}

// 서버 카드(서버실 그리드용) — 스위치/방화벽 카드와 동일 골격.
function _srvCardHTML(s) {
  var sc = s.reachable === false ? "critical" : (s.status === "failed" ? "critical" : "done");
  var loc = s.room_label ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>🗄 " + escHtml(s.room_label) + "</span>" : "";
  return "<div id='srvcard-" + s.id + "' class='sw-card sw-card--" + sc + "' title='클릭하면 이 서버 재수집'>" +
    "<div class='sw-card__icon'><div class='sw-icon'>🖥</div></div>" +
    "<div class='sw-card__name'>🖥 " + escHtml(s.name) + "</div>" +
    "<div class='sw-card__meta'><span>" + escHtml(s.ip) + "</span>" + loc +
      "<span style='font-size:10px'>" + escHtml((s.os_type || "linux")) + " · 서버</span></div>" +
    "<div class='sw-card__status'><span class='dot dot--" + sc + "'></span>" +
      "<span>서버 · " + escHtml(s.status || "new") + "</span></div>" +
    "</div>";
}

function renderRoomGrid(switches, firewalls, servers) {
  switches = _applyLocFilter(switches, "loc-filter-room");
  firewalls = _applyLocFilter(firewalls || [], "loc-filter-room");
  servers = _applyLocFilter(servers || [], "loc-filter-room");
  var grid = document.getElementById("room-grid");
  if (!grid) return;
  if (!switches.length && !firewalls.length && !servers.length) {
    grid.innerHTML = "<p class='placeholder'>" + _ROOM_EMPTY + "</p>";
    return;
  }
  // 현황판 카드뷰와 동일한 평면 그리드(랙 오름차순 → U 내림차순 정렬만 적용)
  switches = switches.slice().sort(_roomSort);
  firewalls = firewalls.slice().sort(_roomSort);
  servers = servers.slice().sort(_roomSort);
  grid.innerHTML = switches.map(function (sw) { return swCardHTML(sw, false); }).join("") +
                   firewalls.map(_fwCardHTML).join("") +
                   servers.map(_srvCardHTML).join("");
  switches.forEach(function (sw) {
    // 그리드 스코프 조회: swcard-<id>가 현황판/서버실 두 그리드에 중복 생성되어
    // document.getElementById는 항상 앞선 현황판 카드를 반환했다(서버실 카드 클릭
    // 무반응) → 각 grid 컨테이너 내부에서만 찾는다.
    var card = grid.querySelector('[id="swcard-' + sw.id + '"]');
    if (!card) return;
    card.addEventListener("click", function (e) {
      if (e.target.closest("[data-action]")) return;
      openCredentialModal(sw);   // 스위치 재수집(계정 입력)
    });
  });
  // 서버실 방화벽 카드 클릭 → 재수집(저장 계정 있으면 바로, 없으면 모달)
  firewalls.forEach(function (f) {
    var card = grid.querySelector('[id="fwcard-' + f.id + '"]');
    if (!card) return;
    card.addEventListener("click", function (e) {
      if (e.target.closest("[data-action]")) return;
      if (f.has_credential) collectFirewallDirect(f.id); else openFwCollect(f);
    });
  });
  // 서버실 서버 카드 클릭 → 재수집(계정 입력 모달)
  servers.forEach(function (s) {
    var card = grid.querySelector('[id="srvcard-' + s.id + '"]');
    if (!card) return;
    card.addEventListener("click", function (e) {
      if (e.target.closest("[data-action]")) return;
      _openServerCollect(s.id);
    });
  });
}

function _roomSort(a, b) {
  if (a.room_rack !== b.room_rack) return a.room_rack < b.room_rack ? -1 : 1;
  return (b.room_unit || 0) - (a.room_unit || 0);  // 유닛 높은 번호가 위(실제 랙과 동일)
}

// 장비 종류 → 랙 셀 색/라벨(구분 컬럼 우선, 없으면 이름 패턴 추론)
var _RACK_KIND = {
  "Firewall": { c: "#ef4444", t: "FW" }, "BackBone": { c: "#a855f7", t: "Core" },
  "L3 Switch": { c: "#8b5cf6", t: "L3" }, "L4 Switch": { c: "#f59e0b", t: "L4" },
  "L2 Switch": { c: "#14b8a6", t: "L2" }, "Server": { c: "#3b82f6", t: "SRV" },
  "AP": { c: "#22c55e", t: "AP" }, "_": { c: "#64748b", t: "" }
};
function _roomInferDT(name) {
  var t = (name || "").toUpperCase();
  if (/_FW|-FW|FIREWALL|ASA|PALO|FORTI/.test(t)) return "Firewall";
  if (/L4|SLB|ADC|ALTEON|OASVR/.test(t)) return "L4 Switch";
  if (/BACKBONE|\bBB\b|BB\d|CORE/.test(t)) return "BackBone";
  if (/L3|DSW/.test(t)) return "L3 Switch";
  if (/L2|FASW|ASW|ACC|SW/.test(t)) return "L2 Switch";
  return "";
}
function _roomKind(d) {
  if (d.k === "fw") return _RACK_KIND["Firewall"];
  if (d.k === "srv") return _RACK_KIND["Server"];
  var dt = d.o.device_type || _roomInferDT(d.o.name);
  return _RACK_KIND[dt] || _RACK_KIND["_"];
}

// 실제 42U 랙 배치도 — U42(상단)→U1(하단), 장비를 해당 U에 종류색으로 배치
function renderRoomRackView(switches, firewalls, servers) {
  var host = document.getElementById("room-rack-view");
  if (!host) return;
  switches = _applyLocFilter(switches, "loc-filter-room");
  firewalls = _applyLocFilter(firewalls || [], "loc-filter-room");
  servers = _applyLocFilter(servers || [], "loc-filter-room");
  if (!switches.length && !firewalls.length && !servers.length) {
    host.innerHTML = "<p class='placeholder'>" + _ROOM_EMPTY + "</p>";
    return;
  }
  var racks = {};   // {rack: {unit: device}}
  function _put(d) {
    var rk = d.o.room_rack, u = d.o.room_unit;
    if (!rk || !u) return;
    (racks[rk] = racks[rk] || {})[u] = d;
  }
  switches.forEach(function (sw) { _put({ k: "sw", o: sw }); });
  firewalls.forEach(function (f) { _put({ k: "fw", o: f }); });
  servers.forEach(function (s) { _put({ k: "srv", o: s }); });

  // 열(A/B) 단위로 줄 분리, 각 줄에 랙 나란히
  var rows = {};
  Object.keys(racks).forEach(function (rk) {
    var m = rk.match(/^[A-Za-z]+/);
    (rows[m ? m[0].toUpperCase() : "#"] = rows[(m ? m[0].toUpperCase() : "#")] || []).push(rk);
  });
  var RACK_U = 42;

  function _rackHtml(rk) {
    var map = racks[rk];
    var maxU = RACK_U;
    Object.keys(map).forEach(function (u) { if (+u > maxU) maxU = +u; });
    var slots = "";
    for (var u = maxU; u >= 1; u--) {
      var d = map[u];
      if (d) {
        var k = _roomKind(d);
        var obj = d.o, isFw = d.k === "fw", isSrv = d.k === "srv";
        var down = obj.status === "failed" || obj.reachable === false;
        var act = isFw ? ("data-action='detail-fw' data-id='" + obj.id + "'")
                       : isSrv ? ""   // 서버는 랙뷰에서 클릭 상세 없음(서버 현황 탭에서 관리)
                       : ("data-action='detail-switch' data-payload='" + payloadAttr((obj)) + "'");
        slots += "<div class='ru ru--dev' " + act +
          " style='background:" + k.c + "22;border-left:4px solid " + k.c + "'" +
          " title='" + escHtml((obj.name || "") + " · " + (obj.ip || obj.host || "") + " · U" + u) + "'>" +
          "<span class='ru__u'>U" + u + "</span>" +
          "<span class='ru__tag' style='background:" + k.c + "'>" + (k.t || "") + "</span>" +
          "<span class='ru__name'>" + (down ? "🔴 " : "") + escHtml(obj.name || "") + "</span>" +
          "</div>";
      } else {
        slots += "<div class='ru ru--empty'><span class='ru__u'>U" + u + "</span></div>";
      }
    }
    return "<div class='rackframe'>" +
      "<div class='rackframe__label'>🗄 " + escHtml(rk) + " <span style='font-size:10px;color:#94a3b8'>(" + maxU + "U)</span></div>" +
      "<div class='rackframe__slots'>" + slots + "</div></div>";
  }

  var legend = "<div class='rack-legend'>" +
    Object.keys(_RACK_KIND).filter(function (k) { return k !== "_" && _RACK_KIND[k].t; }).map(function (k) {
      return "<span><i style='background:" + _RACK_KIND[k].c + "'></i>" + _RACK_KIND[k].t + "</span>";
    }).join("") + "</div>";

  host.innerHTML = legend + Object.keys(rows).sort().map(function (letter) {
    var racksHtml = rows[letter].sort().map(_rackHtml).join("");
    return "<div class='rack-group'><div class='rack-group__title'>🗄 " + escHtml(letter) +
      " 열</div><div class='rack-row rack-row--frames'>" + racksHtml + "</div></div>";
  }).join("");
}

function renderSwitchGrid(switches) {
  switches = _dashSwitches(switches);   // 현황판 = 현장 TPS 스위치 전용(서버실/서버/방화벽 제외)
  _updateStatusCounts(_applyLocFilter(switches, "loc-filter-dash"));
  switches = _applyStatusFilter(_applyLocFilter(switches, "loc-filter-dash"));
  var grid = document.getElementById("switch-grid");
  if (!switches.length) {
    grid.innerHTML = "<p class='placeholder'>" +
      (_dashStatusFilter === "all"
        ? "표시할 TPS 스위치가 없습니다. (위치 필터를 확인하거나 스위치를 추가하세요)"
        : "해당 상태의 스위치가 없습니다.") + "</p>";
    _updateBulkCollectBtn();
    return;
  }
  grid.innerHTML = switches.map(function (sw) { return swCardHTML(sw, true); }).join("");
  switches.forEach(function(sw) {
    // 그리드 스코프 조회: swcard-<id>가 현황판/서버실 두 그리드에 중복 생성되어
    // document.getElementById는 항상 앞선 현황판 카드를 반환했다(서버실 카드 클릭
    // 무반응) → 각 grid 컨테이너 내부에서만 찾는다.
    var card = grid.querySelector('[id="swcard-' + sw.id + '"]');
    if (!card) return;
    card.addEventListener("click", function(e) {
      // 카드 안의 버튼(상세보기 등) + 수집 선택 체크박스는 개별 수집 모달을 띄우지 않음
      if (e.target.closest("[data-action]") || e.target.classList.contains("sw-collect-check")) return;
      openCredentialModal(sw);
    });
  });
  _updateBulkCollectBtn();
}

function swCardHTML(sw, withCheck) {
  var checkbox = withCheck
    ? "<input type='checkbox' class='sw-collect-check' value='" + sw.id + "'" +
      (_bulkSel[sw.id] ? " checked" : "") + " title='수집 대상 선택' " +
      "style='position:absolute;top:8px;left:8px;width:16px;height:16px;z-index:3;cursor:pointer'>"
    : "";
  var alertClass = sw.alert === "critical" ? "sw-card--critical"
    : sw.alert === "warning" ? "sw-card--warning"
    : sw.status === "done" ? "sw-card--ok"
    : sw.status === "collecting" ? "sw-card--collecting"
    : "sw-card--new";

  var alertBadge = (sw.alert && sw.alert !== "none")
    ? "<span class='sw-card__alert-badge badge--" + sw.alert + "'>" + (sw.alert === "critical" ? "⚠ LOOP" : "⚠ FLAP") + "</span>"
    : (sw.reachable === false
       ? "<span class='sw-card__alert-badge badge--critical reach-down' title='도달성 감시(TCP-22)에서 응답 없음'><span class='reach-dot'></span> 도달불가</span>"
       : "");

  var dotClass = sw.alert === "critical" ? "dot--critical"
    : sw.alert === "warning" ? "dot--warning"
    : sw.status === "done" ? "dot--ok"
    : sw.status === "collecting" ? "dot--collecting"
    : "dot--new";

  var statusLabel = sw.status === "done" ? "정상"
    : sw.status === "collecting" ? "수집중"
    : sw.status === "failed" ? "오류"
    : "미수집";

  var swJson = payloadAttr((sw));

  return "<div id='swcard-" + sw.id + "' class='sw-card " + alertClass + "' title='" +
    escHtml(sw.ip) + (sw.hostname ? "\n" + escHtml(sw.hostname) : "") + "'>" +
    checkbox +
    alertBadge +
    "<div class='sw-card__icon'><div class='sw-icon'><div class='sw-icon__ports'>" +
    renderMiniPorts(sw) +
    "</div></div></div>" +
    "<div class='sw-card__name'>" + escHtml(sw.name) + "</div>" +
    "<div class='sw-card__meta'>" +
    "<span>" + escHtml(sw.ip) + "</span>" +
    (sw.hostname ? "<span>" + escHtml(sw.hostname) + "</span>" : "") +
    (sw.tps_location ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>📍 " + escHtml(sw.tps_location) + "</span>" : "") +
    (sw.location ? "<span style='font-size:10px'>" + escHtml(sw.location) + "</span>"
      : (!sw.tps_location && _hostnameZone(sw.hostname || sw.name)
         ? "<span style='font-size:10px;color:#64748b'>🗂 " + escHtml(_hostnameZone(sw.hostname || sw.name)) + "</span>" : "")) +
    (sw.note ? "<span style='font-size:10px;color:#9a3412'>📝 " + escHtml(sw.note) + "</span>" : "") +
    (sw.status === "failed" && sw.last_error
      ? "<span style='font-size:10px;color:#991b1b' title='" + escHtml(sw.last_error) + "'>⚠ " +
        escHtml(sw.last_error.slice(0, 40)) + (sw.last_error.length > 40 ? "…" : "") + "</span>"
      : "") +
    "</div>" +
    "<div class='sw-card__status'>" +
    "<span class='dot " + dotClass + "'></span>" +
    "<span>" + escHtml(sw.model || _vendorLabel(sw.vendor)) +
    (sw.os_version ? " · " + escHtml(sw.os_version) : "") +
    " · " + statusLabel + "</span>" +
    "</div>" +
    "<div class='sw-card__actions'>" +
    "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' " +
    "data-action='detail-switch' data-payload='" + swJson + "'>상세보기</button> " +
    "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' " +
    "data-action='delete-switch' data-id='" + sw.id + "'>삭제</button>" +
    "</div>" +
    "</div>";
}

function renderMiniPorts(sw) {
  var count = 24;
  var html = "";
  for (var i = 0; i < count; i++) {
    var cls = sw.status === "done" ? (i % 7 === 0 ? "sw-port--down" : "sw-port--up") : "";
    html += "<span class='sw-port " + cls + "'></span>";
  }
  return html;
}

// 장비 구분(유형) — 서버 화이트리스트(DEVICE_TYPES)와 동일
var _DEVICE_TYPES = ["BackBone", "L3 Switch", "L2 Switch", "L4 Switch",
                     "Server", "Firewall", "AP", "Tablet", "PC", "기타"];

// 벤더 표준 값 ↔ 표시 라벨(표·카드·수정 모달을 하나의 표준으로 통일)
var _VENDOR_ALIAS = { cisco: "cisco_ios", nexus: "cisco_nxos", cisco_nexus: "cisco_nxos",
                      arista: "arista_eos", extreme: "extreme_exos", extremexos: "extreme_exos",
                      exos: "extreme_exos", juniper: "juniper_junos", radware: "alteon" };
// 표기는 순수 벤더명만(OS 구분은 '버전' 컬럼이 담당: IOS-XE 17.x / NX-OS 9.x ...)
var _VENDOR_LABELS = { cisco_ios: "Cisco", cisco_nxos: "Cisco",
                       arista_eos: "Arista", extreme_exos: "Extreme",
                       juniper_junos: "Juniper", alteon: "Radware",
                       unknown: "알 수 없음" };
function _canonVendor(v) {
  v = (v || "").toLowerCase();
  if (!v) return "unknown";
  return _VENDOR_ALIAS[v] || v;
}
function _vendorLabel(v) {
  var c = _canonVendor(v);
  return _VENDOR_LABELS[c] || c;
}
// 이웃(링크) 수집 방식 뱃지 — CDP/LLDP=정확, 추론(disabled)=경고
function _nbrSrcBadge(sw) {
  var s = sw.neighbor_source;
  if (!s) return "";
  if (s === "cdp" || s === "lldp") {
    return " <span style='font-size:9px;color:#16a34a' title='" + s.toUpperCase() +
      "로 정확한 물리 연결 수집'>●" + s.toUpperCase() + "</span>";
  }
  if (s === "disabled") {
    return " <span style='font-size:9px;color:#b45309;cursor:help' title='" +
      escHtml(sw.neighbor_note || "CDP/LLDP 비활성 — MAC 추론 링크 사용") + "'>⚠추론</span>";
  }
  return "";
}

// 구분(L2/L3/L4)은 running-config·벤더로 자동 분류된다(topology.classify_switch_kind).
// 수동 드롭다운·일괄변경 UI는 제거됨(API /api/switches/bulk-set-type은 유지).

// 존은 hostname 명명규칙으로 자동 분류된다(topology.infer_zone —
// 예: SKBA_F1_DMZ_SW_1 → DMZ, SKBA_F1_VDI_NASSW_1 → VDI NAS).
// 수동 일괄 지정 UI는 제거됨(API /api/switches/bulk-zone은 유지).

// ─── 스위치 테이블 (스위치 현황 탭) ─────────────────────────────
// 스위치 현황 통합 검색(우측 상단 검색창 하나로 전 컬럼 검색)
function _applySwSearch(list) {
  var el = document.getElementById("loc-filter-sw");
  var q = el ? el.value.trim().toLowerCase() : "";
  if (!q) return list;
  return (list || []).filter(function (s) {
    var hay = [s.name, s.ip, s.hostname, s.vendor, s.model, s.os_version,
               s.serial, s.device_type, s.location, s.tps_location]
      .map(function (x) { return x || ""; }).join(" ").toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

function renderSwitchTable(switches) {
  // 서버(구분=Server)는 스위치 현황에서 제외 — 서버 현황/서버실 현황에만 표시
  switches = _applySwSearch((switches || []).filter(function (s) {
    return (s.device_type || "") !== "Server";
  }));
  var tbody = document.getElementById("switch-table-body");
  if (!tbody) return;  // 요소 부재 시 조기 반환(가드 역전 → tbody.innerHTML 크래시 방지)
  if (!switches.length) {
    tbody.innerHTML = "<tr><td colspan='13' style='color:#64748b'>조건에 맞는 스위치가 없습니다. (검색어를 지우면 전체 표시)</td></tr>";
    var allChk0 = document.getElementById("sw-check-all");
    if (allChk0) allChk0.checked = false;
    _updateBulkDeleteBtn();
    return;
  }
  tbody.innerHTML = switches.map(function(sw) {
    var sc = swStatusClass(sw);
    var locCell = sw.tps_location
      ? "<span style='color:#2563eb;font-weight:600'>📍 " + escHtml(sw.tps_location) + "</span>" +
        (sw.location ? "<br><span style='font-size:11px;color:#64748b'>" + escHtml(sw.location) + "</span>" : "")
      : escHtml(sw.location || "-");
    // 구분: 수동 지정(수정에서 L2/L3/L4·BackBone 선택)이 있으면 그걸 우선,
    // 없으면 running-config·벤더로 자동 분류(kind_auto). 둘 다 없으면 'SWITCH'.
    var _manual = ["BackBone", "L2 Switch", "L3 Switch", "L4 Switch"].indexOf(sw.device_type) >= 0
      ? sw.device_type : "";
    var kind = _manual || sw.kind_auto || "";
    var kindLabel = kind
      ? "<span class='status-badge' style='background:#e0e7ff;color:#3730a3'" +
        (_manual ? " title='수동 지정'" : " title='자동 분류(running-config 기준). 틀리면 수정에서 변경'") +
        ">" + escHtml(kind) + "</span>"
      : "<span class='status-badge' style='background:#f1f5f9;color:#475569' title='running-config를 수집하면 L2/L3/L4로 자동 분류됩니다. 수정에서 수동 지정도 가능합니다'>SWITCH</span>";
    // 모델·버전(수집 시 show version에서 자동 추출) — 별도 컬럼
    return "<tr>" +
      "<td style='text-align:center'><input type='checkbox' class='sw-check' value='" + sw.id + "'" +
      (_tblSel[sw.id] ? " checked" : "") + "></td>" +
      "<td>" + kindLabel + "</td><td><code>" + escHtml(sw.ip) + "</code></td><td>" +
      escHtml(sw.hostname || "-") + "</td><td>" + escHtml(_vendorLabel(sw.vendor)) +
      _nbrSrcBadge(sw) + "</td><td>" +
      (sw.model ? escHtml(sw.model)
        : "<span style='color:#94a3b8' title='이 버전으로 한 번 재수집하면 show version/show switch에서 자동으로 채워집니다'>-</span>") + "</td><td>" +
      (sw.os_version ? escHtml(sw.os_version)
        : "<span style='color:#94a3b8' title='이 버전으로 한 번 재수집하면 자동으로 채워집니다'>-</span>") + "</td><td>" +
      (sw.serial ? "<code style='font-size:11px'>" + escHtml(sw.serial) + "</code>"
        : "<span style='color:#94a3b8' title='재수집하면 show version/inventory에서 자동으로 채워집니다'>-</span>") + "</td><td>" +
      locCell + "</td><td><span class='status-badge status-badge--" + sc + "'>" +
      escHtml(sw.status) + "</span>" +
      (sw.status === "failed" && sw.last_error
        ? "<div style='font-size:11px;color:#991b1b;max-width:260px'>" + escHtml(sw.last_error) + "</div>"
        : "") +
      "</td><td>" +
      (sw.alert && sw.alert !== "none" ? "<span class='status-badge status-badge--" + sw.alert + "'>" + sw.alert + "</span>" : "<span title='정상 — 포트 flapping/loop 이벤트 없음'>-</span>") +
      "</td><td>" + fmtTime(sw.last_collected) + "</td>" +
      "<td>" +
      "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' " +
      "title='계정을 입력해 이 스위치를 재수집' data-action='collect-switch' data-payload='" + payloadAttr((sw)) + "'>수집</button> " +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "data-action='edit-switch' data-payload='" + payloadAttr((sw)) + "'>수정</button> " +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "title='실제 배너/프롬프트/show version 응답을 확인(벤더 미인식 원인 파악)' " +
      "data-action='diagnose-switch' data-id='" + sw.id + "'>진단</button> " +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "title='SSH 터미널로 직접 접속' data-action='terminal-switch' data-id='" + sw.id + "'>💻</button> " +
      "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' " +
      "data-action='delete-switch' data-id='" + sw.id + "'>삭제</button></td></tr>";
  }).join("");
  // _tblSel에 있으나 현재 목록에 없는 id는 정리(삭제된 스위치)
  var visible = {};
  switches.forEach(function (s) { visible[s.id] = true; });
  Object.keys(_tblSel).forEach(function (id) { if (!visible[id]) delete _tblSel[id]; });
  var allChk = document.getElementById("sw-check-all");
  if (allChk) allChk.checked = switches.length > 0 &&
    switches.every(function (s) { return _tblSel[s.id]; });
  _updateBulkDeleteBtn();
}

// 선택 삭제 버튼 상태(개수) 갱신
function _updateBulkDeleteBtn() {
  var n = document.querySelectorAll("#switch-table-body .sw-check:checked").length;
  var btn = document.getElementById("btn-sw-bulk-delete");
  if (btn) { btn.textContent = "선택 삭제 (" + n + ")"; btn.disabled = n === 0; }
  var cbtn = document.getElementById("btn-sw-collect");
  if (cbtn) { cbtn.textContent = "정보 수집 (" + n + ")"; cbtn.disabled = n === 0; }
}

(function () {
  // 전체 선택 체크박스
  var allChk = document.getElementById("sw-check-all");
  if (allChk) allChk.addEventListener("change", function () {
    document.querySelectorAll("#switch-table-body .sw-check").forEach(function (c) {
      // 검색 필터로 숨겨진 행은 선택 제외
      if (c.closest("tr").style.display !== "none") {
        c.checked = allChk.checked;
        var id = parseInt(c.value, 10);
        if (allChk.checked) _tblSel[id] = true; else delete _tblSel[id];
      }
    });
    _updateBulkDeleteBtn();
  });
  // 개별 체크박스 변경 위임
  var tbody = document.getElementById("switch-table-body");
  if (tbody) tbody.addEventListener("change", function (e) {
    if (e.target && e.target.classList.contains("sw-check")) {
      var id = parseInt(e.target.value, 10);
      if (e.target.checked) _tblSel[id] = true; else delete _tblSel[id];
      _updateBulkDeleteBtn();
    }
  });
  // 선택 삭제
  var del = document.getElementById("btn-sw-bulk-delete");
  if (del) del.addEventListener("click", function () {
    var ids = Array.prototype.map.call(
      document.querySelectorAll("#switch-table-body .sw-check:checked"),
      function (c) { return parseInt(c.value, 10); });
    if (!ids.length) return;
    if (!confirm(ids.length + "대의 스위치를 삭제하시겠습니까? (관련 수집 데이터도 함께 삭제됩니다)")) return;
    fetch("/api/switches/bulk-delete", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids: ids}),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) { alert(res.deleted + "대 삭제 완료"); pollState(); }
      else alert(res.error || "삭제 실패");
    }).catch(function (e) { console.error(e); alert("삭제 오류"); });
  });
})();

var _editSwitchId = null;

function editSwitch(sw) {
  _editSwitchId = sw.id;
  document.getElementById("add-name").value = sw.name || "";
  document.getElementById("add-ip").value = sw.ip || "";
  document.getElementById("add-hostname").value = sw.hostname || "";
  // 저장값이 별칭(cisco/extreme 등)이어도 표준 값으로 매핑해 드롭다운과 일치시킴
  document.getElementById("add-vendor").value = _canonVendor(sw.vendor);
  var dt = document.getElementById("add-devtype"); if (dt) dt.value = sw.device_type || "";
  document.getElementById("add-location").value = sw.location || "";
  document.getElementById("add-note").value = sw.note || "";
  openModal("modal-add-switch");
}

// 장비 진단 — 실제 배너/프롬프트/show version 응답을 모달로 표시
function diagnoseSwitch(id) {
  var prog = document.getElementById("diag-result");
  openModal("modal-diagnose");
  if (prog) prog.textContent = "진단 중... (SSH 접속 → 배너/프롬프트/show version 확인, 최대 30초)";
  fetch("/api/switches/" + id + "/diagnose", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({}),
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (!prog) return;
    if (!res.ok) { prog.textContent = "진단 실패: " + (res.error || ""); return; }
    var d = res.diag || {};
    prog.textContent =
      "TCP-22 도달: " + (d.tcp ? "성공" : "실패") + "\n" +
      "SSH 로그인: " + (d.ssh_login ? "성공" : "실패") + "\n" +
      "감지 결과(guess): " + (d.guess || "인식 못 함") + "\n" +
      (d.vendor_corrected ? "→ 벤더를 '" + d.vendor_corrected + "'(으)로 자동 교정했습니다. 이제 재수집하세요.\n" : "") +
      (d.model_version_filled ? "→ 모델/버전 저장: " + d.model_version_filled + "\n" : "") +
      (d.error ? "오류: " + d.error + "\n" : "") +
      "\n── 프롬프트(마지막 줄) ──\n" + (d.prompt || "(없음)") +
      "\n\n── 로그인 배너(끝부분) ──\n" + (d.banner_head || "(없음)") +
      "\n\n── " + (d.probe_cmd || "show version") + " 응답(앞부분) ──\n" + (d.version_head || "(없음)");
  }).catch(function (e) {
    if (prog) prog.textContent = "진단 오류: " + e;
  });
}

function deleteSwitch(id) {
  if (!confirm("이 스위치를 삭제하시겠습니까?")) return;
  fetch("/api/switches/" + id, {method: "DELETE"})
    .then(function(r) { return r.json(); })
    .then(function() { pollState(); })
    .catch(function(e) { console.error(e); alert("삭제 오류"); });
}

function swStatusClass(sw) {
  if (sw.alert === "critical") return "critical";
  if (sw.alert === "warning") return "warning";
  if (sw.status === "done") return "ok";
  if (sw.status === "collecting") return "collecting";
  return "new";
}

// ─── VLAN 탭 (VLAN 기준 그룹 + 드롭다운) ─────────────────────────
function loadVlans() {
  var host = document.getElementById("vlan-accordion");
  if (host && !host.children.length) {
    host.innerHTML = "<p style='color:#64748b'>VLAN 현황 계산 중... (스위치가 많으면 수 초 걸릴 수 있습니다)</p>";
  }
  fetch("/api/vlans").then(function(r) { return r.json(); }).then(function(data) {
    renderVlanAccordion(data.vlans || []);
  }).catch(function(e) {
    console.error("vlan load:", e);
    // 로딩 문구가 영구 잔류하지 않도록 실패 안내로 교체
    var h = document.getElementById("vlan-accordion");
    if (h) h.innerHTML = "<p style='color:#991b1b'>VLAN 현황을 불러오지 못했습니다. 새로고침 후 다시 시도하세요.</p>";
  });
}

function renderVlanAccordion(rows) {
  var host = document.getElementById("vlan-accordion");
  if (!host) return;
  if (!rows.length) {
    host.innerHTML = "<p class='placeholder'>VLAN 정보 없음 (스위치를 수집하면 표시됩니다)</p>";
    return;
  }
  // VLAN 번호 기준 그룹핑
  var groups = {};
  rows.forEach(function(v) {
    var k = v.vlan;
    if (!groups[k]) groups[k] = { vlan: k, name: "", switches: [], mac: 0 };
    if (v.vlan_name && !groups[k].name) groups[k].name = v.vlan_name;
    groups[k].switches.push(v);
    groups[k].mac += (v.mac_count || 0);
  });
  var keys = Object.keys(groups).sort(function(a, b) { return (parseInt(a, 10) || 0) - (parseInt(b, 10) || 0); });
  host.innerHTML = keys.map(function(k) {
    var g = groups[k];
    var rowsHtml = g.switches.map(function(v) {
      return "<tr><td>" + escHtml(v.switch_name || "-") + "</td><td>" +
        escHtml(v.switch_hostname || "-") + "</td><td><code>" + escHtml(v.switch_ip || "-") +
        "</code></td><td style='text-align:right'>" + (v.mac_count || 0) + "</td></tr>";
    }).join("");
    var nameLabel = g.name ? " · " + escHtml(g.name) : "";
    return "<div class='vlan-item' data-vlan='" + escHtml(String(g.vlan)) + "' data-name='" + escHtml((g.name || "").toLowerCase()) + "'>" +
      "<div class='vlan-head' data-action='vlan-toggle'>" +
        "<span class='vlan-caret'>▶</span> " +
        "<strong>VLAN " + escHtml(String(g.vlan)) + "</strong>" + nameLabel +
        "<span class='vlan-meta'>스위치 " + g.switches.length + "대 · MAC " + g.mac + "</span>" +
      "</div>" +
      "<div class='vlan-body' style='display:none'>" +
        "<table class='data-table'><thead><tr><th>스위치(구분)</th><th>호스트네임</th><th>IP</th><th style='text-align:right'>MAC 수</th></tr></thead>" +
        "<tbody>" + rowsHtml + "</tbody></table>" +
      "</div></div>";
  }).join("");
}

function toggleVlanGroup(headEl) {
  var item = headEl.closest(".vlan-item");
  if (!item) return;
  var body = item.querySelector(".vlan-body");
  var caret = item.querySelector(".vlan-caret");
  var open = body.style.display !== "none";
  body.style.display = open ? "none" : "";
  if (caret) caret.textContent = open ? "▶" : "▼";
}

// VLAN 검색(번호/이름) — 아코디언 항목 표시/숨김
(function () {
  var inp = document.getElementById("vlan-search");
  if (!inp) return;
  inp.addEventListener("input", function () {
    var q = inp.value.trim().toLowerCase();
    document.querySelectorAll("#vlan-accordion .vlan-item").forEach(function (it) {
      var vlan = (it.getAttribute("data-vlan") || "").toLowerCase();
      var name = it.getAttribute("data-name") || "";
      it.style.display = (!q || vlan.indexOf(q) >= 0 || name.indexOf(q) >= 0) ? "" : "none";
    });
  });
})();

// ─── 설비 현황 (대역 ping sweep + ARP + MAC 대조) ────────────────
var _facPollTimer = null;

function loadFacility() {
  // 11번 스위치 드롭다운(등록 스위치 목록)
  var sel = document.getElementById("fac-switch");
  if (sel) {
    var cur = sel.value;
    // 설비 게이트웨이는 현장 TPS 스위치 — 서버·서버실·방화벽은 제외(_dashSwitches)
    sel.innerHTML = "<option value=''>TPS 스위치 선택</option>" +
      _dashSwitches(_switches || []).map(function (s) {
        return "<option value='" + s.id + "'" + (String(s.id) === cur ? " selected" : "") +
          ">" + escHtml(s.name) + " (" + escHtml(s.ip) + ")</option>";
      }).join("");
  }
  fetch("/api/facility").then(function (r) { return r.json(); }).then(function (data) {
    renderFacilityProgress(data.status);
    renderFacilityTable(data.hosts || []);
    // 수집 중이면 폴링
    if (data.status && data.status.running) {
      if (!_facPollTimer) _facPollTimer = setInterval(loadFacility, 3000);
    } else if (_facPollTimer) {
      clearInterval(_facPollTimer); _facPollTimer = null;
    }
  }).catch(function (e) { console.error("facility:", e); });
}

// ─── 재사용 진행바(수집/진단/스캔 공통) ─────────────────────────
// 완료(running=false) 후 일정 시간 뒤 자동으로 사라지게 함
function _autoHideProgress(el, ms) {
  if (!el) return;
  if (el._hideTimer) clearTimeout(el._hideTimer);
  el._hideTimer = setTimeout(function () { el.innerHTML = ""; el._hideTimer = null; }, ms || 6000);
}
function renderProgressBar(el, st, stopUrl) {
  if (!el) return;
  if (el._hideTimer) { clearTimeout(el._hideTimer); el._hideTimer = null; }  // 새 진행 시 숨김 취소
  if (!st || (!st.running && !st.message)) { el.innerHTML = ""; return; }
  var total = st.total || 0, done = st.done || 0;
  var pct = total ? Math.round(done / total * 100) : (st.running ? 0 : 100);
  var barCls = st.running ? "" : " np-progress__bar--done";
  var stopBtn = (st.running && stopUrl)
    ? "<button class='btn btn--ghost np-stop-btn' data-stop-url='" + escHtml(stopUrl) +
      "' style='font-size:11px;padding:2px 10px;margin-left:8px'>⏹ 수집 중지</button>"
    : "";
  el.innerHTML =
    "<div class='np-progress'>" +
      "<div class='np-progress__track'><div class='np-progress__bar" + barCls +
        "' style='width:" + pct + "%'></div></div>" +
      "<span class='np-progress__label'>" + (st.running ? "⏳ " : "✅ ") +
        (total ? done + "/" + total + " (" + pct + "%)" : "") +
        (st.message ? " · " + escHtml(st.message) : "") + "</span>" + stopBtn +
    "</div>";
}

// '⏹ 수집 중지' 위임 핸들러 — 어느 진행바의 중지 버튼이든 그 stop URL로 POST
document.addEventListener("click", function (e) {
  var b = e.target.closest(".np-stop-btn");
  if (!b) return;
  var url = b.getAttribute("data-stop-url");
  if (!url) return;
  b.disabled = true; b.textContent = "중지 중…";
  fetch(url, { method: "POST" }).catch(function () {});
});

// 진행 상태 폴링: url을 1.5초마다 조회 → el에 진행바. running=false면 종료 후 onDone().
function pollProgress(url, elId, onDone, stopUrl) {
  var el = document.getElementById(elId);
  var timer = setInterval(function () {
    fetch(url).then(function (r) { return r.json(); }).then(function (st) {
      renderProgressBar(el, st, stopUrl);
      if (!st.running) {
        clearInterval(timer);
        if (typeof onDone === "function") onDone(st);
        _autoHideProgress(el);   // 100% 완료 후 몇 초 뒤 자동 숨김
      }
    }).catch(function () { clearInterval(timer); });
  }, 1500);
}

function renderFacilityProgress(st) {
  var el = document.getElementById("fac-progress");
  if (!el) return;
  if (!st || (!st.running && !st.message)) { el.innerHTML = ""; return; }
  if (st.running) {
    // 진행바 + 대역/메시지 + 중지 버튼
    renderProgressBar(el, {running: true, done: st.done, total: st.total,
      message: (st.subnet ? st.subnet + " · " : "") + (st.message || "")},
      "/api/facility/stop");
  } else {
    var html = st.message ? "<span>" + escHtml(st.message) + "</span>" : "";
    // 완료 diff 배너 — 직전 스캔에서 새로 추가되거나 끊긴 설비를 한눈에(대상 대역 라벨 포함)
    var added = st.last_added || [], removed = st.last_removed || [];
    if (added.length || removed.length) {
      html += "<div style='margin-top:6px;display:flex;flex-wrap:wrap;gap:6px;align-items:center'>";
      if (st.last_subnet) {
        html += "<span style='font-size:12px;color:#475569'>📍 " + escHtml(st.last_subnet) + " 스캔 결과</span>";
      }
      if (added.length) {
        html += "<span style='background:#dcfce7;color:#166534;border-radius:6px;padding:3px 8px;font-size:12px' " +
          "title='" + escHtml(added.join(', ')) + "'>➕ 새 설비 " + added.length + "대: " +
          escHtml(added.slice(0, 8).join(', ')) + (added.length > 8 ? " …" : "") + "</span>";
      }
      if (removed.length) {
        html += "<span style='background:#fee2e2;color:#991b1b;border-radius:6px;padding:3px 8px;font-size:12px' " +
          "title='" + escHtml(removed.join(', ')) + "'>➖ 끊김 " + removed.length + "대: " +
          escHtml(removed.slice(0, 8).join(', ')) + (removed.length > 8 ? " …" : "") + "</span>";
      }
      html += "</div>";
    }
    el.innerHTML = html;
  }
}

var _facHosts = [];

// 직접 연결로 확신할 수 있는가(물리 액세스 포트에서 관측 + 연결 스위치 있음)
function _facIsDirect(h) {
  var d = (h.direct === undefined || h.direct === null) ? 1 : h.direct;
  return d === 1 && !!h.switch_name;
}

function renderFacilityTable(hosts) {
  _facHosts = hosts || [];
  // 대역 필터 드롭다운 옵션 갱신(선택 유지)
  var sel = document.getElementById("fac-subnet-filter");
  if (sel) {
    var cur = sel.value;
    var subnets = {};
    _facHosts.forEach(function (h) { if (h.subnet) subnets[h.subnet] = (subnets[h.subnet] || 0) + 1; });
    sel.innerHTML = "<option value=''>전체 대역</option>" +
      Object.keys(subnets).sort().map(function (s) {
        return "<option value='" + escHtml(s) + "'>" + escHtml(s) + " (" + subnets[s] + ")</option>";
      }).join("");
    sel.value = cur;
  }
  _renderFacilityRows();
}

// 설비 IP 정렬 상태(1=오름차순, -1=내림차순) — 헤더 클릭으로 전환
var _facIpSortDir = 1;

function _ipToInt(ip) {
  var p = String(ip || "").split(".");
  if (p.length !== 4) return 0;
  return ((+p[0]) << 24 >>> 0) + ((+p[1]) << 16) + ((+p[2]) << 8) + (+p[3]);
}

(function () {
  var th = document.getElementById("fac-sort-ip");
  if (th) th.addEventListener("click", function () {
    _facIpSortDir = -_facIpSortDir;
    var ar = document.getElementById("fac-sort-arrow");
    if (ar) ar.textContent = _facIpSortDir === 1 ? "▲" : "▼";
    _renderFacilityRows();
  });
})();

// 설비 검색: IP·대역·연결 스위치·포트는 부분 일치, MAC은 구분자(:.-) 무시 비교
function _facMatchesSearch(h, q) {
  if (!q) return true;
  var ql = q.toLowerCase();
  var hay = [(h.ip || ""), (h.subnet || ""), (h.switch_name || ""), (h.port || ""),
             (h.port_desc || ""), (h.via || ""), (h.hist_switch || ""), (h.hist_port || "")]
    .join(" ").toLowerCase();
  if (hay.indexOf(ql) >= 0) return true;
  var qhex = ql.replace(/[^0-9a-f]/g, "");
  if (qhex.length >= 4) {
    var machex = (h.mac || "").toLowerCase().replace(/[^0-9a-f]/g, "");
    if (machex.indexOf(qhex) >= 0) return true;
  }
  return (h.mac || "").toLowerCase().indexOf(ql) >= 0;
}

function _renderFacilityRows() {
  var tbody = document.getElementById("facility-table-body");
  if (!tbody) return;
  var all = _facHosts;
  var directCount = all.filter(_facIsDirect).length;

  // 대역 필터 + 통합 검색(IP/대역/MAC/연결 스위치)
  var subnetSel = document.getElementById("fac-subnet-filter");
  var subnet = subnetSel ? subnetSel.value : "";
  var searchEl = document.getElementById("fac-search");
  var q = searchEl ? searchEl.value.trim() : "";
  var filtered = all.filter(function (h) {
    if (subnet && h.subnet !== subnet) return false;
    return _facMatchesSearch(h, q);
  });

  var sum = document.getElementById("fac-summary");
  if (sum) {
    var base = all.length
      ? ("전체 <b>" + all.length + "</b>건 · 직접 연결 <b style='color:#15803d'>" + directCount +
         "</b>건 · 미확인 <b style='color:#b45309'>" + (all.length - directCount) + "</b>건")
      : "";
    if (base && (subnet || q)) base += " · 필터 결과 <b style='color:#2563eb'>" + filtered.length + "</b>건";
    sum.innerHTML = base + (base
      ? "  <span style='color:#94a3b8'>(미확인 = 업링크 Po/Vl 경유로만 관측 — 직접 연결된 액세스 스위치 미수집일 수 있음)</span>"
      : "");
  }

  var onlyDirect = document.getElementById("fac-only-direct");
  var rows = (onlyDirect && onlyDirect.checked) ? filtered.filter(_facIsDirect) : filtered;

  // IP 숫자 기준 정렬(문자열 정렬로 10 < 2가 되던 것 교정) — 헤더 클릭으로 방향 전환
  rows = rows.slice().sort(function (a, b) {
    return _facIpSortDir * (_ipToInt(a.ip) - _ipToInt(b.ip));
  });
  if (!rows.length) {
    var emptyMsg;
    if (!all.length) emptyMsg = "수집된 설비가 없습니다. '대역 수집(ping)'을 실행하세요.";
    else if (subnet || q) emptyMsg = "필터/검색 조건에 맞는 설비가 없습니다.";
    else emptyMsg = "직접 연결로 확인된 설비가 없습니다. ('직접 연결만' 해제 시 전체 표시)";
    tbody.innerHTML = "<tr><td colspan=7 style='color:#64748b'>" + emptyMsg + "</td></tr>";
    return;
  }
  tbody.innerHTML = rows.map(function (h) {
    var swCell, portCell, descCell, remarkCell;
    var remarks = [];   // 비고 컬럼 — 상태/사유/과거연결
    if (!h.online) remarks.push("오프라인(마지막 수집 무응답)");
    if (_facIsDirect(h) && !h.online) {
      // 오프라인이지만 마지막 관측 위치는 유지 — 회색 표기
      swCell = "<span style='color:#94a3b8'>" + escHtml(h.switch_name) +
        "</span> <span class='status-badge status-badge--new'>마지막 관측</span>";
      portCell = "<code style='color:#94a3b8'>" + escHtml(h.port || "-") + "</code>";
      descCell = "<span style='color:#94a3b8'>" + escHtml(h.port_desc || "-") + "</span>";
      remarks.push("연결이 끊기기 전 마지막으로 관측된 위치");
    } else if (_facIsDirect(h)) {
      swCell = "<span style='font-weight:600'>" + escHtml(h.switch_name) +
        "</span> <span class='status-badge status-badge--ok'>직접</span>";
      portCell = "<code>" + escHtml(h.port || "-") + "</code>";
      descCell = h.port_desc
        ? "<span title='연결 스위치에서 수집한 포트 설명'>" + escHtml(h.port_desc) + "</span>"
        : "<span style='color:#cbd5e1'>-</span>";
    } else {
      // 직접 연결 미확인 — 연결 스위치 셀은 간결히, 사유·과거연결은 '비고'로
      swCell = "<span style='color:#b45309'>직접 연결 미확인</span>" +
        (h.hist_switch ? " <span class='status-badge status-badge--new'>과거 연결</span>" : "");
      portCell = "<span style='color:#94a3b8'>—</span>";
      descCell = "<span style='color:#94a3b8'>—</span>";
      if (h.via) remarks.push("업링크(Po/Vl) 경유로만 관측: " + h.via);
      remarks.push("연결된 액세스 스위치 미수집이거나 최신 MAC 테이블에 없음(노후)");
      if (h.hist_switch) {
        remarks.push("과거 연결: " + h.hist_switch + (h.hist_port ? " " + h.hist_port : "") +
          (h.hist_ts ? " (" + String(h.hist_ts).slice(0, 16) + ")" : ""));
      }
    }
    remarkCell = remarks.length
      ? "<span style='font-size:12px;color:#64748b'>" + escHtml(remarks.join(" · ")) + "</span>"
      : "<span style='color:#cbd5e1'>-</span>";
    // 오프라인(연결 실패)은 행 배경(빨강)으로 신호
    var trStyle = h.online ? "" : " style='background:#fef2f2'";
    return "<tr" + trStyle + "><td>" + escHtml(h.subnet || "-") + "</td><td><code>" + escHtml(h.ip) + "</code></td>" +
      "<td><code>" + escHtml(h.mac || "-") + "</code></td><td>" + swCell + "</td><td>" +
      portCell + "</td><td>" + descCell + "</td><td>" + remarkCell + "</td></tr>";
  }).join("");
}

// "직접 연결만" 토글 + 대역 필터 + 통합 검색 + "새로고침(재매칭)" 버튼
(function () {
  var only = document.getElementById("fac-only-direct");
  if (only) only.addEventListener("change", _renderFacilityRows);
  var sf = document.getElementById("fac-subnet-filter");
  var delBtn = document.getElementById("btn-fac-delete-subnet");
  if (sf) sf.addEventListener("change", function () {
    if (delBtn) delBtn.disabled = !sf.value;   // 특정 대역 선택 시에만 삭제 가능
    _renderFacilityRows();
  });
  if (delBtn) delBtn.addEventListener("click", function () {
    var subnet = sf ? sf.value : "";
    if (!subnet) { alert("먼저 삭제할 대역을 선택하세요."); return; }
    if (!confirm("'" + subnet + "' 대역의 수집 결과를 모두 삭제할까요?")) return;
    delBtn.disabled = true;
    fetch("/api/facility/delete-subnet", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ subnet: subnet }),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) { if (sf) sf.value = ""; loadFacility(); }
      else { alert(res.error || "삭제 실패"); delBtn.disabled = false; }
    }).catch(function (e) { console.error(e); alert("삭제 오류"); delBtn.disabled = false; });
  });
  var fs = document.getElementById("fac-search");
  if (fs) fs.addEventListener("input", _renderFacilityRows);
  var ex = document.getElementById("btn-fac-export-xlsx");
  if (ex) ex.addEventListener("click", function () { window.location = "/api/facility/export?format=xlsx"; });
  var et = document.getElementById("btn-fac-export-txt");
  if (et) et.addEventListener("click", function () { window.location = "/api/facility/export?format=txt"; });
  var rf = document.getElementById("btn-fac-refresh");
  if (rf) rf.addEventListener("click", function () {
    rf.disabled = true;
    var prog = document.getElementById("fac-progress");
    if (prog) prog.textContent = "최신 MAC 테이블 기준으로 재대조 중...";
    fetch("/api/facility/rematch", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (prog) prog.textContent = res.ok ? ("재매칭 완료 (" + res.updated + "건 갱신)") : (res.error || "재매칭 실패");
        loadFacility();
      })
      .catch(function (e) { console.error(e); if (prog) prog.textContent = "재매칭 오류"; })
      .then(function () { rf.disabled = false; });
  });
})();

(function () {
  var dbtn = document.getElementById("btn-fac-detect");
  if (dbtn) dbtn.addEventListener("click", function () {
    var sid = document.getElementById("fac-switch").value;
    if (!sid) { alert("먼저 11번 스위치를 선택하세요."); return; }
    document.getElementById("fac-progress").textContent = "대역 조회 중...";
    fetch("/api/facility/detect-subnets", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({switch_id: parseInt(sid, 10)}),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok && res.subnets && res.subnets.length) {
        document.getElementById("fac-subnet").value = res.subnets[0];
        document.getElementById("fac-progress").innerHTML =
          "찾은 대역: " + res.subnets.map(escHtml).join(", ") +
          (res.subnets.length > 1 ? " (대역을 바꿔가며 각각 수집하세요)" : "");
      } else {
        document.getElementById("fac-progress").textContent =
          "directly-connected 대역을 찾지 못했습니다. 대역을 직접 입력하세요.";
      }
    }).catch(function (e) { console.error(e); document.getElementById("fac-progress").textContent = "조회 오류"; });
  });

  var btn = document.getElementById("btn-fac-collect");
  if (!btn) return;
  btn.addEventListener("click", function () {
    var sid = document.getElementById("fac-switch").value;
    var subnet = document.getElementById("fac-subnet").value.trim();
    if (!sid || !subnet) { alert("11번 스위치와 대역(CIDR)을 입력하세요."); return; }
    fetch("/api/facility/collect", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({switch_id: parseInt(sid, 10), subnet: subnet}),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) { alert("대역 수집을 시작했습니다(백그라운드). 진행률을 확인하세요."); loadFacility(); }
      else alert(res.error || "시작 실패");
    }).catch(function (e) { console.error(e); alert("서버 오류"); });
  });
})();

// ─── M8: 장부 대조(Reconcile) ────────────────────────────────────
var _reconcileVerdictMeta = {
  match:           { label: "일치",        badge: "ok" },
  port_mismatch:   { label: "포트 불일치",  badge: "warning" },
  switch_mismatch: { label: "스위치 불일치", badge: "critical" },
  ledger_only:     { label: "장부에만",     badge: "info" },
  measured_only:   { label: "실측에만",     badge: "info" },
  no_data:         { label: "정보 없음",     badge: "new" },
};

function verdictBadgeClass(verdict) {
  var meta = _reconcileVerdictMeta[verdict];
  return meta ? meta.badge : "new";
}

function verdictLabel(verdict) {
  var meta = _reconcileVerdictMeta[verdict];
  return meta ? meta.label : verdict;
}

function loadReconcile() {
  fetch("/api/reconcile")
    .then(function(r) { return r.json(); })
    .then(function(data) { renderReconcile(data); })
    .catch(function(e) { console.error("reconcile load:", e); });
}

(function () {
  var btn = document.getElementById("btn-reconcile-refresh");
  if (btn) btn.addEventListener("click", loadReconcile);
})();

function renderReconcile(data) {
  var summary = (data && data.summary) || {};
  var hosts = (data && data.hosts) || [];

  // 요약 카드: 판정 6종 카운트
  var order = ["match", "port_mismatch", "switch_mismatch", "ledger_only", "measured_only", "no_data"];
  var summaryHtml = order.map(function(v) {
    var count = summary[v] || 0;
    return "<div class='reconcile-stat'>" +
      "<span class='status-badge status-badge--" + verdictBadgeClass(v) + "'>" + escHtml(verdictLabel(v)) + "</span>" +
      "<span class='reconcile-stat__count'>" + count + "</span>" +
      "</div>";
  }).join("");
  var summaryEl = document.getElementById("reconcile-summary");
  if (summaryEl) summaryEl.innerHTML = summaryHtml;

  // 호스트 판정 테이블
  var tbody = document.getElementById("reconcile-table-body");
  if (!tbody) return;
  if (!hosts.length) {
    tbody.innerHTML = "<tr><td colspan=7 style='color:#64748b'>대조할 호스트가 없습니다. 엑셀 장부를 가져오고 스위치 정보를 수집하세요.</td></tr>";
    return;
  }
  tbody.innerHTML = hosts.map(function(h) {
    return "<tr><td><code>" + escHtml(h.ip) + "</code></td>" +
      "<td>" + escHtml(h.hostname || "-") + "</td>" +
      "<td><span class='status-badge status-badge--" + verdictBadgeClass(h.verdict) + "'>" +
        escHtml(verdictLabel(h.verdict)) + "</span></td>" +
      "<td>" + escHtml(h.ledger_switch || "-") + "</td>" +
      "<td>" + escHtml(h.ledger_port || "-") + "</td>" +
      "<td>" + escHtml(h.actual_switch || "-") + "</td>" +
      "<td>" + escHtml(h.actual_port || "-") + "</td></tr>";
  }).join("");
}

// ─── M10: 방화벽 현황 (Palo Alto / Fortinet) ─────────────────────
var _fwStatusMeta = {
  done: "ok", collecting: "collecting", failed: "critical", new: "new",
};

function loadFirewalls() {
  fetch("/api/firewalls")
    .then(function(r) { return r.json(); })
    .then(function(data) {
      _firewalls = data.firewalls || [];
      renderFirewalls(_firewalls);
      renderRoom(_switches);            // 서버실 현황
      renderSwitchGrid(_switches);      // 현황판 카드뷰에 방화벽 반영
      if (_viewMode === "rack") renderRackView(_switches);  // 현황판 랙뷰
    })
    .catch(function(e) { console.error("firewalls load:", e); });
}

function renderFirewalls(firewalls) {
  var tbody = document.getElementById("firewall-table-body");
  if (!tbody) return;
  if (!firewalls.length) {
    tbody.innerHTML = "<tr><td colspan=7 style='color:#64748b'>등록된 방화벽이 없습니다. '+ 방화벽 추가'로 등록하세요.</td></tr>";
    return;
  }
  tbody.innerHTML = firewalls.map(function(f) {
    var sc = _fwStatusMeta[f.status] || "new";
    var fjson = payloadAttr((f));
    var locCell = f.room_label
      ? "<span style='color:#2563eb;font-weight:600'>🗄 " + escHtml(f.room_label) + "</span>"
      : escHtml(f.location || "-");
    return "<tr><td>" + escHtml(f.name) + "</td>" +
      "<td>" + escHtml(f.vendor) + "</td>" +
      "<td><code>" + escHtml(f.host) + "</code></td>" +
      "<td>" + locCell + "</td>" +
      "<td><span class='status-badge status-badge--" + sc + "'>" + escHtml(f.status || "new") + "</span></td>" +
      "<td>" + (f.reachable === false
        ? "<span class='status-badge status-badge--critical' title='도달성 감시: 관리 포트 TCP 응답 없음'>🔴 끊김</span>"
        : f.reachable === true
          ? "<span class='status-badge status-badge--ok'>🟢 연결됨</span>"
          : "<span class='status-badge status-badge--new' title='감시 첫 주기(최대 1분) 대기 중'>확인 중</span>") + "</td>" +
      "<td>" +
        "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' " +
        "data-action='collect-fw' data-payload='" + fjson + "'>수집</button> " +
        "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
        "data-action='detail-fw' data-id='" + f.id + "'>상세</button> " +
        "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
        "data-action='edit-fw' data-payload='" + payloadAttr((f)) + "'>수정</button> " +
        "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' " +
        "data-action='delete-fw' data-id='" + f.id + "'>삭제</button>" +
      "</td></tr>";
  }).join("");
}

var _editFirewallId = null;

function editFirewall(f) {
  _editFirewallId = f.id;
  document.getElementById("fw-name").value = f.name || "";
  document.getElementById("fw-vendor").value = f.vendor || "fortigate";
  document.getElementById("fw-host").value = f.host || "";
  document.getElementById("fw-port").value = f.port || "";
  var locEl = document.getElementById("fw-location"); if (locEl) locEl.value = f.location || "";
  // 수정 시 자격증명은 변경하지 않음(비워두면 기존 유지) — 안내
  ["fw-add-token", "fw-add-username", "fw-add-password"].forEach(function(id) {
    var el = document.getElementById(id); if (el) el.value = "";
  });
  openModal("modal-add-firewall");
}

function deleteFirewall(fid) {
  if (!confirm("이 방화벽을 삭제하시겠습니까?")) return;
  fetch("/api/firewalls/" + fid, {method: "DELETE"})
    .then(function(r) { return r.json(); })
    .then(function() {
      loadFirewalls();
      var d = document.getElementById("firewall-detail"); if (d) d.innerHTML = "";
    })
    .catch(function(e) { console.error(e); alert("삭제 오류"); });
}

function showFirewallDetail(fid) {
  fetch("/api/firewalls/" + fid)
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var el = document.getElementById("firewall-detail");
      if (!el) return;
      var ifaces = data.interfaces || [];
      var arp = data.arp || [];
      var ifHtml = ifaces.length
        ? "<table class='data-table'><thead><tr><th>인터페이스</th><th>IP (Primary / Secondary)</th><th>Prefix</th><th>VDOM/Zone</th></tr></thead><tbody>" +
          ifaces.map(function(i) {
            // primary + secondary IP를 한 칸에 위·아래로. 마스크는 prefix(/N).
            var pfx = _fmtPrefix(i.mask);
            var ipStack = "<div><code>" + escHtml(i.ip || "-") + "</code>" +
              (pfx ? "<span style='color:#94a3b8'>" + pfx + "</span>" : "") + "</div>";
            var secs = i.secondary_ips || [];
            secs.forEach(function (s) {
              // s는 "ip/prefix" 또는 "ip"
              var parts = String(s).split("/");
              ipStack += "<div style='color:#0369a1'><code>" + escHtml(parts[0]) + "</code>" +
                (parts[1] ? "<span style='color:#94a3b8'>/" + escHtml(parts[1]) + "</span>" : "") +
                " <span class='status-badge status-badge--new' style='font-size:9px'>2nd</span></div>";
            });
            return "<tr><td>" + escHtml(i.name) + "</td><td>" + ipStack + "</td><td>" +
              (pfx || "-") + "</td><td>" + escHtml(i.vdom_zone || "-") + "</td></tr>";
          }).join("") + "</tbody></table>"
        : "<p style='color:#64748b'>인터페이스 정보 없음</p>";
      var arpHtml = arp.length
        ? _searchBox("fw-arp-tbody", "IP/MAC/인터페이스 검색...") +
          "<table class='data-table'><thead><tr><th>IP</th><th>MAC</th><th>인터페이스</th></tr></thead><tbody id='fw-arp-tbody'>" +
          arp.map(function(a) {
            return "<tr><td>" + escHtml(a.ip) + "</td><td><code>" + escHtml(a.mac) + "</code></td><td>" +
              escHtml(a.interface || "-") + "</td></tr>";
          }).join("") + "</tbody></table>"
        : "<p style='color:#64748b'>ARP 정보 없음</p>";
      el.innerHTML = "<h3 style='margin:16px 0 8px'>" + escHtml(data.firewall.name) +
        " — 인터페이스</h3>" + ifHtml +
        "<h3 style='margin:16px 0 8px'>ARP (연결된 IP)</h3>" + arpHtml;
    })
    .catch(function(e) { console.error("firewall detail:", e); });
}

var _selectedFirewall = null;

function collectFirewallDirect(fid) {
  // 저장된 자격증명으로 즉시 수집(빈 body → 서버가 저장된 토큰 사용)
  var url = "/api/firewalls/" + fid + "/collect";
  fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"})
    .then(function(r) { return r.json().then(function(d) { return {status: r.status, d: d}; }); })
    .then(function(res) {
      if (res.status === 200) {
        alert("수집 완료 (인터페이스 " + res.d.interfaces + ", ARP " + res.d.arp + ")");
      } else {
        alert("수집 실패: " + (res.d.detail || res.d.error || ""));
      }
      loadFirewalls();
    })
    .catch(function(e) { console.error(e); alert("서버 오류"); });
}

function openFwCollect(fw) {
  _selectedFirewall = fw;
  document.getElementById("modal-fw-collect-title").textContent = fw.name + " 수집";
  document.getElementById("modal-fw-collect-info").innerHTML =
    "<strong>벤더:</strong> " + escHtml(fw.vendor) + "&nbsp;&nbsp;<strong>호스트:</strong> " + escHtml(fw.host);
  document.getElementById("fw-cred-hint").textContent =
    fw.vendor === "fortigate"
      ? "FortiGate: API 토큰 또는 아이디/패스워드 중 하나를 입력하세요."
      : "Palo Alto: 아이디/패스워드를 입력하세요.";
  document.getElementById("fw-token").value = "";
  document.getElementById("fw-username").value = "";
  document.getElementById("fw-password").value = "";
  openModal("modal-fw-collect");
}

document.getElementById("btn-add-firewall").addEventListener("click", function() {
  _editFirewallId = null;  // 신규 추가 모드
  ["fw-name", "fw-host", "fw-port", "fw-location", "fw-add-token", "fw-add-username", "fw-add-password"].forEach(function(id) {
    var el = document.getElementById(id); if (el) el.value = "";
  });
  document.getElementById("fw-vendor").value = "fortigate";
  openModal("modal-add-firewall");
});

document.getElementById("btn-fw-add-confirm").addEventListener("click", function() {
  var host = document.getElementById("fw-host").value.trim();
  if (!host) { alert("호스트 IP를 입력하세요."); return; }
  var portVal = document.getElementById("fw-port").value.trim();
  var body = {
    name: document.getElementById("fw-name").value.trim(),
    vendor: document.getElementById("fw-vendor").value,
    host: host,
    port: portVal ? parseInt(portVal, 10) : null,
    location: (document.getElementById("fw-location") || {}).value ?
              document.getElementById("fw-location").value.trim() : "",
  };
  var url, method;
  if (_editFirewallId) {
    // 수정 모드: name/vendor/host/port만 변경(자격증명은 유지)
    url = "/api/firewalls/" + _editFirewallId; method = "PUT";
  } else {
    // 신규: 자격증명 포함
    body.token = document.getElementById("fw-add-token").value;
    body.username = document.getElementById("fw-add-username").value.trim();
    body.password = document.getElementById("fw-add-password").value;
    url = "/api/firewalls"; method = "POST";
  }
  fetch(url, {
    method: method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
  }).then(function(r) { return r.json().then(function(d) { return {status: r.status, d: d}; }); })
    .then(function(res) {
      if (res.status === 200 || res.status === 201) { closeModal("modal-add-firewall"); _editFirewallId = null; loadFirewalls(); }
      else alert(res.d.error || "저장 실패");
    }).catch(function(e) { console.error(e); alert("서버 오류"); });
});

document.getElementById("btn-fw-test").addEventListener("click", function() {
  if (!_selectedFirewall) return;
  document.getElementById("fw-test-result").textContent = "테스트 중...";
  fetch("/api/firewalls/test", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      vendor: _selectedFirewall.vendor, host: _selectedFirewall.host, port: _selectedFirewall.port,
      token: document.getElementById("fw-token").value,
      username: document.getElementById("fw-username").value.trim(),
      password: document.getElementById("fw-password").value,
      verify_ssl: document.getElementById("fw-verify-ssl").checked,
    }),
  }).then(function(r) { return r.json(); })
    .then(function(res) { _renderTestResult("fw-test-result", res); })
    .catch(function(e) { console.error(e); document.getElementById("fw-test-result").textContent = "테스트 오류"; });
});

document.getElementById("btn-fw-collect").addEventListener("click", function() {
  if (!_selectedFirewall) return;
  var payload = {
    token: document.getElementById("fw-token").value,
    username: document.getElementById("fw-username").value.trim(),
    password: document.getElementById("fw-password").value,
    verify_ssl: document.getElementById("fw-verify-ssl").checked,
  };
  closeModal("modal-fw-collect");
  var fid = _selectedFirewall.id;
  fetch("/api/firewalls/" + fid + "/collect", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload),
  }).then(function(r) { return r.json().then(function(d) { return {status: r.status, d: d}; }); })
    .then(function(res) {
      if (res.status === 200) {
        alert("수집 완료 (인터페이스 " + res.d.interfaces + ", ARP " + res.d.arp + ")");
        loadFirewalls();
        showFirewallDetail(fid);
      } else {
        alert("수집 실패: " + (res.d.detail || res.d.error || ""));
        loadFirewalls();
      }
    }).catch(function(e) { console.error(e); alert("서버 오류"); });
});

// ─── 계정 입력 모달 ──────────────────────────────────────────────
var _selectedSwitch = null;

function openCredentialModal(sw) {
  _selectedSwitch = sw;
  document.getElementById("modal-cred-title").textContent = sw.name + " 접속";
  document.getElementById("modal-cred-info").innerHTML =
    "<strong>IP:</strong> " + escHtml(sw.ip) +
    (sw.hostname ? "&nbsp;&nbsp;<strong>호스트네임:</strong> " + escHtml(sw.hostname) : "") +
    (sw.location ? "<br><strong>위치:</strong> " + escHtml(sw.location) : "");
  // 상단 공통 계정이 입력돼 있으면 자동 채움(개별 수집도 재입력 불필요)
  var hu = document.getElementById("dash-cred-user");
  var hp = document.getElementById("dash-cred-pass");
  document.getElementById("cred-username").value = hu ? hu.value.trim() : "";
  document.getElementById("cred-password").value = hp ? hp.value : "";
  var ce = document.getElementById("cred-enable"); if (ce) ce.value = "";
  openModal("modal-credential");
}

document.getElementById("btn-collect").addEventListener("click", function() {
  if (!_selectedSwitch) return;
  var username = document.getElementById("cred-username").value.trim();
  var password = document.getElementById("cred-password").value;
  if (!username || !password) { alert("아이디와 패스워드를 입력하세요."); return; }
  var persist = document.getElementById("cred-persist");
  var enEl = document.getElementById("cred-enable");
  var enableSecret = enEl ? enEl.value : "";
  closeModal("modal-credential");
  collectSwitch(_selectedSwitch.id, username, password, persist && persist.checked, enableSecret);
});

// ─── M11: 연결 테스트 (수집 전 선검증) ───────────────────────────
function _renderTestResult(elId, res) {
  var el = document.getElementById(elId);
  if (!el) return;
  el.style.color = res.ok ? "#15803d" : "#991b1b";
  var label = res.ok ? "✓ 연결 가능" : "✗ 연결 실패";
  // 출발지 IP 안내: 설정값이 있으면 그 IP, 없으면 자동(OS 기본) 경고
  var srcNote = res.source_ip
    ? "  · 출발지 IP: " + res.source_ip
    : "  · 출발지: 자동(OS 기본) — 헤더 '접근 IP'에서 이더넷 IP를 선택하세요";
  // textContent 사용 → XSS 안전 (서버 detail은 sanitize되지만 이중 안전)
  el.textContent = label + " [" + (res.stage || "") + "] " + (res.detail || "") + srcNote;
}

document.getElementById("btn-test-switch").addEventListener("click", function() {
  if (!_selectedSwitch) return;
  var username = document.getElementById("cred-username").value.trim();
  var password = document.getElementById("cred-password").value;
  document.getElementById("cred-test-result").textContent = "테스트 중...";
  fetch("/api/switches/test", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ip: _selectedSwitch.ip, vendor: _selectedSwitch.vendor,
                          username: username, password: password}),
  }).then(function(r) { return r.json(); })
    .then(function(res) { _renderTestResult("cred-test-result", res); })
    .catch(function(e) { console.error(e); document.getElementById("cred-test-result").textContent = "테스트 오류"; });
});

function collectSwitch(switchId, username, password, persist, enableSecret) {
  var body = {username: username, password: password, persist: !!persist};
  if (enableSecret) body.enable_secret = enableSecret;  // 선택 — 비우면 서버가 패스워드 사용
  fetch("/api/switches/" + switchId + "/collect", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  }).then(function(r) { return r.json(); }).then(function() {
    pollState();
  }).catch(function(e) { console.error("collect error:", e); });
}

// ─── 일괄 정보 수집 (공통 계정) ──────────────────────────────────
function _updateBulkCollectBtn() {
  var n = Object.keys(_bulkSel).length;
  var btn = document.getElementById("btn-bulk-collect");
  if (btn) {
    btn.textContent = "정보 수집 (" + n + ")";
    btn.disabled = n === 0;
  }
  var del = document.getElementById("btn-dash-bulk-delete");
  if (del) {
    del.textContent = "선택 삭제 (" + n + ")";
    del.disabled = n === 0;
  }
}

// 수집 선택 체크박스 변경(위임)
document.addEventListener("change", function (e) {
  var t = e.target;
  if (!t || !t.classList || !t.classList.contains("sw-collect-check")) return;
  var id = parseInt(t.value, 10);
  if (t.checked) _bulkSel[id] = true; else delete _bulkSel[id];
  _updateBulkCollectBtn();
});

(function () {
  // 전체 선택(현재 현황판 카드에 한함)
  var all = document.getElementById("dash-check-all");
  if (all) all.addEventListener("change", function () {
    document.querySelectorAll("#switch-grid .sw-collect-check").forEach(function (c) {
      c.checked = all.checked;
      var id = parseInt(c.value, 10);
      if (all.checked) _bulkSel[id] = true; else delete _bulkSel[id];
    });
    _updateBulkCollectBtn();
  });

  // "선택 삭제(N)" → 현황판에서 선택한 스위치 일괄 삭제
  var dashDel = document.getElementById("btn-dash-bulk-delete");
  if (dashDel) dashDel.addEventListener("click", function () {
    var ids = Object.keys(_bulkSel).map(function (x) { return parseInt(x, 10); });
    if (!ids.length) return;
    if (!confirm(ids.length + "대의 스위치를 삭제하시겠습니까? (관련 수집 데이터도 함께 삭제됩니다)")) return;
    fetch("/api/switches/bulk-delete", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids: ids}),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) {
        _bulkSel = {};
        var allc = document.getElementById("dash-check-all"); if (allc) allc.checked = false;
        alert(res.deleted + "대 삭제 완료");
        pollState();
      } else alert(res.error || "삭제 실패");
    }).catch(function (e) { console.error(e); alert("삭제 오류"); });
  });

  // "전체 진단" → 등록된 전 스위치 일괄 진단(벤더 미지정/오지정 자동 교정)
  var diagAllBtn = document.getElementById("btn-diagnose-all");
  var _diagAllPoll = null;
  function _pollDiagnoseAll() {
    fetch("/api/switches/diagnose-all/status")
      .then(function (r) { return r.json(); })
      .then(function (s) {
        if (diagAllBtn) diagAllBtn.textContent = "진단 중 " + s.done + "/" + s.total;
        renderProgressBar(document.getElementById("diag-progress"),
          {running: s.running, done: s.done, total: s.total,
           message: "벤더 교정 " + (s.corrected || 0) + "대"});
        if (s.running) return;                    // 계속 폴링
        clearInterval(_diagAllPoll); _diagAllPoll = null;
        _autoHideProgress(document.getElementById("diag-progress"));
        if (diagAllBtn) { diagAllBtn.disabled = false; diagAllBtn.textContent = "전체 진단"; }
        var errs = (s.results || []).filter(function (x) { return x.error; });
        var msg = "일괄 진단 완료: " + s.total + "대 중 벤더 교정 " + s.corrected + "대.";
        if (errs.length) {
          msg += "\n진단 실패 " + errs.length + "대:";
          errs.slice(0, 10).forEach(function (x) {
            msg += "\n  - " + (x.name || x.id) + ": " + x.error;
          });
          if (errs.length > 10) msg += "\n  ... 외 " + (errs.length - 10) + "대";
        }
        alert(msg);
        pollState();                              // 교정된 벤더 반영
      })
      .catch(function () {
        clearInterval(_diagAllPoll); _diagAllPoll = null;
        if (diagAllBtn) { diagAllBtn.disabled = false; diagAllBtn.textContent = "전체 진단"; }
      });
  }
  if (diagAllBtn) diagAllBtn.addEventListener("click", function () {
    if (!confirm("등록된 전 스위치를 일괄 진단합니다.\n각 스위치에 저장된 계정을 사용하며, 벤더가 잘못/미지정된 장비를 자동 교정합니다.\n계속할까요?")) return;
    diagAllBtn.disabled = true; diagAllBtn.textContent = "진단 시작…";
    fetch("/api/switches/diagnose-all", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: "{}",
    }).then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (!res.ok) {
          diagAllBtn.disabled = false; diagAllBtn.textContent = "전체 진단";
          alert((res.b && res.b.error) || "일괄 진단 시작 실패");
          return;
        }
        if (_diagAllPoll) clearInterval(_diagAllPoll);
        _diagAllPoll = setInterval(_pollDiagnoseAll, 2000);
        _pollDiagnoseAll();
      })
      .catch(function () {
        diagAllBtn.disabled = false; diagAllBtn.textContent = "전체 진단";
        alert("일괄 진단 시작 오류");
      });
  });

  var _swCollectIds = null;   // 스위치 현황 탭에서 선택한 수집 대상(있으면 _bulkSel 대신 사용)

  // 일괄 수집 실행(공통) — 성공 시 선택 해제 + 안내
  function _runBulkCollect(ids, username, password, persist, enableSecret) {
    var body = {ids: ids, username: username, password: password, persist: !!persist};
    if (enableSecret) body.enable_secret = enableSecret;  // 선택 — 비우면 서버가 패스워드 사용
    fetch("/api/switches/bulk-collect", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      closeModal("modal-bulk-collect");
      if (res.ok) {
        _bulkSel = {};
        var allc = document.getElementById("dash-check-all"); if (allc) allc.checked = false;
        var msg = res.queued_count + "대 수집을 시작했습니다(백그라운드).";
        if (res.skipped_count) msg += "\n제외 " + res.skipped_count + "대(이미 수집 중이거나 IP 거부).";
        alert(msg);
        pollState();
      } else {
        alert(res.error || "일괄 수집 실패");
      }
    }).catch(function (e) { console.error("bulk collect:", e); alert("일괄 수집 오류"); });
  }

  // "정보 수집(N)" — 상단 공통 계정이 입력돼 있으면 팝업 없이 바로 수집,
  // 비어 있으면 기존처럼 계정 입력 팝업.
  var open = document.getElementById("btn-bulk-collect");
  if (open) open.addEventListener("click", function () {
    _swCollectIds = null;   // 현황판 경로 — 표 선택 컨텍스트 해제
    var ids = Object.keys(_bulkSel);
    if (!ids.length) { alert("먼저 수집할 스위치를 선택하세요."); return; }
    var hu = document.getElementById("dash-cred-user");
    var hp = document.getElementById("dash-cred-pass");
    var hpersist = document.getElementById("dash-cred-persist");
    var user = hu ? hu.value.trim() : "";
    var pass = hp ? hp.value : "";
    if (user && pass) {
      // 상단 계정으로 즉시 수집(대량 선택 시 팝업 생략)
      _runBulkCollect(ids.map(function (x) { return parseInt(x, 10); }),
                      user, pass, hpersist && hpersist.checked);
      return;
    }
    var names = ids.map(function (id) {
      var s = (_switches || []).find(function (x) { return String(x.id) === String(id); });
      return s ? (s.name + " (" + s.ip + ")") : ("#" + id);
    });
    document.getElementById("bulk-cred-info").innerHTML =
      "<strong>" + ids.length + "대</strong> 선택됨<br>" +
      "<span style='font-size:12px;color:#475569'>" + names.map(escHtml).join(", ") + "</span>";
    document.getElementById("bulk-username").value = "";
    document.getElementById("bulk-password").value = "";
    var be = document.getElementById("bulk-enable"); if (be) be.value = "";
    var bp = document.getElementById("bulk-persist"); if (bp) bp.checked = false;
    openModal("modal-bulk-collect");
  });

  // "수집 시작" → 일괄 수집 요청(팝업 경로) — 표 선택(_swCollectIds) 우선, 없으면 현황판 선택
  var start = document.getElementById("btn-bulk-start");
  if (start) start.addEventListener("click", function () {
    var ids = (_swCollectIds && _swCollectIds.length)
      ? _swCollectIds.slice()
      : Object.keys(_bulkSel).map(function (x) { return parseInt(x, 10); });
    if (!ids.length) { closeModal("modal-bulk-collect"); return; }
    var username = document.getElementById("bulk-username").value.trim();
    var password = document.getElementById("bulk-password").value;
    if (!username || !password) { alert("아이디와 패스워드를 입력하세요."); return; }
    var persist = document.getElementById("bulk-persist");
    var be = document.getElementById("bulk-enable");
    _runBulkCollect(ids, username, password, persist && persist.checked,
                    be ? be.value : "");
    _swCollectIds = null;
  });

  // 스위치 현황 탭: 체크된 스위치 일괄 수집(계정 입력 팝업 재사용)
  var swCol = document.getElementById("btn-sw-collect");
  if (swCol) swCol.addEventListener("click", function () {
    var ids = Array.prototype.map.call(
      document.querySelectorAll("#switch-table-body .sw-check:checked"),
      function (c) { return parseInt(c.value, 10); });
    if (!ids.length) { alert("먼저 수집할 스위치를 체크하세요."); return; }
    _swCollectIds = ids;
    var names = ids.map(function (id) {
      var s = (_switches || []).find(function (x) { return String(x.id) === String(id); });
      return s ? (s.name + " (" + s.ip + ")") : ("#" + id);
    });
    document.getElementById("bulk-cred-info").innerHTML =
      "<strong>" + ids.length + "대</strong> 선택됨<br>" +
      "<span style='font-size:12px;color:#475569'>" + names.map(escHtml).join(", ") + "</span>";
    document.getElementById("bulk-username").value = "";
    document.getElementById("bulk-password").value = "";
    var be2 = document.getElementById("bulk-enable"); if (be2) be2.value = "";
    var bp2 = document.getElementById("bulk-persist"); if (bp2) bp2.checked = false;
    openModal("modal-bulk-collect");
  });
})();

// ─── 수동 추가 모달 ──────────────────────────────────────────────
document.getElementById("btn-add-manual").addEventListener("click", function() {
  _editSwitchId = null;  // 신규 추가 모드
  ["add-name","add-ip","add-hostname","add-location","add-note"].forEach(function(id) {
    document.getElementById(id).value = "";
  });
  document.getElementById("add-vendor").value = "unknown";
  var _dt = document.getElementById("add-devtype"); if (_dt) _dt.value = "";
  openModal("modal-add-switch");
});

document.getElementById("btn-add-confirm").addEventListener("click", function() {
  var ip = document.getElementById("add-ip").value.trim();
  if (!ip) { alert("IP를 입력하세요."); return; }
  // 수정 모드(_editSwitchId)면 PUT, 신규면 POST
  var url = _editSwitchId ? ("/api/switches/" + _editSwitchId) : "/api/switches/manual";
  var method = _editSwitchId ? "PUT" : "POST";
  function submit(force) {
    fetch(url, {
      method: method,
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        name: document.getElementById("add-name").value.trim(),
        ip: ip,
        hostname: document.getElementById("add-hostname").value.trim(),
        vendor: document.getElementById("add-vendor").value,
        device_type: (document.getElementById("add-devtype") || {value: ""}).value,
        location: document.getElementById("add-location").value.trim(),
        note: document.getElementById("add-note").value,
        force: !!force,
      }),
    }).then(function(r) { return r.json(); }).then(function(data) {
      if (data.ok) { closeModal("modal-add-switch"); _editSwitchId = null; pollState(); }
      else if (data.unreachable && !force) {
        // 도달 불가 → 강제 등록 확인
        if (confirm((data.error || "도달 불가") + "\n\n그래도 강제로 등록할까요?")) submit(true);
      }
      else alert(data.error || "저장 실패");
    }).catch(function(e) { console.error(e); alert("서버 오류"); });
  }
  submit(false);
});

// ─── M9: 보고서 내보내기 ─────────────────────────────────────────
(function () {
  var btn = document.getElementById("btn-export-report");
  if (btn) btn.addEventListener("click", function() { window.location = "/api/report"; });
})();

// ─── 엑셀 가져오기 ───────────────────────────────────────────────
document.getElementById("btn-import-excel").addEventListener("click", function() {
  document.getElementById("excel-file-input").click();
});
document.getElementById("excel-file-input").addEventListener("change", function() {
  var file = this.files[0];
  if (!file) return;
  var fd = new FormData();
  fd.append("file", file);
  // M4: Use new /api/upload endpoint for multiblock excel loader
  fetch("/api/upload", {method: "POST", body: fd})
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.ok) {
        // M4: Show diagnostics and import summary
        if (data.diagnostics) {
          showDiagnostics(data.diagnostics);
        }
        var nSw = data.imported_switch_ids ? data.imported_switch_ids.length : 0;
        var nFw = data.imported_firewall_ids ? data.imported_firewall_ids.length : 0;
        var nHost = data.imported_host_ids ? data.imported_host_ids.length : 0;
        alert((nSw + nFw + nHost) + "개 항목 임포트 완료 (스위치: " + nSw +
              ", 방화벽: " + nFw + ", 호스트: " + nHost + ")" +
              (nFw ? "\n방화벽은 벤더 미지정으로 등록됐습니다 — 방화벽 현황에서 벤더/계정을 설정하세요." : ""));
        pollState();
        loadFirewalls();
      }
      else alert(data.error || "가져오기 실패");
    })
    .catch(function(e) { console.error(e); alert("서버 오류"); });
  this.value = "";
});

// ─── IP 검색 ─────────────────────────────────────────────────────
document.getElementById("ip-search-btn").addEventListener("click", doSearch);
document.getElementById("ip-search-input").addEventListener("keydown", function(e) {
  if (e.key === "Enter") doSearch();
});

function doSearch() {
  var ip = document.getElementById("ip-search-input").value.trim();
  if (!ip) return;
  fetch("/api/search?ip=" + encodeURIComponent(ip))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var body = document.getElementById("search-result-body");
      var results = data.results || [];
      if (results.length) {
        body.innerHTML =
          "<p style='margin-bottom:8px'><strong>" + results.length + "건</strong> 발견 — '" + escHtml(ip) + "'</p>" +
          "<table class='data-table'><thead><tr><th>구분</th><th>IP</th><th>이름</th><th>상세</th></tr></thead><tbody>" +
          results.map(function(r) {
            return "<tr><td>" + escHtml(r.source) + "</td><td><code>" + escHtml(r.ip || "-") + "</code></td><td>" +
              escHtml(r.label || "-") + "</td><td>" + escHtml(r.detail || "") + "</td></tr>";
          }).join("") + "</tbody></table>";
      } else {
        body.innerHTML = "<p style='color:#64748b'><strong>" + escHtml(ip) +
          "</strong> 검색 결과가 없습니다. (등록 스위치·방화벽, 수집 ARP/MAC 테이블, 설비 현황, 장부에서 IP·이름·MAC으로 찾습니다 — 수집 전이면 ARP/MAC/설비 결과가 없습니다)</p>";
      }
      openModal("modal-search-result");
    })
    .catch(function(e) { console.error(e); alert("검색 오류"); });
}

// ─── 토폴로지: [서버실 구성도] / [TPS 구역도] 2탭 (중간 카드, 가시성 우선) ──
var _topoData = null;    // {nodes, links}
var _topoMode = "zone";  // 단일 뷰: 존·대역 구성도(SVG 선+포트). core/tps 코드는 보존(미노출)
// Contrail식 인터랙티브: 드래그로 재배치한 노드 위치를 저장(세션 간 유지)
var _topoLayout = (function () {
  try { return JSON.parse(localStorage.getItem("netdash_topo_layout") || "{}") || {}; }
  catch (e) { return {}; }
})();
var _topoRenderedPos = {};   // 현재 렌더의 노드 절대 위치(드래그 기준)
function _saveTopoLayout() {
  try { localStorage.setItem("netdash_topo_layout", JSON.stringify(_topoLayout)); } catch (e) {}
}
function _resetTopoLayout() { _topoLayout = {}; _saveTopoLayout(); renderTopology(); }
var _topoZone = null;    // TPS 모드에서 선택된 구역
var _topoExpandL2 = false;  // false=L2를 대역 뱃지로 접음(기본), true=개별 노드로 펼침
var _topoOpenBand = null;   // 드릴다운으로 펼쳐본 대역 key
var _topoBandsById = {};    // 현재 렌더의 대역 id→band (드릴다운 조회용)

// 장비 종류 아이콘/색/심볼 — device_type 우선, 없으면 hostname 추론(백엔드 inferred)
// sym: _deviceSymbol에 넘길 심볼 키(방화벽/백본/L3/L4/서버/기본)
var _TOPO_KIND = {
  "Firewall": { color: "#ef4444", label: "방화벽", sym: "방화벽" },
  "BackBone": { color: "#a855f7", label: "Core", sym: "백본" },
  "L3 Switch": { color: "#8b5cf6", label: "Distribution", sym: "L3" },
  "L4 Switch": { color: "#f59e0b", label: "L4", sym: "L4" },
  "L2 Switch": { color: "#14b8a6", label: "Access", sym: "L2" },
  "Server": { color: "#3b82f6", label: "서버", sym: "서버" },
  "AP": { color: "#22c55e", label: "AP", sym: "L2" },
  "_default": { color: "#64748b", label: "", sym: "L2" }
};
function _topoKindOf(n) {
  var dt = n.device_type || "";
  if (dt && _TOPO_KIND[dt]) return _TOPO_KIND[dt];
  if (n.kind === "fw") return _TOPO_KIND["Firewall"];
  var name = (n.name || "").toUpperCase();
  if (/BACKBONE|BB|CORE/.test(name)) return _TOPO_KIND["BackBone"];
  if (/L3/.test(name)) return _TOPO_KIND["L3 Switch"];
  if (/L4|SLB|ADC/.test(name)) return _TOPO_KIND["L4 Switch"];
  if (/L2|ACC|SW/.test(name)) return _TOPO_KIND["L2 Switch"];
  return _TOPO_KIND["_default"];
}
function _topoStatusDot(n) {
  if (n.alert === "critical" || n.status === "failed" || n.reachable === false) return "#ef4444";
  if (n.alert === "warning") return "#f59e0b";
  if (n.status === "done") return "#22c55e";
  return "#64748b";
}
function _topoZoneOf(n) {
  if (n.depth === 0) return "🏢 백본/코어";
  return (n.group || "").trim() || "미지정";
}
// 서버실(코어) 장비 = 방화벽/백본/L3/L4 (+ L2 중 코어 연결). TPS(액세스)와 분리.
function _isCoreDevice(n) {
  var dt = n.device_type || "";
  if (n.kind === "fw") return true;
  if (["BackBone", "L3 Switch", "L4 Switch", "Server"].indexOf(dt) >= 0) return true;
  if (!dt) {  // 미지정: 이름 패턴으로 코어 추정
    var name = (n.name || "").toUpperCase();
    if (/BACKBONE|BB|CORE|L3|L4|SLB|ADC|OASVR/.test(name)) return true;
  }
  return false;
}

// ═══ 하이브리드 토폴로지 편집기 (v4.4) ═══════════════════════════
// 사람이 배치(팔레트 드래그·연결) + 툴이 정보 자동 채움(IP→hostname, 선→포트).
var _tdiag = { nodes: [], edges: [] };   // {nodes:[{id,kind,ip,name,x,y,subnets,...}], edges}
var _tEditMode = false;                   // 편집 모드(끄면 보기 전용 — 실수 클릭 방지)
var _tLinkFrom = null;                    // 연결 시작 노드(🔗 손잡이 클릭)
var _tEditId = null;                      // 편집 중 노드 id
var _tSelId = null;                       // 마지막 클릭 노드(단일 선택)
var _tSel = {};                           // 다중 선택 집합 {id:true} — 드래그 영역/Shift 클릭
var _tClip = null;                        // 복사 버퍼(노드 스냅샷 배열)
var _tView = null;                        // 줌/팬 뷰박스 {x,y,w,h} — 재렌더에도 유지
var _tLineStyle = null;                   // 선 그리기 도구 {style:'straight'|'elbow', dash:bool}
var _tLoaded = false;                     // 구성도 최초 로드 완료(탭 재진입 시 유지)
var _tSaveTimer = null;                   // 자동 저장 디바운스
var _tSeq = 1;

// 변경 후 자동 저장(디바운스 1.5s) — 탭 전환/새로고침에도 유지. 읽기 전용은 스킵.
function _tAutoSave() {
  if (!_tLoaded) return;
  if (_tSaveTimer) clearTimeout(_tSaveTimer);
  _tSaveTimer = setTimeout(function () {
    fetch("/api/topology/diagram", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(_tdiag) }).catch(function () {});
  }, 1500);
}

// 현재 선택된 노드 id 목록(다중 우선, 없으면 단일)
function _tSelIds() {
  var ks = Object.keys(_tSel);
  return ks.length ? ks : (_tSelId ? [_tSelId] : []);
}
function _tIsSel(id) { return !!_tSel[id] || _tSelId === id; }

// 각 장비 종류 → 전용 SVG 심볼(_deviceSymbol) + 색 + 팔레트 라벨
var _TOPO_KIND = {
  internet: { sym: "인터넷", color: "#0ea5e9", pal: "인터넷", noinfo: true },
  firewall: { sym: "방화벽", color: "#ef4444", pal: "방화벽" },
  backbone: { sym: "백본", color: "#a855f7", pal: "백본" },
  l3: { sym: "L3", color: "#8b5cf6", pal: "L3 스위치" },
  l4: { sym: "L4", color: "#f59e0b", pal: "L4 스위치" },
  l2: { sym: "L2", color: "#14b8a6", pal: "L2 스위치" },
  ap: { sym: "AP", color: "#22c55e", pal: "AP (무선)" },
  server: { sym: "서버", color: "#3b82f6", pal: "서버" },
  pc: { sym: "PC", color: "#94a3b8", pal: "PC" },
  facility: { sym: "설비", color: "#f472b6", pal: "설비" },
  subnet: { sym: null, color: "#38bdf8", pal: "대역 박스", box: true },   // 아이콘 없이 네모 박스+대역
  zone: { sym: null, color: "#8b5cf6", pal: "존(그룹) 박스", zone: true },  // 여러 아이콘 묶는 반투명 배경
};

function _loadTopoSubnets() {
  var sel = document.getElementById("topo-subnet");
  if (!sel) return;
  fetch("/api/topology/subnets").then(function (r) { return r.json(); }).then(function (d) {
    var cur = sel.value;
    sel.innerHTML = "<option value=''>대역 선택…</option>" +
      (d.subnets || []).map(function (s) { return "<option>" + escHtml(s) + "</option>"; }).join("");
    if (cur) sel.value = cur;
  }).catch(function () {});
}

// 백엔드 노드(ref/kind/ip/name/subnets)를 편집기 노드로 변환(중복 IP는 건너뜀). 종류별 행 배치.
function _addLoadedNodes(list, replace) {
  var ROW = { internet: 0, firewall: 1, backbone: 2, l4: 3, l3: 4, l2: 5, ap: 6, server: 7, pc: 7, facility: 8 };
  if (replace) _tdiag = { nodes: [], edges: [] };
  var haveIp = {}; _tdiag.nodes.forEach(function (n) { if (n.ip) haveIp[n.ip] = true; });
  var cnt = {}; var baseY = replace ? 0 : 0;
  var added = 0;
  (list || []).forEach(function (n) {
    if (n.ip && haveIp[n.ip]) return;                  // 이미 있는 장비는 스킵
    var kind = _TOPO_KIND[n.kind] ? n.kind : "l2";
    var row = ROW[kind] || 5; cnt[row] = (cnt[row] || 0) + 1;
    _tdiag.nodes.push({ id: "n" + (_tSeq++), kind: kind, ip: n.ip || "", name: n.name || "",
      x: 120 + cnt[row] * 175, y: 90 + row * 150 + baseY,
      reachable: n.reachable, status: n.status, subnets: n.subnets || [] });
    if (n.ip) haveIp[n.ip] = true; added++;
  });
  return added;
}

function loadTopology(force) {
  _buildPalette();
  _loadTopoSubnets();
  // 이미 불러온 뒤 탭을 다시 열면: 서버에서 다시 안 불러오고 편집 중이던 구성도 유지
  if (_tLoaded && !force) { _renderEditor(); return; }
  _tView = null; _tSel = {}; _tSelId = null;   // 새로 불러올 땐 전체 화면 + 선택 초기화
  fetch("/api/topology/diagram").then(function (r) { return r.json(); }).then(function (d) {
    _tdiag = { nodes: d.nodes || [], edges: d.edges || [] };
    _tdiag.nodes.forEach(function (n) {
      var m = /(\d+)/.exec(n.id || ""); if (m && +m[1] >= _tSeq) _tSeq = +m[1] + 1;
    });
    _tLoaded = true;
    _renderEditor();
  }).catch(function (e) {
    console.error("topology:", e);
    var h = document.getElementById("topology-canvas");
    if (h) h.innerHTML = "<p style='color:#991b1b;padding:16px'>구성도를 불러오지 못했습니다. 새로고침 후 다시 시도하세요.</p>";
  });
}

function _buildPalette() {
  var pal = document.getElementById("topo-palette");
  if (!pal || pal.dataset.built) return;
  pal.dataset.built = "1";
  // 실제 장비 아이콘(_deviceSymbol) 미리보기 + 라벨
  var order = ["internet", "firewall", "backbone", "l3", "l4", "l2", "ap", "server", "pc", "facility", "subnet", "zone"];
  order.forEach(function (kind) {
    var meta = _TOPO_KIND[kind];
    var b = document.createElement("button");
    b.className = "btn btn--secondary";
    b.style.cssText = "display:flex;align-items:center;gap:6px;width:100%;font-size:11px;margin-bottom:5px;text-align:left;padding:4px 6px";
    // 대역 박스/존 박스는 아이콘 대신 네모 미리보기, 그 외는 장비 아이콘
    var icon = (meta.box || meta.zone)
      ? "<svg width='22' height='22' viewBox='0 0 34 34' style='flex-shrink:0'><rect x='3' y='6' width='28' height='22' rx='3' fill='" + meta.color + "' fill-opacity='" + (meta.zone ? "0.25" : "0.15") + "' stroke='" + meta.color + "' stroke-width='1.6'" + (meta.zone ? " stroke-dasharray='3 2'" : "") + "/></svg>"
      : "<svg width='22' height='22' viewBox='0 0 34 34' style='flex-shrink:0'>" + _deviceSymbol(meta.sym, 0, 0, meta.color) + "</svg>";
    b.innerHTML = icon + "<span>" + escHtml(meta.pal) + "</span>";
    b.addEventListener("click", function () { _addNode(kind); });
    pal.appendChild(b);
  });
  // ── 선(연결) 도구 ── 선택 후 장비 두 개를 클릭해 그 스타일로 연결
  var sep = document.createElement("div");
  sep.style.cssText = "border-top:1px solid #1e293b;margin:6px 0 4px;font-size:11px;color:#64748b;padding-top:4px";
  sep.textContent = "선 연결";
  pal.appendChild(sep);
  var lines = [
    ["직선", { style: "straight", dash: false }, "M2 11 H20"],
    ["꺾은선", { style: "elbow", dash: false }, "M2 4 H11 V18"],
    ["점선", { style: "straight", dash: true }, "M2 11 H20"],
    ["꺾은 점선", { style: "elbow", dash: true }, "M2 4 H11 V18"],
  ];
  lines.forEach(function (ln) {
    var b = document.createElement("button");
    b.className = "btn btn--secondary tline-btn"; b.dataset.style = JSON.stringify(ln[1]);
    b.style.cssText = "display:flex;align-items:center;gap:6px;width:100%;font-size:11px;margin-bottom:5px;text-align:left;padding:4px 6px";
    b.innerHTML = "<svg width='22' height='22' viewBox='0 0 22 22' style='flex-shrink:0'>" +
      "<path d='" + ln[2] + "' fill='none' stroke='#22c55e' stroke-width='2'" + (ln[1].dash ? " stroke-dasharray='3 2'" : "") + "/></svg><span>" + ln[0] + "</span>";
    b.addEventListener("click", function () {
      if (!_tEditMode) { alert("먼저 '✏️ 편집 모드'를 켜세요."); return; }
      _tLineStyle = (JSON.stringify(_tLineStyle) === b.dataset.style) ? null : JSON.parse(b.dataset.style);
      _tLinkFrom = null;
      _tHighlightLineBtn();
    });
    pal.appendChild(b);
  });
}

function _tHighlightLineBtn() {
  document.querySelectorAll(".tline-btn").forEach(function (b) {
    var on = _tLineStyle && b.dataset.style === JSON.stringify(_tLineStyle);
    b.className = "btn tline-btn " + (on ? "btn--primary" : "btn--secondary");
    b.style.cssText = "display:flex;align-items:center;gap:6px;width:100%;font-size:11px;margin-bottom:5px;text-align:left;padding:4px 6px";
  });
}

function _addNode(kind) {
  if (!_tEditMode) { alert("먼저 '✏️ 편집 모드'를 켜세요."); return; }
  var id = "n" + (_tSeq++);
  var meta = _TOPO_KIND[kind] || _TOPO_KIND.l2;
  var node = { id: id, kind: kind, ip: "", name: kind === "internet" ? "Internet" : (meta.pal || kind),
    x: 260 + (_tdiag.nodes.length % 5) * 40, y: 120 + (_tdiag.nodes.length % 4) * 40, subnets: [] };
  if (meta.zone) { node.name = "ZONE"; node.color = meta.color; node.w = 340; node.h = 240;
    node.x = 300; node.y = 220; }
  _tdiag.nodes.push(node);
  _renderEditor();
  if (!meta.noinfo) _openNodeModal(id);   // 인터넷은 정보 입력 불필요 → 모달 안 열음
}

function _tNode(id) { return _tdiag.nodes.find(function (n) { return n.id === id; }); }

function _renderEditor() {
  var host = document.getElementById("topology-canvas");
  if (!host) return;
  var W = 1600, H = 1000;
  if (!_tView) _tView = { x: 0, y: 0, w: W, h: H };
  var vbStr = _tView.x + " " + _tView.y + " " + _tView.w + " " + _tView.h;   // 줌/팬 유지
  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='100%'" +
    " viewBox='" + vbStr + "' preserveAspectRatio='xMidYMid meet'" +
    " style='display:block;background:#0f172a;cursor:grab'>"];
  // 존(그룹) 박스 — 가장 뒤(배경)에 반투명 색상 사각형 + 존 이름. 여러 아이콘을 감쌈.
  _tdiag.nodes.forEach(function (n) {
    var m = _TOPO_KIND[n.kind]; if (!m || !m.zone) return;
    var col = n.color || m.color, w = n.w || 320, h = n.h || 220;
    var x = n.x - w / 2, y = n.y - h / 2;
    svg.push("<g class='tnode' data-id='" + escHtml(n.id) + "' style='cursor:" + (_tEditMode ? "move" : "default") + "'>");
    svg.push("<rect x='" + x + "' y='" + y + "' width='" + w + "' height='" + h +
      "' rx='10' fill='" + col + "' fill-opacity='0.12' stroke='" + col + "' stroke-width='2' stroke-dasharray='6 4'/>");
    svg.push("<rect x='" + x + "' y='" + y + "' width='" + Math.min(w, 8 + (n.name || "").length * 9 + 12) +
      "' height='22' rx='6' fill='" + col + "' fill-opacity='0.9'/>");
    svg.push("<text x='" + (x + 8) + "' y='" + (y + 16) + "' fill='#0b1220' font-size='13' font-weight='700'>" + escHtml(n.name || "ZONE") + "</text>");
    if (_tEditMode) {   // 우하단 리사이즈 손잡이
      svg.push("<rect class='tzone-resize' data-id='" + escHtml(n.id) + "' x='" + (x + w - 12) + "' y='" + (y + h - 12) +
        "' width='12' height='12' fill='" + col + "' fill-opacity='0.9' style='cursor:nwse-resize'/>");
    }
    svg.push("</g>");
  });
  // 연결선 — 일직선. 같은 두 장비 사이 여러 선은 '나란히 평행'하게 벌려(각각 다른 물리 링크).
  // 포트 라벨은 평소 숨김, 선에 마우스 올리면 그 선의 양쪽 포트를 툴팁으로 표시.
  var pairTotal = {}, pairIdx = {};
  _tdiag.edges.forEach(function (e) {
    var pk = [e.a, e.b].sort().join("|"); pairTotal[pk] = (pairTotal[pk] || 0) + 1;
  });
  _tdiag.edges.forEach(function (e) {
    var a = _tNode(e.a), b = _tNode(e.b);
    if (!a || !b) return;
    var pk = [e.a, e.b].sort().join("|");
    var total = pairTotal[pk], k = (pairIdx[pk] = (pairIdx[pk] || 0) + 1) - 1;
    var dx = b.x - a.x, dy = b.y - a.y, len = Math.sqrt(dx * dx + dy * dy) || 1;
    var nx = -dy / len, ny = dx / len;                 // 수직 단위벡터
    var spread = (total > 1 ? (k - (total - 1) / 2) * 16 : 0);   // 선을 나란히 벌림
    var ax = a.x + nx * spread, ay = a.y + ny * spread;
    var bx = b.x + nx * spread, by = b.y + ny * spread;
    var tipParts = [];
    if (e.a_port) tipParts.push((a.name || "A") + ": " + e.a_port);
    if (e.b_port) tipParts.push((b.name || "B") + ": " + e.b_port);
    var tip = tipParts.length ? tipParts.join("  ↔  ") : (e.note || "포트 미확인");
    var dash = e.dash ? " stroke-dasharray='7 5'" : "";
    var pathD;
    if (e.style === "elbow") {   // 꺾은선(ㄱ자): 긴 축부터 이동해 코너에서 꺾음
      pathD = (Math.abs(dx) >= Math.abs(dy))
        ? "M" + ax + " " + ay + " H" + bx + " V" + by
        : "M" + ax + " " + ay + " V" + by + " H" + bx;
    } else {
      pathD = "M" + ax + " " + ay + " L" + bx + " " + by;
    }
    svg.push("<path d='" + pathD + "' fill='none' stroke='#22c55e' stroke-width='2'" + dash + "/>");
    // 넓은 투명 히트 영역(가는 선도 쉽게 호버) + data-tip(그 선의 포트)
    svg.push("<path d='" + pathD + "' fill='none' stroke='transparent' stroke-width='14'" +
      " data-tip=\"" + escHtml(tip) + "\" style='cursor:help'/>");
  });
  // 노드(존 박스는 위에서 배경으로 이미 그림 → 제외)
  _tdiag.nodes.forEach(function (n) {
    var meta = _TOPO_KIND[n.kind] || _TOPO_KIND.l2;
    if (meta.zone) return;
    var color = (n.reachable === false || n.status === "failed") ? "#ef4444" : meta.color;
    var hl = (_tLinkFrom === n.id) ? "<circle cx='" + n.x + "' cy='" + n.y + "' r='26' fill='none' stroke='#38bdf8' stroke-width='2'/>" :
      _tIsSel(n.id) ? "<rect x='" + (n.x - 24) + "' y='" + (n.y - 24) + "' width='48' height='48' rx='6' fill='none' stroke='#facc15' stroke-width='2' stroke-dasharray='4 3'/>" : "";
    var ncur = (_tLineStyle || _tLinkFrom) ? "crosshair" : (_tEditMode ? "move" : "default");
    svg.push("<g class='tnode' data-id='" + escHtml(n.id) + "' style='cursor:" + ncur + "'>");
    svg.push(hl);
    if (meta.box) {
      // 대역 박스 — 아이콘 없이 네모 안에 대역 숫자만. 박스 자체가 노드.
      var lines = (n.subnets || []).slice(0, 12);
      var bw2 = 150, bh2 = Math.max(30, 12 + Math.max(1, lines.length) * 15);
      var bx2 = n.x - bw2 / 2, by2 = n.y - bh2 / 2;
      svg.push("<rect x='" + bx2 + "' y='" + by2 + "' width='" + bw2 + "' height='" + bh2 +
        "' rx='5' fill='#0b1220' stroke='" + meta.color + "' stroke-width='1.8'/>");
      if (n.name) svg.push("<text x='" + n.x + "' y='" + (by2 - 4) + "' fill='#94a3b8' font-size='10' text-anchor='middle'>" + escHtml(n.name) + "</text>");
      if (!lines.length) svg.push("<text x='" + n.x + "' y='" + (n.y + 4) + "' fill='#475569' font-size='11' text-anchor='middle'>대역 입력…</text>");
      lines.forEach(function (s, i) {
        var v = s.vlan != null ? ("V" + s.vlan + " ") : "";
        svg.push("<text x='" + (bx2 + 10) + "' y='" + (by2 + 18 + i * 15) + "' fill='#e2e8f0' font-size='11'>" + escHtml(v + s.cidr) + "</text>");
      });
    } else {
      svg.push(_deviceSymbol(meta.sym, n.x - 17, n.y - 17, color));   // 종류별 전용 아이콘
      svg.push("<text x='" + n.x + "' y='" + (n.y + 32) + "' fill='#e2e8f0' font-size='12' text-anchor='middle'>" +
        escHtml(n.name || "") + "</text>");
      if (n.ip) svg.push("<text x='" + n.x + "' y='" + (n.y + 45) + "' fill='#64748b' font-size='10' text-anchor='middle'>" + escHtml(n.ip) + "</text>");
      // 장비 아래 대역 박스(L3/L2 등)
      var subs = n.subnets || [];
      if (subs.length) {
        var bx = n.x - 80, by = n.y + 52, bw = 160, bh = 18 + subs.slice(0, 8).length * 14;
        svg.push("<rect x='" + bx + "' y='" + by + "' width='" + bw + "' height='" + bh +
          "' rx='4' fill='#0b1220' stroke='" + meta.color + "' stroke-opacity='0.5'/>");
        subs.slice(0, 8).forEach(function (s, i) {
          var v = s.vlan != null ? ("V" + s.vlan + " ") : "";
          var col = s.source === "manual" ? "#60a5fa" : "#cbd5e1";
          svg.push("<text x='" + (bx + 7) + "' y='" + (by + 14 + i * 14) + "' fill='" + col +
            "' font-size='10'>" + escHtml(v + s.cidr) + "</text>");
        });
      }
    }
    // 편집 모드: 연결 손잡이(🔗)
    if (_tEditMode) {
      var hxo = meta.box ? 78 : 16, hyo = meta.box ? -18 : -16;
      svg.push("<g class='tlink-handle' data-id='" + escHtml(n.id) + "' style='cursor:crosshair'>" +
        "<circle cx='" + (n.x + hxo) + "' cy='" + (n.y + hyo) + "' r='8' fill='#0f172a' stroke='#38bdf8' stroke-width='1.5'/>" +
        "<text x='" + (n.x + hxo) + "' y='" + (n.y + hyo + 4) + "' font-size='9' text-anchor='middle'>🔗</text></g>");
    }
    svg.push("</g>");
  });
  svg.push("</svg>");
  host.innerHTML = "<div id='topo-tip' style='position:fixed;display:none;background:#1e293b;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:12px;z-index:99;pointer-events:none'></div>" + svg.join("");
  _tBindEditor(host, W, H);
  _tAutoSave();   // 변경 반영 시 자동 저장(디바운스) — 탭 전환/새로고침에도 유지
}

function _tBindEditor(host, W, H) {
  var svgEl = host.querySelector("#topo-svg");
  if (!svgEl) return;
  // 편집기 전용 줌/팬(뷰 상태 _tView 유지 — 재렌더에도 안 튐) + 선 포트 툴팁
  _topoWinClear(); _tBindView(host, W, H, svgEl); _topoBindTips(host);
  // 존 박스 리사이즈 손잡이(우하단 드래그 → w/h 변경)
  host.querySelectorAll(".tzone-resize").forEach(function (rz) {
    rz.addEventListener("mousedown", function (e) {
      e.stopPropagation();
      var n = _tNode(rz.getAttribute("data-id")); if (!n) return;
      var vb = svgEl._vb || { w: W, h: H }, rect = svgEl.getBoundingClientRect();
      var sx = vb.w / (rect.width || 1), sy = vb.h / (rect.height || 1);
      var ow = n.w || 320, oh = n.h || 220, ox = n.x, oy = n.y, px = e.clientX, py = e.clientY;
      function mm(ev) {
        // 좌상단 고정, 우하단만 늘어남(자유 리사이즈): w/h 증가분의 절반만큼 중심 이동
        var nw = Math.max(120, ow + (ev.clientX - px) * sx);
        var nh = Math.max(90, oh + (ev.clientY - py) * sy);
        n.x = ox + (nw - ow) / 2; n.y = oy + (nh - oh) / 2;
        n.w = nw; n.h = nh;
        _renderEditor();
      }
      function mu() { window.removeEventListener("mousemove", mm); window.removeEventListener("mouseup", mu); }
      window.addEventListener("mousemove", mm); window.addEventListener("mouseup", mu);
    });
  });
  // 연결 손잡이(🔗): 시작 노드 지정 → 다음 노드 클릭으로 완성
  host.querySelectorAll(".tlink-handle").forEach(function (h) {
    h.addEventListener("mousedown", function (e) { e.stopPropagation(); });
    h.addEventListener("click", function (e) {
      e.stopPropagation();
      var id = h.getAttribute("data-id");
      _tLinkFrom = (_tLinkFrom === id) ? null : id;   // 다시 누르면 취소
      _renderEditor();
    });
  });
  host.querySelectorAll(".tnode").forEach(function (g) {
    var id = g.getAttribute("data-id");
    // 노드 클릭: 선/연결 도구 사용 중이면 시작점→끝점으로 연결, 아니면 선택만(설정은 더블클릭)
    g.addEventListener("click", function (e) {
      if (!_tEditMode) return;
      if (_tLineStyle || _tLinkFrom) {
        e.stopPropagation();
        if (!_tLinkFrom) { _tLinkFrom = id; _renderEditor(); return; }   // 시작점 지정
        if (_tLinkFrom !== id) _tMakeEdge(_tLinkFrom, id, _tLineStyle);  // 끝점 → 연결
        _tLinkFrom = null; _renderEditor();                             // 선 도구는 계속 활성(연속 연결)
      }
    });
    // 더블클릭 = 설정 편집(단순 클릭으로 팝업 뜨는 불편 제거)
    g.addEventListener("dblclick", function (e) {
      if (!_tEditMode || _tLinkFrom || _tLineStyle) return;
      e.stopPropagation(); _openNodeModal(id);
    });
    // 드래그 이동(단일 클릭은 선택만). 다중 선택 상태면 선택 전체 함께 이동.
    g.addEventListener("mousedown", function (e) {
      if (_tLinkFrom || _tLineStyle) return;   // 연결/선 도구 중이면 클릭으로 연결
      e.stopPropagation();
      // 선택 갱신(재렌더는 mousedown 중엔 하지 않음 — 상호작용 흔들림 방지, mouseup에서 반영)
      var selChanged = false;
      if (e.shiftKey) { if (_tSel[id]) delete _tSel[id]; else _tSel[id] = true; _tSelId = id; selChanged = true; }
      else if (!_tSel[id]) { _tSel = {}; _tSelId = id; selChanged = true; }
      var moveIds = (_tSel[id] && Object.keys(_tSel).length) ? Object.keys(_tSel) : [id];
      var moveNodes = moveIds.map(_tNode).filter(Boolean);
      var moveGs = {};
      host.querySelectorAll(".tnode").forEach(function (gg) {
        if (moveIds.indexOf(gg.getAttribute("data-id")) >= 0) moveGs[gg.getAttribute("data-id")] = gg;
      });
      var single = moveIds.length === 1 ? _tNode(id) : null;
      var vb = svgEl._vb || { w: W, h: H };
      var rect = svgEl.getBoundingClientRect();
      var sx = vb.w / (rect.width || 1), sy = vb.h / (rect.height || 1);
      var px = e.clientX, py = e.clientY, moved = false, dx = 0, dy = 0;
      var SNAP = 8 * sx;               // 정렬 스냅 허용치(뷰 단위)
      function guide(gid, x1, y1, x2, y2, on) {
        var el = document.getElementById(gid);
        if (!on) { if (el) el.remove(); return; }
        if (!el) { el = document.createElementNS("http://www.w3.org/2000/svg", "line");
          el.id = gid; el.setAttribute("stroke", "#f0abfc"); el.setAttribute("stroke-width", "1");
          el.setAttribute("stroke-dasharray", "4 3"); svgEl.appendChild(el); }
        el.setAttribute("x1", x1); el.setAttribute("y1", y1); el.setAttribute("x2", x2); el.setAttribute("y2", y2);
      }
      function mm(ev) {
        dx = (ev.clientX - px) * sx; dy = (ev.clientY - py) * sy;
        if (Math.abs(ev.clientX - px) + Math.abs(ev.clientY - py) > 3) moved = true;
        var gx = false, gy = false;
        if (single) {   // 단일 이동: 다른 노드와 수직/수평 정렬 시 스냅 + 가이드
          var lx = single.x + dx, ly = single.y + dy;
          _tdiag.nodes.forEach(function (o) {
            if (o.id === id) return;
            if (!gx && Math.abs(lx - o.x) < SNAP) { dx = o.x - single.x; gx = o.x; }
            if (!gy && Math.abs(ly - o.y) < SNAP) { dy = o.y - single.y; gy = o.y; }
          });
          guide("tg-v", gx || 0, 0, gx || 0, vb.y + vb.h, gx !== false);
          guide("tg-h", 0, gy || 0, vb.x + vb.w, gy || 0, gy !== false);
        }
        moveIds.forEach(function (mid) {
          if (moveGs[mid]) moveGs[mid].setAttribute("transform", "translate(" + dx + "," + dy + ")");
        });
      }
      function mu() {
        window.removeEventListener("mousemove", mm); window.removeEventListener("mouseup", mu);
        guide("tg-v", 0, 0, 0, 0, false); guide("tg-h", 0, 0, 0, 0, false);
        if (moved) { moveNodes.forEach(function (nn) { nn.x += dx; nn.y += dy; }); _renderEditor(); }
        else if (selChanged) _renderEditor();   // 이동 없이 클릭(선택만) → 선택 표시 갱신
      }
      window.addEventListener("mousemove", mm); window.addEventListener("mouseup", mu);
    });
  });
  // 러버밴드(영역 선택)는 _tBindView에서 편집 모드일 때 바인딩됨(중복 방지).
}

function _tBindRubberBand(host, W, H, svgEl) {
  svgEl.addEventListener("mousedown", function (e) {
    if (e.target !== svgEl) return;            // 빈 배경에서 시작할 때만(노드 위 X)
    // 선/연결 도구 중 빈 곳 클릭 = 도구 취소
    if (_tLineStyle || _tLinkFrom) { _tLineStyle = null; _tLinkFrom = null; _tHighlightLineBtn(); _renderEditor(); return; }
    var vb = svgEl._vb || { w: W, h: H };
    var rect = svgEl.getBoundingClientRect();
    function toVb(cx, cy) {
      return { x: vb.x + (cx - rect.left) / rect.width * vb.w,
               y: vb.y + (cy - rect.top) / rect.height * vb.h };
    }
    var s = toVb(e.clientX, e.clientY);
    window._tRubberActive = true;
    if (!e.shiftKey) { _tSel = {}; _tSelId = null; }
    var rc = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rc.setAttribute("fill", "#38bdf8"); rc.setAttribute("fill-opacity", "0.12");
    rc.setAttribute("stroke", "#38bdf8"); rc.setAttribute("stroke-dasharray", "4 3");
    svgEl.appendChild(rc);
    function mm(ev) {
      var c = toVb(ev.clientX, ev.clientY);
      var x = Math.min(s.x, c.x), y = Math.min(s.y, c.y), w = Math.abs(c.x - s.x), h = Math.abs(c.y - s.y);
      rc.setAttribute("x", x); rc.setAttribute("y", y); rc.setAttribute("width", w); rc.setAttribute("height", h);
      rc._box = { x: x, y: y, w: w, h: h };
    }
    function mu() {
      window.removeEventListener("mousemove", mm); window.removeEventListener("mouseup", mu);
      window._tRubberActive = false;
      var box = rc._box;
      if (box && box.w > 4 && box.h > 4) {
        _tdiag.nodes.forEach(function (n) {
          if (n.x >= box.x && n.x <= box.x + box.w && n.y >= box.y && n.y <= box.y + box.h)
            _tSel[n.id] = true;
        });
      }
      if (rc.parentNode) rc.parentNode.removeChild(rc);
      _renderEditor();
    }
    window.addEventListener("mousemove", mm); window.addEventListener("mouseup", mu);
  });
}

// 편집기 전용 줌/팬 — 뷰 상태(_tView)를 유지해 재렌더에도 화면이 안 튄다.
function _tBindView(host, W, H, svgEl) {
  var vb = _tView;                          // 같은 참조를 계속 갱신 → 다음 렌더에 반영
  function apply() { svgEl.setAttribute("viewBox", vb.x + " " + vb.y + " " + vb.w + " " + vb.h); }
  svgEl._vb = vb; svgEl._applyVB = apply;
  svgEl._fit = function () { _tView = vb = { x: 0, y: 0, w: W, h: H }; svgEl._vb = vb; apply(); };
  // 휠 줌(커서 기준)
  svgEl.addEventListener("wheel", function (e) {
    e.preventDefault();
    var scale = e.deltaY > 0 ? 1.15 : 1 / 1.15;
    var rect = svgEl.getBoundingClientRect();
    var mx = vb.x + (e.clientX - rect.left) / rect.width * vb.w;
    var my = vb.y + (e.clientY - rect.top) / rect.height * vb.h;
    var nw = Math.min(W * 4, Math.max(W / 12, vb.w * scale));
    var nh = nw * (vb.h / vb.w);
    vb.x = mx - (mx - vb.x) * (nw / vb.w);
    vb.y = my - (my - vb.y) * (nh / vb.h);
    vb.w = nw; vb.h = nh; apply();
  }, { passive: false });
  // 빈 캔버스 드래그: 뷰 모드=팬 / 편집 모드=영역 선택(러버밴드가 처리)
  var pan = null;
  svgEl.addEventListener("mousedown", function (e) {
    if (window._tRubberActive || _tLinkFrom) return;
    if (e.target !== svgEl) return;         // 노드/손잡이 위에서는 무시
    if (_tEditMode) return;                 // 편집 모드 빈 드래그는 영역 선택
    pan = { sx: e.clientX, sy: e.clientY, vx: vb.x, vy: vb.y }; svgEl.style.cursor = "grabbing";
  });
  _topoWinOn("mousemove", function (e) {
    if (!pan) return;
    var rect = svgEl.getBoundingClientRect();
    vb.x = pan.vx - (e.clientX - pan.sx) / rect.width * vb.w;
    vb.y = pan.vy - (e.clientY - pan.sy) / rect.height * vb.h; apply();
  });
  _topoWinOn("mouseup", function () { pan = null; if (svgEl) svgEl.style.cursor = "grab"; });
  if (_tEditMode) _tBindRubberBand(host, W, H, svgEl);
}

function _tMakeEdge(a, b, style) {
  // 같은 두 장비 사이 '두 번째 선'도 허용(물리 링크가 2개인 경우). 3개 이상은 방지.
  var between = _tdiag.edges.filter(function (e) {
    return (e.a === a && e.b === b) || (e.a === b && e.b === a); });
  if (between.length >= 4) { _renderEditor(); return; }
  var idx = between.length;              // 0=첫 선, 1=두 번째 선 → 멤버 포트 배정 인덱스
  var edge = { a: a, b: b, a_port: null, b_port: null,
    style: (style && style.style) || "straight", dash: !!(style && style.dash) };
  _tdiag.edges.push(edge); _renderEditor();
  // 포트 자동 인식(양쪽 IP 있을 때). 선의 방향(a,b)이 응답의 a/b와 다를 수 있어 IP로 매칭.
  var na = _tNode(a), nb = _tNode(b);
  if (na && nb && na.ip && nb.ip) {
    fetch("/api/topology/link-ports", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a_ip: na.ip, b_ip: nb.ip }) })
      .then(function (r) { return r.json(); }).then(function (res) {
        // 각 선(idx)에 서로 다른 포트 배정: Po면 멤버, 아니면 관측 물리포트 목록,
        // 그것도 하나뿐이면 단일 포트. → 두 선이면 두 포트로 각각 표시.
        function pick(port, members, ports) {
          var list = (members && members.length) ? members
            : (ports && ports.length > 1) ? ports : null;
          if (list) return list[idx] || list[list.length - 1];
          return port || (ports && ports[0]) || null;
        }
        edge.a_port = pick(res.a_port, res.a_members, res.a_ports);
        edge.b_port = pick(res.b_port, res.b_members, res.b_ports);
        if (!edge.a_port && !edge.b_port) edge.note = "포트 미확인";
        _renderEditor();
      }).catch(function () {});
  }
}

function _openNodeModal(id) {
  var n = _tNode(id); if (!n) return;
  _tEditId = id;
  document.getElementById("tn-ip").value = n.ip || "";
  document.getElementById("tn-name").value = n.name || "";
  document.getElementById("tn-kind").value = n.kind || "l2";
  document.getElementById("tn-color").value = n.color || "#8b5cf6";
  document.getElementById("tn-auto").textContent = "";
  _tnToggleFields(n.kind || "l2");
  _renderChips();
  openModal("modal-topo-node");
}

// 종류별 입력 필드 표시/숨김: 대역박스=IP 숨김·대역만, 존박스=IP/대역 숨김·색상, 그 외=IP+대역
function _tnToggleFields(kind) {
  var meta = _TOPO_KIND[kind] || {};
  var show = function (elid, on) { var el = document.getElementById(elid); if (el) el.style.display = on ? "" : "none"; };
  show("tn-ip-row", !meta.box && !meta.zone);
  show("tn-subnet-row", !meta.zone);          // 존 박스는 대역 없음
  show("tn-color-row", !!meta.zone);          // 존 박스만 색상
}

function _renderChips() {
  var n = _tNode(_tEditId); if (!n) return;
  var box = document.getElementById("tn-chips");
  box.innerHTML = (n.subnets || []).map(function (s, i) {
    var v = s.vlan != null ? ("V" + s.vlan + " ") : "";
    var bg = s.source === "manual" ? "#1e3a5f" : "#334155";
    return "<span style='background:" + bg + ";color:#e2e8f0;font-size:11px;padding:2px 6px;border-radius:10px'>" +
      escHtml(v + s.cidr) + " <a href='#' data-chip='" + i + "' style='color:#f87171;text-decoration:none'>✕</a></span>";
  }).join("");
  box.querySelectorAll("[data-chip]").forEach(function (a) {
    a.addEventListener("click", function (e) {
      e.preventDefault();
      n.subnets.splice(+a.getAttribute("data-chip"), 1); _renderChips();
    });
  });
}

(function () {
  // 팔레트/모달 이벤트는 탭 진입 전에도 안전하게 바인딩(요소 존재 시)
  var ksel = document.getElementById("tn-kind");
  if (ksel) ksel.addEventListener("change", function () { _tnToggleFields(ksel.value); });
  var lk = document.getElementById("tn-lookup");
  if (lk) lk.addEventListener("click", function () {
    var ip = document.getElementById("tn-ip").value.trim();
    if (!ip) return;
    fetch("/api/topology/lookup?ip=" + encodeURIComponent(ip)).then(function (r) { return r.json(); })
      .then(function (d) {
        var el = document.getElementById("tn-auto");
        if (!d.found) { el.style.color = "#f59e0b"; el.textContent = "등록된 장비에 없는 IP입니다(수동 입력 가능)."; return; }
        el.style.color = "#22c55e";
        el.textContent = "✓ " + (d.name || "") + (d.hostname ? " · " + d.hostname : "") +
          (d.model ? " · " + d.model : "") + (d.device_type ? " · " + d.device_type : "");
        var nm = document.getElementById("tn-name");
        if (!nm.value || nm.value === _tNode(_tEditId).kind) nm.value = d.hostname || d.name || nm.value;
        // 구분 자동 매핑
        var dt = (d.device_type || "").toLowerCase();
        var ks = document.getElementById("tn-kind");
        if (d.kind === "fw") ks.value = "firewall";
        else if (d.kind === "srv") ks.value = "server";
        else if (dt.indexOf("backbone") >= 0 || dt.indexOf("core") >= 0) ks.value = "backbone";
        else if (dt === "ap" || dt.indexOf("access point") >= 0) ks.value = "ap";
        else if (dt === "pc" || dt.indexOf("tablet") >= 0) ks.value = "pc";
        else if (d.l3_class === "L3" || dt.indexOf("l3") >= 0) ks.value = "l3";
        else if (dt.indexOf("l4") >= 0) ks.value = "l4";
        else ks.value = "l2";
      }).catch(function () {});
  });
  var sg = document.getElementById("tn-subnet-suggest");
  if (sg) sg.addEventListener("click", function () {
    var ip = document.getElementById("tn-ip").value.trim();
    if (!ip) { alert("먼저 IP를 입력하세요."); return; }
    fetch("/api/topology/subnet-suggest?ip=" + encodeURIComponent(ip)).then(function (r) { return r.json(); })
      .then(function (d) {
        var n = _tNode(_tEditId); if (!n) return;
        n.subnets = n.subnets || [];
        (d.subnets || []).forEach(function (s) {
          if (!n.subnets.some(function (x) { return x.cidr === s.cidr; }))
            n.subnets.push({ vlan: s.vlan, cidr: s.cidr, source: "auto" });
        });
        _renderChips();
      }).catch(function () {});
  });
  var addS = document.getElementById("tn-subnet-add");
  if (addS) addS.addEventListener("click", function () {
    var inp = document.getElementById("tn-subnet-input");
    var v = inp.value.trim(); if (!v) return;
    var n = _tNode(_tEditId); if (!n) return;
    n.subnets = n.subnets || [];
    if (!n.subnets.some(function (x) { return x.cidr === v; }))
      n.subnets.push({ vlan: null, cidr: v, source: "manual" });
    inp.value = ""; _renderChips();
  });
  var sv = document.getElementById("tn-save");
  if (sv) sv.addEventListener("click", function () {
    var n = _tNode(_tEditId); if (!n) return;
    n.ip = document.getElementById("tn-ip").value.trim();
    n.name = document.getElementById("tn-name").value.trim() || n.name;
    n.kind = document.getElementById("tn-kind").value;
    if ((_TOPO_KIND[n.kind] || {}).zone) {
      n.color = document.getElementById("tn-color").value;
      if (!n.w) { n.w = 340; n.h = 240; }   // 존으로 바꾸면 기본 크기 부여
    }
    closeModal("modal-topo-node"); _renderEditor();
  });
  var del = document.getElementById("tn-delete");
  if (del) del.addEventListener("click", function () {
    if (!confirm("이 노드를 삭제할까요?")) return;
    _tdiag.nodes = _tdiag.nodes.filter(function (n) { return n.id !== _tEditId; });
    _tdiag.edges = _tdiag.edges.filter(function (e) { return e.a !== _tEditId && e.b !== _tEditId; });
    closeModal("modal-topo-node"); _renderEditor();
  });
})();

function renderTopology() {
  var host = document.getElementById("topology-canvas");
  if (!host || !_topoData) return;
  _topoWinClear();               // 이전 렌더의 window 리스너 정리(누수 방지)
  if (!_topoData.nodes.length) {
    host.innerHTML = "<p style='color:#94a3b8;padding:20px'>표시할 장비가 없습니다. 스위치·방화벽을 수집하면 연결 관계가 그려집니다.</p>";
    return;
  }
  // 모드 버튼 상태 + 구역 셀렉트 표시
  document.querySelectorAll(".topo-mode").forEach(function (b) {
    b.className = "btn topo-mode " + (b.getAttribute("data-mode") === _topoMode ? "btn--primary" : "btn--secondary");
    b.style.fontSize = "12px";
  });
  var zsel = document.getElementById("topo-zone-select");
  if (zsel) zsel.style.display = (_topoMode === "tps") ? "" : "none";
  var l2b = document.getElementById("btn-topo-l2");
  if (l2b) {
    l2b.style.display = (_topoMode === "core") ? "" : "none";
    l2b.textContent = _topoExpandL2 ? "🌐 L2 대역 접기" : "🌐 L2 펼치기";
    l2b.className = "btn " + (_topoExpandL2 ? "btn--primary" : "btn--secondary");
    l2b.style.fontSize = "12px";
  }

  _renderTree(host);   // v4.2: 서버실 트리 단일 뷰(존/TPS/코어 모드 폐지)
}

// ─── 서버실 트리 구성도 (v4.2) ──────────────────────────────────────
// role→아이콘 라벨(_deviceSymbol) 및 색
var _TREE_ICON = {
  internet_fw: "방화벽", firewall: "방화벽", backbone: "백본", l3: "L3", l4: "L4",
};
var _TREE_COLOR = {
  internet_fw: "#ef4444", firewall: "#ef4444", backbone: "#a855f7",
  l3: "#8b5cf6", l4: "#f59e0b",
};

function _renderTree(host) {
  var nodes = _topoData.nodes || [];
  var links = _topoData.links || [];
  if (!nodes.length) {
    host.innerHTML = "<p style='color:#94a3b8;padding:20px'>서버실(위치 A09U27 형식)에 지정된 방화벽·L3/백본 스위치가 없습니다. 장비 위치를 지정하고 수집하면 구성도가 그려집니다.</p>";
    return;
  }
  var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });

  // 가상 Internet 루트 + 상위 연결(논리) — 물리 링크가 없어도 계층을 세운다
  var hasInternetFw = nodes.some(function (n) { return n.role === "internet_fw"; });
  var backbones = nodes.filter(function (n) { return n.role === "backbone"; });

  // tier: 0=Internet(가상) 1=internet_fw 2=backbone 3=l3/l4/firewall
  var TIER_INTERNET = 0;
  var tierNodes = { 0: [], 1: [], 2: [], 3: [] };
  nodes.forEach(function (n) { (tierNodes[n.tier] = tierNodes[n.tier] || []).push(n); });

  // 레이아웃 좌표 계산
  var colW = 200, rowH = 170, marginX = 90, marginY = 70;
  var maxCols = Math.max(1, tierNodes[1].length, tierNodes[2].length, tierNodes[3].length);
  var width = Math.max(720, marginX * 2 + maxCols * colW);
  // tier3에 대역 박스가 붙으므로 하단 여유
  var height = marginY * 2 + 4 * rowH + 120;

  _topoRenderedPos = {};
  function _place(tierList, tierIdx) {
    var n = tierList.length;
    tierList.forEach(function (node, i) {
      var x = n === 1 ? width / 2 : marginX + (i + 0.5) * ((width - marginX * 2) / n);
      var y = marginY + tierIdx * rowH;
      var ov = _topoLayout[node.id];
      _topoRenderedPos[node.id] = ov ? { x: ov.x, y: ov.y } : { x: x, y: y };
    });
  }
  _place(tierNodes[1], 1); _place(tierNodes[2], 2); _place(tierNodes[3], 3);
  var internetPos = { x: width / 2, y: marginY + TIER_INTERNET * rowH };

  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='100%'" +
    " preserveAspectRatio='xMidYMid meet' viewBox='0 0 " + width + " " + height +
    "' style='cursor:grab;display:block;background:#0f172a'>"];

  function _pos(id) { return _topoRenderedPos[id]; }
  function _line(x1, y1, x2, y2, color, dashed, label) {
    var d = dashed ? " stroke-dasharray='5 4'" : "";
    var s = "<line x1='" + x1 + "' y1='" + y1 + "' x2='" + x2 + "' y2='" + y2 +
      "' stroke='" + (color || "#475569") + "' stroke-width='1.8'" + d + "/>";
    if (label) {
      s += "<text x='" + ((x1 + x2) / 2) + "' y='" + ((y1 + y2) / 2 - 3) +
        "' fill='#94a3b8' font-size='10' text-anchor='middle'>" + escHtml(label) + "</text>";
    }
    return s;
  }

  // 1) 가상 계층 링크(Internet→FW→Backbone) — 물리 데이터 없이도 트리 골격
  var internetChildren = hasInternetFw ? tierNodes[1] : backbones;
  internetChildren.forEach(function (n) {
    var p = _pos(n.id);
    svg.push(_line(internetPos.x, internetPos.y + 20, p.x, p.y - 20, "#334155", true));
  });
  if (hasInternetFw) {
    tierNodes[1].forEach(function (fw) {
      backbones.forEach(function (bb) {
        var a = _pos(fw.id), b = _pos(bb.id);
        svg.push(_line(a.x, a.y + 20, b.x, b.y - 20, "#334155", true));
      });
    });
  }

  // 2) 실측 링크(직결 CDP/LLDP/ARP-MAC) — 실선, 포트 라벨
  links.forEach(function (l) {
    var a = _pos(l.a), b = _pos(l.b);
    if (!a || !b) return;
    var port = [l.a_port, l.b_port].filter(Boolean).join(" ↔ ");
    svg.push(_line(a.x, a.y, b.x, b.y, l.l3 ? "#38bdf8" : "#22c55e", !!l.l3, port));
  });

  // 3) Internet 가상 노드
  svg.push("<g transform='translate(" + (internetPos.x - 17) + "," + (internetPos.y - 17) + ")'>" +
    "<circle cx='17' cy='17' r='16' fill='#0ea5e9' fill-opacity='0.15' stroke='#0ea5e9' stroke-width='1.8'/>" +
    "<text x='17' y='21' fill='#0ea5e9' font-size='11' text-anchor='middle'>🌐</text></g>" +
    "<text x='" + internetPos.x + "' y='" + (internetPos.y + 34) +
    "' fill='#94a3b8' font-size='11' text-anchor='middle'>Internet</text>");

  // 4) 장비 노드 + 대역 박스
  nodes.forEach(function (n) {
    var p = _pos(n.id);
    var color = _TREE_COLOR[n.role] || "#64748b";
    var down = n.reachable === false || n.status === "failed";
    var label = _TREE_ICON[n.role] || "L2";
    svg.push("<g class='topo-node' data-swid='" + escHtml(n.id) + "' style='cursor:move'>");
    svg.push(_deviceSymbol(label, p.x - 17, p.y - 17, down ? "#ef4444" : color));
    svg.push("<text x='" + p.x + "' y='" + (p.y + 32) + "' fill='#e2e8f0' font-size='12'" +
      " text-anchor='middle'>" + (down ? "🔴 " : "") + escHtml(n.name || "") + "</text>");
    svg.push("<text x='" + p.x + "' y='" + (p.y + 46) + "' fill='#64748b' font-size='10'" +
      " text-anchor='middle'>" + escHtml(n.ip || "") + "</text>");
    // 대역 박스(L3/백본만) — VLAN·CIDR 세로 나열
    var subs = n.subnets_vlan || [];
    if (subs.length && (n.role === "l3" || n.role === "backbone")) {
      var bx = p.x - 82, by = p.y + 56, bw = 164;
      var shown = subs.slice(0, 10);
      var bh = 20 + shown.length * 15;
      svg.push("<rect x='" + bx + "' y='" + by + "' width='" + bw + "' height='" + bh +
        "' rx='5' fill='#0b1220' stroke='" + color + "' stroke-opacity='0.5'/>");
      svg.push("<text x='" + (bx + 8) + "' y='" + (by + 14) + "' fill='" + color +
        "' font-size='10' font-weight='700'>대역 " + subs.length + "개</text>");
      shown.forEach(function (s, i) {
        var vtag = (s.vlan != null ? "V" + s.vlan + " " : "");
        svg.push("<text x='" + (bx + 8) + "' y='" + (by + 30 + i * 15) +
          "' fill='#cbd5e1' font-size='10'>" + escHtml(vtag + s.cidr) + "</text>");
      });
      if (subs.length > shown.length) {
        svg.push("<text x='" + (bx + 8) + "' y='" + (by + 30 + shown.length * 15) +
          "' fill='#64748b' font-size='9'>+" + (subs.length - shown.length) + " more</text>");
      }
    }
    svg.push("</g>");
  });

  svg.push("</svg>");
  host.innerHTML = "<div id='topo-tip' style='position:fixed;display:none;background:#1e293b;" +
    "color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:12px;z-index:99;pointer-events:none'></div>" +
    svg.join("");
  _topoBindZoomPan(host, width, height);
  _topoBindDrag(host);
  _topoBindTips(host);
}

// 장비 심볼(SVG) — 실제 네트워크 구성도 스타일 아이콘(34x34 기준, 채색 + 입체감)
function _deviceSymbol(label, x, y, color) {
  var f = "' fill='" + color + "' fill-opacity='0.16' stroke='" + color + "' stroke-width='1.8'";
  var g = "<g transform='translate(" + x + "," + y + ")'>";
  if (label === "방화벽") {
    // 벽돌벽(방화벽 표준 아이콘) — 엇갈린 벽돌 + 불꽃
    g += "<rect x='2' y='6' width='30' height='22' rx='2" + f + "/>";
    g += "<line x1='2' y1='13' x2='32' y2='13' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='2' y1='20' x2='32' y2='20' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='12' y1='6' x2='12' y2='13' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='22' y1='6' x2='22' y2='13' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='7' y1='13' x2='7' y2='20' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='17' y1='13' x2='17' y2='20' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='27' y1='13' x2='27' y2='20' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='12' y1='20' x2='12' y2='28' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<line x1='22' y1='20' x2='22' y2='28' stroke='" + color + "' stroke-width='1.4'/>";
  } else if (label === "백본") {
    // Cisco 라우터 표준 — 원형 퍽 + 사방 화살표(상하좌우 in/out)
    g += "<circle cx='17' cy='17' r='13" + f + "/>";
    g += "<path d='M17 7 v20 M7 17 h20' stroke='" + color + "' stroke-width='1.4' fill='none'/>";
    // 화살촉(위·아래·좌·우) — 라우팅(사방 전달) 표현
    g += "<path d='M17 7 l-3 4 M17 7 l3 4 M17 27 l-3 -4 M17 27 l3 -4" +
      " M7 17 l4 -3 M7 17 l4 3 M27 17 l-4 -3 M27 17 l-4 3' stroke='" + color + "' stroke-width='1.4' fill='none'/>";
  } else if (label === "L3") {
    // Cisco L3 스위치 — 둥근 퍽(사각) + 상하 화살표(라우팅) + 좌우 화살표(스위칭)
    g += "<rect x='3' y='9' width='28' height='16' rx='3" + f + "/>";
    g += "<path d='M17 5 v6 M17 29 v-6 M17 5 l-2.5 3 M17 5 l2.5 3 M17 29 l-2.5 -3 M17 29 l2.5 -3'" +
      " stroke='" + color + "' stroke-width='1.4' fill='none'/>";
    g += "<path d='M9 14 h16 M9 20 h16 M9 14 l3 -2 M9 14 l3 2 M25 20 l-3 -2 M25 20 l-3 2'" +
      " stroke='#e2e8f0' stroke-width='1.2' fill='none'/>";
  } else if (label === "L4") {
    // L4 로드밸런서 — 박스 + 분기 화살표
    g += "<path d='M4 12 l13 -6 l13 6 l-13 6 z" + f + "/>";
    g += "<path d='M4 12 v10 l13 6 v-10 z' fill='" + color + "' fill-opacity='0.1' stroke='" + color + "' stroke-width='1.6'/>";
    g += "<path d='M30 12 v10 l-13 6 v-10 z' fill='" + color + "' fill-opacity='0.22' stroke='" + color + "' stroke-width='1.6'/>";
    g += "<text x='17' y='16' fill='#e2e8f0' font-size='8' font-weight='700' text-anchor='middle'>L4</text>";
  } else if (label === "서버") {
    // 서버 랙 — 슬롯 3칸 + LED
    g += "<rect x='7' y='3' width='20' height='28' rx='2" + f + "/>";
    for (var i = 0; i < 3; i++) {
      g += "<rect x='10' y='" + (6 + i * 8) + "' width='14' height='5' rx='1' fill='none' stroke='" + color + "' stroke-width='1.2'/>";
      g += "<circle cx='12' cy='" + (8.5 + i * 8) + "' r='1' fill='" + color + "'/>";
    }
  } else if (label === "인터넷") {
    // 클라우드(인터넷)
    g += "<path d='M9 24 a7 7 0 0 1 0 -14 a9 9 0 0 1 17 2 a5 5 0 0 1 -1 12 z" + f + "/>";
  } else if (label === "AP") {
    // 무선 AP — 본체 + 전파(호)
    g += "<rect x='9' y='18' width='16' height='10' rx='2" + f + "/>";
    g += "<circle cx='17' cy='23' r='1.6' fill='" + color + "'/>";
    g += "<path d='M11 12 a8 8 0 0 1 12 0 M13.5 15 a4.5 4.5 0 0 1 7 0' stroke='" + color + "' stroke-width='1.5' fill='none'/>";
  } else if (label === "PC") {
    // 데스크톱 — 모니터 + 받침
    g += "<rect x='5' y='6' width='24' height='16' rx='2" + f + "/>";
    g += "<rect x='8' y='9' width='18' height='10' rx='1' fill='none' stroke='" + color + "' stroke-width='1' stroke-opacity='0.6'/>";
    g += "<path d='M14 22 v4 M20 22 v4 M11 30 h12' stroke='" + color + "' stroke-width='1.6' fill='none'/>";
  } else if (label === "설비") {
    // 일반 설비(장비함) — 함체 + 기어(범용 장치)
    g += "<rect x='6' y='6' width='22' height='22' rx='3" + f + "/>";
    g += "<circle cx='17' cy='17' r='5' fill='none' stroke='" + color + "' stroke-width='1.4'/>";
    g += "<circle cx='17' cy='17' r='1.6' fill='" + color + "'/>";
    g += "<path d='M17 10 v3 M17 21 v3 M10 17 h3 M21 17 h3' stroke='" + color + "' stroke-width='1.4'/>";
  } else {
    // Cisco L2 스위치 표준 — 둥근 퍽(사각) + 4개 양방향 화살표(스위칭)
    g += "<rect x='3' y='10' width='28' height='14' rx='3" + f + "/>";
    g += "<path d='M8 14 h18 M8 20 h18' stroke='#e2e8f0' stroke-width='1.2' fill='none'/>";
    g += "<path d='M8 14 l3 -2 M8 14 l3 2 M26 14 l-3 -2 M26 14 l-3 2" +
      " M8 20 l3 -2 M8 20 l3 2 M26 20 l-3 -2 M26 20 l-3 2' stroke='#e2e8f0' stroke-width='1.2' fill='none'/>";
  }
  return g + "</g>";
}

// 카드(중간): 실제 심볼 + 호스트명 1줄, IP 작게, 상태 점. 대역/포트는 툴팁.
var _CARD_W = 210, _CARD_H = 64;
function _drawNode(svg, n, x, y, opts) {
  opts = opts || {};
  if (n.kind === "band") { _drawBand(svg, n, x, y); return; }
  var k = _topoKindOf(n), dot = _topoStatusDot(n);
  var isGhost = opts.ghost;
  var tipLines = [k.label ? ("[" + k.label + "] " + (n.name || "")) : (n.name || ""),
                  (n.ip || "") + (n.vendor ? " · " + n.vendor : "")];
  if (n.subnets && n.subnets.length) tipLines.push("연결 대역: " + n.subnets.join(", "));
  if (n.interfaces && n.interfaces.length) tipLines.push("인터페이스:\n  " + n.interfaces.join("\n  "));
  if (opts.linkPort) tipLines.push("업링크: " + opts.linkPort);
  var tip = tipLines.join("\n");
  svg.push("<g class='topo-node' data-swid='" + n.id + "' data-kind='" + (n.kind || "sw") +
    "' data-ghost='" + (isGhost ? 1 : 0) + "' data-tip=\"" + escHtml(tip) + "\" style='cursor:pointer'" +
    (isGhost ? " opacity='0.6'" : "") + ">");
  svg.push("<rect x='" + x + "' y='" + y + "' width='" + _CARD_W + "' height='" + _CARD_H +
    "' rx='9' fill='" + (isGhost ? "#0b1220" : "#1e293b") + "' stroke='" + k.color +
    "' data-basestroke='" + k.color + "' stroke-width='2.5'" +
    (isGhost ? " stroke-dasharray='5 4'" : "") + "/>");
  svg.push("<rect x='" + x + "' y='" + y + "' width='6' height='" + _CARD_H + "' rx='3' fill='" + k.color + "'/>");
  svg.push(_deviceSymbol(k.sym || "L2", x + 12, y + (_CARD_H - 34) / 2, k.color));
  svg.push("<text x='" + (x + 54) + "' y='" + (y + 27) +
    "' fill='#f1f5f9' font-size='13' font-weight='700'>" + escHtml((n.name || "").slice(0, 20)) + "</text>");
  svg.push("<text x='" + (x + 54) + "' y='" + (y + 45) +
    "' fill='#94a3b8' font-size='11'>" + escHtml(n.ip || "") + "</text>");
  svg.push("<circle cx='" + (x + _CARD_W - 14) + "' cy='" + (y + 16) + "' r='5' fill='" + dot + "'/>");
  if (n.subnets && n.subnets.length) {
    svg.push("<rect x='" + (x + _CARD_W - 42) + "' y='" + (y + _CARD_H - 20) + "' width='36' height='15' rx='7' fill='#0f172a' stroke='#334155'/>");
    svg.push("<text x='" + (x + _CARD_W - 24) + "' y='" + (y + _CARD_H - 9) +
      "' fill='#7dd3fc' font-size='9' text-anchor='middle'>" + n.subnets.length + "대역</text>");
  }
  svg.push("</g>");
}

// 대역(subnet) 뱃지 카드 — L2 스위치 무리를 한 장으로 접어 표현. 클릭 시 하단 드릴다운.
var _BAND_C = "#14b8a6";
function _drawBand(svg, n, x, y) {
  var open = _topoOpenBand === n.id;
  var termN = (n.termCount || 0);
  var tip = "대역 " + (n.cidr || "") + "\nL2 스위치 " + n.l2s.length + "대" +
    (termN ? " · 단말 " + termN + "대" : "") + "\n클릭 → 소속 L2 목록 보기";
  svg.push("<g class='topo-band' data-band='" + escHtml(n.id) + "' data-tip=\"" + escHtml(tip) +
    "\" style='cursor:pointer'>");
  // 카드(대역 강조: 청록 굵은 테두리 + 좌측 바)
  svg.push("<rect x='" + x + "' y='" + y + "' width='" + _CARD_W + "' height='" + _CARD_H +
    "' rx='9' fill='#0e2a2a' stroke='" + _BAND_C + "' stroke-width='" + (open ? 3.5 : 2.5) + "'/>");
  svg.push("<rect x='" + x + "' y='" + y + "' width='6' height='" + _CARD_H + "' rx='3' fill='" + _BAND_C + "'/>");
  // 지구본 아이콘(대역)
  svg.push("<g transform='translate(" + (x + 12) + "," + (y + (_CARD_H - 32) / 2) + ")'>" +
    "<circle cx='16' cy='16' r='14' fill='" + _BAND_C + "' fill-opacity='0.16' stroke='" + _BAND_C + "' stroke-width='1.8'/>" +
    "<ellipse cx='16' cy='16' rx='6' ry='14' fill='none' stroke='" + _BAND_C + "' stroke-width='1.3'/>" +
    "<line x1='2' y1='16' x2='30' y2='16' stroke='" + _BAND_C + "' stroke-width='1.3'/>" +
    "<line x1='4.5' y1='9' x2='27.5' y2='9' stroke='" + _BAND_C + "' stroke-width='1'/>" +
    "<line x1='4.5' y1='23' x2='27.5' y2='23' stroke='" + _BAND_C + "' stroke-width='1'/></g>");
  // 대역(CIDR) + VLAN
  svg.push("<text x='" + (x + 54) + "' y='" + (y + 25) +
    "' fill='#5eead4' font-size='13' font-weight='700'>🌐 " + escHtml((n.cidr || "").slice(0, 20)) + "</text>");
  svg.push("<text x='" + (x + 54) + "' y='" + (y + 44) +
    "' fill='#94a3b8' font-size='11'>L2 " + n.l2s.length + "대" +
    (termN ? " · 단말 " + termN : "") + (n.vlan ? " · VLAN " + escHtml(String(n.vlan)) : "") + "</text>");
  // 펼침 표시(쉐브론)
  svg.push("<text x='" + (x + _CARD_W - 16) + "' y='" + (y + 40) +
    "' fill='" + _BAND_C + "' font-size='16' text-anchor='middle'>" + (open ? "▾" : "▸") + "</text>");
  // L2 대수 배지
  svg.push("<circle cx='" + (x + _CARD_W - 16) + "' cy='" + (y + 16) + "' r='9' fill='" + _BAND_C + "'/>");
  svg.push("<text x='" + (x + _CARD_W - 16) + "' y='" + (y + 20) +
    "' fill='#04201f' font-size='11' font-weight='700' text-anchor='middle'>" + n.l2s.length + "</text>");
  svg.push("</g>");
}

// L2 무리를 (상위 L3 → /24 대역)으로 그룹핑해 대역 뱃지 노드 배열로 반환
function _ipBand(ip) {
  if (!ip) return null;
  var m = String(ip).match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  return m ? (m[1] + "." + m[2] + "." + m[3] + ".0/24") : null;
}
function _buildBands(l2s, links, upperById) {
  var l2ids = {};
  l2s.forEach(function (n) { l2ids[n.id] = n; });
  // 각 L2의 상위(코어/L3) 부모 후보: 링크로 이어진 upper 노드 중 최다
  var parentOf = {};
  links.forEach(function (l) {
    [[l.a, l.b], [l.b, l.a]].forEach(function (p) {
      if (l2ids[p[0]] && upperById[p[1]]) {
        var m = parentOf[p[0]] = parentOf[p[0]] || {};
        m[p[1]] = (m[p[1]] || 0) + 1;
      }
    });
  });
  function bestParent(id) {
    var m = parentOf[id];
    if (!m) return null;
    return Object.keys(m).sort(function (a, b) { return m[b] - m[a]; })[0];
  }
  var bands = {};
  l2s.forEach(function (n) {
    var cidr = _ipBand(n.ip) || "기타 대역";
    var par = bestParent(n.id);
    var key = (par || "none") + "|" + cidr;
    var b = bands[key];
    if (!b) {
      b = bands[key] = { id: "band:" + key, kind: "band", device_type: "L2 Switch",
        name: cidr, cidr: cidr, parent: par, l2s: [], _subset: {} };
    }
    b.l2s.push(n);
    (n.subnets || []).forEach(function (s) { b._subset[s] = 1; });
  });
  return Object.keys(bands).map(function (key) {
    var b = bands[key];
    b.subnets = Object.keys(b._subset);
    return b;
  });
}
// 링크를 대역 단위로 재매핑(L2 endpoint → band id), 중복 제거
function _remapBandLinks(links, l2ToBand, keepIds) {
  var seen = {}, out = [];
  links.forEach(function (l) {
    var a = l2ToBand[l.a] || l.a, b = l2ToBand[l.b] || l.b;
    if (a === b || !keepIds[a] || !keepIds[b]) return;
    var kk = a < b ? a + "~" + b : b + "~" + a;
    if (seen[kk]) return;
    seen[kk] = 1;
    out.push({ a: a, b: b, mutual: l.mutual, l3: l.l3, source: l.source,
      a_port: (l2ToBand[l.a] ? "" : l.a_port), b_port: (l2ToBand[l.b] ? "" : l.b_port) });
  });
  return out;
}

function _legendHTML(extra) {
  return "<div style='display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:8px 14px;color:#94a3b8;font-size:11px;border-bottom:1px solid #1e293b'>" +
    "<span style='color:#ef4444'>🛡 Firewall</span><span style='color:#a855f7'>◆ Core(백본)</span>" +
    "<span style='color:#8b5cf6'>◆ Distribution(L3)</span><span style='color:#f59e0b'>⬡ L4</span><span style='color:#14b8a6'>▭ Access(L2)</span>" +
    "<span style='color:#22c55e'>● 정상</span><span style='color:#ef4444'>● 실패/끊김</span>" +
    (extra || "") +
    "<span style='margin-left:auto'>노드에 마우스=대역·포트·인터페이스, 클릭=상세, 휠=확대 · 드래그=이동</span></div>";
}

// ── 서버실 구성도: 이중화 쌍 인식 + 계층형(방화벽→백본/L3→L4→L2) ──────
function _coreRank(n) {
  // 3-Tier: 0=Firewall, 1=Core(백본), 2=Distribution(L3·L4), 3=Access(L2/대역)
  var dt = n.device_type || "", nm = (n.name || "").toUpperCase();
  if (n.kind === "band") return 3;               // 대역 뱃지 = 액세스 계층
  if (n.kind === "fw" || dt === "Firewall") return 0;
  if (dt === "BackBone" || /BACKBONE|\bBB\b|BB\d|CORE/.test(nm)) return 1;
  if (dt === "L3 Switch" || dt === "L4 Switch" || /\bL3\b|\bL4\b|SLB|ADC|DIST|AGG/.test(nm)) return 2;
  return 3;
}

function _renderCoreMap(host) {
  var rawCore = _topoData.nodes.filter(_isCoreDevice);
  var core, links, coreIds = {};
  var l2s = rawCore.filter(function (n) { return _coreRank(n) === 3; });
  var upper = rawCore.filter(function (n) { return _coreRank(n) !== 3; });

  if (!_topoExpandL2 && l2s.length) {
    // ── L2 접기: L2 무리를 대역 뱃지로 축약 ──
    var upperById = {};
    upper.forEach(function (n) { upperById[n.id] = n; });
    var bands = _buildBands(l2s, _topoData.links, upperById);
    _topoBandsById = {};
    bands.forEach(function (b) { _topoBandsById[b.id] = b; });
    var l2ToBand = {};
    bands.forEach(function (b) { b.l2s.forEach(function (n) { l2ToBand[n.id] = b.id; }); });
    core = upper.concat(bands);
    core.forEach(function (n) { coreIds[n.id] = true; });
    // upper-upper 링크(기존 필터) + 대역 링크(L3→대역, 항상 표시)
    var upperLinks = _topoData.links.filter(function (l) {
      if (!(upperById[l.a] && upperById[l.b])) return false;
      var isFw = String(l.a)[0] === "f" || String(l.b)[0] === "f";
      return l.mutual || isFw;
    });
    var l2Uplinks = _topoData.links.filter(function (l) {
      return (l2ToBand[l.a] && upperById[l.b]) || (l2ToBand[l.b] && upperById[l.a]);
    });
    links = upperLinks.concat(_remapBandLinks(l2Uplinks, l2ToBand, coreIds));
  } else {
    // ── L2 펼치기: 개별 노드 그대로 ──
    core = rawCore;
    core.forEach(function (n) { coreIds[n.id] = true; });
    links = _topoData.links.filter(function (l) {
      if (!(coreIds[l.a] && coreIds[l.b])) return false;
      var isFw = String(l.a)[0] === "f" || String(l.b)[0] === "f";
      return l.mutual || isFw;
    });
  }
  if (!core.length) {
    host.innerHTML = _legendHTML() +
      "<p style='color:#94a3b8;padding:20px'>서버실(코어) 장비가 없습니다. 스위치 '구분'을 방화벽/백본/L3/L4로 지정하면 여기에 표시됩니다.</p>";
    _bindTopoModeButtons();
    return;
  }

  var byId = {};
  core.forEach(function (n) { byId[n.id] = n; });
  var adj = {};
  links.forEach(function (l) {
    (adj[l.a] = adj[l.a] || []).push(l.b);
    (adj[l.b] = adj[l.b] || []).push(l.a);
  });

  var byRank = {};
  core.forEach(function (n) { var r = _coreRank(n); (byRank[r] = byRank[r] || []).push(n); });
  var ranks = Object.keys(byRank).map(Number).sort(function (a, b) { return a - b; });

  // 이중화 쌍 인식: 같은 rank에서 서로 직접 연결된 두 노드 = 쌍(붙여서 배치)
  function _orderRank(list) {
    var ids = {}; list.forEach(function (n) { ids[n.id] = n; });
    var used = {}, ordered = [], pairs = {};
    list.slice().sort(function (a, b) { return (a.name || "").localeCompare(b.name || ""); })
      .forEach(function (n) {
        if (used[n.id]) return;
        var partner = (adj[n.id] || []).map(function (x) { return ids[x]; })
          .filter(function (x) { return x && !used[x.id]; })[0];
        used[n.id] = true; ordered.push(n);
        if (partner) { used[partner.id] = true; ordered.push(partner); pairs[n.id] = partner.id; pairs[partner.id] = n.id; }
      });
    return { ordered: ordered, pairs: pairs };
  }

  var GAP_X = 46, PAIR_GAP = 16, GAP_Y = 118;
  var layout = {}, maxRowW = 0;
  ranks.forEach(function (r) {
    var res = _orderRank(byRank[r]);
    layout[r] = res;
    var w = 0, prev = null;
    res.ordered.forEach(function (n) { w += _CARD_W + (prev && res.pairs[prev] === n.id ? PAIR_GAP : GAP_X); prev = n.id; });
    maxRowW = Math.max(maxRowW, w - GAP_X);
  });
  var width = Math.max(960, maxRowW + 80);
  var height = ranks.length * (_CARD_H + GAP_Y) + 60;

  var pos = {};
  ranks.forEach(function (r, ri) {
    var res = layout[r], rowW = 0, prev = null;
    res.ordered.forEach(function (n) { rowW += _CARD_W + (prev && res.pairs[prev] === n.id ? PAIR_GAP : GAP_X); prev = n.id; });
    rowW -= GAP_X;
    var px = (width - rowW) / 2; prev = null;
    res.ordered.forEach(function (n) {
      if (prev) px += _CARD_W + (res.pairs[prev] === n.id ? PAIR_GAP : GAP_X);
      pos[n.id] = { x: px, y: 30 + ri * (_CARD_H + GAP_Y) };
      prev = n.id;
    });
  });

  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='100%'" +
             " preserveAspectRatio='xMidYMid meet' viewBox='0 0 " + width + " " + height +
             "' style='cursor:grab;display:block'>"];

  // 세그먼트(구역) 컨테이너 — 첨부 구성도처럼 계층별 라운드 박스 + 좌측 라벨
  var _RANK_SEG = { 0: { t: "🛡 보안 계층 (Firewall)", c: "#ef4444", solid: true }, 1: { t: "🏢 코어 계층 (백본)", c: "#a855f7" },
                    2: { t: "🔀 분배 계층 (L3 · L4)", c: "#f59e0b" },
                    3: { t: _topoExpandL2 ? "🔌 액세스 계층 (L2)" : "🌐 액세스 계층 (L2 대역)", c: "#14b8a6" } };
  ranks.forEach(function (r, ri) {
    var row = layout[r].ordered;
    if (!row.length) return;
    var xs = row.map(function (n) { return pos[n.id].x; });
    var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs) + _CARD_W;
    var y = 30 + ri * (_CARD_H + GAP_Y);
    var seg = _RANK_SEG[r] || { t: "", c: "#64748b" };
    var padX = 22, padY = 16;
    // 보안 계층은 실선 강조, 나머지는 은은한 점선
    var dash = seg.solid ? "" : " stroke-dasharray='2 4'";
    svg.push("<rect x='" + (minX - padX) + "' y='" + (y - padY) + "' width='" + (maxX - minX + padX * 2) +
      "' height='" + (_CARD_H + padY * 2) + "' rx='16' fill='" + seg.c + "' fill-opacity='" + (seg.solid ? "0.09" : "0.06") +
      "' stroke='" + seg.c + "' stroke-opacity='" + (seg.solid ? "0.75" : "0.45") + "' stroke-width='" +
      (seg.solid ? "2" : "1.5") + "'" + dash + "/>");
    svg.push("<text x='" + (minX - padX + 4) + "' y='" + (y - padY - 6) + "' fill='" + seg.c +
      "' font-size='12' font-weight='700'>" + escHtml(seg.t) + "</text>");
  });

  links.forEach(function (l) {
    var a = pos[l.a], b = pos[l.b];
    if (!a || !b) return;
    var ra = _coreRank(byId[l.a]), rb = _coreRank(byId[l.b]);
    if (ra === rb && layout[ra] && layout[ra].pairs[l.a] === l.b) {
      // 이중화 쌍: 두 카드 사이 굵은 수평 실선(교차 표현)
      var yy = a.y + _CARD_H / 2;
      var x1 = Math.min(a.x, b.x) + _CARD_W, x2 = Math.max(a.x, b.x);
      svg.push("<line class='topo-edge' data-ea='" + l.a + "' data-eb='" + l.b +
        "' data-tip=\"이중화 링크: " + escHtml((byId[l.a] || {}).name || "") + " ═ " + escHtml((byId[l.b] || {}).name || "") +
        "\" x1='" + x1 + "' y1='" + yy + "' x2='" + x2 + "' y2='" + yy + "' stroke='#22d3ee' stroke-width='4'/>");
      return;
    }
    var top = (a.y <= b.y) ? l.a : l.b, bot = (top === l.a) ? l.b : l.a;
    var x1 = pos[top].x + _CARD_W / 2, y1 = pos[top].y + _CARD_H;
    var x2 = pos[bot].x + _CARD_W / 2, y2 = pos[bot].y;
    var mid = (y1 + y2) / 2;
    var pa = (top === l.a) ? l.a_port : l.b_port;
    var pb = (top === l.a) ? l.b_port : l.a_port;
    var _srcTxt = l.source === "cdp/lldp" ? "  · CDP/LLDP 확정"
      : l.source === "mac" ? "  · MAC 추론" : "";
    var tip = ((byId[top] || {}).name || "") + (pa ? " [" + pa + "]" : "") + "  ↕  " +
      ((byId[bot] || {}).name || "") + (pb ? " [" + pb + "]" : "") +
      (l.l3 ? "  (L3 대역 인접)" : l.mutual ? "  (양방향)" : "") + _srcTxt;
    // L3 인접 링크(대역 기반)는 파란 점선, 관측 링크는 실선
    var lstroke = l.l3 ? "#38bdf8" : (l.mutual ? "#94a3b8" : "#475569");
    var lwidth = l.l3 ? "2" : (l.mutual ? "2.5" : "1.5");
    var ldash = l.l3 ? " stroke-dasharray='7 4'" : (l.mutual ? "" : " stroke-dasharray='6 4'");
    svg.push("<path class='topo-edge' data-ea='" + l.a + "' data-eb='" + l.b + "' data-tip=\"" + escHtml(tip) +
      "\" d='M" + x1 + "," + y1 + " C" + x1 + "," + mid + " " + x2 + "," + mid + " " + x2 + "," + y2 +
      "' fill='none' stroke='" + lstroke + "' stroke-width='" + lwidth + "'" + ldash + "/>");
    if (pa) {
      svg.push("<text x='" + ((x1 + x2) / 2) + "' y='" + (mid - 3) + "' fill='#7dd3fc' font-size='9' text-anchor='middle'>" +
        escHtml((pa || "").split("(")[0].slice(0, 12)) + "</text>");
    }
  });
  core.forEach(function (n) { var pp = pos[n.id]; if (pp) _drawNode(svg, n, pp.x, pp.y, {}); });
  svg.push("</svg>");

  var l2hint = _topoExpandL2 ? "<span style='color:#5eead4'>▭ L2 개별 노드</span>"
    : "<span style='color:#5eead4'>🌐 L2=대역 뱃지(클릭→목록)</span>";
  host.innerHTML = _legendHTML("<span style='color:#22d3ee'>═ 이중화</span><span style='color:#38bdf8'>┄ L3 대역 인접</span>" + l2hint) +
    "<div class='topo-stage'>" + svg.join("") + "</div>" +
    _bandDetailHTML() +
    "<div id='topo-tip' style='position:fixed;display:none;background:#0b1220;color:#e2e8f0;border:1px solid #334155;" +
    "border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;z-index:500;max-width:460px;white-space:pre-line'></div>";
  _bindTopoModeButtons();
  _topoBindTips(host);
  _topoBindNodeEvents(host);
  _bindBandDetailEvents(host);
  _topoBindZoomPan(host, width, height);
}

// 대역 드릴다운 패널(HTML) — 열린 대역의 소속 L2 목록
function _bandDetailHTML() {
  var b = _topoOpenBand && _topoBandsById[_topoOpenBand];
  if (!b) return "";
  var rows = b.l2s.slice().sort(function (a, c) { return (a.name || "").localeCompare(c.name || ""); })
    .map(function (n) {
      var dot = _topoStatusDot(n);
      return "<tr class='band-l2-row' data-swid='" + n.id + "' style='cursor:pointer'>" +
        "<td><span style='display:inline-block;width:8px;height:8px;border-radius:50%;background:" + dot + ";margin-right:6px'></span>" +
        escHtml(n.name || "") + "</td>" +
        "<td style='color:#94a3b8'>" + escHtml(n.ip || "") + "</td>" +
        "<td style='color:#7dd3fc'>" + escHtml((n.subnets || []).join(", ")) + "</td></tr>";
    }).join("");
  return "<div class='band-detail'>" +
    "<div class='band-detail__head'>🌐 " + escHtml(b.cidr || "") + " — 소속 L2 " + b.l2s.length + "대" +
    "<button class='band-detail__close' data-band-close='1'>✕</button></div>" +
    "<table class='band-detail__tbl'><thead><tr><th>스위치</th><th>관리 IP</th><th>연결 대역</th></tr></thead>" +
    "<tbody>" + rows + "</tbody></table></div>";
}
function _bindBandDetailEvents(host) {
  var cl = host.querySelector("[data-band-close]");
  if (cl) cl.addEventListener("click", function () { _topoOpenBand = null; renderTopology(); });
  host.querySelectorAll(".band-l2-row").forEach(function (tr) {
    tr.addEventListener("click", function () {
      var id = tr.getAttribute("data-swid");
      var sw = (_switches || []).find(function (s) { return String(s.id) === String(id); });
      if (sw) openDetailPanel(sw);
    });
  });
}

// ── 존·대역 뷰(아이콘형): ISP GW→Internet SW→Internet FW→OA Backbone 중심축
//    + Zone별 방화벽 분기 + L3/L4 밑 "대역 정보만"(L2 아이콘 없음) ──
function _zoneIcon(kind) {
  var C = { isp: "#38bdf8", sw: "#38bdf8", fw: "#ef4444", bb: "#a855f7", l3: "#8b5cf6", l4: "#f59e0b" }[kind] || "#64748b";
  var inner;
  if (kind === "isp")
    inner = "<path d='M8,26 a9,9 0 0,1 1.5,-17 a12,10 0 0,1 22,-1 a10,9 0 0,1 9,18 z' fill='" + C +
      "' fill-opacity='0.16' stroke='" + C + "' stroke-width='1.8'/>";
  else if (kind === "fw") inner = _deviceSymbol("방화벽", 0, 0, C);
  else if (kind === "bb") inner = _deviceSymbol("백본", 0, 0, C);
  else if (kind === "l3") inner = _deviceSymbol("L3", 0, 0, C);
  else if (kind === "l4") inner = _deviceSymbol("L4", 0, 0, C);
  else inner = _deviceSymbol("L2", 0, 0, C);
  return "<svg class='znode__ic' width='40' height='40' viewBox='0 0 34 34'>" + inner + "</svg>";
}
function _zoneIconKind(n) {
  var r = _coreRank(n), dt = n.device_type || "", nm = (n.name || "").toUpperCase();
  if (n.kind === "fw" || dt === "Firewall" || r === 0) return "fw";
  if (r === 1) return "bb";
  if (dt === "L4 Switch" || /\bL4\b|SLB|ADC/.test(nm)) return "l4";
  if (r === 2) return "l3";
  return "sw";
}
// 호스트명에서 Zone 구분에 쓸 토큰 추출(역할/이중화/숫자 토큰 제외)
// 예: SKBA_F1_OASVR_FW_M → [SKBA, F1, OASVR] · SKBA_F2_FA_L3_1 → [SKBA, F2, FA]
function _hostTokens(name) {
  return (name || "").toUpperCase().split(/[^A-Z0-9]+/).filter(function (t) {
    return t && !/^(FW|BB|L2|L3|L4|SW|SLB|ADC|GW|CORE|VISS|M|B|A|\d{1,3})$/.test(t);
  });
}
// 이중화 쌍 키: 이름 끝의 이중화 표식(M/B, 1/2, PRI/SEC 등) 제거 → 쌍은 같은 키
// 예: SKBA_OASVR_L3_1 · SKBA_OASVR_L3_2 → SKBA_OASVR_L3 (동일 쌍)
function _pairKey(name) {
  var parts = (name || "").toUpperCase().split(/[_\-#/]/).filter(Boolean);
  if (parts.length > 1) {
    var last = parts[parts.length - 1];
    if (/^(M|B|A|\d{1,2}|PRI|SEC|STBY|ACT|STANDBY)$/.test(last)) {
      parts.pop();                                   // 구분자로 분리된 이중화 표식(_M/_1 등)
    } else {
      // 'BB1','SW2','FW1'처럼 역할글자+뒤 1~2자리 숫자면 숫자만 제거(단, L2/L3/L4 역할은 유지)
      var m = last.match(/^([A-Z]{2,})(\d{1,2})$/);
      if (m && !/^L[234]$/.test(last)) parts[parts.length - 1] = m[1];
    }
  }
  return parts.join("_");
}
function _renderZoneMap(host) {
  var nodes = _topoData.nodes || [], links = _topoData.links || [];
  if (!nodes.length) {
    host.innerHTML = _zoneLegend() + "<p style='color:#94a3b8;padding:20px'>표시할 장비가 없습니다.</p>";
    _bindTopoModeButtons();
    return;
  }
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  var adj = {};
  links.forEach(function (l) { (adj[l.a] = adj[l.a] || []).push(l.b); (adj[l.b] = adj[l.b] || []).push(l.a); });
  function rk(n) { return _coreRank(n); }        // 0 FW,1 Core,2 L3/L4,3 L2
  function nbrRank(id, r) {
    return (adj[id] || []).map(function (x) { return byId[x]; })
      .filter(function (x) { return x && rk(x) === r; });
  }
  var firewalls = nodes.filter(function (n) { return rk(n) === 0; });
  var cores = nodes.filter(function (n) { return rk(n) === 1; });
  function reName(re, arr) { return (arr || nodes).filter(function (n) { return re.test(n.name || ""); }); }
  // 중심축 특수 장비(호스트명 패턴)
  var isp = reName(/ISP|GATEWAY|\bGW\b|\bWAN\b/i)[0] || null;
  // 인터넷 스위치: 이름 패턴(넓게). rk 제한 없음(구분 L2로 지정돼도 중심축에 표시)
  var internetSw = nodes.filter(function (n) {
    return n.kind !== "fw" && /INTERNET|\bINET\b|\bINT[_-]?SW\b|EXT[_-]?SW/i.test(n.name || "");
  })[0] || null;
  // OA Backbone = 백본 계층 전체(구분=BackBone 또는 이름 BB/CORE/BACKBONE).
  // VISS처럼 이름에 BB가 없는 백본은 '구분'을 BackBone으로 지정해야 여기 포함됨.
  var backbones = cores;
  var bbIds = {}; backbones.forEach(function (n) { bbIds[n.id] = true; });
  // Internet FW(경계): 이름 패턴 or 백본에 붙고 L3/L4 없는 방화벽
  var internetFw = reName(/INTERNET|\bINT[_-]?FW\b|경계|EXT|BOUNDARY/i, firewalls)[0] ||
    firewalls.filter(function (f) {
      return nbrRank(f.id, 2).length === 0 && (adj[f.id] || []).some(function (x) { return bbIds[x]; });
    })[0] || null;
  // 인터넷 스위치 폴백: 이름으로 못 찾으면, 인터넷 방화벽에 링크된 비-방화벽·비-백본 스위치
  if (!internetSw && internetFw) {
    internetSw = (adj[internetFw.id] || []).map(function (x) { return byId[x]; })
      .filter(function (n) { return n && n.kind !== "fw" && !bbIds[n.id]; })[0] || null;
  }
  // ── HA(VIP 공유) 그룹: 같은 host(ip)의 방화벽들 = 이중화 쌍.
  //    Backup은 VIP로 수집돼 데이터가 Active와 동일 → 링크로 판단하지 않고 쌍으로만 표현.
  var vipGroup = {};   // ip → [fw...]
  firewalls.forEach(function (f) { if (f.ip) (vipGroup[f.ip] = vipGroup[f.ip] || []).push(f); });
  var haPartner = {};  // fwId → 같은 VIP의 파트너들
  Object.keys(vipGroup).forEach(function (ip) {
    if (vipGroup[ip].length >= 2) vipGroup[ip].forEach(function (f) { haPartner[f.id] = vipGroup[ip]; });
  });
  // 인터넷 방화벽도 HA면 쌍 전체를 중심축에
  var internetFwGroup = internetFw ? (haPartner[internetFw.id] || [internetFw]) : [];
  var internetFwIds = {};
  internetFwGroup.forEach(function (f) { internetFwIds[f.id] = 1; });

  // ── Zone 분류: 방화벽 hostname 토큰 기준(1순위) + 링크(보조) ──
  var zoneFws = firewalls.filter(function (f) { return !internetFwIds[f.id]; });
  if (!zoneFws.length) zoneFws = firewalls.slice();
  // 방화벽 공통 토큰(회사/사이트 접두어, 예: SKBA)은 구분에서 제외
  var fwTok = {};
  zoneFws.forEach(function (f) { fwTok[f.id] = _hostTokens(f.name); });
  var common = null;
  zoneFws.forEach(function (f) {
    var s = fwTok[f.id];
    common = (common === null) ? s.slice() : common.filter(function (t) { return s.indexOf(t) >= 0; });
  });
  common = common || [];
  function distinctive(tokens) { return tokens.filter(function (t) { return common.indexOf(t) < 0; }); }
  function zoneKeyOf(f) {
    // HA(VIP 공유) 파트너는 항상 같은 Zone — 멤버 공통 토큰(교집합)을 키로
    // (예: OASVR_FGT_PRIMARY ∩ OASVR_FGT_SECONDARY → OASVR_FGT)
    var grp = haPartner[f.id];
    if (grp) {
      var inter = null;
      grp.forEach(function (m) {
        var d0 = distinctive(fwTok[m.id] || _hostTokens(m.name));
        inter = (inter === null) ? d0.slice() : inter.filter(function (t) { return d0.indexOf(t) >= 0; });
      });
      if (inter && inter.length) return inter.join("_");
      for (var i = 0; i < grp.length; i++) {
        var d1 = distinctive(fwTok[grp[i].id] || _hostTokens(grp[i].name));
        if (d1.length) return d1.join("_");
      }
    }
    var d = distinctive(fwTok[f.id]);
    return d.length ? d.join("_") : (f.name || String(f.id));
  }
  // zoneKey로 방화벽 병합(이중화 쌍 M/B·VIP 공유 → 한 Zone)
  var zoneMap = {}, zoneOrder = [];
  zoneFws.forEach(function (f) {
    var k = zoneKeyOf(f);
    if (!zoneMap[k]) { zoneMap[k] = { key: k, fws: [], bbs: [], dists: [], zL2: [] }; zoneOrder.push(k); }
    zoneMap[k].fws.push(f);
  });
  // 링크 기반 소유자(보조): 각 방화벽 아래 BFS(rank>=2)
  var linkOwner = {};
  zoneFws.forEach(function (f) {
    var k = zoneKeyOf(f), seen = {}; seen[f.id] = 1;
    var q = [f.id];
    while (q.length) {
      var id = q.shift();
      (adj[id] || []).forEach(function (nb) {
        var nn = byId[nb];
        if (!nn || seen[nb] || rk(nn) < 2) return;
        seen[nb] = 1; q.push(nb);
        if (!linkOwner[nb]) linkOwner[nb] = k;
      });
    }
  });
  // ── CDP/LLDP 확정 링크 우선(있으면 실제 물리 구성으로 배정) ──
  var internetFwId0 = internetFw ? internetFw.id : null;
  function linkedToInternetFw(id) {
    return (adj[id] || []).some(function (x) { return internetFwIds[x]; });
  }
  // 중심 OA BB 후보: 인터넷 방화벽에 링크됨 or 구별 토큰 없는 백본(VISS 등)
  var centralBBids = {};
  backbones.forEach(function (bb) {
    var linkedInt = linkedToInternetFw(bb.id);
    if (linkedInt || !distinctive(_hostTokens(bb.name)).length) centralBBids[bb.id] = 1;
  });
  // 직결 확정 인접: CDP/LLDP 확정 + '양방향 MAC 확인(mutual)' 링크.
  // MAC/ARP/CONFIG 교차대조로 양쪽이 서로를 직결 포트에서 관측한 링크는 실제 물리 직결로 신뢰.
  var adjC = {};
  links.forEach(function (l) {
    var strong = l.source === "cdp/lldp" || (l.source === "mac" && l.mutual);
    if (!strong) return;
    (adjC[l.a] = adjC[l.a] || []).push(l.b);
    (adjC[l.b] = adjC[l.b] || []).push(l.a);
  });
  // 경계(중심 OA BB·인터넷 FW·다른 Zone FW)에서 멈추는 확정링크 BFS → 소유 Zone
  var blocked = {};
  internetFwGroup.forEach(function (f) { blocked[f.id] = 1; });
  Object.keys(centralBBids).forEach(function (id) { blocked[id] = 1; });
  zoneFws.forEach(function (f) { blocked[f.id] = 1; });
  var confirmedOwner = {};
  zoneFws.forEach(function (f) {
    var k = zoneKeyOf(f), seen = {}; seen[f.id] = 1; var q = [f.id];
    while (q.length) {
      var id = q.shift();
      (adjC[id] || []).forEach(function (nb) {
        var nn = byId[nb];
        if (!nn || seen[nb] || rk(nn) < 1) return;   // 백본(1)~L2(3) 통과
        seen[nb] = 1;
        if (blocked[nb]) return;                      // 경계 노드: 소유·전파 금지
        if (!confirmedOwner[nb]) confirmedOwner[nb] = k;
        q.push(nb);
      });
    }
  });
  // 장비 → Zone: 확정링크(1순위) → 호스트명 토큰 → 보조 링크
  function zoneByName(n) {
    var t = distinctive(_hostTokens(n.name));
    if (!t.length) return null;
    var best = null, score = 0;
    zoneOrder.forEach(function (k) {
      var sc = k.split("_").filter(function (x) { return t.indexOf(x) >= 0; }).length;
      if (sc > score) { score = sc; best = k; }
    });
    return score > 0 ? best : null;
  }
  // config의 'ip address'에서 도출된 직결 대역(authoritative)만 사용
  function cfgSubs(node) {
    var set = {};
    ((node && node.subnets) || []).forEach(function (c) { set[c] = 1; });
    return set;
  }

  var assigned = {};
  [isp, internetSw].forEach(function (n) { if (n) assigned[n.id] = 1; });
  internetFwGroup.forEach(function (f) { assigned[f.id] = 1; });
  zoneFws.forEach(function (f) { assigned[f.id] = 1; });
  // 백본(cores) → 중심 OA BB vs Zone 백본 구분:
  //  · 인터넷 방화벽에 링크된 백본 = 중심 OA BB(중심축)
  //  · 호스트명 토큰이 특정 Zone과 맞는 백본 = 그 Zone 백본(Zone 내부에 표시)
  //  · 그 외(VISS처럼 구별 토큰 없음) = 중심 OA BB
  var centralBBs = [];
  backbones.forEach(function (bb) {
    assigned[bb.id] = 1;
    if (centralBBids[bb.id]) { centralBBs.push(bb); return; }
    var k = confirmedOwner[bb.id] || zoneByName(bb) || linkOwner[bb.id];
    if (k && zoneMap[k]) zoneMap[k].bbs.push(bb);
    else centralBBs.push(bb);
  });
  centralBBs.sort(function (a, b) {
    var p = _pairKey(a.name).localeCompare(_pairKey(b.name));
    return p !== 0 ? p : (a.name || "").localeCompare(b.name || "");
  });
  // rank2(L3/L4) → Zone 배정
  nodes.forEach(function (n) {
    if (rk(n) !== 2 || assigned[n.id]) return;
    var k = confirmedOwner[n.id] || zoneByName(n) || linkOwner[n.id];
    if (k && zoneMap[k]) { assigned[n.id] = 1; zoneMap[k].dists.push(n); }
  });
  // rank3(L2)는 아이콘 없이 대역만 → Zone 배정
  nodes.forEach(function (n) {
    if (rk(n) !== 3 || assigned[n.id]) return;
    var k = confirmedOwner[n.id] || zoneByName(n) || linkOwner[n.id];
    if (k && zoneMap[k]) { assigned[n.id] = 1; zoneMap[k].zL2.push(n); }
  });
  // 이중화 쌍이 인접하도록 pairKey→이름 순 정렬
  function _byPairName(a, b) {
    var pk = _pairKey(a.name).localeCompare(_pairKey(b.name));
    return pk !== 0 ? pk : (a.name || "").localeCompare(b.name || "");
  }
  // Zone 완성: dist 대역 = 그 L3의 config SVI 대역만(중복 방지). 나머지 L2 /24는 Zone 기타로.
  var zones = zoneOrder.map(function (k) {
    var z = zoneMap[k];
    z.fws.sort(_byPairName);
    z.bbs.sort(_byPairName);
    z.dists.sort(_byPairName);
    var usedCidr = {};
    var dists = z.dists.map(function (d) {
      var subs = Object.keys(cfgSubs(d)).sort();   // 그 L3 자신의 config 대역만
      subs.forEach(function (c) { usedCidr[c] = 1; });
      return { node: d, subs: subs };
    });
    // dist를 이중화 pairKey로 묶기(나란히 배치 + 대역 1회 표기)
    var gmap = {}, groups = [];
    dists.forEach(function (d) {
      var pk = _pairKey(d.node.name);
      if (!gmap[pk]) { gmap[pk] = { key: pk, items: [], _set: {} }; groups.push(gmap[pk]); }
      gmap[pk].items.push(d);
      d.subs.forEach(function (c) { gmap[pk]._set[c] = 1; });
    });
    groups.forEach(function (g) { g.subs = Object.keys(g._set).sort(); });
    // 어느 L3 config에도 없는 Zone L2 /24 → 기타(직결 L2), 1회만
    var zExtra = {};
    z.zL2.forEach(function (l2) { var c = _ipBand(l2.ip); if (c && !usedCidr[c]) zExtra[c] = 1; });
    return { fws: z.fws, bbs: z.bbs, label: k, dists: dists, distGroups: groups, zSubs: Object.keys(zExtra).sort() };
  });
  zones.sort(function (a, b) { return a.label.localeCompare(b.label); });
  // 미분류(어느 Zone에도 못 들어간 L3/L4)
  // 미분류 = 어느 곳에도 배정 못 된 '모든' 등록 장비(L2/스위치 포함) → 아이콘으로 표시(누락 방지).
  // 인터넷 스위치·백본이 이름/링크로 못 잡혀도, 서버실 L2가 Zone에 안 붙어도 여기 나타남.
  var orphanDists = nodes.filter(function (n) {
    return !assigned[n.id] && (n.device_type || n.kind === "fw" || rk(n) <= 3);
  });

  // ── SVG 렌더(아이콘 + 연결선 + 포트) ──
  function zoneSym(kind, x, y) {
    var C = { isp: "#38bdf8", sw: "#38bdf8", fw: "#ef4444", bb: "#a855f7", l3: "#8b5cf6", l4: "#f59e0b" }[kind] || "#64748b";
    if (kind === "isp")
      return "<g transform='translate(" + x + "," + y + ")'><path d='M6,26 a10,10 0 0,1 1.5,-19 a13,11 0 0,1 25,-1 a11,10 0 0,1 10,20 z' fill='" +
        C + "' fill-opacity='0.16' stroke='" + C + "' stroke-width='1.8'/></g>";
    var label = { fw: "방화벽", bb: "백본", l3: "L3", l4: "L4", sw: "L2" }[kind] || "L2";
    return _deviceSymbol(label, x, y, C);
  }
  var IC = 40, PAIRGAP = 34, DW = 186, DGAP = 16, ZGAP = 34, PADX = 30;
  zones.forEach(function (z) {
    var slots = Math.max(1, z.dists.length) + (z.zSubs.length ? 1 : 0);
    z._w = Math.max(206, slots * DW + (slots - 1) * DGAP + 24);
    z._maxSub = z.zSubs.length ? z.zSubs.length + 1 : 0;
    (z.distGroups || []).forEach(function (g) { z._maxSub = Math.max(z._maxSub, g.subs.length); });
  });
  var orphW = orphanDists.length ? Math.max(206, orphanDists.length * DW + 24) : 0;
  var totalW = Math.max(900, PADX * 2 + zones.reduce(function (s, z) { return s + z._w; }, 0) +
    ZGAP * Math.max(0, zones.length - 1) + (orphW ? orphW + ZGAP : 0));
  var cx = totalW / 2, pos = {};
  function placeRow(list, centerX, yy) {
    var n = list.length; if (!n) return;
    var tw = n * IC + (n - 1) * PAIRGAP, sx = centerX - tw / 2 + IC / 2;
    list.forEach(function (nd, i) { pos[nd.id] = { x: sx + i * (IC + PAIRGAP), y: yy }; });
  }
  // 중심축(세로)
  var yy = 46;
  if (isp) { placeRow([isp], cx, yy); yy += 78; }
  if (internetSw) { placeRow([internetSw], cx, yy); yy += 78; }
  if (internetFwGroup.length) { placeRow(internetFwGroup, cx, yy); yy += 78; }
  if (centralBBs.length) { placeRow(centralBBs, cx, yy); yy += 78; }
  var FW_Y = yy + 46, BB_Y = FW_Y + 74, L3_Y = BB_Y + 74;
  var SUB_DY = 24;   // 대역 박스는 각 L3 노드 바로 아래(노드 위치 따라감)
  var zx = PADX, boxes = [];
  zones.forEach(function (z) {
    var zcx = zx + z._w / 2;
    z._cx = zcx;
    placeRow(z.fws, zcx, FW_Y);
    if (z.bbs.length) placeRow(z.bbs, zcx, BB_Y);
    var slots = Math.max(1, z.dists.length) + (z.zSubs.length ? 1 : 0);
    var tw = slots * DW + (slots - 1) * DGAP, sx = zcx - tw / 2 + DW / 2;
    z.dists.forEach(function (d, i) { pos[d.node.id] = { x: sx + i * (DW + DGAP), y: L3_Y }; });
    z._extraX = z.zSubs.length ? (sx + z.dists.length * (DW + DGAP)) : null;
    var mem = z.fws.map(function (f) { return f.id; })
      .concat(z.bbs.map(function (b) { return b.id; }))
      .concat(z.dists.map(function (d) { return d.node.id; }));
    boxes.push({ members: mem, dists: z.dists, extraX: z._extraX, extraN: z.zSubs.length,
                 maxSub: z._maxSub, label: z.label });
    zx += z._w + ZGAP;
  });
  if (orphanDists.length) {
    var tw2 = orphanDists.length * DW, sx2 = zx + orphW / 2 - tw2 / 2 + DW / 2;
    orphanDists.forEach(function (d, i) { pos[d.id] = { x: sx2 + i * DW, y: L3_Y }; });
    boxes.push({ members: orphanDists.map(function (d) { return d.id; }), orphanNodes: orphanDists,
                 maxSub: 4, label: "미분류 (연결·Zone 미확인 — 재수집 시 편입)", orphan: true });
  }

  // ── 저장된 드래그 위치 적용(Contrail식 persist) ──
  Object.keys(_topoLayout).forEach(function (id) { if (pos[id]) pos[id] = { x: _topoLayout[id].x, y: _topoLayout[id].y }; });
  _topoRenderedPos = pos;

  // 존 박스 경계를 실제(드래그 반영) 노드 위치로 재계산 → 박스가 노드를 감쌈
  boxes.forEach(function (b) {
    var xs = [], ys = [];
    b.members.forEach(function (id) { if (pos[id]) { xs.push(pos[id].x); ys.push(pos[id].y); } });
    if (!xs.length) { b.skip = true; return; }
    var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
    var minY = Math.min.apply(null, ys), maxY = Math.max.apply(null, ys);
    // 대역 박스(각 L3 아래)까지 포함해 하단 확장
    var subBottom = maxY;
    (b.dists || []).forEach(function (d) {
      var p = pos[d.node.id]; if (p) subBottom = Math.max(subBottom, p.y + SUB_DY + Math.max(1, d.subs.length) * 15 + 8);
    });
    (b.orphanNodes || []).forEach(function (d) {
      var p = pos[d.id]; if (p) subBottom = Math.max(subBottom, p.y + SUB_DY + 4 * 15 + 8);
    });
    var padX = DW / 2 + 8;
    b.x = minX - padX; b.w = (maxX - minX) + padX * 2;
    b.y = minY - 34; b.h = (subBottom + 12) - b.y;
  });

  // 전체 크기(드래그로 벗어난 노드까지 포함)
  var allX = [], allY = [];
  Object.keys(pos).forEach(function (id) { allX.push(pos[id].x); allY.push(pos[id].y); });
  var maxSub = zones.reduce(function (m, z) { return Math.max(m, z._maxSub); }, 0);
  var totalW2 = Math.max(totalW, (allX.length ? Math.max.apply(null, allX) : 0) + 220);
  totalW = totalW2;
  var totalH = Math.max(680, (allY.length ? Math.max.apply(null, allY) : 0) + maxSub * 15 + 90);

  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='100%'" +
    " preserveAspectRatio='xMidYMid meet' viewBox='0 0 " + totalW + " " + totalH + "' style='cursor:grab;display:block'>"];
  // 존 박스
  boxes.forEach(function (b) {
    if (b.skip) return;
    var c = b.orphan ? "#64748b" : "#8b5cf6";
    svg.push("<rect x='" + b.x + "' y='" + b.y + "' width='" + b.w + "' height='" + b.h +
      "' rx='12' fill='" + c + "' fill-opacity='0.05' stroke='" + c + "' stroke-opacity='0.4' stroke-width='1.4' stroke-dasharray='3 4'/>");
    svg.push("<text x='" + (b.x + b.w / 2) + "' y='" + (b.y - 6) + "' fill='" + (b.orphan ? "#94a3b8" : "#c4b5fd") +
      "' font-size='12' font-weight='700' text-anchor='middle'>🗂 " + escHtml(b.label) + "</text>");
  });
  // 연결선 + 포트(그려진 노드끼리만): 확정=실선, 추론=점선
  // HA(VIP 공유) 방화벽: Backup의 수집 데이터는 Active와 동일(같은 VIP·MAC) →
  // 같은 상대로의 링크는 VIP 그룹당 1회만 그림(중복 곡선 방지). 쌍 관계는 이중화 선으로 표현.
  var drawn = {};
  function _vipKey(id) {
    var n = byId[id];
    return (n && n.kind === "fw" && n.ip && haPartner[id]) ? ("vip:" + n.ip) : String(id);
  }
  (_topoData.links || []).forEach(function (l) {
    var A = pos[l.a], B = pos[l.b];
    if (!A || !B) return;
    var ka = _vipKey(l.a), kb = _vipKey(l.b);
    var kk = (ka < kb) ? ka + "~" + kb : kb + "~" + ka;
    if (drawn[kk]) return; drawn[kk] = 1;
    var confirmed = l.source === "cdp/lldp";
    var macDirect = l.source === "mac" && l.mutual;   // 양방향 MAC 확인 = 실제 직결로 신뢰
    var sameRow = Math.abs(A.y - B.y) < 4;
    var col = confirmed ? (sameRow ? "#22d3ee" : "#38bdf8") : (macDirect ? "#5eead4" : "#64748b");
    var dash = (confirmed || macDirect) ? "" : " stroke-dasharray='6 4'";  // 직결=실선, 단방향 추론=점선
    var d;
    if (sameRow) {
      d = "M" + (Math.min(A.x, B.x) + IC / 2) + "," + A.y + " L" + (Math.max(A.x, B.x) - IC / 2) + "," + B.y;
    } else {
      var t = A.y < B.y ? A : B, bo = A.y < B.y ? B : A, my = (t.y + bo.y) / 2;
      d = "M" + t.x + "," + (t.y + IC / 2) + " C" + t.x + "," + my + " " + bo.x + "," + my + " " + bo.x + "," + (bo.y - IC / 2 - 12);
    }
    var pa = l.a_port, pb = l.b_port;
    var srcTxt = confirmed ? "CDP/LLDP 확정 링크" : (macDirect ? "MAC 양방향 확인(직결)" : "MAC 추론 링크");
    var tip = ((byId[l.a] || {}).name || "") + (pa ? " [" + pa + "]" : "") + "  ↔  " +
      ((byId[l.b] || {}).name || "") + (pb ? " [" + pb + "]" : "") + "\n" + srcTxt;
    svg.push("<path class='topo-edge' data-ea='" + l.a + "' data-eb='" + l.b + "' data-tip=\"" + escHtml(tip) +
      "\" d='" + d + "' fill='none' stroke='" + col + "' stroke-width='" + (confirmed ? 2 : (macDirect ? 1.8 : 1.6)) + "'" + dash + "/>");
    if ((pa || pb) && !sameRow) {
      var ptxt = ((confirmed || macDirect) ? "" : "~") + ((pa || "?").split("(")[0].slice(0, 9)) + "↔" + ((pb || "?").split("(")[0].slice(0, 9));
      svg.push("<text x='" + ((A.x + B.x) / 2) + "' y='" + ((A.y + B.y) / 2 - 2) + "' fill='" +
        (confirmed ? "#7dd3fc" : (macDirect ? "#5eead4" : "#94a3b8")) + "' font-size='8.5' text-anchor='middle'>" + escHtml(ptxt) + "</text>");
    }
  });
  // 이중화 연결선(같은 pairKey 인접 장비): 링크 데이터 없어도 쌍을 청록 선으로 표시
  function _redunPairs(list) {
    var g = {}, order = [], pairs = [], paired = {};
    list.forEach(function (n) { var k = _pairKey(n.name); if (!g[k]) { g[k] = []; order.push(k); } g[k].push(n); });
    // 정확히 2대인 그룹만 이중화 쌍으로 간주(3대 이상은 별개 장비들로 취급)
    order.forEach(function (k) {
      if (g[k].length === 2) { pairs.push([g[k][0], g[k][1]]); paired[g[k][0].id] = paired[g[k][1].id] = 1; }
    });
    // HA(VIP 공유): 같은 ip 방화벽 2대도 이중화 쌍(이름 패턴 무관 — VIP 공유가 확실한 근거)
    var byIp = {};
    list.forEach(function (n) { if (n.kind === "fw" && n.ip) (byIp[n.ip] = byIp[n.ip] || []).push(n); });
    Object.keys(byIp).forEach(function (ip) {
      var grp = byIp[ip];
      if (grp.length === 2 && !paired[grp[0].id] && !paired[grp[1].id]) pairs.push([grp[0], grp[1]]);
    });
    return pairs;
  }
  var redun = _redunPairs(centralBBs).concat(_redunPairs(internetFwGroup));
  zones.forEach(function (z) {
    redun = redun.concat(_redunPairs(z.fws), _redunPairs(z.bbs),
      _redunPairs(z.dists.map(function (d) { return d.node; })));
  });
  redun.forEach(function (pr) {
    var A = pos[pr[0].id], B = pos[pr[1].id];
    if (!A || !B || Math.abs(A.y - B.y) > 4) return;
    var kk = (String(pr[0].id) < String(pr[1].id)) ? pr[0].id + "~" + pr[1].id : pr[1].id + "~" + pr[0].id;
    if (drawn[kk]) return; drawn[kk] = 1;
    // 수집된 HA 구성(hbdev)이 있으면 이중화 선에 HA 포트 표기 (예: 이중화 ha1·ha2)
    var haPorts = [];
    [pr[0], pr[1]].forEach(function (n) {
      if (n.ha && n.ha.hbdev) n.ha.hbdev.forEach(function (p) {
        if (haPorts.indexOf(p) < 0) haPorts.push(p);
      });
    });
    var label = haPorts.length ? ("이중화 " + haPorts.slice(0, 3).join("·")) : "이중화";
    var tip = (pr[0].name || "") + " ═ " + (pr[1].name || "") +
      (haPorts.length ? "\nHA heartbeat: " + haPorts.join(", ") : "") +
      (pr[0].ha && pr[0].ha.mode ? "\n모드: " + pr[0].ha.mode : "");
    svg.push("<path class='topo-edge' data-tip=\"" + escHtml(tip) + "\" d='M" +
      (Math.min(A.x, B.x) + IC / 2) + "," + A.y + " L" + (Math.max(A.x, B.x) - IC / 2) +
      "," + B.y + "' stroke='#22d3ee' stroke-width='2.5' fill='none'/>");
    svg.push("<text x='" + ((A.x + B.x) / 2) + "' y='" + (A.y - IC / 2 - 1) +
      "' fill='#22d3ee' font-size='7.5' text-anchor='middle'>" + escHtml(label) + "</text>");
  });
  // 노드(아이콘+라벨)
  function drawNode(nd, kindOverride) {
    var p = pos[nd.id]; if (!p) return;
    var kind = kindOverride || _zoneIconKind(nd);
    svg.push("<g class='topo-node' data-swid='" + nd.id + "' data-kind='" + (nd.kind || "sw") +
      "' data-tip=\"" + escHtml((nd.name || "") + " · " + (nd.ip || "")) + "\" style='cursor:pointer'>");
    svg.push(zoneSym(kind, p.x - 17, p.y - 17));
    svg.push("<text x='" + p.x + "' y='" + (p.y + 30) + "' fill='#e2e8f0' font-size='9.5' font-weight='700' text-anchor='middle'>" +
      escHtml((nd.name || "").slice(0, 20)) + "</text>");
    svg.push("</g>");
  }
  if (isp) drawNode(isp, "isp");
  if (internetSw) drawNode(internetSw, "sw");
  internetFwGroup.forEach(function (f) { drawNode(f, "fw"); });
  centralBBs.forEach(function (n) { drawNode(n, "bb"); });
  zones.forEach(function (z) {
    z.fws.forEach(function (f) { drawNode(f, "fw"); });
    z.bbs.forEach(function (b) { drawNode(b, "bb"); });
    z.dists.forEach(function (d) { drawNode(d.node); });
  });
  orphanDists.forEach(function (d) { drawNode(d); });
  // L3/L4 밑 대역 텍스트(L2는 아이콘 없이 여기 표기)
  function subText(centerX, topY, subs, title, width) {
    var w = width || (DW - 20), bx = centerX - w / 2, h = subs.length * 15 + (title ? 16 : 4) + 6;
    svg.push("<rect x='" + bx + "' y='" + topY + "' width='" + w + "' height='" + h +
      "' rx='7' fill='#0e2a2a' stroke='#14b8a6' stroke-width='1.1'/>");
    var ty = topY + 13;
    if (title) { svg.push("<text x='" + (bx + 7) + "' y='" + ty + "' fill='#5eead4' font-size='8.5' font-weight='700'>" + escHtml(title) + "</text>"); ty += 15; }
    subs.forEach(function (c) { svg.push("<text x='" + (bx + 7) + "' y='" + ty + "' fill='#a7f3d0' font-size='9.5'>🌐 " + escHtml(c) + "</text>"); ty += 15; });
    if (!subs.length) svg.push("<text x='" + (bx + 7) + "' y='" + ty + "' fill='#64748b' font-size='9' font-style='italic'>대역 정보 없음</text>");
  }
  zones.forEach(function (z) {
    // 정확히 2대인 이중화 쌍만 대역 박스 1개로 병합(동일 SVI 공유), 그 외는 장비별 박스
    (z.distGroups || []).forEach(function (g) {
      var ps = g.items.map(function (d) { return pos[d.node.id]; }).filter(Boolean);
      if (!ps.length) return;
      var topY = Math.min.apply(null, ps.map(function (p) { return p.y; })) + SUB_DY;
      if (g.items.length === 2) {
        var cxg = (Math.min.apply(null, ps.map(function (p) { return p.x; })) +
          Math.max.apply(null, ps.map(function (p) { return p.x; }))) / 2;
        subText(cxg, topY, g.subs, null, g.items.length * DW - 20);
      } else {
        g.items.forEach(function (d) { var p = pos[d.node.id]; if (p) subText(p.x, p.y + SUB_DY, d.subs, null); });
      }
    });
    if (z.zSubs.length && z._extraX != null) subText(z._extraX, L3_Y + SUB_DY, z.zSubs, "기타(직결 L2)", DW - 20);
    else if (z.zSubs.length && !z.dists.length) subText(z._cx, L3_Y + SUB_DY, z.zSubs, "기타(직결 L2)", DW - 20);
  });
  orphanDists.forEach(function (d) {
    var p = pos[d.id]; if (!p) return;
    var subs = Object.keys(cfgSubs(d)).sort();
    if (!subs.length) { var c = _ipBand(d.ip); if (c) subs = [c]; }   // config 없으면 관리 IP /24
    subText(p.x, p.y + SUB_DY, subs, null);
  });
  svg.push("</svg>");

  if (!zones.length && !orphanDists.length && !isp && !internetFw && !centralBBs.length) {
    host.innerHTML = _zoneLegend() + "<p style='color:#94a3b8;padding:16px'>Zone 방화벽/L3를 인식하지 못했습니다. 스위치 '구분'을 방화벽/백본/L3/L4로 지정하고 재수집하면 자동 구성됩니다.</p>";
    _bindTopoModeButtons();
    return;
  }
  host.innerHTML = _zoneLegend() + "<div class='topo-stage'>" + svg.join("") + "</div>" +
    "<div id='topo-tip' style='position:fixed;display:none;background:#0b1220;color:#e2e8f0;border:1px solid #334155;" +
    "border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;z-index:500;max-width:460px;white-space:pre-line'></div>";
  _bindTopoModeButtons();
  _topoBindTips(host);
  _topoBindNodeEvents(host);
  _topoBindZoomPan(host, totalW, totalH);
  _topoBindDrag(host);
}
function _zoneLegend() {
  return "<div style='display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:8px 14px;color:#94a3b8;font-size:11px;border-bottom:1px solid #1e293b'>" +
    "<span style='color:#38bdf8'>☁ ISP GW</span><span style='color:#38bdf8'>🔷 Internet SW</span>" +
    "<span style='color:#ef4444'>🛡 방화벽</span><span style='color:#a855f7'>◆ OA Backbone</span>" +
    "<span style='color:#8b5cf6'>⬛ L3</span><span style='color:#f59e0b'>⬡ L4</span><span style='color:#14b8a6'>🌐 대역(L3 하위)</span>" +
    "<span style='color:#38bdf8'>— CDP/LLDP 확정</span><span style='color:#5eead4'>— MAC 직결</span><span style='color:#94a3b8'>┄ MAC 추론</span>" +
    "<span style='margin-left:auto'>선=실제 직결(포트 표시) · L2는 대역 정보로 · 카드 클릭=상세</span></div>";
}
function _bindZoneMapEvents(host) {
  host.querySelectorAll(".znode").forEach(function (el) {
    el.addEventListener("click", function () {
      var id = el.getAttribute("data-swid");
      if (el.getAttribute("data-kind") === "fw") { showFirewallDetail(parseInt(String(id).slice(1), 10)); return; }
      var sw = (_switches || []).find(function (s) { return String(s.id) === String(id); });
      if (sw) openDetailPanel(sw);
    });
  });
}

// ── TPS 구역도: 구역 드롭다운 → 그 구역 액세스 스위치 트리 ──────────
function _renderTpsMap(host) {
  var access = _topoData.nodes.filter(function (n) { return !_isCoreDevice(n); });
  // 구역 목록 채우기
  var zones = {};
  access.forEach(function (n) { zones[_topoZoneOf(n)] = (zones[_topoZoneOf(n)] || 0) + 1; });
  var zkeys = Object.keys(zones).sort();
  var zsel = document.getElementById("topo-zone-select");
  if (zsel) {
    var cur = _topoZone || zkeys[0] || "";
    zsel.innerHTML = zkeys.map(function (z) {
      return "<option" + (z === cur ? " selected" : "") + ">" + escHtml(z) + " (" + zones[z] + ")</option>";
    }).join("");
    _topoZone = cur;
  }
  if (!zkeys.length) {
    host.innerHTML = _legendHTML() + "<p style='color:#94a3b8;padding:20px'>TPS(액세스) 스위치가 없습니다.</p>";
    _bindTopoModeButtons();
    return;
  }
  var zone = _topoZone || zkeys[0];
  var inZone = {};
  access.forEach(function (n) { if (_topoZoneOf(n) === zone) inZone[n.id] = true; });
  // 업링크(코어) 고스트 포함
  var ghost = {};
  _topoData.links.forEach(function (l) {
    if (inZone[l.a] && !inZone[l.b]) ghost[l.b] = true;
    if (inZone[l.b] && !inZone[l.a]) ghost[l.a] = true;
  });
  var nodes = _topoData.nodes.filter(function (n) { return inZone[n.id] || ghost[n.id]; });
  var links = _topoData.links.filter(function (l) {
    return (inZone[l.a] || inZone[l.b]) && (inZone[l.a] || ghost[l.a]) && (inZone[l.b] || ghost[l.b]);
  });
  _layoutLayered(host, nodes, links, function (n) { return ghost[n.id] ? 0 : 1; }, zone, ghost);
}

// 공통 계층 레이아웃 + 렌더 + 상호작용
function _layoutLayered(host, nodes, links, rankFn, title, ghostMap) {
  ghostMap = ghostMap || {};
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  // depth = rank, 같은 rank는 이름순 가로 배치
  var byRank = {};
  nodes.forEach(function (n) {
    var r = rankFn(n);
    (byRank[r] = byRank[r] || []).push(n);
  });
  var ranks = Object.keys(byRank).map(Number).sort(function (a, b) { return a - b; });
  var GAP_X = 34, GAP_Y = 96;
  var maxCols = 0;
  ranks.forEach(function (r) {
    byRank[r].sort(function (a, b) { return (a.name || "").localeCompare(b.name || ""); });
    maxCols = Math.max(maxCols, byRank[r].length);
  });
  var width = Math.max(920, maxCols * (_CARD_W + GAP_X) + 60);
  var height = ranks.length * (_CARD_H + GAP_Y) + 60;
  var pos = {};
  ranks.forEach(function (r, ri) {
    var row = byRank[r];
    var rowW = row.length * (_CARD_W + GAP_X) - GAP_X;
    row.forEach(function (n, ci) {
      pos[n.id] = { x: (width - rowW) / 2 + ci * (_CARD_W + GAP_X), y: 30 + ri * (_CARD_H + GAP_Y) };
    });
  });

  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='100%'" +
             " preserveAspectRatio='xMidYMid meet' viewBox='0 0 " + width + " " + height +
             "' style='cursor:grab;display:block'>"];
  // 링크(포트 라벨 표시)
  links.forEach(function (l) {
    var a = pos[l.a], b = pos[l.b];
    if (!a || !b) return;
    var top = (a.y <= b.y) ? l.a : l.b, bot = (top === l.a) ? l.b : l.a;
    var x1 = pos[top].x + _CARD_W / 2, y1 = pos[top].y + _CARD_H;
    var x2 = pos[bot].x + _CARD_W / 2, y2 = pos[bot].y;
    var mid = (y1 + y2) / 2;
    var pa = (top === l.a) ? l.a_port : l.b_port;
    var pb = (top === l.a) ? l.b_port : l.a_port;
    var tip = ((byId[top] || {}).name || "") + (pa ? " [" + pa + "]" : "") + "  ↕  " +
      ((byId[bot] || {}).name || "") + (pb ? " [" + pb + "]" : "") + (l.mutual ? "  (양방향)" : "");
    svg.push("<path class='topo-edge' data-ea='" + l.a + "' data-eb='" + l.b + "' data-tip=\"" + escHtml(tip) +
      "\" d='M" + x1 + "," + y1 + " C" + x1 + "," + mid + " " + x2 + "," + mid + " " + x2 + "," + y2 +
      "' fill='none' stroke='#64748b' stroke-width='2'" + (l.mutual ? "" : " stroke-dasharray='6 4'") + "/>");
    // 포트 라벨(짧게)
    if (pa || pb) {
      svg.push("<text x='" + ((x1 + x2) / 2) + "' y='" + (mid - 3) + "' fill='#7dd3fc' font-size='9' text-anchor='middle'>" +
        escHtml((pa || "").split("(")[0].slice(0, 10)) + "</text>");
    }
  });
  // 노드
  nodes.forEach(function (n) {
    var pp = pos[n.id];
    if (pp) _drawNode(svg, n, pp.x, pp.y, { ghost: ghostMap[n.id] });
  });
  svg.push("</svg>");

  host.innerHTML = _legendHTML(title ? "<span style='color:#e2e8f0;font-weight:600'>· " + escHtml(title) + "</span>" : "") +
    "<div class='topo-stage'>" + svg.join("") + "</div>" +
    "<div id='topo-tip' style='position:fixed;display:none;background:#0b1220;color:#e2e8f0;border:1px solid #334155;" +
    "border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;z-index:500;max-width:460px;white-space:pre-line'></div>";
  _bindTopoModeButtons();
  _topoBindTips(host);
  _topoBindNodeEvents(host);
  if (false) {
  // (구 인라인 이벤트 — _topoBindNodeEvents로 대체)
  host.querySelectorAll(".topo-node").forEach(function (g) {
    g.addEventListener("click", function () {
      var id = g.getAttribute("data-swid");
      if (g.getAttribute("data-ghost") === "1") { _topoMode = "core"; renderTopology(); return; }
      if (g.getAttribute("data-kind") === "fw") { showFirewallDetail(parseInt(id.slice(1), 10)); return; }
      var sw = (_switches || []).find(function (s) { return String(s.id) === String(id); });
      if (sw) openDetailPanel(sw);
    });
  });
  host.querySelectorAll(".topo-node").forEach(function (g) {
    var id = g.getAttribute("data-swid");
    g.addEventListener("mouseenter", function () {
      var nb = {}; nb[id] = true;
      host.querySelectorAll(".topo-edge").forEach(function (pth) {
        var on = pth.getAttribute("data-ea") === id || pth.getAttribute("data-eb") === id;
        if (on) { nb[pth.getAttribute("data-ea")] = true; nb[pth.getAttribute("data-eb")] = true; }
        pth.setAttribute("stroke", on ? "#38bdf8" : "#334155");
        pth.setAttribute("stroke-width", on ? "3.5" : "1");
        pth.style.opacity = on ? "1" : "0.12";
        pth.style.filter = on ? "drop-shadow(0 0 4px #38bdf8)" : "";
      });
      host.querySelectorAll(".topo-node").forEach(function (nn) {
        var nid = nn.getAttribute("data-swid");
        nn.style.opacity = nb[nid] ? "1" : "0.2";
      });
    });
    g.addEventListener("mouseleave", function () {
      host.querySelectorAll(".topo-edge").forEach(function (pth) {
        pth.setAttribute("stroke", "#64748b"); pth.setAttribute("stroke-width", "2");
        pth.style.opacity = "1"; pth.style.filter = "";
      });
      host.querySelectorAll(".topo-node").forEach(function (nn) {
        nn.style.opacity = nn.getAttribute("data-ghost") === "1" ? "0.6" : "1";
      });
    });
  });
  } // end if(false)
  _topoBindZoomPan(host, width, height);
}

function _topoBindNodeEvents(host) {
  // 대역 뱃지 클릭 → 드릴다운(소속 L2 목록) 토글
  host.querySelectorAll(".topo-band").forEach(function (g) {
    g.addEventListener("click", function () {
      var bid = g.getAttribute("data-band");
      _topoOpenBand = (_topoOpenBand === bid) ? null : bid;
      renderTopology();
    });
  });
  host.querySelectorAll(".topo-node").forEach(function (g) {
    g.addEventListener("click", function () {
      if (g._justDragged) { g._justDragged = false; return; }   // 드래그 직후 상세 억제
      var id = g.getAttribute("data-swid");
      if (g.getAttribute("data-ghost") === "1") { _topoMode = "core"; renderTopology(); return; }
      if (g.getAttribute("data-kind") === "fw") { showFirewallDetail(parseInt(id.slice(1), 10)); return; }
      var sw = (_switches || []).find(function (s) { return String(s.id) === String(id); });
      if (sw) openDetailPanel(sw);
    });
    var id = g.getAttribute("data-swid");
    g.addEventListener("mouseenter", function () {
      var nb = {}; nb[id] = true;
      host.querySelectorAll(".topo-edge").forEach(function (pth) {
        var on = pth.getAttribute("data-ea") === id || pth.getAttribute("data-eb") === id;
        if (on) { nb[pth.getAttribute("data-ea")] = true; nb[pth.getAttribute("data-eb")] = true; }
        pth.style.opacity = on ? "1" : "0.1";
        pth.style.filter = on ? "drop-shadow(0 0 4px #38bdf8)" : "";
      });
      host.querySelectorAll(".topo-node").forEach(function (nn) {
        nn.style.opacity = nb[nn.getAttribute("data-swid")] ? "1" : "0.2";
      });
    });
    g.addEventListener("mouseleave", function () {
      host.querySelectorAll(".topo-edge").forEach(function (pth) { pth.style.opacity = "1"; pth.style.filter = ""; });
      host.querySelectorAll(".topo-node").forEach(function (nn) {
        nn.style.opacity = nn.getAttribute("data-ghost") === "1" ? "0.6" : "1";
      });
    });
  });
}

function _topoBindTips(host) {
  var tipEl = host.querySelector("#topo-tip");
  if (!tipEl) return;
  host.querySelectorAll("[data-tip]").forEach(function (el) {
    el.addEventListener("mousemove", function (e) {
      tipEl.textContent = el.getAttribute("data-tip");
      tipEl.style.display = "block";
      tipEl.style.left = (e.clientX + 12) + "px";
      tipEl.style.top = (e.clientY + 12) + "px";
    });
    el.addEventListener("mouseleave", function () { tipEl.style.display = "none"; });
  });
}

function _topoBindZoomPan(host, width, height) {
  var svgEl = host.querySelector("#topo-svg");
  if (!svgEl) return;
  var vb = { x: 0, y: 0, w: width, h: height };
  function applyVB() { svgEl.setAttribute("viewBox", vb.x + " " + vb.y + " " + vb.w + " " + vb.h); }
  svgEl._vb = vb; svgEl._applyVB = applyVB;   // 드래그/맞춤에서 재사용
  svgEl._fit = function () { vb.x = 0; vb.y = 0; vb.w = width; vb.h = height; applyVB(); };
  svgEl.addEventListener("wheel", function (e) {
    e.preventDefault();
    var scale = e.deltaY > 0 ? 1.15 : 1 / 1.15;
    var rect = svgEl.getBoundingClientRect();
    var mx = vb.x + (e.clientX - rect.left) / rect.width * vb.w;
    var my = vb.y + (e.clientY - rect.top) / rect.height * vb.h;
    var nw = Math.min(width * 3, Math.max(width / 8, vb.w * scale));
    var nh = nw * (vb.h / vb.w);
    vb.x = mx - (mx - vb.x) * (nw / vb.w);
    vb.y = my - (my - vb.y) * (nh / vb.h);
    vb.w = nw; vb.h = nh; applyVB();
  }, { passive: false });
  var drag = null;
  svgEl.addEventListener("mousedown", function (e) {
    // 노드/연결손잡이 위에서는 팬하지 않음. 편집 모드의 빈 캔버스 드래그는 '영역 선택'이
    // 처리하므로 팬 안 함(뷰 모드에서만 빈 캔버스 팬).
    if (window._tRubberActive) return;
    if (e.target.closest && e.target.closest(".topo-node, .tnode, .tlink-handle")) return;
    if (typeof _tEditMode !== "undefined" && _tEditMode) return;   // 편집 모드=영역 선택
    drag = { sx: e.clientX, sy: e.clientY, vx: vb.x, vy: vb.y }; svgEl.style.cursor = "grabbing";
  });
  // window 리스너는 추적 등록 — 재렌더 시 _topoWinClear로 정리(누수 방지)
  _topoWinOn("mousemove", function (e) {
    if (!drag) return;
    var rect = svgEl.getBoundingClientRect();
    vb.x = drag.vx - (e.clientX - drag.sx) / rect.width * vb.w;
    vb.y = drag.vy - (e.clientY - drag.sy) / rect.height * vb.h; applyVB();
  });
  _topoWinOn("mouseup", function () { drag = null; if (svgEl) svgEl.style.cursor = "grab"; });
}

// Contrail식 노드 드래그 — 드래그로 재배치 후 위치 저장(세션 간 유지)
function _topoBindDrag(host) {
  var svgEl = host.querySelector("#topo-svg");
  if (!svgEl) return;
  host.querySelectorAll(".topo-node").forEach(function (g) {
    g.addEventListener("mousedown", function (e) {
      e.stopPropagation();               // 팬 방지
      var id = g.getAttribute("data-swid");
      var base = _topoRenderedPos[id];
      if (!base) return;
      var vb = svgEl._vb || { w: svgEl.clientWidth, h: svgEl.clientHeight };
      var rect = svgEl.getBoundingClientRect();
      var sx = vb.w / (rect.width || 1), sy = vb.h / (rect.height || 1);
      var startX = e.clientX, startY = e.clientY, moved = false;
      function mm(ev) {
        var dx = (ev.clientX - startX) * sx, dy = (ev.clientY - startY) * sy;
        if (Math.abs(ev.clientX - startX) + Math.abs(ev.clientY - startY) > 3) moved = true;
        g.setAttribute("transform", "translate(" + dx + "," + dy + ")");
        g._dxy = { dx: dx, dy: dy };
      }
      function mu() {
        window.removeEventListener("mousemove", mm);
        window.removeEventListener("mouseup", mu);
        if (moved && g._dxy) {
          _topoLayout[id] = { x: base.x + g._dxy.dx, y: base.y + g._dxy.dy };
          _saveTopoLayout();
          g._justDragged = true;         // 클릭(상세) 억제
          renderTopology();              // 링크·박스 재연결
        }
      }
      window.addEventListener("mousemove", mm);
      window.addEventListener("mouseup", mu);
    });
  });
}

// 토폴로지 뷰가 window에 붙인 리스너 추적/정리(재렌더마다 누적 방지)
var _topoWinListeners = [];
function _topoWinOn(type, fn) { window.addEventListener(type, fn); _topoWinListeners.push([type, fn]); }
function _topoWinClear() {
  _topoWinListeners.forEach(function (p) { window.removeEventListener(p[0], p[1]); });
  _topoWinListeners = [];
}

// 토폴로지 모드/존/L2 툴바 UI는 현재 제공하지 않는다(단일 존·대역 뷰 + ghost
// 클릭 전환만 사용). 관련 DOM 요소(.topo-mode·topo-zone-select·btn-topo-l2)가
// HTML에 없어 예전 바인딩은 전부 죽은 코드였다 → no-op로 정리(호출부는 무해).
function _bindTopoModeButtons() { /* 툴바 미제공 — no-op */ }

(function () {
  var b = document.getElementById("btn-topo-clear");
  if (b) b.addEventListener("click", function () {
    if (!_tdiag.nodes.length && !_tdiag.edges.length) return;
    if (!confirm("캔버스를 모두 비울까요? (모든 아이콘·선 삭제 — 처음부터 다시 그립니다)")) return;
    _tdiag = { nodes: [], edges: [] };
    _tSel = {}; _tSelId = null; _tLinkFrom = null; _tLineStyle = null; _tHighlightLineBtn();
    _tView = null;                 // 전체 화면으로
    _renderEditor();               // 자동 저장으로 빈 구성도 반영
  });
  var fit = document.getElementById("btn-topo-fit");
  if (fit) fit.addEventListener("click", function () {
    var svgEl = document.querySelector("#topo-svg");
    if (svgEl && svgEl._fit) svgEl._fit();
  });
  // 편집 모드 토글(끄면 보기 전용 — 실수 클릭 방지)
  var edit = document.getElementById("btn-topo-edit");
  if (edit) edit.addEventListener("click", function () {
    _tEditMode = !_tEditMode; _tLinkFrom = null;
    edit.className = "btn " + (_tEditMode ? "btn--primary" : "btn--secondary");
    edit.style.fontSize = "12px";
    edit.textContent = _tEditMode ? "✏️ 편집 모드 (켜짐)" : "✏️ 편집 모드";
    _renderEditor();
  });
  // 저장
  var save = document.getElementById("btn-topo-save");
  if (save) save.addEventListener("click", function () {
    fetch("/api/topology/diagram", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(_tdiag) }).then(function (r) { return r.json(); }).then(function (res) {
        if (res.ok) { save.textContent = "💾 저장됨"; setTimeout(function () { save.textContent = "💾 저장"; }, 1500); }
        else alert(res.error || "저장 실패");
      }).catch(function () { alert("저장 오류"); });
  });
  // 서버실 현황 불러오기 — 등록 장비를 정보 채운 아이콘으로 나열(종류별 행 배치)
  var draft = document.getElementById("btn-topo-draft");
  if (draft) draft.addEventListener("click", function () {
    if (_tdiag.nodes.length && !confirm("현재 구성도를 서버실 장비로 다시 채울까요? (저장 전이면 사라집니다)")) return;
    fetch("/api/topology/serverroom").then(function (r) { return r.json(); }).then(function (d) {
      // 종류별 행(y) + 순서(x)로 정렬 배치 → 사용자가 골라서 이동
      var ROW = { internet: 0, firewall: 1, backbone: 2, l4: 3, l3: 4, l2: 5, ap: 6, server: 7, pc: 7 };
      var cnt = {};
      var nodes = (d.nodes || []).map(function (n) {
        var kind = _TOPO_KIND[n.kind] ? n.kind : "l2";
        var row = ROW[kind] || 5; cnt[row] = (cnt[row] || 0) + 1;
        return { id: "n" + (_tSeq++), kind: kind, ip: n.ip || "", name: n.name || "",
          x: 120 + cnt[row] * 175, y: 90 + row * 150,
          reachable: n.reachable, status: n.status, subnets: n.subnets || [] };
      });
      _tdiag = { nodes: nodes, edges: [] };   // 링크는 편집 모드에서 직접 연결(포트 자동 인식)
      _tView = null; _tSel = {}; _tSelId = null;   // 전체 화면으로 리셋
      _renderEditor();
      if (!nodes.length) alert("서버실 현황(위치 A09U27 지정)에 등록된 장비가 없습니다.");
    }).catch(function () { alert("서버실 현황 불러오기 오류"); });
  });

  // 스위치 현황 불러오기 — 선택한 대역의 스위치를 캔버스에 추가(기존 유지)
  var swBtn = document.getElementById("btn-topo-switches");
  if (swBtn) swBtn.addEventListener("click", function () {
    var sel = document.getElementById("topo-subnet");
    var subnet = sel ? sel.value : "";
    if (!subnet) { alert("먼저 네트워크 대역을 선택하세요."); return; }
    fetch("/api/topology/switches?subnet=" + encodeURIComponent(subnet))
      .then(function (r) { return r.json(); }).then(function (d) {
        var n = _addLoadedNodes(d.nodes || [], false);
        _renderEditor();
        if (!n) alert("해당 대역(" + subnet + ")에 추가할 스위치가 없습니다(이미 있거나 없음).");
      }).catch(function () { alert("스위치 현황 불러오기 오류"); });
  });

  // 키보드: 편집 모드에서 Ctrl+C 복사 / Ctrl+V 붙여넣기 / Delete 삭제
  document.addEventListener("keydown", function (e) {
    // 토폴로지 탭 활성 + 편집 모드일 때만. 입력창/모달 포커스 중이면 무시(일반 복사 보존)
    var topoActive = document.getElementById("tab-topology");
    if (!topoActive || !topoActive.classList.contains("active") || !_tEditMode) return;
    var t = e.target, tag = (t && t.tagName || "").toUpperCase();
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    var mod = e.ctrlKey || e.metaKey;
    var ids = _tSelIds();
    if (e.key === "Escape") {   // 선/연결 도구·선택 취소
      _tLineStyle = null; _tLinkFrom = null; _tSel = {}; _tSelId = null;
      _tHighlightLineBtn(); _renderEditor(); e.preventDefault();
    } else if (mod && (e.key === "a" || e.key === "A")) {
      _tSel = {}; _tdiag.nodes.forEach(function (n) { _tSel[n.id] = true; });   // 전체 선택
      _renderEditor(); e.preventDefault();
    } else if (mod && (e.key === "c" || e.key === "C")) {
      var picked = ids.map(_tNode).filter(Boolean);
      if (picked.length) { _tClip = JSON.parse(JSON.stringify(picked)); e.preventDefault(); }
    } else if (mod && (e.key === "v" || e.key === "V")) {
      if (_tClip && _tClip.length) {
        _tSel = {};
        _tClip.forEach(function (src) {
          var c = JSON.parse(JSON.stringify(src));
          c.id = "n" + (_tSeq++); c.x = (c.x || 100) + 40; c.y = (c.y || 100) + 40;
          _tdiag.nodes.push(c); _tSel[c.id] = true;
        });
        _renderEditor(); e.preventDefault();
      }
    } else if (e.key === "Delete") {   // Delete만(Backspace 제거 — 사이드버튼/제스처 오삭제 방지)
      if (ids.length) {
        var del = {}; ids.forEach(function (i) { del[i] = true; });
        _tdiag.nodes = _tdiag.nodes.filter(function (x) { return !del[x.id]; });
        _tdiag.edges = _tdiag.edges.filter(function (ed) { return !del[ed.a] && !del[ed.b]; });
        _tSel = {}; _tSelId = null; _renderEditor(); e.preventDefault();
      }
    }
  });
})();

// ─── 설정(config) 백업/diff 탭 ───────────────────────────────────
function loadConfigTab(switchId) {
  var pane = document.getElementById("dtab-config");
  if (!pane) return;
  pane.innerHTML = "<p style='color:#64748b'>불러오는 중...</p>";
  fetch("/api/switches/" + switchId + "/configs")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      var backups = data.backups || [];
      if (!backups.length) {
        pane.innerHTML = "<p style='color:#64748b'>저장된 설정 백업이 없습니다. 이 스위치를 수집하면 running-config가 자동 백업됩니다(변경 시에만 새 버전 저장).</p>";
        return;
      }
      var opts = backups.map(function (b) {
        return "<option value='" + b.id + "'>" + escHtml((b.ts || "").replace("T", " ").slice(0, 16)) + "</option>";
      }).join("");
      pane.innerHTML =
        "<div style='display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap'>" +
        "<label style='font-size:12px'>버전:</label><select id='cfg-sel-a' style='font-size:12px'>" + opts + "</select>" +
        "<button id='btn-cfg-diff' class='btn btn--primary' style='font-size:12px;padding:4px 10px'>직전 버전과 비교</button>" +
        "<a id='btn-cfg-download' class='btn btn--secondary' style='font-size:12px;padding:4px 10px' target='_blank'>원문 다운로드</a>" +
        "<span style='font-size:11px;color:#64748b'>백업 " + backups.length + "개(변경 시에만 저장)</span>" +
        "</div><div id='cfg-diff-body' style='font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap;" +
        "background:#0f172a;color:#e2e8f0;border-radius:6px;padding:12px;max-height:55vh;overflow:auto'>버전을 선택하고 '직전 버전과 비교'를 누르세요.</div>";
      function _syncDl() {
        var sel = document.getElementById("cfg-sel-a");
        var dl = document.getElementById("btn-cfg-download");
        if (sel && dl) dl.href = "/api/configs/" + sel.value;
      }
      _syncDl();
      document.getElementById("cfg-sel-a").addEventListener("change", _syncDl);
      document.getElementById("btn-cfg-diff").addEventListener("click", function () {
        var aid = document.getElementById("cfg-sel-a").value;
        var body = document.getElementById("cfg-diff-body");
        body.textContent = "비교 중...";
        fetch("/api/configs/diff?a=" + encodeURIComponent(aid))
          .then(function (r) { return r.json(); })
          .then(function (res) {
            if (!res.ok) { body.textContent = res.error || "비교 실패"; return; }
            if (res.same) { body.textContent = "직전 버전과 차이가 없습니다."; return; }
            if (!res.older_ts) { body.textContent = "이전 백업이 없습니다(첫 백업)."; return; }
            body.innerHTML = (res.diff || []).map(function (line) {
              var color = line.charAt(0) === "+" ? "#4ade80"
                        : line.charAt(0) === "-" ? "#f87171"
                        : line.slice(0, 2) === "@@" ? "#60a5fa" : "#94a3b8";
              return "<span style='color:" + color + "'>" + escHtml(line) + "</span>";
            }).join("\n");
          })
          .catch(function () { body.textContent = "비교 오류"; });
      });
    })
    .catch(function (e) { console.error(e); pane.innerHTML = "<p style='color:#991b1b'>불러오기 오류</p>"; });
}

// ─── 구성도 PPTX 생성 ────────────────────────────────────────────
(function () {
  var btn = document.getElementById("btn-pptx-report");
  if (btn) btn.addEventListener("click", function () {
    var di = document.getElementById("pptx-date");
    if (di && !di.value) { di.value = new Date().toISOString().slice(0, 10); }
    openModal("modal-pptx");
  });
  var gen = document.getElementById("pptx-generate");
  if (gen) gen.addEventListener("click", function () {
    var c = (document.getElementById("pptx-customer") || {}).value || "";
    var d = (document.getElementById("pptx-date") || {}).value || "";
    if (!c.trim()) { alert("고객사명을 입력하세요."); return; }
    var url = "/api/report/pptx?customer=" + encodeURIComponent(c.trim()) +
      (d ? "&date=" + encodeURIComponent(d) : "");
    window.location = url;
    closeModal("modal-pptx");
  });
})();

// ─── config 다운로드(ZIP) — 체크된 스위치만(선택 필수) ──────────
(function () {
  var btn = document.getElementById("btn-configs-export");
  if (btn) btn.addEventListener("click", function () {
    var ids = Array.prototype.map.call(
      document.querySelectorAll("#switch-table-body .sw-check:checked"),
      function (c) { return c.value; });
    if (ids.length) {
      window.location = "/api/configs/export-all?ids=" + ids.join(",");
    } else {
      alert("config를 다운로드할 스위치를 먼저 체크하세요.");
    }
  });
})();

// ─── 저장 계정 관리 (관리자) ─────────────────────────────────────
function loadCreds() {
  var sw = document.getElementById("creds-switches");
  var fw = document.getElementById("creds-firewalls");
  var pf = document.getElementById("creds-profiles");
  sw.innerHTML = fw.innerHTML = pf.innerHTML =
    "<tr><td colspan=6 style='color:#64748b'>불러오는 중...</td></tr>";
  fetch("/api/credentials").then(function (r) { return r.json(); }).then(function (d) {
    var delBtn = function (kind, key) {
      return "<button class='btn btn--secondary creds-del' style='font-size:11px;padding:2px 8px' " +
        "data-kind='" + kind + "' data-key='" + encodeURIComponent(key) + "'>삭제</button>";
    };
    var rows = (d.switches || []).map(function (s) {
      return "<tr><td>" + escHtml(s.name || "-") + "</td><td><code>" + escHtml(s.ip || "-") +
        "</code></td><td>" + delBtn("switch", s.id) + "</td></tr>";
    });
    sw.innerHTML = rows.length ? rows.join("")
      : "<tr><td colspan=3 style='color:#64748b'>저장된 계정이 없습니다.</td></tr>";
    rows = (d.firewalls || []).map(function (f) {
      return "<tr><td>" + escHtml(f.name || "-") + "</td><td><code>" + escHtml(f.host || "-") +
        "</code></td><td>" + delBtn("firewall", f.id) + "</td></tr>";
    });
    fw.innerHTML = rows.length ? rows.join("")
      : "<tr><td colspan=3 style='color:#64748b'>저장된 계정이 없습니다.</td></tr>";
    rows = (d.pc_profiles || []).map(function (p) {
      return "<tr><td>" + escHtml(p.hostname || "-") + "</td><td><code>" + escHtml(p.mac || "-") +
        "</code></td><td><code>" + escHtml(p.source_ip || "(자동)") + "</code></td><td>" +
        (p.has_cred ? "저장됨" : "-") + "</td><td style='font-size:11px;color:#64748b'>" +
        escHtml((p.updated_at || "").slice(0, 16)) + "</td><td>" +
        delBtn("profile", p.mac) + "</td></tr>";
    });
    pf.innerHTML = rows.length ? rows.join("")
      : "<tr><td colspan=6 style='color:#64748b'>등록된 PC 프로필이 없습니다.</td></tr>";
  }).catch(function (e) {
    console.error(e);
    sw.innerHTML = "<tr><td colspan=3>오류</td></tr>";
  });
}

(function () {
  var btn = document.getElementById("btn-creds");
  if (!btn) return;
  btn.addEventListener("click", function () { openModal("modal-creds"); loadCreds(); });

  // 개별 삭제(위임)
  document.getElementById("modal-creds").addEventListener("click", function (e) {
    var t = e.target.closest(".creds-del");
    if (!t) return;
    var kind = t.getAttribute("data-kind");
    var key = decodeURIComponent(t.getAttribute("data-key"));
    var label = {switch: "스위치", firewall: "방화벽", profile: "PC 프로필"}[kind] || kind;
    if (!confirm(label + " 저장 계정을 삭제할까요? (장비 설정은 그대로, 접속 계정만 삭제)")) return;
    var body = {kind: kind};
    if (kind === "profile") body.mac = key; else body.id = parseInt(key, 10);
    fetch("/api/credentials/delete", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) loadCreds(); else alert(res.error || "삭제 실패");
    }).catch(function (e2) { console.error(e2); alert("삭제 오류"); });
  });

  // 전체 삭제
  var clearBtn = document.getElementById("btn-creds-clear-all");
  if (clearBtn) clearBtn.addEventListener("click", function () {
    if (!confirm("저장된 접속 계정을 전부 삭제할까요?\n(스위치·방화벽·PC 프로필 계정 — 이후 수집 시 계정을 다시 입력해야 합니다)")) return;
    fetch("/api/credentials/delete", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({kind: "all"}),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) {
        alert("삭제 완료 — 스위치 " + (res.switches || 0) + "건, 방화벽 " + (res.firewalls || 0) +
          "건, PC 프로필 " + (res.profiles || 0) + "건");
        loadCreds();
      } else alert(res.error || "삭제 실패");
    }).catch(function (e2) { console.error(e2); alert("삭제 오류"); });
  });
})();

// ─── 서버 현황 (리눅스/윈도우) ───────────────────────────────────
var _srvCollectId = null;
var _srvEditId = null;   // 서버 수정 대상 id(null=신규 등록)

// 서버 수집 모달 오픈(서버 현황 테이블 + 서버실 카드 공용)
function _openServerCollect(id) {
  _srvCollectId = id;
  var s = _servers.find(function (x) { return x.id === id; });
  var t = document.getElementById("srv-collect-title");
  if (t) t.textContent = "서버 수집 — " + (s ? s.name : id);
  var u = document.getElementById("srv-username"); if (u) u.value = "";
  var p = document.getElementById("srv-password"); if (p) p.value = "";
  var pe = document.getElementById("srv-persist"); if (pe) pe.checked = false;
  openModal("modal-server-collect");
}

function loadServers() {
  return fetch("/api/servers").then(function (r) { return r.json(); }).then(function (d) {
    _servers = d.servers || [];
    renderServers();
    // 서버실 현황이 열려 있으면 물리 서버 반영
    if (document.getElementById("tab-room").classList.contains("active")) renderRoom(_switches);
  }).catch(function (e) { console.error("servers:", e); });
}

function renderServers() {
  var body = document.getElementById("server-table-body");
  if (!body) return;
  var q = (document.getElementById("server-search") || {}).value;
  q = (q || "").trim().toLowerCase();
  var rows = _servers.filter(function (s) {
    if (!q) return true;
    return [s.name, s.ip, s.hostname, s.mac].some(function (v) {
      return (v || "").toLowerCase().indexOf(q) >= 0;
    });
  });
  if (!rows.length) {
    body.innerHTML = "<tr><td colspan='14' style='color:#64748b'>" +
      (_servers.length ? "검색 결과가 없습니다." : "등록된 서버가 없습니다. [+ 서버 추가]로 추가하세요.") + "</td></tr>";
    return;
  }
  body.innerHTML = rows.map(function (s) {
    var kind = s.is_vm ? "<span style='color:#8b5cf6'>VM</span>"
                       : "<span style='color:#2563eb'>물리</span>";
    var sc = s.status === "failed" ? "critical" : (s.status === "done" ? "done" : "new");
    var swp = [s.switch_name, s.switch_port].filter(Boolean).join(" ");
    return "<tr>" +
      "<td style='text-align:center'><input type='checkbox' class='srv-check' value='" + s.id + "'></td>" +
      "<td>" + escHtml(s.name) + "</td>" +
      "<td><code>" + escHtml(s.ip) + "</code></td>" +
      "<td>" + escHtml(s.hostname || "-") + "</td>" +
      "<td><code style='font-size:11px'>" + escHtml(s.mac || "-") + "</code></td>" +
      "<td>" + escHtml(s.os_info || s.os_type || "-") + "</td>" +
      "<td>" + kind + "</td>" +
      "<td style='font-size:11px;max-width:180px'>" + escHtml(s.open_ports || "-") + "</td>" +
      "<td>" + escHtml(s.switch_name || "-") + "</td>" +
      "<td>" + escHtml(s.switch_port || "-") + "</td>" +
      "<td>" + escHtml(s.location || "-") + "</td>" +
      "<td><span class='status-badge status-badge--" + sc + "'>" + escHtml(s.status || "new") + "</span>" +
        (s.status === "failed" && s.last_error ? "<div style='font-size:11px;color:#991b1b'>" + escHtml(s.last_error) + "</div>" : "") + "</td>" +
      "<td><button class='btn btn--primary' style='font-size:11px;padding:2px 8px' data-action='collect-server' data-id='" + s.id + "'>수집</button></td>" +
      "<td><button class='btn btn--secondary' style='font-size:11px;padding:2px 8px' data-action='edit-server' data-id='" + s.id + "'>수정</button> " +
        "<button class='btn btn--ghost' style='font-size:11px;padding:2px 8px' data-action='delete-server' data-id='" + s.id + "'>삭제</button></td>" +
      "</tr>";
  }).join("");
}

(function () {
  var addBtn = document.getElementById("btn-server-add");
  if (addBtn) addBtn.addEventListener("click", function () {
    _srvEditId = null;   // 신규 등록 모드
    ["srv-name", "srv-ip", "srv-location"].forEach(function (id) { document.getElementById(id).value = ""; });
    document.getElementById("srv-os").value = "auto";
    document.getElementById("srv-isvm").checked = false;
    var mh = document.querySelector("#modal-add-server .modal__header span");
    if (mh) mh.textContent = "서버 등록";
    var sb = document.getElementById("btn-srv-save"); if (sb) sb.textContent = "등록";
    openModal("modal-add-server");
  });
  var saveBtn = document.getElementById("btn-srv-save");
  if (saveBtn) saveBtn.addEventListener("click", function () {
    var body = {
      name: document.getElementById("srv-name").value.trim(),
      ip: document.getElementById("srv-ip").value.trim(),
      os_type: document.getElementById("srv-os").value,
      location: document.getElementById("srv-location").value.trim(),
      is_vm: document.getElementById("srv-isvm").checked,
    };
    if (!body.name || !body.ip) { alert("이름과 IP는 필수입니다."); return; }
    var editing = _srvEditId != null;
    var url = editing ? ("/api/servers/" + _srvEditId) : "/api/servers";
    fetch(url, {
      method: editing ? "PUT" : "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json().then(function (j) { return {s: r.status, j: j}; }); })
      .then(function (res) {
        if (res.j && res.j.ok || res.s === 201) { _srvEditId = null; closeModal("modal-add-server"); loadServers(); }
        else alert((res.j && res.j.error) || (editing ? "수정 실패" : "등록 실패"));
      }).catch(function (e) { console.error(e); alert("저장 오류"); });
  });

  var searchEl = document.getElementById("server-search");
  if (searchEl) searchEl.addEventListener("input", renderServers);

  // 서버 전체선택 체크박스
  var srvAll = document.getElementById("srv-check-all");
  if (srvAll) srvAll.addEventListener("change", function () {
    Array.prototype.forEach.call(document.querySelectorAll("#server-table-body .srv-check"),
      function (c) { c.checked = srvAll.checked; });
  });

  var allBtn = document.getElementById("btn-server-collect-all");
  if (allBtn) allBtn.addEventListener("click", function () {
    if (!_servers.length) { alert("등록된 서버가 없습니다."); return; }
    // 체크된 서버만(없으면 전체)
    var ids = Array.prototype.map.call(
      document.querySelectorAll("#server-table-body .srv-check:checked"),
      function (c) { return parseInt(c.value, 10); });
    var body = {
      username: (document.getElementById("server-common-user") || {}).value || "",
      password: (document.getElementById("server-common-pass") || {}).value || "",
      persist: (document.getElementById("server-common-persist") || {}).checked || false,
    };
    if (ids.length) body.ids = ids;
    var withCred = body.username && body.password;
    var scope = ids.length ? ("선택한 " + ids.length + "대") : "전체";
    var msg = withCred
      ? scope + " 서버를 공통 계정으로 재수집합니다. OS 자동 인식·상세까지 수집합니다.\n계속할까요?"
      : scope + " 서버를 수집합니다. (공통 계정 미입력 — 포트/hostname/연결 스위치만, 저장 계정 있는 서버는 상세 포함)\n계속할까요?";
    if (!confirm(msg)) return;
    fetch("/api/servers/collect-all", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json(); })
      .then(function () {
        // 비밀번호 입력란은 비워 화면 잔류 방지
        var pw = document.getElementById("server-common-pass"); if (pw) pw.value = "";
        // 진행바 폴링 → 완료 시 목록 새로고침
        pollProgress("/api/servers/collect-all/status", "server-progress", loadServers,
          "/api/servers/collect-all/stop");
      }).catch(function (e) { console.error(e); alert("수집 오류"); });
  });

  // 방화벽 전체 수집 — 진행바 폴링
  var fwAllBtn = document.getElementById("btn-firewall-collect-all");
  if (fwAllBtn) fwAllBtn.addEventListener("click", function () {
    if (!confirm("등록된 전 방화벽을 저장된 계정으로 일괄 수집합니다.\n계속할까요?")) return;
    fetch("/api/firewalls/collect-all", { method: "POST" })
      .then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (!res.ok) { alert((res.b && res.b.error) || "일괄 수집 시작 실패"); return; }
        pollProgress("/api/firewalls/collect-all/status", "firewall-progress", loadFirewalls,
          "/api/firewalls/collect-all/stop");
      }).catch(function (e) { console.error(e); alert("수집 오류"); });
  });

  // 설비 전체 대역 수집 — 시작 후 loadFacility가 fac-progress 폴링
  var facScanAll = document.getElementById("btn-fac-scan-all");
  if (facScanAll) facScanAll.addEventListener("click", function () {
    if (!confirm("기억된 모든 대역을 순차로 일괄 스캔합니다(동시 1개 대역만).\n계속할까요?")) return;
    fetch("/api/facility/scan-all", { method: "POST" })
      .then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (!res.ok) { alert((res.b && res.b.error) || "전체 스캔 시작 실패"); return; }
        if (typeof loadFacility === "function") loadFacility();
      }).catch(function (e) { console.error(e); alert("스캔 오류"); });
  });

  // 수집(계정 입력) / 삭제 위임
  document.getElementById("tab-server").addEventListener("click", function (e) {
    var t = e.target.closest("[data-action]");
    if (!t) return;
    var id = parseInt(t.getAttribute("data-id"), 10);
    var action = t.getAttribute("data-action");
    if (action === "collect-server") {
      _openServerCollect(id);
    } else if (action === "edit-server") {
      var sv = _servers.find(function (x) { return x.id === id; });
      if (!sv) return;
      _srvEditId = id;
      document.getElementById("srv-name").value = sv.name || "";
      document.getElementById("srv-ip").value = sv.ip || "";
      // linux/windows 외 OS(aix·solaris·hpux·esxi·bsd·macos·unix)도 드롭다운에서 복원
      var _osOpts = ["linux", "windows", "aix", "solaris", "hpux", "esxi", "bsd", "macos", "unix"];
      document.getElementById("srv-os").value =
        _osOpts.indexOf(sv.os_type) >= 0 ? sv.os_type : "auto";
      document.getElementById("srv-location").value = sv.location || "";
      document.getElementById("srv-isvm").checked = !!sv.is_vm;
      var mh = document.querySelector("#modal-add-server .modal__header span");
      if (mh) mh.textContent = "서버 수정";
      var sb = document.getElementById("btn-srv-save"); if (sb) sb.textContent = "수정";
      openModal("modal-add-server");
    } else if (action === "delete-server") {
      if (!confirm("이 서버를 삭제할까요?")) return;
      fetch("/api/servers/" + id, {method: "DELETE"}).then(function (r) { return r.json(); })
        .then(function (res) { if (res.ok) loadServers(); else alert(res.error || "삭제 실패"); });
    }
  });

  var collectBtn = document.getElementById("btn-srv-collect");
  if (collectBtn) collectBtn.addEventListener("click", function () {
    if (_srvCollectId == null) return;
    var body = {
      username: document.getElementById("srv-username").value.trim(),
      password: document.getElementById("srv-password").value,
      persist: document.getElementById("srv-persist").checked,
    };
    fetch("/api/servers/" + _srvCollectId + "/collect", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) {
        closeModal("modal-server-collect");
        alert("수집을 시작했습니다. 잠시 후 결과가 반영됩니다.");
        setTimeout(loadServers, 6000);
      } else alert(res.error || "수집 실패");
    }).catch(function (e) { console.error(e); alert("수집 오류"); });
  });
})();

// ─── 접근 로그(감사) ─────────────────────────────────────────────
(function () {
  var btn = document.getElementById("btn-audit");
  if (!btn) return;
  btn.addEventListener("click", function () {
    openModal("modal-audit");
    var body = document.getElementById("audit-body");
    body.innerHTML = "<tr><td colspan=4 style='color:#64748b'>불러오는 중...</td></tr>";
    fetch("/api/audit").then(function (r) { return r.json(); }).then(function (data) {
      var logs = data.logs || [];
      if (!logs.length) {
        body.innerHTML = "<tr><td colspan=4 style='color:#64748b'>기록이 없습니다.</td></tr>";
        return;
      }
      body.innerHTML = logs.map(function (l) {
        return "<tr><td style='white-space:nowrap'>" + escHtml((l.ts || "").replace("T", " ").slice(0, 16)) +
          "</td><td><code>" + escHtml(l.client_ip || "-") + "</code></td><td><strong>" +
          escHtml(l.action || "-") + "</strong></td><td style='color:#64748b;font-size:12px'>" +
          escHtml(l.target || "") + "</td></tr>";
      }).join("");
    }).catch(function (e) { console.error(e); body.innerHTML = "<tr><td colspan=4>오류</td></tr>"; });
  });
})();

// ─── 포트 이력(누가 언제 꽂았나) ─────────────────────────────────
function loadPortHistory(switchId, port) {
  var pane = document.getElementById("dtab-history");
  if (!pane) return;
  pane.innerHTML = "<p style='color:#64748b'>불러오는 중...</p>";
  var qs = port ? "?port=" + encodeURIComponent(port) : "";
  fetch("/api/switches/" + switchId + "/port-history" + qs)
    .then(function (r) { return r.json(); })
    .then(function (data) {
      var rows = data.history || [];
      var head =
        "<div style='display:flex;gap:8px;align-items:center;margin-bottom:8px'>" +
        "<input id='ph-port' class='tbl-search' data-target='ph-body' placeholder='포트/MAC 필터...' " +
        "style='padding:5px 9px;border:1px solid #cbd5e1;border-radius:4px;font-size:13px'>" +
        "<span style='font-size:11px;color:#64748b'>스냅샷 이력 기반 — 수집할수록 정밀해집니다. " +
        "'현재 없음'은 뽑혔거나 교체된 것.</span></div>";
      if (!rows.length) {
        pane.innerHTML = head + "<p style='color:#64748b'>이력이 없습니다. 이 스위치를 2회 이상 수집하면 변화가 기록됩니다.</p>";
        return;
      }
      pane.innerHTML = head +
        "<table class='data-table'><thead><tr><th>포트</th><th>MAC</th><th>최초 관측</th><th>최근 관측</th><th>관측 횟수</th><th>상태</th></tr></thead>" +
        "<tbody id='ph-body'>" + rows.map(function (h) {
          var cur = h.current
            ? "<span class='status-badge status-badge--ok'>현재 연결</span>"
            : "<span class='status-badge status-badge--new'>현재 없음</span>";
          return "<tr><td><code>" + escHtml(h.port || "-") + "</code></td>" +
            "<td><code>" + escHtml(h.mac || "-") + "</code></td>" +
            "<td>" + escHtml((h.first_seen || "").slice(0, 16)) + "</td>" +
            "<td>" + escHtml((h.last_seen || "").slice(0, 16)) + "</td>" +
            "<td style='text-align:center'>" + (h.seen_count || 0) + "</td>" +
            "<td>" + cur + "</td></tr>";
        }).join("") + "</tbody></table>";
    })
    .catch(function (e) { console.error(e); pane.innerHTML = "<p style='color:#991b1b'>불러오기 오류</p>"; });
}

// ─── 알람(변경 이벤트) ───────────────────────────────────────────
var _ALERT_KIND = {
  new_device: "새 설비", device_offline: "설비 연결 끊김", device_online: "설비 복구",
  device_moved: "설비 이동", config_changed: "설정 변경",
  switch_unreachable: "스위치 연결 실패", switch_recovered: "스위치 복구",
  flapping: "포트 flapping", looping: "포트 looping",
};

function _alertFilterQS() {
  var k = document.getElementById("alert-filter-kind");
  var d = document.getElementById("alert-filter-days");
  var u = document.getElementById("alert-filter-unack");
  var qs = [];
  if (k && k.value) qs.push("kind=" + encodeURIComponent(k.value));
  if (d && d.value) qs.push("days=" + encodeURIComponent(d.value));
  if (u && u.checked) qs.push("unack=1");
  return qs.length ? "?" + qs.join("&") : "";
}

function loadAlerts(renderList) {
  var url = "/api/alerts" + (renderList ? _alertFilterQS() : "");
  fetch(url).then(function (r) { return r.json(); }).then(function (data) {
    var badge = document.getElementById("alert-badge");
    var n = data.unacked || 0;
    if (badge) {
      badge.textContent = n > 99 ? "99+" : String(n);
      badge.classList.toggle("hidden", n === 0);
    }
    if (renderList) _renderAlerts(data.events || []);
  }).catch(function (e) { console.error("alerts:", e); });
}

function _renderAlerts(events) {
  var body = document.getElementById("alerts-body");
  if (!body) return;
  if (!events.length) {
    body.innerHTML = "<p style='color:#64748b'>알람이 없습니다.</p>";
    return;
  }
  body.innerHTML = events.map(function (ev) {
    var sev = ev.severity || "info";
    var kind = _ALERT_KIND[ev.kind] || ev.kind || "-";
    var where = [ev.label, ev.ip, ev.subnet].filter(Boolean).map(escHtml).join(" · ");
    var unread = ev.ack ? "" : " style='background:#fffbeb'";
    return "<div class='alert-row'" + unread + ">" +
      "<span class='alert-dot alert-dot--" + sev + "'></span>" +
      "<div style='flex:1'>" +
        "<div><strong>" + escHtml(kind) + "</strong>" + (where ? " — " + where : "") + "</div>" +
        (ev.message ? "<div style='color:#475569;font-size:12px'>" + escHtml(ev.message) + "</div>" : "") +
      "</div>" +
      "<span class='alert-row__time'>" + escHtml((ev.ts || "").replace("T", " ")) + "</span>" +
      "</div>";
  }).join("");
}

(function () {
  var bell = document.getElementById("btn-alerts");
  if (bell) bell.addEventListener("click", function () {
    openModal("modal-alerts");
    loadAlerts(true);
  });
  ["alert-filter-kind", "alert-filter-days", "alert-filter-unack"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener("change", function () { loadAlerts(true); });
  });
  var ack = document.getElementById("btn-alerts-ack");
  if (ack) ack.addEventListener("click", function () {
    fetch("/api/alerts/ack", { method: "POST", headers: {"Content-Type": "application/json"},
                               body: "{}" })
      .then(function (r) { return r.json(); })
      .then(function () { loadAlerts(true); })
      .catch(function (e) { console.error(e); });
  });
})();

// ─── 폴링 ────────────────────────────────────────────────────────
function pollState() {
  fetch("/api/state")
    .then(function(r) { return r.json(); })
    .then(function(data) {
      // DB 오류면 상세 원인 배너 표시 후 중단(부분 렌더 방지)
      if (data && data.db_error) { showDbErrorBanner(data.db_error); return; }
      clearDbErrorBanner();
      if (data.readonly) showReadonlyBanner(data.primary_host);
      else clearReadonlyBanner();
      _switches = data.switches || [];
      renderSwitchGrid(_switches);
      renderSwitchTable(_switches);
      if (_viewMode === "rack") renderRackView(_switches);
      renderRoom(_switches);

      if (_currentSwitchId) {
        var sw = _switches.find(function(s) { return s.id === _currentSwitchId; });
        if (sw) {
          document.getElementById("detail-title").textContent = sw.name;
          document.getElementById("detail-subtitle").textContent =
            sw.ip + (sw.hostname ? " · " + sw.hostname : "");
        }
      }
      document.getElementById("last-updated").textContent = "갱신: " + new Date().toLocaleTimeString("ko-KR");
      loadAlerts(false);  // 알람 배지 갱신(준실시간)
      _notifyZoneOutages(data.zone_outages || []);
    })
    .catch(function(e) {
      console.error("poll error:", e);
      // 응답 자체가 실패(서버 다운/DB 접근 불가) — health로 원인 조회해 배너 표시
      fetch("/api/health").then(function (r) { return r.json(); }).then(function (h) {
        if (h && h.ok === false && h.db_error) showDbErrorBanner(h.db_error);
      }).catch(function () {});
    });
}

// TPS 구역 전원다운 감지 팝업 — 새로 발생한 구역만 1회 알림(반복 방지)
var _zoneOutageSeen = {};
function _notifyZoneOutages(list) {
  var cur = {};
  var fresh = [];
  (list || []).forEach(function (z) {
    cur[z.group] = true;
    if (!_zoneOutageSeen[z.group]) fresh.push(z);
  });
  _zoneOutageSeen = cur;   // 복구된 구역은 목록에서 빠져 다음 발생 시 재알림
  if (fresh.length) {
    var msg = "⚡ 구역 전원 다운 의심\n\n" + fresh.map(function (z) {
      return "· " + z.group + " — 스위치 " + z.total + "대 전부 도달불가";
    }).join("\n") + "\n\n해당 구역의 정전/전원을 확인하세요.";
    try { alert(msg); } catch (e) {}
  }
}

// ─── M4: 진단 화면 표시 ──────────────────────────────────────────
function showDiagnostics(diagnostics) {
  /**
   * M4: 업로드 응답의 diagnostics 객체를 화면에 표시.
   * diagnostics = {
   *   total_blocks: int,
   *   discarded_blocks: int,
   *   switch_blocks: int,
   *   host_blocks: int,
   *   imported_switches: int,
   *   imported_hosts: int,
   *   warnings: [str]
   * }
   */
  if (!diagnostics) return;

  var warningsHtml = "";
  if (diagnostics.warnings && diagnostics.warnings.length > 0) {
    warningsHtml = "<div style='margin-top: 10px; padding: 8px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 2px;'>" +
      "<h4 style='margin: 0 0 5px 0; color: #856404; font-size: 13px;'>경고</h4>" +
      "<ul style='margin: 0; padding-left: 20px; color: #856404; font-size: 12px;'>" +
      diagnostics.warnings.map(function(w) { return "<li>" + escHtml(w) + "</li>"; }).join("") +
      "</ul>" +
      "</div>";
  }

  var statsHtml = "<div id='upload-diagnostics' style='border: 1px solid #d0d5dd; padding: 12px; margin: 10px 0; background: #f6f8fb; border-radius: 4px;'>" +
    "<h3 style='margin: 0 0 10px 0; font-size: 14px; color: #1f2937;'>업로드 진단</h3>" +
    "<ul style='margin: 0; padding-left: 20px; font-size: 12px; line-height: 1.6; color: #374151;'>" +
    "<li><strong>총 블록:</strong> " + (diagnostics.total_blocks || 0) + "</li>" +
    "<li><strong>폐기된 블록:</strong> " + (diagnostics.discarded_blocks || 0) + "</li>" +
    "<li><strong>스위치 블록:</strong> " + (diagnostics.switch_blocks || 0) + "</li>" +
    "<li><strong>호스트 블록:</strong> " + (diagnostics.host_blocks || 0) + "</li>" +
    "<li><strong>임포트된 스위치:</strong> " + (diagnostics.imported_switches || 0) + "</li>" +
    "<li><strong>임포트된 호스트:</strong> " + (diagnostics.imported_hosts || 0) + "</li>" +
    "</ul>" +
    warningsHtml +
    "</div>";

  var container = document.getElementById("diagnostics-container");
  if (container) {
    container.innerHTML = statsHtml;
  }
}

// ─── 유틸 ────────────────────────────────────────────────────────
function escHtml(s) {
  if (s == null) return "";
  // 작은따옴표(&#39;)도 이스케이프 — 단일따옴표 속성(title='...', data-*='...')에
  // 장비 유래 문자열(SSH 오류 메시지 등)이 들어가 속성을 파괴/주입하던 버그 방지.
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
                  .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
// data-payload용: encodeURIComponent는 작은따옴표를 인코딩하지 않아 단일따옴표
// 속성을 깨뜨린다 → %27로 추가 치환(decodeURIComponent가 다시 ' 로 복원).
function payloadAttr(obj) {
  return encodeURIComponent(JSON.stringify(obj)).replace(/'/g, "%27");
}
function fmtTime(ts) {
  if (!ts) return "-";
  try {
    // DB 시각은 UTC(SQLite datetime('now')/CURRENT_TIMESTAMP, TZ 표기 없음).
    // 'Z'를 붙여 UTC로 해석 후 EST(America/New_York)로 표시.
    var s = String(ts).trim().replace(" ", "T");
    if (!/[zZ]|[+\-]\d\d:?\d\d$/.test(s)) s += "Z";
    var d = new Date(s);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString("en-US", { timeZone: "America/New_York",
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) + " EST";
  } catch (e) { return String(ts); }
}
// 넷마스크/프리픽스 → "/N" 표기. 변환 불가 시 원문(있으면 앞에 /) 반환.
function _fmtPrefix(mask) {
  if (mask == null || mask === "") return "";
  var m = String(mask).trim().replace(/^\//, "");
  if (/^\d+$/.test(m)) return "/" + m;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(m)) {
    var bits = m.split(".").map(function (o) {
      return ("00000000" + (parseInt(o, 10) || 0).toString(2)).slice(-8);
    }).join("");
    if (!/01/.test(bits)) return "/" + (bits.split("1").length - 1);
  }
  return "/" + m;
}

// ─── M11: PC 이더넷 IP 표시 ──────────────────────────────────────
function loadNetInfo() {
  fetch("/api/netinfo")
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var ips = d.local_ips || [];
      var cur = d.source_ip || "";
      var sel = document.getElementById("source-ip-select");
      if (sel) {
        sel.innerHTML = "<option value=''>자동(기본 라우팅)</option>" +
          ips.map(function(ip) {
            return "<option value='" + escHtml(ip) + "'" + (ip === cur ? " selected" : "") + ">" + escHtml(ip) + "</option>";
          }).join("");
        sel.title = "장비 접근 출발지 IP. 127.0.0.1(루프백)로는 장비에 접근할 수 없습니다.";
      }
    })
    .catch(function(e) { console.error("netinfo:", e); });
}

(function () {
  var sel = document.getElementById("source-ip-select");
  if (!sel) return;
  sel.addEventListener("change", function () {
    fetch("/api/settings/source_ip", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ip: this.value}),
    }).then(function(r) { return r.json(); })
      .then(function(res) { if (res.error) alert(res.error); })
      .catch(function(e) { console.error(e); });
  });
})();

// ─── 초기화 ──────────────────────────────────────────────────────
loadNetInfo();
pollState();
loadFirewalls();  // 서버실 현황에 방화벽을 표시하려면 시작 시 방화벽 목록도 로드
_pollTimer = setInterval(pollState, 5000);
