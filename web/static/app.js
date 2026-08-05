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
  window.fetch = function (input, init) {
    // 원격 접속(0.0.0.0 바인드)이면 모든 /api 호출에 토큰 헤더를 붙인다.
    // 서버가 페이지 셸에 심어 준 값이며, 로컬 전용 배포에서는 빈 문자열이라
    // 헤더를 붙이지 않는다.
    var tok = window._API_TOKEN || "";
    if (tok && typeof input === "string" &&
        (input.indexOf("/api/") === 0 ||
         input.indexOf(location.origin + "/api/") === 0)) {
      init = init || {};
      var h = new Headers(init.headers || {});
      h.set("X-API-Token", tok);
      init.headers = h;
    }
    return origFetch.call(this, input, init).then(function (r) {
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
  window._ndReadOnly = true;      // 자동 저장 등 쓰기 동작을 스스로 멈추기 위한 플래그
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
  window._ndReadOnly = false;
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
    case "diagnose-fw": diagnoseFirewall(nid); break;
    case "terminal-fw": openTerminal(nid, "firewall"); break;
    case "delete-fw": deleteFirewall(nid); break;
    case "diagnose-server": diagnoseServer(nid); break;
    case "explain-facility": explainFacility(id); break;   // id는 IP 문자열(정수 아님)
    case "snmp-probe-fw": snmpProbeFirewall(nid); break;
    case "hw-detail":
      e.preventDefault();
      showHwDetail(nid, btn.getAttribute("data-hw"));
      break;
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
      _setVal("ac-timezone", d.display_timezone || "America/New_York");
      _setChk("ac-snmp-enabled", d.snmp_enabled !== false);
      _setVal("ac-metrics-minutes", d.metrics_poll_minutes || "5");
      _setVal("ac-status-minutes", d.status_poll_minutes || "10");
      _setVal("ac-alert-cpu", d.alert_cpu_pct != null ? d.alert_cpu_pct : "80");
      _setVal("ac-alert-mem", d.alert_mem_pct != null ? d.alert_mem_pct : "80");
      _setVal("ac-alert-sessions", d.alert_sessions != null ? d.alert_sessions : "0");
      // 커뮤니티는 자격증명이라 서버가 값을 안 내려준다 — 저장 여부만 안내한다.
      _setVal("ac-snmp-community", "");
      var sc = document.getElementById("ac-snmp-community");
      if (sc) sc.placeholder = d.snmp_has_community ? "저장됨 (변경 시에만 입력)" : "public";
      _applyTimezone(d);            // 표시 즉시 반영
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
        // 저장된 인증정보가 있을 때만 삭제 버튼을 보인다(비우고 저장해도 기존 유지라
        // 지금까지는 UI로 지울 방법이 없었다)
        var ca = document.getElementById("btn-em-clear-auth");
        if (ca) ca.hidden = !e.has_auth;
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
  var emClear = document.getElementById("btn-em-clear-auth");
  if (emClear) emClear.addEventListener("click", function () {
    if (!confirm("저장된 SMTP 인증정보를 삭제할까요?\n(이후 인증 없이 발송을 시도합니다)")) return;
    var tr = document.getElementById("em-test-result");
    fetch("/api/settings/email", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        enabled: _chk("em-enabled"), smtp_host: _val("em-host", ""), smtp_port: _val("em-port", "25"),
        smtp_from: _val("em-from", ""), email_to: _val("em-to", ""), min_sev: _val("em-sev", "warning"),
        smtp_user: "", smtp_pass: "", clear_auth: true,
      }),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) {
        _setVal("em-user", ""); _setVal("em-pass", "");
        emClear.hidden = true;
        if (tr) { tr.textContent = "SMTP 인증정보를 삭제했습니다."; tr.style.color = "#15803d"; }
      } else if (tr) { tr.textContent = res.error || "삭제 실패"; tr.style.color = "#991b1b"; }
    }).catch(function () { if (tr) tr.textContent = "삭제 오류"; });
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
      display_timezone: _val("ac-timezone", "America/New_York"),
      snmp_enabled: _chk("ac-snmp-enabled"),
      metrics_poll_minutes: _val("ac-metrics-minutes", "5"),
      status_poll_minutes: _val("ac-status-minutes", "10"),
      alert_cpu_pct: _val("ac-alert-cpu", "80"),
      alert_mem_pct: _val("ac-alert-mem", "80"),
      alert_sessions: _val("ac-alert-sessions", "0"),
      snmp_community: _val("ac-snmp-community", ""),
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
      if (!r) return;
      closeModal("modal-auto-collect");
      // 시간대를 바꿨으면 표시 시각을 즉시 다시 그린다(새로고침 없이)
      _TZ.zone = body.display_timezone || _TZ.zone;
      pollState(); loadServers(); loadFirewalls();
      alert("자동화 설정이 저장되었습니다.");
    }).catch(function (e) { console.error(e); alert("서버 오류"); });
  });
})();

// 장비 일괄 등록(IP/SUBNET/HOSTNAME 통합 엑셀) UI는 제거됐다 — 탭별 '엑셀 등록'
// (스위치·서버·방화벽 각각)으로 대체. 바인딩할 버튼이 없어 죽은 코드였다.

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

// 서버 사양(CPU·메모리·디스크) 엑셀 일괄 등록 — IP로 **이미 등록된 서버에만** 매칭.
// 응답 형식(matched/unmatched)이 등록용(imported/skipped)과 달라 별도 바인더로 둔다.
(function () {
  var btn = document.getElementById("btn-server-import-specs");
  var inp = document.getElementById("server-import-specs-file");
  if (!btn || !inp) return;
  btn.addEventListener("click", function () { inp.click(); });
  inp.addEventListener("change", function () {
    if (!inp.files.length) return;
    var fd = new FormData();
    fd.append("file", inp.files[0]);
    fetch("/api/servers/import-specs", { method: "POST", body: fd })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (res.ok) {
          alert("서버 사양 반영 완료: " + res.matched + "대 반영" +
            (res.unmatched ? " / 등록 안 된 IP " + res.unmatched + "건(건너뜀)" : "") +
            (res.skipped ? " / 형식 오류 " + res.skipped + "건" : "") +
            " / 전체 " + res.total + "행");
          if (typeof loadServers === "function") loadServers();
        } else alert(res.error || "반영 실패");
        inp.value = "";
      }).catch(function (e) { console.error(e); alert("서버 오류"); inp.value = ""; });
  });
})();

// 테이블 검색창 HTML 생성 헬퍼
function _searchBox(targetId, placeholder) {
  return "<input class='tbl-search' data-target='" + targetId + "' placeholder='" +
    placeholder + "' style='margin-bottom:8px;padding:5px 9px;width:240px;" +
    "border:1px solid #cbd5e1;border-radius:4px;font-size:13px'>";
}

// ─── 페이지 공통 툴바 보조 동작 ──────────────────────────────────
(function () {
  // 스위치 현황: '+ 스위치 추가'·'📥 엑셀 등록' — 현황판의 기존 모달/입력을 재사용
  var add = document.getElementById("btn-sw-add");
  if (add) add.addEventListener("click", function () {
    var b = document.getElementById("btn-add-manual");
    if (b) b.click();
  });
  var imp = document.getElementById("btn-sw-import");
  if (imp) imp.addEventListener("click", function () {
    var inp = document.getElementById("excel-file-input");
    if (inp) inp.click();
  });

  // 서버실 현황: 정보 수집(서버실 장비 일괄) / 전체 진단
  var rc = document.getElementById("btn-room-collect");
  if (rc) rc.addEventListener("click", function () {
    var sw = (_switches || []).filter(function (s) { return s.room_rack; });
    var fw = (_firewalls || []).filter(function (f) { return f.room_rack; });
    var sv = (_servers || []).filter(function (s) { return s.room_rack; });
    var total = sw.length + fw.length + sv.length;
    if (!total) { alert("서버실(위치 A09U27 형식)에 등록된 장비가 없습니다."); return; }
    if (!confirm("서버실 장비 " + total + "대를 저장된 계정으로 재수집합니다.\n" +
                 "(스위치 " + sw.length + " · 방화벽 " + fw.length + " · 서버 " + sv.length + ")\n계속할까요?")) return;
    // 방화벽 → (끝나면) 서버 순서로 하나씩 돌린다.
    // 예전엔 둘을 동시에 시작하고 같은 #room-progress에 각자 써서 진행률이 서로
    // 덮였고, 어느 쪽 진행인지 알 수 없었다.
    function _roomServers() {
      if (!sv.length) return;
      fetch("/api/servers/collect-all", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ids: sv.map(function (s) { return s.id; })}),
      }).then(function () {
        pollProgress("/api/servers/collect-all/status", "room-progress", loadServers,
          "/api/servers/collect-all/stop", loadServers);
      }).catch(function () {});
    }
    if (fw.length) {
      fetch("/api/firewalls/collect-all", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ids: fw.map(function (f) { return f.id; })}),
      }).then(function () {
        pollProgress("/api/firewalls/collect-all/status", "room-progress", function () {
          loadFirewalls();
          _roomServers();          // 방화벽이 끝난 뒤 서버 수집 시작
        }, "/api/firewalls/collect-all/stop", loadFirewalls);
      }).catch(function () { _roomServers(); });
    } else {
      _roomServers();
    }
    if (sw.length) {
      // 스위치는 계정 입력이 필요 — 공통 일괄 수집 모달로 안내
      alert("스위치 " + sw.length + "대는 계정이 필요합니다. 스위치 현황 탭에서 체크 후 '정보 수집'을 사용하세요.");
    }
  });
  // 서버실 전체 진단 — 이 화면의 장비만 대상으로, 진행바도 이 화면에 그린다.
  // 예전엔 스위치 탭의 '전체 진단' 버튼을 대리 클릭해서 (a) 서버실 소속이 아닌
  // 전체 스위치를 진단하고 (b) 서버실의 서버·방화벽은 하나도 진단하지 않으며
  // (c) 진행바가 스위치 탭에만 그려져 이 화면엔 아무 표시도 없었다.
  var rd = document.getElementById("btn-room-diagnose");
  if (rd) rd.addEventListener("click", function () {
    var fw = (_firewalls || []).filter(function (f) { return f.room_rack; });
    var sv = (_servers || []).filter(function (s) { return s.room_rack; });
    if (!fw.length && !sv.length) {
      alert("서버실에 등록된 서버·방화벽이 없습니다.\n" +
            "스위치 진단은 스위치 현황 탭의 '전체 진단'을 사용하세요.");
      return;
    }
    if (!confirm("서버실 장비를 진단합니다(수집하지 않음).\n" +
                 "방화벽 " + fw.length + " · 서버 " + sv.length + "\n계속할까요?")) return;
    function _roomDiagServers() {
      if (!sv.length) return;
      fetch("/api/servers/diagnose-all", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ids: sv.map(function (s) { return s.id; })}),
      }).then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
        .then(function (res) {
          if (!res.ok) { alert((res.b && res.b.error) || "서버 진단 시작 실패"); return; }
          pollProgress("/api/servers/collect-all/status", "room-progress", loadServers,
            "/api/servers/collect-all/stop", loadServers);
        }).catch(function () {});
    }
    if (fw.length) {
      fetch("/api/firewalls/diagnose-all", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ids: fw.map(function (f) { return f.id; })}),
      }).then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
        .then(function (res) {
          if (!res.ok) { alert((res.b && res.b.error) || "방화벽 진단 시작 실패"); return; }
          pollProgress("/api/firewalls/diagnose-all/status", "room-progress", function () {
            loadFirewalls();
            _roomDiagServers();
          }, null, loadFirewalls);
        }).catch(function () { _roomDiagServers(); });
    } else {
      _roomDiagServers();
    }
  });
})();

// ─── 현황 페이지 다운로드: 버튼 클릭 → 형식 선택 팝업 → 저장 ─────
var _exportKind = null;
document.addEventListener("click", function (e) {
  var b = e.target.closest(".nd-export");
  if (!b) return;
  _exportKind = b.getAttribute("data-export");
  if (!_exportKind) return;
  var t = document.getElementById("export-title");
  if (t) t.textContent = (b.getAttribute("data-label") || "목록") + " 다운로드";
  var csv = document.querySelector("input[name='export-fmt'][value='csv']");
  if (csv) csv.checked = true;                 // 기본 CSV
  openModal("modal-export");
});
// 파일 내려받기 공용 — window.location으로 바로 이동하면 서버가 404/500 JSON을
// 돌려줄 때 브라우저가 그 JSON으로 화면을 갈아치운다(열려 있던 탭·선택·미저장
// 토폴로지 편집 상태가 전부 사라짐). 먼저 받아보고 성공했을 때만 저장한다.
function downloadFile(url) {
  fetch(url).then(function (r) {
    if (!r.ok) {
      return r.json().catch(function () { return {}; }).then(function (b) {
        alert((b && b.error) || ("다운로드 실패 (HTTP " + r.status + ")"));
        return null;
      });
    }
    var name = "";
    var cd = r.headers.get("Content-Disposition") || "";
    var m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
    if (m) name = decodeURIComponent(m[1]);
    return r.blob().then(function (blob) { return { blob: blob, name: name }; });
  }).then(function (res) {
    if (!res) return;
    var a = document.createElement("a");
    var href = URL.createObjectURL(res.blob);
    a.href = href;
    a.download = res.name || "netdash-download";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(href); }, 10000);
  }).catch(function (e) { console.error(e); alert("다운로드 오류: " + e); });
}

(function () {
  var go = document.getElementById("btn-export-go");
  if (!go) return;
  go.addEventListener("click", function () {
    if (!_exportKind) return;
    var sel = document.querySelector("input[name='export-fmt']:checked");
    var fmt = sel ? sel.value : "csv";
    closeModal("modal-export");
    downloadFile("/api/export/" + encodeURIComponent(_exportKind) +
      "?format=" + encodeURIComponent(fmt));
  });
})();

// ─── 표 정렬(IP·위치 컬럼) ───────────────────────────────────────
// 헤더 클릭 1회=오름차순, 2회=내림차순. 화살표 표시 없이 클릭만으로 동작.
// 표가 다시 그려져도(수집·폴링) 마지막 정렬을 유지한다.
(function () {
  function ipToInt(s) {
    var m = String(s || "").match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
    if (!m) return -1;                       // IP 없는 행은 뒤로
    return ((+m[1]) * 16777216) + ((+m[2]) * 65536) + ((+m[3]) * 256) + (+m[4]);
  }
  // 위치: '1공장 Assembly(B02) 1층 TPS01', 'A09U27', 'RC_4F' 등 — 숫자는 자연 정렬
  function natKey(s) {
    return String(s || "").trim().toLowerCase()
      .replace(/\d+/g, function (n) { return n.padStart(8, "0"); });
  }
  function cellText(row, idx) {
    var c = row.cells[idx];
    return c ? (c.textContent || "").trim() : "";
  }
  function sortBy(tbl, idx, dir, mode) {
    var tb = tbl.tBodies[0];
    if (!tb) return;
    var rows = Array.prototype.slice.call(tb.rows).filter(function (r) {
      return r.cells.length > idx && !r.querySelector("td[colspan]");
    });
    if (rows.length < 2) return;
    rows.sort(function (a, b) {
      if (mode === "ip") return dir * (ipToInt(cellText(a, idx)) - ipToInt(cellText(b, idx)));
      var ka = natKey(cellText(a, idx)), kb = natKey(cellText(b, idx));
      // 빈 값은 항상 뒤로(정렬 방향과 무관)
      if (!ka && kb) return 1;
      if (ka && !kb) return -1;
      return dir * (ka < kb ? -1 : ka > kb ? 1 : 0);
    });
    rows.forEach(function (r) { tb.appendChild(r); });
  }
  function setup(tbl) {
    if (tbl.dataset.ndSort === "1") return;
    var ths = Array.prototype.slice.call(tbl.querySelectorAll("thead th"));
    if (!ths.length) return;
    tbl.dataset.ndSort = "1";
    ths.forEach(function (th, i) {
      if (th.id === "fac-sort-ip") return;          // 설비 IP는 자체 정렬 사용
      var t = (th.textContent || "").trim().toUpperCase();
      var mode = null;
      if (t === "IP" || t === "호스트" || t === "관리 IP" || t.indexOf("IP") === 0) mode = "ip";
      else if (t === "위치" || t === "랙" || t === "대역") mode = "text";
      // 장비를 성격별로 모아 보기 위한 정렬(서버·스위치 공통)
      else if (t === "MAC" || t === "OS" || t === "구분" || t === "연결 스위치" ||
               t === "벤더" || t === "HOSTNAME") mode = "text";
      if (!mode) return;
      th.style.cursor = "pointer";
      th.title = "클릭: 오름차순 / 다시 클릭: 내림차순";
      th.addEventListener("click", function (e) {
        if (e.target.closest(".col-resizer")) return;   // 폭 조절 핸들 클릭 제외
        // 같은 컬럼 재클릭이면 방향 반전, 다른 컬럼이면 오름차순부터
        var dir = (tbl._sortIdx === i && tbl._sortDir === 1) ? -1 : 1;
        tbl._sortIdx = i; tbl._sortDir = dir; tbl._sortMode = mode;
        sortBy(tbl, i, dir, mode);
      });
    });
    // 재렌더 후 마지막 정렬 유지
    var tb = tbl.tBodies[0];
    if (tb && window.MutationObserver) {
      var mo = new MutationObserver(function () {
        if (tbl._sortDir) {
          mo.disconnect();
          sortBy(tbl, tbl._sortIdx, tbl._sortDir, tbl._sortMode);
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
    // 저장 키에 컬럼 수를 포함한다. 폭은 컬럼 '인덱스'로 저장되므로 표에 컬럼이
    // 추가/삭제되면 예전 저장분이 통째로 밀려(예: 구6 폭이 새 6열에 적용) 표가
    // 어긋나고, col-sized(table-layout:fixed) 때문에 버튼 열까지 잘린다.
    // 컬럼 수가 바뀌면 다른 키가 되어 자동으로 무시된다.
    var baseKey = tableKey(tbl);
    var key = baseKey + ":c" + ths.length;
    try { localStorage.removeItem("nd_colw:" + baseKey); } catch (e) {}   // 구 형식 정리
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

// kind: "switch"(기본) | "firewall" | "server"
function openTerminal(targetId, kind) {
  kind = kind || "switch";
  var list = kind === "firewall" ? (_firewalls || [])
    : kind === "server" ? (_servers || []) : (_switches || []);
  var dev = list.find(function (s) { return s.id === targetId; });
  var addr = dev ? (dev.ip || dev.host || "") : "";
  var kindLabel = kind === "firewall" ? "방화벽" : kind === "server" ? "서버" : "스위치";
  var title = document.getElementById("term-title");
  if (title) {
    title.textContent = "💻 SSH 터미널 (" + kindLabel + ") — " +
      (dev ? (dev.name + (addr ? " (" + addr + ")" : "")) : ("#" + targetId));
  }
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
  var url = proto + "://" + location.host + "/ws/shell/" + kind + "/" + targetId +
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
      renderDetailSummary(ports, macs, arps, detail.env);
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

function renderDetailSummary(ports, macs, arps, env) {
  var el = document.getElementById("detail-summary");
  if (!el) return;
  renderDetailEnv(env);
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

// 환경 정보(온도·팬) 센서 목록 — 요약 줄 아래에 붙인다.
// 값이 없는 게 흔하므로(SNMP 미설정 / 이 MIB 미지원) 그럴 땐 영역을 통째로 숨긴다.
function renderDetailEnv(env) {
  var box = document.getElementById("detail-env");
  if (!box) return;
  var sensors = (env && env.sensors) || [];
  if (!sensors.length) { box.innerHTML = ""; box.style.display = "none"; return; }
  box.style.display = "";
  var rows = sensors.map(function (s) {
    var unit = s.type === "celsius" ? "°C" : (s.type === "rpm" ? " RPM" : "");
    var lvl = s.level || "";
    var color = lvl === "critical" ? "#b91c1c" : lvl === "warning" ? "#b45309" : "#334155";
    var val = (s.value === null || s.value === undefined) ? "-" : (s.value + unit);
    var st = s.status === "ok" ? "" :
      " <span class='status-badge' style='background:#fee2e2;color:#b91c1c'>" + escHtml(s.status) + "</span>";
    return "<tr><td>" + escHtml(s.name) + "</td>" +
      "<td style='color:" + color + ";font-weight:600'>" + escHtml(val) + "</td>" +
      "<td>" + escHtml(s.type) + st + "</td></tr>";
  }).join("");
  box.innerHTML =
    "<h4 style='margin:12px 0 6px'>환경 정보 (SNMP)</h4>" +
    "<table class='data-table'><thead><tr><th>센서</th><th>값</th><th>종류</th></tr></thead>" +
    "<tbody>" + rows + "</tbody></table>" +
    (env.updated ? "<p style='font-size:11px;color:#64748b;margin-top:6px'>수집: " +
      escHtml(env.updated) + "</p>" : "");
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

// 수집 상태 → 한글 표기(스위치·서버·방화벽 공용).
// 예전엔 스위치만 한글이고 서버·방화벽 표는 'collecting'/'done' 영문을 그대로
// 노출해 같은 상태가 화면마다 다르게 보였다.
function _statusKo(st) {
  return st === "done" ? "정상"
    : st === "collecting" ? "수집중"
    : st === "failed" ? "오류"
    : st === "unsupported" ? "미지원"
    : "미수집";
}


// ─── 상태 필터(4개 현황 공용) ─────────────────────────────────────
// 표의 '상태' 컬럼 값으로 걸러 본다. 빈 값이면 전체.
function _statusFilterValue(selId) {
  var el = document.getElementById(selId);
  return el ? (el.value || "") : "";
}
function _byStatusSel(rows, selId, getStatus) {
  var want = _statusFilterValue(selId);
  if (!want) return rows;
  return (rows || []).filter(function (r) {
    var st = (getStatus ? getStatus(r) : r.status) || "new";
    // 'new'는 미수집(빈 값·pending 포함)
    if (want === "new") return !(st === "done" || st === "collecting" || st === "failed");
    return st === want;
  });
}
// 셀렉트 변경 시 각 표를 다시 그린다.
(function () {
  var wire = [
    ["status-filter-sw", function () { pollState(); }],
    ["status-filter-srv", function () { renderServers(); }],
    ["status-filter-fw", function () { loadFirewalls(); }],
    ["status-filter-fac", function () { _renderFacilityRows(); }],
  ];
  wire.forEach(function (w) {
    var el = document.getElementById(w[0]);
    if (el) el.addEventListener("change", w[1]);
  });
})();

// ─── 표 공용 셀(스위치·서버·방화벽·설비 동일 표기) ────────────────
// 화면마다 다른 배지·이모지·색을 쓰던 것을 하나로 모았다.
function _statusCls(st) {
  // CSS에 정의된 클래스만 쓴다(--done 은 존재하지 않는다 → --ok)
  return st === "failed" ? "critical"
    : st === "done" ? "ok"
    : st === "collecting" ? "collecting"
    : "new";
}

// 수집 상태 배지(+실패 사유). 4개 현황 화면 공용.
function statusBadge(status, lastError) {
  var h = "<span class='status-badge status-badge--" + _statusCls(status) + "'>" +
    escHtml(_statusKo(status)) + "</span>";
  if (!lastError) return h;
  if (status === "failed") {
    return h + "<div class='cell-sub cell-sub--err'>" + escHtml(lastError) + "</div>";
  }
  // 도달은 했지만 일부를 못 가져온 경우(예: SSH 인증 실패로 사양 미수집).
  // 예전엔 status==='failed'일 때만 사유를 보여줘서, 화면은 '정상'인데 사양만
  // 비어 있고 **이유가 어디에도 안 보였다.** '부분 수집'으로 함께 알린다.
  return h + " <span class='status-badge status-badge--warning' " +
    "title='" + escHtml(lastError) + "'>부분 수집</span>" +
    "<div class='cell-sub cell-sub--warn'>" + escHtml(lastError) + "</div>";
}

// 도달성(연결 상태) 배지 — 이모지 없이 글씨체 통일.
function reachBadge(reachable) {
  if (reachable === true) return "<span class='status-badge status-badge--ok'>연결됨</span>";
  if (reachable === false) {
    return "<span class='status-badge status-badge--critical' " +
      "title='도달성 감시: 관리 포트 TCP 응답 없음'>끊김</span>";
  }
  return "<span class='status-badge status-badge--new' title='아직 확인되지 않음'>확인 중</span>";
}

// 경보 배지 — 포트 flapping/loop 감지 결과. 전원 차단은 '상태'(도달 불가)로 나온다.
function alertBadge(alert) {
  if (!alert || alert === "none") {
    return "<span class='cell-none' title='정상 — 포트 flapping/loop 이벤트 없음'>-</span>";
  }
  var ko = alert === "critical" ? "LOOP" : alert === "warning" ? "FLAP" : alert;
  return "<span class='status-badge status-badge--" + escHtml(alert) + "' " +
    "title='포트 로그 분석 결과(flapping/loop). 장비 전원·회선 장애는 상태 컬럼에 표시됩니다'>" +
    escHtml(ko) + "</span>";
}

// 위치 셀 — 아이콘·파란색 강조 없이 본문과 같은 글씨. 원문 위치는 보조 줄로.
function locationCell(dev) {
  var raw = (dev.location || "").trim();
  // 서버실 랙 위치는 화면마다 'D10랙 U40' 같은 라벨로 제각각 보였다 →
  // **서버실**로 통일 표기하고 원문 코드(D10U40)를 옆에 병기한다.
  if (dev.room_rack || /^[A-Za-z]{1,3}\d{1,3}\s*U\d{1,3}(\s*-\s*U?\d{1,3})?$/.test(raw)) {
    var code = raw || dev.room_label || "";
    return "서버실" + (code ? " <span class='cell-inline'>(" + escHtml(code) + ")</span>" : "");
  }
  if (dev.tps_location) {
    return escHtml(dev.tps_location) +
      (raw ? "<div class='cell-sub'>" + escHtml(raw) + "</div>" : "");
  }
  return raw ? escHtml(raw) : "<span class='cell-none'>-</span>";
}

// 호스트네임 셀 — 이름 컬럼을 없앴으므로, 미수집 장비는 등록 이름으로 대체 표기한다
// (hostname은 수집에 성공해야 채워져서, 그대로 두면 IP로만 구분해야 한다).
function hostnameCell(dev) {
  if (dev.hostname) return "<strong>" + escHtml(dev.hostname) + "</strong>";
  return "<strong>" + escHtml(dev.name || "-") + "</strong>" +
    "<div class='cell-sub' title='수집에 성공하면 실제 호스트네임으로 바뀝니다'>등록 이름</div>";
}

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
  if (ex) ex.addEventListener("click", function () { downloadFile("/api/serverroom/export"); });
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
      "<span>방화벽 · " + _statusKo(f.status) + "</span></div>" +
    "<div class='sw-card__actions'>" +
      "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' data-action='detail-fw' data-id='" + f.id + "'>상세</button> " +
      "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' data-action='delete-fw' data-id='" + f.id + "'>삭제</button>" +
    "</div></div>";
}

// 서버 카드(서버실 그리드용) — 스위치/방화벽 카드와 동일 골격.
function _srvCardHTML(s) {
  // CSS가 정의한 상태 어휘는 ok/warning/critical/new/collecting 이다.
  // 예전엔 'done'을 써서(존재하지 않는 클래스) 컬러바·상태 dot이 안 보였고,
  // 미수집(new)도 정상 카드처럼 보였다.
  var sc = (s.reachable === false || s.status === "failed") ? "critical"
    : s.status === "collecting" ? "collecting"
    : (!s.status || s.status === "new") ? "new" : "ok";
  var loc = s.room_label ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>🗄 " + escHtml(s.room_label) + "</span>" : "";
  return "<div id='srvcard-" + s.id + "' class='sw-card sw-card--" + sc + "' title='클릭하면 이 서버 재수집'>" +
    "<div class='sw-card__icon'><div class='sw-icon'>🖥</div></div>" +
    "<div class='sw-card__name'>🖥 " + escHtml(s.name) + "</div>" +
    "<div class='sw-card__meta'><span>" + escHtml(s.ip) + "</span>" + loc +
      "<span style='font-size:10px'>" + escHtml((s.os_type || "linux")) + " · 서버</span></div>" +
    "<div class='sw-card__status'><span class='dot dot--" + sc + "'></span>" +
      "<span>서버 · " + _statusKo(s.status) + "</span></div>" +
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
  // {rack: {unit: device}} — 다중 U 장비는 시작 유닛에 두고, 나머지 유닛은
  // spans에 '주인 유닛'을 적어 빈 칸으로 그리지 않는다(한 덩어리로 보이게).
  var racks = {}, spans = {}, conflicts = [];
  function _put(d) {
    var rk = d.o.room_rack, u = d.o.room_unit;
    if (!rk || !u) return;
    var h = Math.max(1, _num(d.o.room_height) || 1);
    var slot = (racks[rk] = racks[rk] || {});
    var span = (spans[rk] = spans[rk] || {});
    // 겹치면 장비를 통째로 빠뜨리면 안 된다. 예전에는 조용히 건너뛰어서,
    // 높이를 잘못 저장하는 순간 장비가 랙뷰에서 사라져 '삭제된 것처럼' 보였다.
    // → 들어가는 만큼만 줄여 배치하고, 시작 유닛까지 이미 찼으면 랙 아래에
    //   '위치 겹침'으로 드러내 사용자가 고칠 수 있게 한다.
    var fit = 0;
    for (var x = u; x < u + h; x++) {
      if (slot[x] || span[x] != null) break;
      fit++;
    }
    if (!fit) { d.h = h; conflicts.push(d); return; }
    d.h = fit;
    d.clipped = fit < h;
    slot[u] = d;
    for (var y = u + 1; y < u + fit; y++) span[y] = u;
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
    var map = racks[rk], span = spans[rk] || {};
    var maxU = RACK_U;
    Object.keys(map).forEach(function (u) {
      var top = +u + Math.max(1, map[u].h || 1) - 1;
      if (top > maxU) maxU = top;
    });
    var slots = "";
    for (var u = maxU; u >= 1; u--) {
      if (span[u] != null) continue;          // 위 장비가 차지 중 — 칸을 만들지 않는다
      var d = map[u];
      if (d) {
        var k = _roomKind(d);
        var obj = d.o, isFw = d.k === "fw", isSrv = d.k === "srv";
        var h = Math.max(1, d.h || 1);
        var down = obj.status === "failed" || obj.reachable === false;
        var act = isFw ? ("data-action='detail-fw' data-id='" + obj.id + "'")
                       : isSrv ? ""   // 서버는 랙뷰에서 클릭 상세 없음(서버 현황 탭에서 관리)
                       : ("data-action='detail-switch' data-payload='" + payloadAttr((obj)) + "'");
        var uLabel = h > 1 ? ("U" + u + "-U" + (u + h - 1)) : ("U" + u);
        if (d.clipped) uLabel = "⚠ " + uLabel;
        slots += "<div class='ru ru--dev" + (h > 1 ? " ru--multi" : "") + "' " + act +
          " data-rack='" + escHtml(rk) + "' data-unit='" + u + "' data-h='" + h + "'" +
          " data-kind='" + d.k + "' data-devid='" + obj.id + "'" +
          " style='background:" + k.c + "22;border-left:4px solid " + k.c +
          ";--ru-span:" + h + "'" +
          " title='" + escHtml((obj.name || "") + " · " + (obj.ip || obj.host || "") +
                               " · " + uLabel + (h > 1 ? (" (" + h + "U)") : "")) + "'>" +
          "<span class='ru__u'>" + uLabel + "</span>" +
          "<span class='ru__tag' style='background:" + k.c + "'>" + (k.t || "") + "</span>" +
          "<span class='ru__name'>" + (down ? "🔴 " : "") + escHtml(obj.name || "") +
            (h > 1 ? " <span class='ru__h'>" + h + "U</span>" : "") + "</span>" +
          // 아래쪽 손잡이를 잡고 끌면 아래 유닛까지 늘어난다(랙 실장 높이 지정)
          "<span class='ru__grip' title='드래그해서 장비 높이(U) 조절'></span>" +
          "</div>";
      } else {
        slots += "<div class='ru ru--empty' data-rack='" + escHtml(rk) + "' data-unit='" + u +
          "'><span class='ru__u'>U" + u + "</span></div>";
      }
    }
    return "<div class='rackframe'>" +
      "<div class='rackframe__label'>🗄 " + escHtml(rk) + " <span style='font-size:10px;color:#94a3b8'>(" + maxU + "U)</span></div>" +
      "<div class='rackframe__slots'>" + slots + "</div></div>";
  }

  var legend = "<div class='rack-legend'><span class='rack-legend__how'>" +
    "장비를 끌어 옮기면 위치가 저장되고, 아래 모서리를 끌면 높이(U)가 조절됩니다" +
    "</span>" +
    Object.keys(_RACK_KIND).filter(function (k) { return k !== "_" && _RACK_KIND[k].t; }).map(function (k) {
      return "<span><i style='background:" + _RACK_KIND[k].c + "'></i>" + _RACK_KIND[k].t + "</span>";
    }).join("") + "</div>";

  // 자리가 겹쳐 랙에 못 그린 장비 — 화면에서 사라지지 않게 따로 보여준다.
  var conflictHtml = !conflicts.length ? "" :
    "<div class='rack-conflicts'><b>⚠ 위치 겹침 " + conflicts.length + "대</b> — " +
    "다른 장비가 이미 쓰는 유닛입니다. 위치(U)를 고쳐주세요: " +
    conflicts.map(function (d) {
      return escHtml((d.o.name || "") + " (" + (d.o.location || "") + ")");
    }).join(", ") + "</div>";

  // 보관본에만 있는 장비(유령) — 현황에서 삭제·재등록으로 사라진 장비를
  // 조용히 없애지 않고 드러낸다. "여기 있었는데 지금 현황에 없다"를 알려야
  // 사용자가 재등록 후 '업데이트'로 위치를 되살릴 수 있다.
  var ghostHtml = !(_roomGhosts && _roomGhosts.length) ? "" :
    "<div class='rack-conflicts' style='border-color:#94a3b8;color:#64748b'>" +
    "<b>👻 보관된 배치에만 있는 장비 " + _roomGhosts.length + "대</b> — 현황에서 삭제됐거나 " +
    "재등록 대기 중입니다. 같은 IP로 재등록하면 '🔄 업데이트'가 위치를 되살립니다: " +
    _roomGhosts.map(function (g) {
      return escHtml((g.name || g.ip) + " (" + (g.location || "") + ")");
    }).join(", ") + "</div>";

  host.innerHTML = legend + Object.keys(rows).sort().map(function (letter) {
    var racksHtml = rows[letter].sort().map(_rackHtml).join("");
    return "<div class='rack-group'><div class='rack-group__title'>🗄 " + escHtml(letter) +
      " 열</div><div class='rack-row rack-row--frames'>" + racksHtml + "</div></div>";
  }).join("") + conflictHtml + ghostHtml;
}

// ─── 랙 배치 저장/업데이트 ───────────────────────────────────────
// 랙뷰는 각 장비의 location에서 파생되므로, 장비를 삭제·재등록하면 위치가 같이
// 사라졌다("서버실이 자동 업데이트되며 삭제된다"). 배치를 스냅샷으로 보관하고
// '업데이트'가 위치 빈 장비에 IP 기준으로 되살린다.
var _roomGhosts = [];

function _loadRoomLayoutInfo() {
  fetch("/api/room/layout").then(function (r) { return r.json(); })
    .then(function (res) {
      if (!res.ok) return;
      _roomGhosts = res.ghosts || [];
      var el = document.getElementById("room-layout-info");
      if (el) {
        el.textContent = res.saved_at
          ? ("보관된 배치: " + (res.layout || []).length + "대 (저장: " +
             String(res.saved_at).slice(0, 16) + ")" +
             (_roomGhosts.length ? " · 현황에 없는 장비 " + _roomGhosts.length + "대" : ""))
          : "보관된 배치 없음 — '💾 배치 저장'을 누르면 장비 삭제·재등록에도 위치가 보존됩니다.";
      }
    }).catch(function () {});
}

(function () {
  var save = document.getElementById("btn-room-save-layout");
  if (save) save.addEventListener("click", function () {
    save.disabled = true;
    fetch("/api/room/layout/save", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        alert(res.ok ? ("현재 랙 배치 " + res.saved + "대를 보관했습니다.")
                     : (res.error || "저장 실패"));
        _loadRoomLayoutInfo();
      })
      .catch(function (e) { alert("저장 오류: " + e); })
      .then(function () { save.disabled = false; });
  });
  var upd = document.getElementById("btn-room-update-layout");
  if (upd) upd.addEventListener("click", function () {
    upd.disabled = true;
    fetch("/api/room/layout/restore", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (!res.ok) { alert(res.error || "업데이트 실패"); return; }
        var msg = "현황에서 다시 불러왔습니다.\n";
        msg += "· 위치 되살림: " + (res.applied || []).length + "대";
        if ((res.applied || []).length) {
          msg += " (" + res.applied.map(function (a) { return a.name || a.ip; }).join(", ") + ")";
        }
        msg += "\n· 이미 배치돼 있어 유지: " + (res.kept || 0) + "대";
        if ((res.ghosts || []).length) {
          msg += "\n· 현황에 없어 대기: " + res.ghosts.length + "대 (같은 IP로 재등록하면 복원됩니다)";
        }
        alert(msg);
        // 최신 현황으로 다시 그리기 — 이 버튼이 곧 '현황에서 정보 불러오기'다.
        if (typeof loadFirewalls === "function") loadFirewalls();
        if (typeof loadServers === "function") loadServers();
        pollState();
        _loadRoomLayoutInfo();
      })
      .catch(function (e) { alert("업데이트 오류: " + e); })
      .then(function () { upd.disabled = false; });
  });
  _loadRoomLayoutInfo();
})();

// ─── 랙 실장 높이(U) 드래그 조절 ─────────────────────────────────
// 장비 아래 모서리 손잡이를 잡고 아래로 끌면 그만큼 유닛을 더 차지한다.
// location을 "A09U13-U15" 형태로 저장하므로 새로고침해도 유지된다.
var _RU_H = 21;   // 슬롯 한 칸(20px) + gap(1px)

function _ruEndpoint(kind, id) {
  if (kind === "fw") return "/api/firewalls/" + id;
  if (kind === "srv") return "/api/servers/" + id;
  return "/api/switches/" + id;
}

// 랙 위치/높이 저장 PUT — 네트워크 단절 시 1회 자동 재시도.
// "TypeError: Failed to fetch"는 서버가 거절한 게 아니라 요청이 도달하기 전에
// 연결이 끊긴 것이다(순간 단절·서버 재시작·절전 복귀 등). location만 담은 PUT은
// 멱등이라 재시도가 안전한데, 예전엔 한 번 실패하면 변경을 그냥 버리고
// 원인 불명의 TypeError만 띄웠다.
function _ruSavePut(kind, devId, loc, doneMsg) {
  function attempt(retryLeft) {
    return fetch(_ruEndpoint(kind, devId), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ location: loc }),
    }).then(function (r) {
      return r.json().catch(function () { return {}; })
        .then(function (b) { return { ok: r.ok, b: b }; });
    }).catch(function (err) {
      if (retryLeft > 0) {
        // 1초 뒤 한 번만 재시도 — 서버 재시작 직후 대부분 이 안에 살아난다.
        return new Promise(function (res) { setTimeout(res, 1000); })
          .then(function () { return attempt(retryLeft - 1); });
      }
      throw err;
    });
  }
  return attempt(1).then(function (res) {
    if (!res.ok) alert((res.b && res.b.error) || (doneMsg + " 실패"));
    // 성공·실패 모두 서버 상태로 다시 그린다(겹침 등은 서버 기준으로 확인)
    if (typeof loadFirewalls === "function") loadFirewalls();
    if (typeof loadServers === "function") loadServers();
    pollState();
  }).catch(function (err) {
    console.error(err);
    alert(doneMsg + " 오류 — 서버에 연결할 수 없습니다(재시도 1회 포함). " +
      "잠시 후 다시 시도하세요. 지금 화면의 배치는 저장되지 않았습니다.\n" +
      "(" + err + ")");
    // 저장 안 된 배치를 화면에 남겨두면 저장된 걸로 오해한다 — 서버 상태로 복원.
    if (typeof loadFirewalls === "function") loadFirewalls();
    if (typeof loadServers === "function") loadServers();
    pollState();
  });
}

function _ruLocation(rack, unit, h) {
  return h > 1 ? (rack + "U" + unit + "-U" + (unit + h - 1)) : (rack + "U" + unit);
}

document.addEventListener("mousedown", function (e) {
  var grip = e.target.closest(".ru__grip");
  if (!grip) return;
  var cell = grip.closest(".ru--dev");
  if (!cell) return;
  e.preventDefault();
  e.stopPropagation();          // 장비 상세가 열리지 않게

  var rack = cell.getAttribute("data-rack");
  var unit = parseInt(cell.getAttribute("data-unit"), 10);
  var kind = cell.getAttribute("data-kind");
  var devId = cell.getAttribute("data-devid");
  var startH = Math.max(1, parseInt(cell.getAttribute("data-h"), 10) || 1);
  var startY = e.clientY;
  var curH = startH;

  // 랙은 위가 U42, 아래가 U1이다. 손잡이는 장비 **아래쪽**에 있으므로 아래로 끌면
  // 아래 유닛(= 더 작은 번호)까지 차지한다 → 윗변(topU)은 그대로, 시작 유닛이 내려간다.
  // 예전에는 시작 유닛을 고정한 채 h만 키워, 화면은 아래로 늘어나는데 저장은
  // 위쪽(U13→U15)으로 됐다. 그래서 새로고침하면 장비가 위로 튀고, 위 장비와
  // 겹치면 랙뷰에서 아예 사라져(= 삭제된 것처럼) 보였다.
  var topU = unit + startH - 1;

  // 아래로 몇 칸까지 늘릴 수 있는지 — 바로 아래 빈 칸 수만큼만 허용한다.
  // (겹치도록 놔두면 저장 후 한 장비가 화면에서 사라진다)
  var freeBelow = 0;
  for (var sib = cell.nextElementSibling; sib; sib = sib.nextElementSibling) {
    if (!sib.classList.contains("ru--empty")) break;
    freeBelow++;
  }
  var maxH = Math.min(42, topU, startH + freeBelow);

  cell.classList.add("ru--resizing");
  document.body.classList.add("ru-resizing");

  function onMove(ev) {
    // 아래로 끌수록(+dy) 아래 유닛을 더 차지 → 높이 증가
    var dy = ev.clientY - startY;
    var h = Math.max(1, Math.min(maxH, startH + Math.round(dy / _RU_H)));
    if (h === curH) return;
    curH = h;
    cell.style.setProperty("--ru-span", h);
    cell.classList.toggle("ru--multi", h > 1);
    var lbl = cell.querySelector(".ru__u");
    var base = topU - h + 1;              // 아래로 늘어난 만큼 시작 유닛이 내려간다
    if (lbl) lbl.textContent = h > 1 ? ("U" + base + "-U" + topU) : ("U" + topU);
  }

  function onUp() {
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
    cell.classList.remove("ru--resizing");
    document.body.classList.remove("ru-resizing");
    if (curH === startH) return;                 // 변화 없음
    var loc = _ruLocation(rack, topU - curH + 1, curH);
    _ruSavePut(kind, devId, loc, "높이 저장");
  }

  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup", onUp);
});

// ─── 랙 장비 드래그 이동 ─────────────────────────────────────────
// 장비를 잡아 다른 유닛(다른 랙도 가능)으로 끌어다 놓으면 위치가 바로 저장된다.
// 손잡이(.ru__grip)는 높이 조절이므로 여기서 제외한다.

function _rackOccupancy(host) {
  // 화면에 그려진 것에서 '어느 랙의 어느 U가 찼는지'를 읽는다.
  // 서버 응답을 다시 조합하는 것보다 화면과 어긋날 여지가 없다.
  var occ = {};
  host.querySelectorAll(".rackframe").forEach(function (frame) {
    frame.querySelectorAll(".ru").forEach(function (cell) {
      var rk = cell.getAttribute("data-rack");
      var u = parseInt(cell.getAttribute("data-unit"), 10);
      if (!rk || !u) return;
      var o = (occ[rk] = occ[rk] || { maxU: 1, taken: {} });
      var h = Math.max(1, parseInt(cell.getAttribute("data-h"), 10) || 1);
      if (cell.classList.contains("ru--dev")) {
        for (var i = u; i < u + h; i++) o.taken[i] = cell.getAttribute("data-devid");
      }
      if (u + h - 1 > o.maxU) o.maxU = u + h - 1;
    });
  });
  return occ;
}

function _rackDropTarget(occ, rack, topU, h, selfId) {
  // topU를 장비 윗변으로 삼는다 — 커서가 가리킨 칸이 곧 장비의 맨 위 칸.
  var base = topU - h + 1;
  var o = occ[rack];
  if (!o || base < 1 || topU > o.maxU) return null;
  for (var u = base; u <= topU; u++) {
    if (o.taken[u] != null && o.taken[u] !== selfId) return null;   // 다른 장비가 이미 씀
  }
  return { rack: rack, unit: base, top: topU };
}

document.addEventListener("mousedown", function (e) {
  if (e.button !== 0) return;
  if (e.target.closest(".ru__grip")) return;          // 높이 조절 손잡이
  var cell = e.target.closest(".ru--dev");
  if (!cell) return;
  var host = cell.closest("#room-rack-view");
  if (!host) return;

  var kind = cell.getAttribute("data-kind");
  var devId = cell.getAttribute("data-devid");
  var h = Math.max(1, parseInt(cell.getAttribute("data-h"), 10) || 1);
  var fromRack = cell.getAttribute("data-rack");
  var fromUnit = parseInt(cell.getAttribute("data-unit"), 10);
  var startX = e.clientX, startY = e.clientY;
  var occ = null, ghost = null, target = null, moved = false;

  function clearHint() {
    host.querySelectorAll(".ru--drop-ok, .ru--drop-bad").forEach(function (c) {
      c.classList.remove("ru--drop-ok", "ru--drop-bad");
    });
  }

  function begin() {
    moved = true;
    occ = _rackOccupancy(host);
    ghost = cell.cloneNode(true);
    ghost.classList.add("ru--ghost");
    ghost.style.width = cell.offsetWidth + "px";
    ghost.style.height = cell.offsetHeight + "px";
    document.body.appendChild(ghost);
    cell.classList.add("ru--moving");
    document.body.classList.add("ru-moving");
  }

  function onMove(ev) {
    if (!moved) {
      // 클릭과 구분한다 — 살짝 흔들린 것으로 상세 팝업을 막으면 안 된다.
      if (Math.abs(ev.clientX - startX) < 4 && Math.abs(ev.clientY - startY) < 4) return;
      begin();
    }
    ev.preventDefault();
    ghost.style.left = (ev.clientX + 10) + "px";
    ghost.style.top = (ev.clientY - 8) + "px";

    // 유령은 pointer-events:none 이라 아래 칸이 그대로 잡힌다
    var under = document.elementFromPoint(ev.clientX, ev.clientY);
    var slot = under && under.closest ? under.closest(".ru") : null;
    clearHint();
    target = null;
    if (!slot || !host.contains(slot)) return;
    var rk = slot.getAttribute("data-rack");
    var u = parseInt(slot.getAttribute("data-unit"), 10);
    if (!rk || !u) return;
    target = _rackDropTarget(occ, rk, u, h, devId);
    if (!target) { slot.classList.add("ru--drop-bad"); return; }
    for (var i = target.unit; i <= target.top; i++) {
      var c = host.querySelector('.ru[data-rack="' + rk + '"][data-unit="' + i + '"]');
      if (c) c.classList.add("ru--drop-ok");
    }
  }

  function onUp() {
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup", onUp);
    if (!moved) return;                       // 그냥 클릭 — 상세 팝업은 그대로 열린다
    clearHint();
    if (ghost) ghost.remove();
    cell.classList.remove("ru--moving");
    document.body.classList.remove("ru-moving");
    // 드래그 직후의 click 한 번은 삼킨다(장비 상세가 딸려 열리지 않게).
    // 단 '방금 끈 그 장비'일 때만 삼킨다 — 무조건 삼키면, 드롭 뒤 click이 오지
    // 않은 경우 리스너가 남아 나중의 멀쩡한 클릭을 대신 잡아먹는다.
    var dragged = cell;
    document.addEventListener("click", function swallow(ce) {
      document.removeEventListener("click", swallow, true);
      if (ce.target.closest && ce.target.closest(".ru--dev") === dragged) {
        ce.stopPropagation();
      }
    }, true);
    if (!target) return;                      // 놓을 자리가 아님 — 원위치
    if (target.rack === fromRack && target.unit === fromUnit) return;
    var loc = _ruLocation(target.rack, target.unit, h);
    _ruSavePut(kind, devId, loc, "위치 저장");
  }

  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup", onUp);
});

function renderSwitchGrid(switches) {
  // 현황판 카드 선택(_bulkSel)에서 더 이상 존재하지 않는 id를 걷어낸다.
  // 예전엔 정리 코드가 없어, 스위치를 삭제하거나 구분을 Server/Firewall로 바꾸거나
  // 위치를 서버실로 지정해 목록에서 빠져도 선택이 남았다 → 버튼은 "정보 수집 (2)"
  // 인데 화면 체크는 1개, 실제 요청에는 없는 id가 실려 갔다.
  var _known = {};
  (_switches || []).forEach(function (s) { _known[s.id] = true; });
  if (Object.keys(_known).length) {
    Object.keys(_bulkSel).forEach(function (id) { if (!_known[id]) delete _bulkSel[id]; });
  }
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
    ? "<span class='sw-card__alert-badge badge--" + escHtml(sw.alert) + "'>" + (sw.alert === "critical" ? "⚠ LOOP" : "⚠ FLAP") + "</span>"
    : (sw.reachable === false
       ? "<span class='sw-card__alert-badge badge--critical reach-down' title='도달성 감시(TCP-22)에서 응답 없음'><span class='reach-dot'></span> 도달불가</span>"
       : "");

  var dotClass = sw.alert === "critical" ? "dot--critical"
    : sw.alert === "warning" ? "dot--warning"
    : sw.status === "done" ? "dot--ok"
    : sw.status === "collecting" ? "dot--collecting"
    : "dot--new";

  var statusLabel = _statusKo(sw.status);

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
                      exos: "extreme_exos", juniper: "juniper_junos", junos: "juniper_junos",
                      hp: "hp_procurve", hpe: "hp_procurve", procurve: "hp_procurve",
                      aruba_procurve: "hp_procurve", arubaos_switch: "aruba_osswitch",
                      aruba: "aruba_os", aruba_cx: "aruba_os", arubaos_cx: "aruba_os",
                      radware: "alteon" };
// 표기는 순수 벤더명만(OS 구분은 '버전' 컬럼이 담당: IOS-XE 17.x / NX-OS 9.x ...)
var _VENDOR_LABELS = { cisco_ios: "Cisco", cisco_nxos: "Cisco",
                       arista_eos: "Arista", extreme_exos: "Extreme",
                       juniper_junos: "Juniper", alteon: "Radware",
                       hp_procurve: "HP/Aruba", aruba_osswitch: "HP/Aruba",
                       aruba_os: "Aruba",
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

// 사용률 막대(방화벽 상세보기 전용) — 값이 없으면 '-'로 두고 막대를 그리지 않는다.
// (v6.25.0에서 방화벽 표의 대시보드를 걷어낼 때 실수로 같이 지워져 상세가 깨졌었다 —
//  테스트가 잡음. 상세보기가 쓰는 함수이므로 여기 남긴다.)
function _fwLvlColor(lvl) {
  return lvl === "critical" ? "#dc2626" : lvl === "warning" ? "#f59e0b" : "#16a34a";
}
function fwBar(label, pct, suffix) {
  if (pct === null || pct === undefined) {
    return "<div class='fw-tile__row'><b>" + escHtml(label) + "</b>" +
      "<div class='fw-bar'></div><span class='fw-tile__val'>-</span></div>";
  }
  var p = Math.max(0, Math.min(100, pct));
  var lvl = pct >= 90 ? "critical" : pct >= 80 ? "warning" : "normal";
  return "<div class='fw-tile__row'><b>" + escHtml(label) + "</b>" +
    "<div class='fw-bar'><div class='fw-bar__fill' style='width:" + p + "%;" +
    "background:" + _fwLvlColor(lvl) + "'></div></div>" +
    "<span class='fw-tile__val'>" + escHtml(String(pct)) + (suffix || "%") + "</span></div>";
}

// 수명주기 배지 — 내장 표(작성 기준일 포함) 기반. 모르면 아무것도 안 붙인다.
function lifeBadge(entry) {
  if (!entry || !entry.status || entry.status === "unknown" || entry.status === "ok") return "";
  var color = entry.status === "expired" ? "background:#fee2e2;color:#b91c1c"
    : entry.status === "imminent" ? "background:#ffedd5;color:#c2410c"
    : "background:#fef3c7;color:#b45309";           // eoes_passed
  var label = entry.status === "expired" ? "지원 종료"
    : entry.status === "imminent" ? "EOS 임박" : "EoES 지남";
  return " <span class='status-badge' style='" + color + "' title='" +
    escHtml(entry.message || "") + "'>" + label + "</span>";
}

// 모델 셀 — get system status(SSH) 또는 REST에서 수집. 없으면 수집 안내.
function fwModelCell(f) {
  if (!f.fw_model) {
    return "<span class='cell-none' title='SSH 계정 또는 REST 토큰으로 수집하면 get system status에서 채워집니다'>-</span>";
  }
  return escHtml(f.fw_model) + lifeBadge(f.lifecycle && f.lifecycle.hw);
}

function fwVersionCell(f) {
  if (!f.fw_version) return "<span class='cell-none'>-</span>";
  return "<code>" + escHtml(f.fw_version) + "</code>" +
    lifeBadge(f.lifecycle && f.lifecycle.os);
}

// 온도 셀 — SNMP(ENTITY-SENSOR-MIB)로 읽은 최고 센서 온도.
// 값이 없는 게 정상인 경우가 많아(이 MIB 미지원 / SNMP 미설정) '-'에 사유를 달아둔다.
function tempCell(d) {
  var c = (d && d.temp_c !== undefined && d.temp_c !== null) ? d.temp_c : null;
  if (c === null) {
    return "<span class='cell-none' title='SNMP 환경 정보 없음 — 설정에서 SNMP 커뮤니티를 넣고 재수집하면 채워집니다. " +
      "장비가 ENTITY-SENSOR-MIB을 지원하지 않으면 계속 비어 있습니다'>-</span>";
  }
  var lvl = d.temp_level || "normal";
  var color = lvl === "critical" ? "#b91c1c" : lvl === "warning" ? "#b45309" : "#166534";
  var mark = lvl === "critical" ? " ⚠" : "";
  var tip = "최고 센서 온도" + (d.env_fan_count ? " · 팬 " + d.env_fan_count + "개" : "") +
    (d.env_updated ? " · " + String(d.env_updated).slice(0, 16) : "");
  return "<span style='color:" + color + ";font-weight:600' title='" + escHtml(tip) + "'>" +
    escHtml(String(c)) + "°C" + mark + "</span>";
}

function renderSwitchTable(switches) {
  // 서버(구분=Server)는 스위치 현황에서 제외 — 서버 현황/서버실 현황에만 표시
  switches = _applySwSearch((switches || []).filter(function (s) {
    return (s.device_type || "") !== "Server";
  }));
  var tbody = document.getElementById("switch-table-body");
  if (!tbody) return;  // 요소 부재 시 조기 반환(가드 역전 → tbody.innerHTML 크래시 방지)
  if (!switches.length) {
    tbody.innerHTML = "<tr><td colspan='14' style='color:#64748b'>조건에 맞는 스위치가 없습니다. (검색어를 지우면 전체 표시)</td></tr>";
    var allChk0 = document.getElementById("sw-check-all");
    if (allChk0) allChk0.checked = false;
    _updateBulkDeleteBtn();
    return;
  }
  switches = _byStatusSel(switches, "status-filter-sw");
  tbody.innerHTML = switches.map(function(sw) {
    var locCell = locationCell(sw);
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
      // 구분을 맨 앞에, 그다음 호스트네임(이름 컬럼 제거 — 대부분 같은 값이었다).
      // 미수집 장비는 hostname이 비므로 hostnameCell이 등록 이름으로 대체 표기한다.
      "<td>" + kindLabel + "</td>" +
      "<td>" + hostnameCell(sw) + "</td>" +
      "<td><code>" + escHtml(sw.ip) + "</code></td><td>" +
      // 서버가 판별한 제조사를 우선한다. JS 표(_VENDOR_LABELS)는 예전 응답 호환용
      // 폴백으로만 남긴다 — 판별 규칙이 둘로 갈라지면 표·엑셀 표기가 달라진다.
      escHtml(sw.manufacturer || _vendorLabel(sw.vendor)) +
      (sw.product ? "<div class='cell-sub'>" + escHtml(sw.product) + "</div>" : "") +
      _nbrSrcBadge(sw) + "</td><td>" +
      (sw.model ? escHtml(sw.model)
        : "<span class='cell-none' title='이 버전으로 한 번 재수집하면 show version/show switch에서 자동으로 채워집니다'>-</span>") + "</td><td>" +
      (sw.os_version ? escHtml(sw.os_version)
        : "<span class='cell-none' title='이 버전으로 한 번 재수집하면 자동으로 채워집니다'>-</span>") + "</td><td>" +
      (sw.serial ? "<code style='font-size:11px'>" + escHtml(sw.serial) + "</code>"
        : "<span class='cell-none' title='재수집하면 show version/inventory에서 자동으로 채워집니다'>-</span>") + "</td><td>" +
      locCell + "</td><td>" + tempCell(sw) + "</td><td>" +
      statusBadge(sw.status, sw.last_error) + "</td><td>" +
      alertBadge(sw.alert) +
      "</td><td>" + fmtTime(sw.last_collected) + "</td>" +
      "<td>" +
      // 상세보기 — 현황판 카드에만 있던 걸 여기에도 둔다(같은 detail-switch 액션 재사용).
      // 미수집 장비도 막지 않는다: 패널이 "수집된 정보 없음"을 보여주는 편이,
      // 버튼이 아예 없어서 "왜 여긴 상세보기가 없지"가 되는 것보다 낫다.
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "title='포트·MAC·ARP·설정 등 수집된 상세 정보 보기' " +
      "data-action='detail-switch' data-payload='" + payloadAttr((sw)) + "'>상세보기</button> " +
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
  // _tblSel에 있으나 **등록 목록 전체**에 없는 id만 정리(삭제된 스위치).
  // 예전엔 검색으로 걸러진 목록(switches)을 기준으로 지워서, 검색어를 치는
  // 순간 화면 밖 선택이 사라지고 검색어를 지워도 돌아오지 않았다
  // (여러 번 검색하며 체크 → 마지막에 일괄 수집이 표준 조작인데 되돌릴 수 없음).
  var known = {};
  (_switches || []).forEach(function (s) { known[s.id] = true; });
  if (Object.keys(known).length) {
    Object.keys(_tblSel).forEach(function (id) { if (!known[id]) delete _tblSel[id]; });
  }
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

// FortiGate SNMP 확인 — 어떤 OID가 실제로 응답하는지 원문으로 보여준다.
// 실장비 없이 작성한 OID가 맞는지 눈으로 확인하기 위한 경로(진단 팝업 재사용).
function snmpProbeFirewall(id) {
  var out = document.getElementById("diag-result");
  openModal("modal-diagnose");
  if (out) out.textContent = "SNMP 조회 중... (최대 25초)";
  fetch("/api/firewalls/" + id + "/snmp-probe", { method: "POST" })
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (!out) return;
      if (!res.ok) { out.textContent = "SNMP 확인 실패: " + (res.error || ""); return; }
      var p = res.probe || {}, L = [];
      L.push("FortiGate SNMP 확인 — " + (res.host || ""));
      L.push("");
      L.push("── 주요 OID 응답 ──");
      (p.scalars || []).forEach(function (s) {
        L.push("  " + s.oid + "  =  " + s.value);
      });
      var sub = p.subtree || [];
      L.push("");
      L.push("── 시스템 정보 하위 트리 (" + sub.length + "건) ──");
      if (!sub.length) L.push("  (없음 — 이 장비는 Fortinet 전용 MIB을 노출하지 않거나 접근이 막혀 있습니다)");
      sub.forEach(function (s) { L.push("  " + s.oid + "  =  " + s.value); });
      L.push("");
      L.push("※ '(응답 없음)'인 항목은 이 장비/펌웨어가 해당 OID를 주지 않는다는 뜻입니다.");
      out.textContent = L.join("\n");
    })
    .catch(function (e) { if (out) out.textContent = "조회 오류: " + e; });
}

// 방화벽 진단 — 관리 포트/SSH 도달성 + 저장 계정 인증(스위치 진단 팝업 재사용)
function diagnoseFirewall(id) {
  var out = document.getElementById("diag-result");
  openModal("modal-diagnose");
  if (out) out.textContent = "진단 중... (관리 포트 도달성 → 저장 계정 인증, 최대 20초)";
  fetch("/api/firewalls/" + id + "/diagnose", { method: "POST" })
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (!out) return;
      if (!res.ok) { out.textContent = "진단 실패: " + (res.error || ""); return; }
      var d = res.diag || {};
      out.textContent =
        d.name + " (" + d.host + ") · 벤더 " + (d.vendor || "-") + "\n" +
        (d.source_ip ? "출발지 IP: " + d.source_ip + "\n" : "") +
        "\n관리 포트 TCP-" + d.mgmt_port + ": " + (d.tcp_mgmt ? "도달" : "실패") + "\n" +
        "SSH TCP-22: " + (d.tcp_ssh ? "도달" : "실패") + "\n" +
        "저장된 자격증명: " +
          (d.has_login ? "계정/비밀번호" : d.has_token ? "API 토큰만" : "없음") + "\n" +
        "인증 확인: " + (d.auth_ok ? "성공" : (d.has_token || d.has_login ? "실패" : "미검증(자격증명 없음)")) + "\n" +
        (d.detail ? "\n상세: " + d.detail + "\n" : "") +
        (d.has_token && !d.has_login
          ? "\n※ API 토큰은 수집에만 쓰입니다. SSH 터미널(💻)을 쓰려면 수집 팝업에서 계정/비밀번호를 저장하세요.\n"
          : "") +
        (!d.tcp_mgmt ? "\n※ 관리 포트가 막혔습니다. 방화벽 정책·관리 인터페이스 허용 IP를 확인하세요.\n" : "");
    })
    .catch(function (e) { if (out) out.textContent = "진단 오류: " + e; });
}

// 서버 진단 — 계정 없이 도달성·열린 포트·hostname·연결 스위치 확인
function diagnoseServer(id) {
  var out = document.getElementById("diag-result");
  openModal("modal-diagnose");
  if (out) out.textContent = "진단 중... (포트 스캔 → hostname → 연결 스위치 대조, 최대 30초)";
  fetch("/api/servers/" + id + "/diagnose", { method: "POST" })
    .then(function (r) { return r.json().then(function (b) { return { ok: r.ok, b: b }; }); })
    .then(function (res) {
      if (!out) return;
      if (!res.ok || !res.b.ok) { out.textContent = "진단 실패: " + ((res.b && res.b.error) || ""); return; }
      var d = res.b.diag || {};
      out.textContent =
        d.name + " (" + d.ip + ")\n" +
        "\n도달성: " + (d.reachable ? "도달(열린 포트 있음)" : "열린 포트 미확인") + "\n" +
        "열린 포트: " + (d.open_ports || "(없음)") + "\n" +
        "SSH 포트: " + (d.ssh_port ? d.ssh_port : "미개방 — 상세(OS·사양) 수집 불가") + "\n" +
        "hostname: " + (d.hostname || "(확인 안 됨 — 역DNS/NetBIOS 무응답)") + "\n" +
        "MAC: " + (d.mac || "(스위치 ARP 테이블에 없음)") + "\n" +
        "연결 스위치: " + (d.switch_name ? (d.switch_name + " " + (d.switch_port || "")) : "(미확인)") + "\n" +
        "OS 추정: " + (d.os_type || "-") + "\n" +
        "저장된 계정: " + (d.has_cred ? "있음" : "없음") + "\n" +
        (d.error ? "\n비고: " + d.error + "\n" : "") +
        (!d.switch_name
          ? "\n※ 연결 스위치는 스위치 수집 데이터(ARP/MAC)와 대조해 찾습니다. 스위치를 먼저 수집하세요.\n"
          : "") +
        (d.ssh_port && !d.has_cred
          ? "\n※ SSH가 열려 있습니다. 계정을 저장하면 OS·CPU·메모리·디스크까지 수집됩니다.\n"
          : "");
      _addSpecDiagButton(out, id);
    })
    .catch(function (e) { if (out) out.textContent = "진단 오류: " + e; });
}

// 사양(CPU·메모리·디스크)이 왜 안 잡히는지 네 경로를 순서대로 두들겨 본다.
// 같은 진단을 CLI(--diag-server)로도 할 수 있지만, 콘솔을 못 쓰는 환경이 있어
// 화면에서도 돌 수 있어야 한다.
function _addSpecDiagButton(out, id) {
  if (!out || document.getElementById("btn-diag-spec")) return;
  var b = document.createElement("button");
  b.id = "btn-diag-spec";
  b.className = "btn btn--secondary";
  b.style.marginTop = "10px";
  b.textContent = "🔎 사양 수집 경로 진단 (SSH·WinRM·WMI·SNMP)";
  b.addEventListener("click", function () {
    b.disabled = true;
    var pre = document.getElementById("diag-spec-out") || document.createElement("pre");
    pre.id = "diag-spec-out";
    pre.style.cssText = "margin-top:10px;white-space:pre-wrap;font-size:12px;" +
      "background:#0b1220;color:#e2e8f0;padding:10px;border-radius:6px;max-height:46vh;overflow:auto";
    pre.textContent = "네 경로를 순서대로 확인 중입니다... 최대 1분 걸릴 수 있습니다.";
    out.parentNode.appendChild(pre);
    fetch("/api/servers/" + id + "/diag-spec", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({}),
    }).then(function (r) { return r.json().then(function (x) { return {ok: r.ok, b: x}; }); })
      .then(function (res) {
        b.disabled = false;
        if (!res.ok || !res.b.ok) {
          pre.textContent = "진단 실패: " + ((res.b && res.b.error) || "");
          return;
        }
        pre.textContent = (res.b.lines || []).join("\n") +
          (res.b.used_credential ? "" :
            "\n\n※ 저장된 계정이 없어 계정이 필요한 경로는 건너뛰었습니다." +
            "\n   서버에 계정을 저장한 뒤 다시 실행하면 SSH·WinRM·WMI까지 확인합니다.");
      })
      .catch(function (e) { b.disabled = false; pre.textContent = "진단 오류: " + e; });
  });
  out.parentNode.appendChild(b);
}

function deleteSwitch(id) {
  if (!confirm("이 스위치를 삭제하시겠습니까?")) return;
  fetch("/api/switches/" + id, {method: "DELETE"})
    .then(function (r) {
      return r.json().catch(function () { return {}; })
        .then(function (b) { return { ok: r.ok, status: r.status, b: b }; });
    })
    .then(function (res) {
      // 실패(404/423 등)를 삼키면 목록에 그대로 남아 "삭제가 안 먹네"로 끝난다
      if (!res.ok) {
        alert((res.b && res.b.error) || ("삭제 실패 (HTTP " + res.status + ")"));
        return;
      }
      pollState();
    })
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
  // 중지 요청이 접수된 뒤에는 버튼을 되살리지 않는다.
  // 예전엔 1.5초마다 진행바를 다시 그리면서 '⏹ 수집 중지' 버튼을 새로 만들어,
  // 눌러도 아무 일 없는 것처럼 보였다(실제로는 접수돼 마무리 중이었다).
  var stopBtn = "";
  if (st.running && stopUrl) {
    stopBtn = st.stopping
      ? "<button class='btn btn--ghost np-stop-btn' disabled " +
        "style='font-size:11px;padding:2px 10px;margin-left:8px;opacity:.6' " +
        "title='중지가 접수됐습니다. 이미 접속 중인 장비만 마무리한 뒤 멈춥니다'>중지 중…</button>"
      : "<button class='btn btn--ghost np-stop-btn' data-stop-url='" + escHtml(stopUrl) +
        "' style='font-size:11px;padding:2px 10px;margin-left:8px'>⏹ 수집 중지</button>";
  }
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
  // 서버가 {"ok":false}나 400을 줘도 예전엔 버튼이 '중지 중…'에서 그대로 굳어
  // 사용자는 중지가 접수된 줄 알았다. 실패면 되돌리고 사유를 알린다.
  fetch(url, { method: "POST" })
    .then(function (r) {
      return r.json().catch(function () { return {}; })
        .then(function (body) { return { ok: r.ok, status: r.status, body: body }; });
    })
    .then(function (res) {
      if (res.ok && res.body.ok !== false) return;   // 정상 접수
      b.disabled = false; b.textContent = "⏹ 수집 중지";
      alert((res.body && res.body.error) || ("중지 실패 (HTTP " + res.status + ")"));
    })
    .catch(function (err) {
      b.disabled = false; b.textContent = "⏹ 수집 중지";
      alert("중지 요청 오류: " + err);
    });
});

// 진행 상태 폴링: url을 1.5초마다 조회 → el에 진행바. running=false면 종료 후 onDone().
// onTick(선택): 매 폴링마다 호출 — **수집 중에도 표를 갱신**하기 위한 훅.
//   예전엔 onDone(완료 시 1회)만 있어서, 일괄 수집 중 서버/방화벽 표가 갱신되지 않아
//   상태가 '수집중'으로 바뀌는 것을 볼 수 없었고 마지막에 결과만 툭 바뀌었다.
//   (스위치 표는 5초 전역 폴러(pollState)가 있어 이 증상이 없었다)
function pollProgress(url, elId, onDone, stopUrl, onTick) {
  var el = document.getElementById(elId);
  var timer = setInterval(function () {
    fetch(url).then(function (r) { return r.json(); }).then(function (st) {
      renderProgressBar(el, st, stopUrl);
      if (st.running && typeof onTick === "function") onTick(st);
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
             (h.port_desc || ""), (h.via || ""), (h.hist_switch || ""), (h.hist_port || ""),
             (h.desc_switch || ""), (h.desc_port || "")]
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
  var stWant = _statusFilterValue("status-filter-fac");
  var filtered = all.filter(function (h) {
    if (subnet && h.subnet !== subnet) return false;
    if (stWant === "online" && !h.online) return false;
    if (stWant === "offline" && h.online) return false;
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
      // 업링크에서만 보였던 이력은 '과거 연결'이 아니다 — 배지를 붙이면 그 스위치에
      // 꽂혀 있었다고 읽힌다. 그럴 땐 실제 단서인 포트 설명 쪽을 내세운다.
      var histReal = h.hist_switch && !h.hist_via_uplink;
      swCell = "<span style='color:#b45309'>직접 연결 미확인</span>" +
        (histReal ? " <span class='status-badge status-badge--new'>과거 연결</span>" :
         h.desc_switch ? " <span class='status-badge status-badge--new'>설명 일치</span>" : "");
      portCell = "<span style='color:#94a3b8'>—</span>";
      descCell = "<span style='color:#94a3b8'>—</span>";
      if (h.switch_name) {
        // direct=0인데 switch_name이 있으면 트렁크(업링크) 경유로만 관측된
        // 것이다 — 그 스위치가 '틀렸다'가 아니라 '거기까지만 확인된다'는 뜻.
        remarks.push("현재는 " + h.switch_name + " " + (h.port || "") +
          " 경유로만 관측(트렁크 — 실제 접속 지점 아님)");
      }
      if (h.via) remarks.push("업링크(Po/Vl) 경유로만 관측: " + h.via);
      remarks.push("연결된 액세스 스위치 미수집이거나 최신 MAC 테이블에 없음(노후)");
      if (h.hist_switch) {
        var histTs = h.hist_ts ? " (" + String(h.hist_ts).slice(0, 16) + ")" : "";
        remarks.push((histReal ? "과거 연결: " : "과거에도 업링크에서만 관측: ") +
          h.hist_switch + (h.hist_port ? " " + h.hist_port : "") + histTs +
          (histReal ? "" : " — 지나간 길목이지 접속 지점이 아님"));
      }
      if (h.desc_switch) {
        remarks.push("포트 설명에 이 IP 기재됨: " + h.desc_switch +
          (h.desc_port ? " " + h.desc_port : "") + " (스위치 설정 라벨 — 참고용)");
      }
    }
    remarkCell = remarks.length
      ? "<span style='font-size:12px;color:#64748b'>" + escHtml(remarks.join(" · ")) + "</span>"
      : "<span style='color:#cbd5e1'>-</span>";
    // 판정 근거 — "왜 이 스위치로 나오냐"를 장비에 직접 들어가 대조하지 않고
    // 화면에서 확인할 수 있게. 판정에 쓰인 입력(MAC 관측 위치·포트별 MAC 수·
    // 포트채널 멤버·CDP 이웃)을 그대로 보여준다.
    remarkCell += " <button class='btn btn--ghost' style='font-size:11px;padding:2px 6px' " +
      "title='이 판정에 쓰인 관측 데이터 보기' data-action='explain-facility' " +
      "data-id='" + escHtml(h.ip) + "'>근거</button>";
    // 오프라인(연결 실패)은 행 배경(빨강) + 상태 배지로 신호.
    // 예전엔 배경색만 있어 다른 현황 화면(상태 배지)과 표기가 달랐다.
    var trStyle = h.online ? "" : " style='background:#fef2f2'";
    return "<tr" + trStyle + "><td>" + escHtml(h.subnet || "-") + "</td><td><code>" + escHtml(h.ip) + "</code></td>" +
      "<td><code>" + escHtml(h.mac || "-") + "</code></td><td>" + swCell + "</td><td>" +
      portCell + "</td><td>" + descCell + "</td><td>" + reachBadge(!!h.online) + "</td><td>" +
      remarkCell + "</td></tr>";
  }).join("");
}

// 설비 1건의 연결 스위치 판정 근거 — 진단 팝업(modal-diagnose) 재사용.
// textContent로만 넣는다(HTML 아님) — 스위치 이름·포트 설명에 <>가 섞여도 안전.
function explainFacility(ip) {
  var out = document.getElementById("diag-result");
  openModal("modal-diagnose");
  if (out) out.textContent = "판정 근거 조회 중...";
  fetch("/api/facility/explain?ip=" + encodeURIComponent(ip))
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (!out) return;
      if (!res.ok) { out.textContent = "조회 실패: " + (res.error || ""); return; }
      var L = [];
      L.push("설비 " + res.ip + "  MAC " + (res.mac || "-"));
      var s = res.stored || {};
      L.push("");
      L.push("── 화면에 저장된 값 ──");
      L.push("연결 스위치: " + (s.switch_name || "(없음)") + "  포트: " + (s.port || "-"));
      L.push("직접 연결: " + (s.direct ? "예" : "아니오") +
             "   상태: " + (s.online ? "온라인" : "오프라인") +
             "   갱신: " + (s.updated || "-"));
      L.push("");
      L.push("── 이 MAC이 관측된 위치(최신 스냅샷) ──");
      var obs = res.observations || [];
      if (!obs.length) {
        L.push("(없음 — 최신 MAC 테이블 어디에도 없음)");
      }
      obs.forEach(function (o) {
        L.push("• " + o.switch_name + "  " + o.port +
               "   MAC수: " + (o.mac_count === null || o.mac_count === undefined ? "미상" : o.mac_count) +
               "   " + (o.physical ? "물리포트" : "논리포트") +
               (o.is_uplink ? "   [업링크 — 너머에 등록 스위치 있음]" : ""));
        if (o.members && o.members.length) L.push("    포트채널 멤버: " + o.members.join(", "));
        if (o.port_desc) L.push("    포트 설명: " + o.port_desc);
        (o.neighbors || []).forEach(function (n) {
          L.push("    이웃(CDP/LLDP) " + (n.local_port || "") + " → " +
                 (n.remote_name || "?") + " " + (n.remote_ip || "") + " " + (n.remote_port || ""));
        });
      });
      var d = res.decision || {};
      L.push("");
      L.push("── 지금 다시 계산한 판정 ──");
      L.push("연결 스위치: " + (d.switch_name || "(없음)") + "  포트: " + (d.port || "-") +
             "  직접 연결: " + (d.direct ? "예" : "아니오"));
      if (d.via && d.via.length) L.push("그 밖에 관측된 경로: " + d.via.join("; "));
      L.push("사유: " + (d.why || "-"));
      var h = res.hints || {};
      if (h.history || h.port_description) {
        L.push("");
        L.push("── 참고 단서 ──");
        if (h.history) {
          L.push("과거 연결 이력: " + (h.history.switch_name || "") + " " +
                 (h.history.port || ""));
        }
        if (h.port_description) {
          var pd = h.port_description;
          var pdPort = pd.port || ((pd.ambiguous_ports || []).join(", ") + " (포트 여럿 — 단정 불가)");
          L.push("포트 설명에 이 IP가 적힌 곳: " + (pd.switch_name || "") + " " + pdPort +
                 "  (\"" + (pd.description || "") + "\")");
          L.push("  ※ 설정 라벨이라 실제 배선과 다를 수 있습니다 — 참고용");
        }
      }
      if (s.switch_name && d.switch_name !== s.switch_name) {
        L.push("");
        L.push("※ 저장된 값과 다시 계산한 값이 다릅니다 — 설비 현황의 '새로고침'을 누르면 반영됩니다.");
      }
      out.textContent = L.join("\n");
    })
    .catch(function (e) { if (out) out.textContent = "조회 오류: " + e; });
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
  if (ex) ex.addEventListener("click", function () { downloadFile("/api/facility/export?format=xlsx"); });
  // 설비 TXT 전용 버튼은 제거됐다 — 툴바 '⬇ 다운로드'(형식 선택)로 통합
  var rf = document.getElementById("btn-fac-refresh");
  if (rf) rf.addEventListener("click", function () {
    rf.disabled = true;
    var prog = document.getElementById("fac-progress");
    if (prog) prog.textContent = "최신 MAC 테이블 기준으로 재대조 중...";
    fetch("/api/facility/rematch", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (res) {
        if (prog) {
          prog.textContent = res.ok
            ? ("재매칭 완료 (" + res.updated + "건 갱신" +
               (res.excluded ? ", 등록 장비 " + res.excluded + "건 제외 — 스위치/방화벽/서버 현황에 있음" : "") + ")")
            : (res.error || "재매칭 실패");
        }
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

// M8 장부 대조 UI는 제거됐다 — 대응하는 표·요약 DOM이 index.html에 없어
// 렌더 함수와 그 API 호출이 도달 불가였다.
// (엔드포인트 자체는 테스트가 있어 서버에 남아 있다)

// ─── M10: 방화벽 현황 (Palo Alto / Fortinet) ─────────────────────
var _fwStatusMeta = {
  done: "ok", collecting: "collecting", failed: "critical", new: "new",
};
var _fwSel = {};    // 방화벽 표 선택 집합 {id: true} — 재렌더에도 유지
var _fwBulkIds = null;   // 일괄 수집 대상(빈 배열=전체). null이면 개별 수집 모드

function _updateFwSelBtns() {
  var n = document.querySelectorAll("#firewall-table-body .fw-check:checked").length;
  var c = document.getElementById("btn-firewall-collect-all");
  if (c) c.textContent = "정보 수집 (" + n + ")";
  var d = document.getElementById("btn-fw-bulk-delete");
  if (d) { d.textContent = "선택 삭제 (" + n + ")"; d.disabled = n === 0; }
}

(function () {
  // 검색
  var s = document.getElementById("fw-search");
  if (s) s.addEventListener("input", function () { renderFirewalls(_firewalls || []); });
  // 전체 선택
  var all = document.getElementById("fw-check-all");
  if (all) all.addEventListener("change", function () {
    document.querySelectorAll("#firewall-table-body .fw-check").forEach(function (c) {
      c.checked = all.checked;
      if (all.checked) _fwSel[c.value] = true; else delete _fwSel[c.value];
    });
    _updateFwSelBtns();
  });
  // 개별 선택(위임)
  var tb = document.getElementById("firewall-table-body");
  if (tb) tb.addEventListener("change", function (e) {
    if (e.target && e.target.classList.contains("fw-check")) {
      if (e.target.checked) _fwSel[e.target.value] = true; else delete _fwSel[e.target.value];
      _updateFwSelBtns();
    }
  });
  // 선택 삭제(개별 DELETE 반복)
  var del = document.getElementById("btn-fw-bulk-delete");
  if (del) del.addEventListener("click", function () {
    var ids = Object.keys(_fwSel);
    if (!ids.length) return;
    if (!confirm(ids.length + "대 방화벽을 삭제할까요? (수집 데이터도 함께 삭제)")) return;
    Promise.all(ids.map(function (id) {
      return fetch("/api/firewalls/" + id, { method: "DELETE" }).catch(function () {});
    })).then(function () { _fwSel = {}; loadFirewalls(); });
  });
  // 전체 진단 — 저장 계정으로 도달성·인증 확인(수집과 동일 경로, 진행바 공유)
  var diag = document.getElementById("btn-fw-diagnose-all");
  if (diag) diag.addEventListener("click", function () {
    if (!confirm("등록된 방화벽의 관리 포트·SSH 도달성과 저장 계정 인증을 확인합니다.\n" +
                 "수집은 하지 않습니다(인터페이스·ARP·상태를 바꾸지 않음).\n계속할까요?")) return;
    // 예전엔 이 버튼이 collect-all을 호출해 실제로는 수집을 했다(안내와 다름)
    fetch("/api/firewalls/diagnose-all", { method: "POST" })
      .then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (!res.ok) { alert((res.b && res.b.error) || "진단 시작 실패"); return; }
        pollProgress("/api/firewalls/diagnose-all/status", "firewall-progress",
                     _showFwDiagResult);
      }).catch(function () { alert("진단 오류"); });
  });

  // 진단 결과를 진단 팝업(장비 진단)에 표로 보여준다
  function _showFwDiagResult() {
    fetch("/api/firewalls/diagnose-all/status").then(function (r) { return r.json(); })
      .then(function (s) {
        var rows = (s && s.results) || [];
        if (!rows.length) return;
        var out = document.getElementById("diag-result");
        if (!out) return;
        out.textContent = rows.map(function (d) {
          return d.name + " (" + d.host + ") · " + (d.vendor || "-") + "\n" +
            "  관리 포트 TCP-" + d.mgmt_port + ": " + (d.tcp_mgmt ? "도달" : "실패") +
            " · SSH TCP-22: " + (d.tcp_ssh ? "도달" : "실패") + "\n" +
            "  저장 자격증명: " + (d.has_login ? "계정/비밀번호" : d.has_token ? "API 토큰만" : "없음") +
            " · 인증: " + (d.auth_ok ? "성공" : (d.has_token || d.has_login ? "실패" : "미검증")) +
            (d.detail ? "\n  " + d.detail : "");
        }).join("\n\n");
        openModal("modal-diagnose");
        loadFirewalls();
      }).catch(function () {});
  }
})();

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
  // 검색 필터(이름·벤더·호스트·위치)
  var q = ((document.getElementById("fw-search") || {}).value || "").trim().toLowerCase();
  if (q) {
    firewalls = (firewalls || []).filter(function (f) {
      return [f.name, f.vendor, f.host, f.location, f.room_label]
        .map(function (x) { return (x || "").toString().toLowerCase(); }).join(" ").indexOf(q) >= 0;
    });
  }
  if (!firewalls.length) {
    tbody.innerHTML = "<tr><td colspan=8 style='color:#64748b'>" +
      (q ? "검색 조건에 맞는 방화벽이 없습니다." : "등록된 방화벽이 없습니다. '+ 방화벽 추가'로 등록하세요.") +
      "</td></tr>";
    _updateFwSelBtns();
    return;
  }
  // 이중화 대기 장비는 status_display 기준으로 걸러야 '정상'으로 보이는 것과 일치한다
  firewalls = _byStatusSel(firewalls, "status-filter-fw",
                           function (f) { return f.status_display || f.status; });
  tbody.innerHTML = firewalls.map(function(f) {
    var fjson = payloadAttr((f));
    // 위치: 스위치·서버 표와 완전히 같은 규칙(서버실 통일 표기 + 원문 병기)
    var locCell = locationCell(f);
    return "<tr>" +
      "<td style='text-align:center'><input type='checkbox' class='fw-check' value='" + f.id + "'" +
      (_fwSel[f.id] ? " checked" : "") + "></td>" +
      // 이중화 역할(Master/Backup) — 같은 VIP를 공유하는 쌍에서만 표시
      "<td>" + escHtml(f.name) +
        (f.ha_role
          ? " <span class='status-badge " +
            (f.ha_role === "master" ? "status-badge--ok" : "status-badge--info") +
            "' title='이중화(HA) 역할 — 동일 VIP 쌍에서 판정'>" +
            (f.ha_role === "master" ? "Master" : "Backup") + "</span>"
          : "") + "</td>" +
      // 제조사와 제품을 나눈다 — 예전엔 'fortigate'(제품 계열)를 '벤더'로 보여줬다.
      "<td>" + (f.manufacturer
        ? escHtml(f.manufacturer)
        : "<span class='cell-none' title='등록된 제품 정보로 제조사를 특정하지 못했습니다'>-</span>") + "</td>" +
      "<td>" + fwModelCell(f) + "</td>" +
      "<td>" + fwVersionCell(f) + "</td>" +
      "<td><code>" + escHtml(f.host) + "</code></td>" +
      "<td>" + locCell + "</td>" +
      // 이중화(동일 VIP) 대기 장비는 개별 수집이 실패할 수밖에 없다 →
      // 짝이 정상이면 정상으로 표기하고 근거를 툴팁에 남긴다.
      "<td>" + (f.ha_via
        ? "<span class='status-badge status-badge--ok' title='이중화(HA) 대기 장비 — 동일 VIP의 " +
          escHtml(f.ha_via) + " 수집 결과 기준'>정상</span>" +
          "<div class='cell-sub'>HA 대기 · " + escHtml(f.ha_via) + " 기준</div>"
        : statusBadge(f.status_display || f.status, f.last_error)) + "</td>" +
      "<td>" + reachBadge(f.reachable) + "</td>" +
      "<td>" +
        "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' " +
        "data-action='collect-fw' data-payload='" + fjson + "'>수집</button> " +
        "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
        "data-action='detail-fw' data-id='" + f.id + "'>상세</button> " +
        (f.vendor === "fortigate"
          ? "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
            "title='SNMP로 실제 어떤 값이 오는지 원문 확인(CPU·메모리·세션 OID)' " +
            "data-action='snmp-probe-fw' data-id='" + f.id + "'>SNMP</button> "
          : "") +
        "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
        "data-action='edit-fw' data-payload='" + payloadAttr((f)) + "'>수정</button> " +
        "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
        "title='관리 포트·SSH 도달성과 저장 계정 인증을 확인' " +
        "data-action='diagnose-fw' data-id='" + f.id + "'>진단</button> " +
        "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
        "title='SSH 터미널로 직접 접속(저장된 계정/비밀번호 필요 — API 토큰은 사용 불가)' " +
        "data-action='terminal-fw' data-id='" + f.id + "'>💻</button> " +
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
      // 404/500이면 data.firewall이 없다. 예전엔 그대로 .name을 읽어 예외가 나고
      // **직전에 보던 다른 방화벽의 인터페이스·ARP가 화면에 그대로 남았다**
      // (다른 PC에서 삭제됐거나 읽기전용/DB 오류일 때 발생 — 무반응보다 나쁘다).
      if (!data || !data.firewall) {
        el.innerHTML = "<p style='color:#b91c1c;margin:16px 0'>방화벽 정보를 불러오지 못했습니다 — " +
          escHtml((data && data.error) || "알 수 없는 오류") +
          "<br><span style='color:#64748b;font-size:12px'>다른 사용자가 삭제했거나 서버 오류일 수 있습니다. 목록을 새로고침하세요.</span></p>";
        return;
      }
      var ifaces = data.interfaces || [];
      var arp = data.arp || [];
      var envHtml = fwStatusHtml(data.firewall, data.env);
      var ifHtml = ifaces.length
        ? "<table class='data-table'><thead><tr><th>인터페이스</th><th>IP (Primary / Secondary)</th><th>Prefix</th><th>VDOM/Zone</th></tr></thead><tbody>" +
          ifaces.map(function(i) {
            // primary + secondary IP를 한 칸에 위·아래로. 마스크는 prefix(/N).
            var pfx = _fmtPrefix(i.mask);
            var ipStack = "<div><code>" + escHtml(i.ip || "-") + "</code>" +
              (pfx ? "<span style='color:#94a3b8'>" + escHtml(pfx) + "</span>" : "") + "</div>";
            var secs = i.secondary_ips || [];
            secs.forEach(function (s) {
              // s는 "ip/prefix" 또는 "ip"
              var parts = String(s).split("/");
              ipStack += "<div style='color:#0369a1'><code>" + escHtml(parts[0]) + "</code>" +
                (parts[1] ? "<span style='color:#94a3b8'>/" + escHtml(parts[1]) + "</span>" : "") +
                " <span class='status-badge status-badge--new' style='font-size:9px'>2nd</span></div>";
            });
            return "<tr><td>" + escHtml(i.name) + "</td><td>" + ipStack + "</td><td>" +
              escHtml(pfx || "-") + "</td><td>" + escHtml(i.vdom_zone || "-") + "</td></tr>";
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
        " — 장비 상태</h3>" + envHtml +
        "<h3 style='margin:16px 0 8px'>인터페이스</h3>" + ifHtml +
        "<h3 style='margin:16px 0 8px'>ARP (연결된 IP)</h3>" + arpHtml;
    })
    .catch(function(e) { console.error("firewall detail:", e); });
}

// 방화벽 상세의 '장비 상태' 블록 — 부하·VPN·정책·센서(PSU/전압/전류).
function fwStatusHtml(fw, env) {
  env = env || {};
  var m = env.metrics || {};
  if (!m.cpu_pct && !m.sessions && !m.vpn && !m.policy && !m.sensors && !env.max_temp_c) {
    return "<p style='color:#64748b'>수집된 상태 정보가 없습니다. " +
      "SNMP 커뮤니티(설정)와 SSH 계정을 지정한 뒤 이 방화벽을 수집하면 채워집니다.</p>";
  }
  var H = "";
  // 부하
  H += "<div style='max-width:420px'>" +
    fwBar("CPU", m.cpu_pct === undefined ? null : m.cpu_pct) +
    fwBar("MEM", m.mem_pct === undefined ? null : m.mem_pct) +
    (m.disk_absent
      ? "<div class='fw-tile__row'><b>DISK</b><div class='fw-bar'></div>" +
        "<span class='fw-tile__val' style='width:auto' title='이 모델은 로그 디스크가 없거나 비활성입니다 — 정상'>없음</span></div>"
      : fwBar("DISK", m.disk_pct === undefined ? null : m.disk_pct)) + "</div>";

  var facts = [];
  if (m.sessions !== undefined) facts.push(["동시 세션", Number(m.sessions).toLocaleString()]);
  if (m.version) facts.push(["펌웨어", m.version]);
  if (m.uptime_sec) facts.push(["업타임", Math.floor(m.uptime_sec / 86400) + "일"]);
  if (m.ha_mode) facts.push(["HA", m.ha_mode + (m.ha_group ? " (" + m.ha_group + ")" : "")]);
  var vpn = m.vpn || {};
  // IPsec/SSL VPN을 안 쓰는 방화벽이 많다 — 0/0, 0명을 보여주면 잡음이다.
  // 설정이 있는(값이 0보다 큰) 장비에만 표기한다.
  if (vpn.tunnel_total) {
    facts.push(["VPN 터널", vpn.tunnel_up + " / " + vpn.tunnel_total + " 연결"]);
  }
  if (vpn.ssl_users) facts.push(["SSL VPN 접속자", vpn.ssl_users]);
  var pol = m.policy || {};
  if (pol.total !== undefined) facts.push(["방화벽 정책", pol.total + "개"]);
  if (pol.proxy_total !== undefined) facts.push(["Proxy 정책", pol.proxy_total + "개"]);
  if (pol.unused !== undefined) facts.push(["히트 0건 정책", pol.unused + "개"]);
  if (pol.disabled !== undefined) facts.push(["비활성 정책", pol.disabled + "개"]);
  var obj = m.objects || {};
  if (obj.total) {
    facts.push(["객체", obj.total + "개 (주소 " + (obj.address || 0) + " · 그룹 " +
      (obj.addrgrp || 0) + " · 서비스 " + (obj.service || 0) + " · VIP " +
      (obj.vip || 0) + ")"]);
  }
  if (facts.length) {
    H += "<table class='data-table' style='margin-top:10px;max-width:520px'><tbody>" +
      facts.map(function (f) {
        return "<tr><td style='width:150px;color:#475569'>" + escHtml(f[0]) +
          "</td><td><b>" + escHtml(String(f[1])) + "</b></td></tr>";
      }).join("") + "</tbody></table>";
  }

  // 라이선스 — FortiGuard 구독·지원계약(수집된 장비만, 만료일 표기)
  if (m.license && m.license.length) {
    H += "<h4 style='margin:14px 0 6px'>라이선스</h4><table class='data-table' style='max-width:520px'>" +
      "<thead><tr><th>구독</th><th>만료일</th><th>상태</th></tr></thead><tbody>" +
      m.license.map(function (l) {
        var st = l.status === "expired"
          ? "<span class='status-badge status-badge--err'>만료</span>"
          : "<span class='status-badge status-badge--ok'>정상</span>";
        return "<tr><td>" + escHtml(l.name || "-") + "</td><td>" +
          escHtml(l.expires || "-") + "</td><td>" + st + "</td></tr>";
      }).join("") + "</tbody></table>";
  }

  // HA 멤버별 부하
  if (m.ha_members && m.ha_members.length) {
    H += "<h4 style='margin:14px 0 6px'>HA 멤버</h4><table class='data-table'>" +
      "<thead><tr><th>호스트네임</th><th>시리얼</th><th>CPU</th><th>MEM</th><th>세션</th></tr></thead><tbody>" +
      m.ha_members.map(function (x) {
        return "<tr><td>" + escHtml(x.hostname || "-") + "</td><td><code style='font-size:11px'>" +
          escHtml(x.serial || "-") + "</code></td><td>" + escHtml(String(x.cpu_pct)) + "%</td><td>" +
          escHtml(String(x.mem_pct)) + "%</td><td>" +
          escHtml(String(x.sessions === null ? "-" : x.sessions)) + "</td></tr>";
      }).join("") + "</tbody></table>";
  }

  // VPN 터널 목록 — 끊긴 것을 위로(현황판에서 먼저 봐야 할 것).
  var tuns = (vpn.tunnels || []).slice().sort(function (a, b) {
    return (a.status === "up") - (b.status === "up");
  });
  if (tuns.length) {
    H += "<h4 style='margin:14px 0 6px'>VPN 터널 (" + vpn.tunnel_up + "/" + vpn.tunnel_total + ")</h4>" +
      "<table class='data-table'><thead><tr><th>터널</th><th>상대</th><th>상태</th><th>수신</th><th>송신</th></tr></thead><tbody>" +
      tuns.map(function (t) {
        var badge = t.status === "up"
          ? "<span class='status-badge status-badge--ok'>연결</span>"
          : "<span class='status-badge status-badge--err'>끊김</span>";
        return "<tr><td>" + escHtml(t.name) + "</td><td><code>" + escHtml(t.peer || "-") +
          "</code></td><td>" + badge + "</td><td>" + escHtml(_fmtBytes(t.incoming_bytes)) +
          "</td><td>" + escHtml(_fmtBytes(t.outgoing_bytes)) + "</td></tr>";
      }).join("") + "</tbody></table>";
  }

  // 하드웨어 센서(execute sensor list) — 알람 걸린 것을 위로.
  var sen = m.sensors || {};
  var list = (sen.sensors || []).slice().sort(function (a, b) {
    return (b.alarm ? 1 : 0) - (a.alarm ? 1 : 0);
  });
  if (list.length) {
    H += "<h4 style='margin:14px 0 6px'>하드웨어 센서 (execute sensor list · " + list.length + "개)</h4>" +
      "<table class='data-table'><thead><tr><th>부품</th><th>센서</th><th>값</th><th>상태</th></tr></thead><tbody>" +
      list.map(function (s) {
        var st = s.alarm
          ? "<span class='status-badge status-badge--err'>알람</span>"
          : "<span class='status-badge status-badge--ok'>정상</span>";
        return "<tr><td>" + escHtml(s.group) + "</td><td>" + escHtml(s.name) + "</td><td><b>" +
          escHtml(String(s.value)) + "</b> " + escHtml(s.unit || "") + "</td><td>" + st + "</td></tr>";
      }).join("") + "</tbody></table>";
  } else if (env.sensors && env.sensors.length) {
    // SSH 센서가 없으면 SNMP로 읽은 온도 센서라도 보여준다.
    H += "<h4 style='margin:14px 0 6px'>환경 센서 (SNMP)</h4>" +
      "<table class='data-table'><thead><tr><th>센서</th><th>값</th></tr></thead><tbody>" +
      env.sensors.map(function (s) {
        var unit = s.type === "celsius" ? "°C" : (s.type === "rpm" ? " RPM" : "");
        return "<tr><td>" + escHtml(s.name) + "</td><td>" +
          escHtml(s.value === null ? "-" : (s.value + unit)) + "</td></tr>";
      }).join("") + "</tbody></table>";
  }
  if (env.updated) {
    H += "<p style='font-size:11px;color:#64748b;margin-top:6px'>수집: " +
      escHtml(env.updated) + (env.source ? " (" + escHtml(env.source) + ")" : "") + "</p>";
  }
  return H;
}

function _fmtBytes(n) {
  n = Number(n || 0);
  if (!n) return "-";
  var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : String(n)) + " " + u[i];
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
  var payload = {
    token: document.getElementById("fw-token").value,
    username: document.getElementById("fw-username").value.trim(),
    password: document.getElementById("fw-password").value,
    verify_ssl: document.getElementById("fw-verify-ssl").checked,
  };
  // '이 세션 동안 기억'은 방화벽 계정으로만 저장한다(스위치·서버에 쓰이지 않음)
  var fwRem = document.getElementById("fw-remember");
  if (fwRem && fwRem.checked && payload.username && payload.password) {
    sessCredRemember(payload.username, payload.password, "firewall");
  }
  // 일괄 수집 모드(툴바 '정보 수집')
  if (!_selectedFirewall && _fwBulkIds) {
    var bulk = _fwBulkIds;
    _fwBulkIds = null;
    closeModal("modal-fw-collect");
    window._fwRunBulk(bulk, payload.token, payload.username, payload.password);
    return;
  }
  if (!_selectedFirewall) return;
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
  }).then(function (r) {
    return r.json().catch(function () { return {}; })
      .then(function (b) { return { ok: r.ok, status: r.status, b: b }; });
  }).then(function (res) {
    // 예전엔 r.ok를 안 봐서 423(읽기 전용)·409(이미 수집 중)·404에도 팝업만 닫히고
    // 아무 안내가 없었다 — 사용자는 수집이 시작된 줄 안다.
    if (!res.ok) {
      alert((res.b && (res.b.error || res.b.message)) ||
            ("수집 요청 실패 (HTTP " + res.status + ")"));
      return;
    }
    pollState();
  }).catch(function (e) { console.error("collect error:", e); alert("수집 요청 오류: " + e); });
}

// ─── 일괄 정보 수집 (공통 계정) ──────────────────────────────────
// 선택 대상 요약 HTML. 이름을 전부 나열하면(수백 대) 팝업이 화면 밖으로 자라
// 계정 입력칸과 '수집 시작' 버튼을 누를 수 없게 된다 → 앞 몇 대만 보이고
// 전체는 접어 둔다(펼치면 스크롤 목록).
var _BULK_PREVIEW = 5;
function _bulkTargetInfo(ids) {
  var names = ids.map(function (id) {
    var s = (_switches || []).find(function (x) { return String(x.id) === String(id); });
    return s ? (s.name + " (" + s.ip + ")") : ("#" + id);
  });
  var head = "<strong>" + ids.length + "대</strong> 선택됨";
  if (names.length <= _BULK_PREVIEW) {
    return head + "<div style='margin-top:4px;color:var(--text-2)'>" +
      names.map(escHtml).join(", ") + "</div>";
  }
  return head +
    "<div style='margin-top:4px;color:var(--text-2)'>" +
      names.slice(0, _BULK_PREVIEW).map(escHtml).join(", ") +
      " <span style='color:var(--text-faint)'>외 " + (names.length - _BULK_PREVIEW) + "대</span>" +
    "</div>" +
    "<details class='target-list' style='margin-top:6px'>" +
      "<summary>대상 " + names.length + "대 전체 보기</summary>" +
      "<div class='target-list__items'>" + names.map(escHtml).join("<br>") + "</div>" +
    "</details>";
}

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

  // 새로고침 복구 — 백그라운드 진단은 계속 도는데 UI만 초기화되던 것을 되살린다.
  if (diagAllBtn) {
    fetch("/api/switches/diagnose-all/status").then(function (r) { return r.json(); })
      .then(function (s) {
        if (!s || !s.running) return;
        diagAllBtn.disabled = true;
        _diagAllPoll = setInterval(_pollDiagnoseAll, 2000);
        _pollDiagnoseAll();
      }).catch(function () {});
  }

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
        if (res.skipped_count) {
          alert("제외 " + res.skipped_count + "대(이미 수집 중이거나 IP 거부).");
        }
        // 진행바 + 중지 버튼(다른 화면들과 동일). 예전엔 alert 한 번이 전부라
        // 200대를 걸면 진척 확인도 중단도 불가능했다.
        pollProgress("/api/switches/bulk-collect/status", "sw-bulk-progress",
                     pollState, "/api/switches/bulk-collect/stop");
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
    document.getElementById("bulk-cred-info").innerHTML = _bulkTargetInfo(ids);
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
    // '스위치' 세션 계정이 살아 있으면 빈칸으로 두어도 서버가 그 계정을 쓴다.
    // (서버·방화벽 계정이 기억돼 있어도 스위치에는 쓰지 않는다 — 계정 체계가 다르다)
    if ((!username || !password) && !sessCredActive("switch")) {
      alert("스위치 계정(아이디·패스워드)을 입력하세요."); return;
    }
    var persist = document.getElementById("bulk-persist");
    var be = document.getElementById("bulk-enable");
    var rem = document.getElementById("bulk-remember");
    if (rem && rem.checked && username && password) {
      sessCredRemember(username, password, "switch");
    }
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
    document.getElementById("bulk-cred-info").innerHTML = _bulkTargetInfo(ids);
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
  if (btn) btn.addEventListener("click", function() { downloadFile("/api/report"); });
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

// 예전 자동 렌더 뷰(renderTopology 계열)의 상태 변수·헬퍼는 제거했다.
// _topoData 에 값을 대입하는 코드가 없어 렌더러 전체가 도달 불가였고,
// 여기 있던 _TOPO_KIND(표시명 키)는 아래 편집기의 동명 선언에 가려져
// 런타임에는 존재하지도 않았다(같은 이름 var 중복 선언).
// 실제 화면은 아래 '하이브리드 토폴로지 편집기'만 사용한다.

// ═══ 하이브리드 토폴로지 편집기 (v4.4) ═══════════════════════════
// 사람이 배치(팔레트 드래그·연결) + 툴이 정보 자동 채움(IP→hostname, 선→포트).
var _tdiag = { nodes: [], edges: [] };   // {nodes:[{id,kind,ip,name,x,y,subnets,...}], edges}
var _tEditMode = false;                   // 편집 모드(끄면 보기 전용 — 실수 클릭 방지)
var _tLinkFrom = null;                    // 연결 시작 노드(연결 손잡이 클릭)
var _tEditId = null;                      // 편집 중 노드 id
var _tSelId = null;                       // 마지막 클릭 노드(단일 선택)
var _tSel = {};                           // 다중 선택 집합 {id:true} — 드래그 영역/Shift 클릭
var _tClip = null;                        // 복사 버퍼(노드 스냅샷 배열)
var _tView = null;                        // 줌/팬 뷰박스 {x,y,w,h} — 재렌더에도 유지
var _tLineStyle = null;                   // 선 그리기 도구 {style:'straight'|'elbow', dash:bool}
var _tLoaded = false;                     // 구성도 최초 로드 완료(탭 재진입 시 유지)
var _tSaveTimer = null;                   // 자동 저장 디바운스
var _tSeq = 1;

var _tUndo = null;              // 되돌리기용 직전 구성도(불러오기·초기화 직전 스냅샷)
var _tSuppressSave = false;     // 이번 렌더는 자동 저장하지 않는다

// 변경 후 자동 저장(디바운스 1.5s) — 탭 전환/새로고침에도 유지. 읽기 전용은 스킵.
function _tAutoSave() {
  if (!_tLoaded) return;
  if (window._ndReadOnly) return;   // 주석과 달리 검사가 없어 423만 반복 요청하던 것 수정
  if (_tSuppressSave) return;       // '불러오기' 직후 — 사용자가 손대기 전엔 저장하지 않는다
  if (_tSaveTimer) clearTimeout(_tSaveTimer);
  _tSaveTimer = setTimeout(function () {
    fetch("/api/topology/diagram", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(_tdiag) }).catch(function () {});
  }, 1500);
}

// 파괴적 교체(불러오기·초기화) 직전에 되돌릴 수 있게 스냅샷을 잡는다.
// 예전엔 '저장 전이면 사라집니다'라고 안내해 저장본은 안전하다는 인상을 줬지만,
// 교체 후 _renderEditor()가 자동 저장을 불러 서버 구성도까지 덮어썼다(되돌리기 없음).
function _tSnapshotForUndo() {
  try {
    _tUndo = JSON.parse(JSON.stringify(_tdiag));
  } catch (e) { _tUndo = null; }
  var b = document.getElementById("btn-topo-undo");
  if (b) b.classList.remove("hidden");
}

function _tRestoreUndo() {
  if (!_tUndo) return;
  _tdiag = _tUndo;
  _tUndo = null;
  var b = document.getElementById("btn-topo-undo");
  if (b) b.classList.add("hidden");
  _tView = null; _tSel = {}; _tSelId = null;
  _renderEditor();          // 되돌린 내용은 저장한다(서버 구성도 복구)
}

// 현재 선택된 노드 id 목록(다중 우선, 없으면 단일)
function _tSelIds() {
  var ks = Object.keys(_tSel);
  return ks.length ? ks : (_tSelId ? [_tSelId] : []);
}
function _tIsSel(id) { return !!_tSel[id] || _tSelId === id; }

// 도구 버튼용 라인 아이콘(툴바 인라인 SVG와 동일 문법) — JS가 라벨을 갱신하는 버튼용
var _TICO = {
  pencil: "<svg class='ticon' viewBox='0 0 24 24'><path d='M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z'/></svg>",
  save: "<svg class='ticon' viewBox='0 0 24 24'><path d='M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z'/><path d='M17 21v-8H7v8M7 3v5h8'/></svg>",
};

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
      if (!_tEditMode) { alert("먼저 '편집 모드'를 켜세요."); return; }
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
  if (!_tEditMode) { alert("먼저 '편집 모드'를 켜세요."); return; }
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
    // color/w/h는 API로 저장되는 값이라 임의 문자열이 올 수 있다 — 속성에 그대로
    // 넣으면 따옴표를 닫고 태그를 열 수 있다. 색은 이스케이프, 크기는 숫자로 강제.
    var col = escHtml(n.color || m.color), w = _num(n.w) || 320, h = _num(n.h) || 220;
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
    // 선 양끝 인터페이스 도트 — 각 도트에 그 장비의 포트만 툴팁으로(사용자 요청:
    // 선 하나의 합본 툴팁만으로는 어느 장비의 어느 포트인지 구분이 어렵다).
    // 꺾은선은 끝 구간의 진행 방향이 다르므로 끝별로 안쪽 방향을 따로 계산한다.
    var INSET = 27;                        // 노드 아이콘(반경 ~24) 바로 바깥
    var aIn, bIn;                          // 각 끝에서 선 안쪽으로 향하는 단위벡터
    if (e.style === "elbow") {
      if (Math.abs(dx) >= Math.abs(dy)) {  // A에서 수평 출발 → B로 수직 도착
        aIn = [dx >= 0 ? 1 : -1, 0];
        bIn = [0, by >= ay ? -1 : 1];
      } else {
        aIn = [0, dy >= 0 ? 1 : -1];
        bIn = [bx >= ax ? -1 : 1, 0];
      }
    } else {
      aIn = [dx / len, dy / len];
      bIn = [-dx / len, -dy / len];
    }
    [[ax + aIn[0] * INSET, ay + aIn[1] * INSET, a, e.a_port],
     [bx + bIn[0] * INSET, by + bIn[1] * INSET, b, e.b_port]].forEach(function (d) {
      var known = !!d[3];
      var dtip = (d[2].name || d[2].ip || "장비") + " 인터페이스: " + (d[3] || "미확인");
      svg.push("<g class='tport-dot' data-tip=\"" + escHtml(dtip) + "\">" +
        "<circle cx='" + d[0] + "' cy='" + d[1] + "' r='4.5' fill='" +
        (known ? "#22c55e" : "#334155") + "' fill-opacity='" + (known ? "0.95" : "0.9") +
        "' stroke='" + (known ? "#bbf7d0" : "#64748b") + "' stroke-width='1.3'/>" +
        "<circle cx='" + d[0] + "' cy='" + d[1] + "' r='10' fill='transparent'/></g>");
    });
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
    // 편집 모드: 연결 손잡이(링크 아이콘)
    if (_tEditMode) {
      var hxo = meta.box ? 78 : 16, hyo = meta.box ? -18 : -16;
      svg.push("<g class='tlink-handle' data-id='" + escHtml(n.id) + "' style='cursor:crosshair'>" +
        "<circle cx='" + (n.x + hxo) + "' cy='" + (n.y + hyo) + "' r='8' fill='#0f172a' stroke='#38bdf8' stroke-width='1.5'/>" +
        "<g transform='translate(" + (n.x + hxo - 5) + "," + (n.y + hyo - 5) + ") scale(0.42)' " +
        "fill='none' stroke='#38bdf8' stroke-width='2.4' stroke-linecap='round'>" +
        "<path d='M9 17H7A5 5 0 0 1 7 7h2M15 7h2a5 5 0 1 1 0 10h-2M8 12h8'/></g></g>");
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
  // 연결 손잡이: 시작 노드 지정 → 다음 노드 클릭으로 완성
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
        // 구분 자동 매핑 — 서버가 내려준 topo_kind가 정답이다.
        // 예전엔 여기서 device_type을 다시 해석했는데 판정 우선순위가
        // 서버(_switch_kind)와 달라(L4보다 L3를 먼저 봄) 같은 장비가
        // '스위치 현황 불러오기'와 다른 행에 놓였다.
        var ks = document.getElementById("tn-kind");
        if (d.topo_kind && _TOPO_KIND[d.topo_kind]) { ks.value = d.topo_kind; }
        else if (d.kind === "fw") ks.value = "firewall";
        else if (d.kind === "srv") ks.value = "server";
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

// ─── 구성도 공용 헬퍼 ─────────────────────────────────────────
// 아래 3개는 실제 사용되는 토폴로지 '편집기'(_renderEditor)가 쓴다.
// 예전 자동 렌더 뷰(renderTopology 계열 ~1400줄)는 _topoData 에 값을
// 대입하는 코드가 어디에도 없어 전부 도달 불가였고, 이번에 제거했다.

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

// 토폴로지 뷰가 window에 붙인 리스너 추적/정리(재렌더마다 누적 방지)
var _topoWinListeners = [];
function _topoWinOn(type, fn) { window.addEventListener(type, fn); _topoWinListeners.push([type, fn]); }
function _topoWinClear() {
  _topoWinListeners.forEach(function (p) { window.removeEventListener(p[0], p[1]); });
  _topoWinListeners = [];
}

(function () {
  var b = document.getElementById("btn-topo-clear");
  if (b) b.addEventListener("click", function () {
    if (!_tdiag.nodes.length && !_tdiag.edges.length) return;
    if (!confirm("캔버스를 모두 비울까요? (모든 아이콘·선 삭제 — 처음부터 다시 그립니다)\n" +
                 "[되돌리기]로 복원할 수 있습니다.")) return;
    _tSnapshotForUndo();
    _tdiag = { nodes: [], edges: [] };
    _tSel = {}; _tSelId = null; _tLinkFrom = null; _tLineStyle = null; _tHighlightLineBtn();
    _tView = null;                 // 전체 화면으로
    _renderEditor();               // 자동 저장으로 빈 구성도 반영
  });
  var undo = document.getElementById("btn-topo-undo");
  if (undo) undo.addEventListener("click", function () {
    if (!_tUndo) { alert("되돌릴 내용이 없습니다."); return; }
    if (!confirm("직전 상태로 되돌릴까요? (지금 화면의 변경은 사라집니다)")) return;
    _tRestoreUndo();
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
    edit.innerHTML = _TICO.pencil + (_tEditMode ? "편집 모드 (켜짐)" : "편집 모드");
    _renderEditor();
  });
  // 저장
  var save = document.getElementById("btn-topo-save");
  if (save) save.addEventListener("click", function () {
    fetch("/api/topology/diagram", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(_tdiag) }).then(function (r) { return r.json(); }).then(function (res) {
        if (res.ok) { save.innerHTML = _TICO.save + "저장됨"; setTimeout(function () { save.innerHTML = _TICO.save + "저장"; }, 1500); }
        else alert(res.error || "저장 실패");
      }).catch(function () { alert("저장 오류"); });
  });
  // 서버실 현황 불러오기 — 등록 장비를 정보 채운 아이콘으로 나열(종류별 행 배치)
  var draft = document.getElementById("btn-topo-draft");
  if (draft) draft.addEventListener("click", function () {
    if (_tdiag.nodes.length && !confirm(
        "현재 구성도를 서버실 장비로 다시 채웁니다.\n" +
        "저장된 구성도(배치·연결선·존/대역 박스)도 함께 바뀝니다.\n" +
        "바꾼 뒤에는 [되돌리기]로 복원할 수 있습니다.\n계속할까요?")) return;
    _tSnapshotForUndo();
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
      // 불러온 초안은 아직 저장하지 않는다 — 사용자가 손대거나 [저장]을 눌러야 반영된다.
      // (이 억제가 없으면 1.5초 뒤 자동 저장이 서버 구성도를 덮어써 되돌릴 수 없었다)
      _tSuppressSave = true;
      _renderEditor();
      _tSuppressSave = false;
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

  // ── v6.32: 자동 연결·자동 정렬·코어 초안·검색 ──
  // 방향(사용자): 전체 자동 배치는 장비가 너무 많아 폐기. 코어(방화벽·백본·L3)만
  // 그리고, "올려진 장비끼리"만 수집 근거(CDP/LLDP·ARP+MAC)로 선을 자동으로 긋는다.

  // 계층 행 정렬 — 그려진 노드를 종류별 행으로(행 안에서는 현재 x 순서 유지)
  function _tAutoArrange() {
    var ROW = { internet: 0, firewall: 1, backbone: 2, l4: 3, l3: 4, l2: 5,
                ap: 6, server: 7, pc: 7, facility: 8 };
    var rows = {};
    _tdiag.nodes.forEach(function (n) {
      var meta = _TOPO_KIND[n.kind] || {};
      if (meta.zone) return;                       // 존 박스는 배경 — 그대로 둔다
      var r = meta.box ? 9 : (ROW[n.kind] !== undefined ? ROW[n.kind] : 5);
      (rows[r] = rows[r] || []).push(n);
    });
    Object.keys(rows).forEach(function (r) {
      rows[r].sort(function (a, b) { return a.x - b.x; })   // 좌우 순서는 존중
        .forEach(function (n, i) { n.x = 150 + i * 185; n.y = 100 + r * 150; });
    });
    _tView = null;
    _renderEditor();
  }

  // 자동 연결 — 올려진 장비 IP들로 서버에 인접 조회, 없는 선만 추가(포트 자동 기입)
  function _tAutoLink(opts) {
    opts = opts || {};
    var ips = _tdiag.nodes.filter(function (n) {
      var m = _TOPO_KIND[n.kind] || {};
      return n.ip && !m.box && !m.zone;
    }).map(function (n) { return n.ip; });
    if (ips.length < 2) {
      if (!opts.quiet) alert("IP가 등록된 장비가 2대 이상 있어야 자동 연결할 수 있습니다.\n(장비 더블클릭 → IP 입력)");
      if (opts.done) opts.done(0);
      return;
    }
    fetch("/api/topology/autolink", { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips: ips }) })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var byIp = {};
        _tdiag.nodes.forEach(function (n) { if (n.ip && !byIp[n.ip]) byIp[n.ip] = n; });
        var have = {};
        _tdiag.edges.forEach(function (e) { have[[e.a, e.b].sort().join("|")] = true; });
        var added = 0, dup = 0;
        (d.links || []).forEach(function (l) {
          var a = byIp[l.a_ip], b = byIp[l.b_ip];
          if (!a || !b) return;
          var k = [a.id, b.id].sort().join("|");
          if (have[k]) { dup++; return; }         // 이미 그린 선은 존중(평행 링크 오해 방지)
          have[k] = true;
          _tdiag.edges.push({ a: a.id, b: b.id, a_port: l.a_port || "", b_port: l.b_port || "" });
          added++;
        });
        _renderEditor();
        if (!opts.quiet) {
          alert(added
            ? "자동 연결: " + added + "건 추가" + (dup ? " (이미 연결된 " + dup + "건 제외)" : "")
            : (dup ? "추가할 선 없음 — 찾은 인접 " + dup + "건은 이미 연결돼 있습니다."
                   : "수집된 인접 근거(CDP/LLDP·ARP+MAC)가 없습니다.\n장비 수집을 먼저 실행했는지 확인하세요."));
        }
        if (opts.done) opts.done(added);
      })
      .catch(function () { if (!opts.quiet) alert("자동 연결 오류"); if (opts.done) opts.done(0); });
  }

  var alBtn = document.getElementById("btn-topo-autolink");
  if (alBtn) alBtn.addEventListener("click", function () {
    if (!_tEditMode) { alert("먼저 '편집 모드'를 켜세요."); return; }
    _tAutoLink({});
  });

  var arBtn = document.getElementById("btn-topo-arrange");
  if (arBtn) arBtn.addEventListener("click", function () {
    if (!_tEditMode) { alert("먼저 '편집 모드'를 켜세요."); return; }
    _tSnapshotForUndo();
    _tAutoArrange();
  });

  // 코어 초안 — 서버실 장비 중 방화벽·백본·L3/L4만 → 자동 연결 → 자동 정렬
  var coreBtn = document.getElementById("btn-topo-core");
  if (coreBtn) coreBtn.addEventListener("click", function () {
    if (_tdiag.nodes.length && !confirm(
        "현재 구성도를 코어 초안(방화벽·백본·L3/L4)으로 다시 채웁니다.\n" +
        "수집된 인접 정보로 선까지 자동 연결한 뒤 계층 정렬합니다.\n" +
        "바꾼 뒤에는 [되돌리기]로 복원할 수 있습니다.\n계속할까요?")) return;
    _tSnapshotForUndo();
    fetch("/api/topology/serverroom").then(function (r) { return r.json(); }).then(function (d) {
      var CORE = { firewall: 1, backbone: 1, l3: 1, l4: 1 };
      var nodes = (d.nodes || []).filter(function (n) { return CORE[n.kind]; });
      if (!nodes.length) {
        alert("서버실 현황에 방화벽·백본·L3 장비가 없습니다.\n('서버실 현황 불러오기'로 전체를 확인해 보세요)");
        return;
      }
      _tdiag = { nodes: [], edges: [] };
      _addLoadedNodes(nodes, false);
      _tView = null; _tSel = {}; _tSelId = null;
      _tSuppressSave = true;
      _tAutoLink({ quiet: true, done: function (added) {
        _tAutoArrange();
        _tSuppressSave = false;
        alert("코어 초안: 장비 " + _tdiag.nodes.length + "대" +
          (added ? ", 자동 연결 " + added + "건" : ", 자동 연결 근거 없음(수집 후 [자동 연결] 재시도)") +
          "\n배치를 다듬고 [저장]을 누르면 반영됩니다.");
      } });
    }).catch(function () { alert("코어 초안 불러오기 오류"); });
  });

  // 검색 → 해당 장비로 화면 이동 + 선택 표시(대형 구성도에서 장비 찾기)
  var sIn = document.getElementById("topo-search");
  if (sIn) sIn.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    var q = (sIn.value || "").trim().toLowerCase();
    if (!q) return;
    var hit = _tdiag.nodes.filter(function (n) {
      var m = _TOPO_KIND[n.kind] || {};
      return !m.zone && ((n.ip || "").toLowerCase().indexOf(q) >= 0 ||
                         (n.name || "").toLowerCase().indexOf(q) >= 0);
    })[0];
    if (!hit) { alert("'" + sIn.value + "' 와 일치하는 장비가 캔버스에 없습니다."); return; }
    _tSel = {}; _tSel[hit.id] = true; _tSelId = hit.id;
    _tView = { x: hit.x - 400, y: hit.y - 250, w: 800, h: 500 };   // 노드 중심으로 줌
    _renderEditor();
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
      downloadFile("/api/configs/export-all?ids=" + ids.join(","));
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
  if (!sw || !fw || !pf) return;
  sw.innerHTML = fw.innerHTML = pf.innerHTML =
    "<tr><td colspan=6 style='color:#64748b'>불러오는 중...</td></tr>";
  fetch("/api/credentials").then(function (r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }).then(function (d) {
    var delBtn = function (kind, key) {
      return "<button class='btn btn--secondary creds-del' style='font-size:11px;padding:2px 8px' " +
        "data-kind='" + escHtml(kind) + "' data-key='" +
        encodeURIComponent(key).replace(/'/g, "%27") + "'>삭제</button>";
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
    // 세 표를 모두 되돌린다. 예전엔 스위치 표만 '오류'로 바꾸고
    // 방화벽·PC 프로필은 '불러오는 중...'에서 영구히 멈춰 있었다.
    var msg = "<tr><td colspan=%d style='color:#b91c1c'>불러오지 못했습니다 — " +
      escHtml(String(e && e.message || e)) +
      " <button type='button' class='btn btn--secondary creds-retry' " +
      "style='font-size:11px;padding:2px 8px;margin-left:6px'>다시 시도</button></td></tr>";
    sw.innerHTML = msg.replace("%d", "3");
    fw.innerHTML = msg.replace("%d", "3");
    pf.innerHTML = msg.replace("%d", "6");
  });
}

(function () {
  var btn = document.getElementById("btn-creds");
  if (!btn) return;
  btn.addEventListener("click", function () { openModal("modal-creds"); loadCreds(); });

  // 개별 삭제(위임)
  document.getElementById("modal-creds").addEventListener("click", function (e) {
    if (e.target.closest(".creds-retry")) { loadCreds(); return; }
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
var _srvCollectIds = null;   // 일괄 수집 대상 id 목록(null/빈=전체)
var _srvEditId = null;   // 서버 수정 대상 id(null=신규 등록)

function _selectedServerIds() {
  return Array.prototype.map.call(
    document.querySelectorAll("#server-table-body .srv-check:checked"),
    function (c) { return parseInt(c.value, 10); });
}
function _updateSrvSelBtns() {
  var n = _selectedServerIds().length;
  var c = document.getElementById("btn-server-collect-all");
  if (c) c.textContent = "정보 수집 (" + n + ")";
  var d = document.getElementById("btn-server-bulk-delete");
  if (d) { d.textContent = "선택 삭제 (" + n + ")"; d.disabled = n === 0; }
}

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

// 개별 서버 수집 감시 — '수집중'인 행이 없어질 때까지 주기적으로 갱신한다.
// (서버 표에는 5초 폴링이 없어 한 번만 갱신하면 상태가 멈춰 보였다)
var _srvWatchTimer = null;
function _watchServerCollecting(maxSec) {
  if (_srvWatchTimer) clearInterval(_srvWatchTimer);
  var deadline = Date.now() + (maxSec || 300) * 1000;
  _srvWatchTimer = setInterval(function () {
    loadServers().then(function () {
      var busy = (_servers || []).some(function (s) { return s.status === "collecting"; });
      if (!busy || Date.now() > deadline) {
        clearInterval(_srvWatchTimer);
        _srvWatchTimer = null;
      }
    });
  }, 3000);
  loadServers();
}

function loadServers() {
  return fetch("/api/servers").then(function (r) { return r.json(); }).then(function (d) {
    _servers = d.servers || [];
    renderServers();
    // 서버실 현황이 열려 있으면 물리 서버 반영
    if (document.getElementById("tab-room").classList.contains("active")) renderRoom(_switches);
  }).catch(function (e) { console.error("servers:", e); });
}

// 사양 표기 헬퍼 — 수집 안 된 값은 "-"로 비워 둔다(0과 구분).
function fmtCpu(s) {
  var model = s.cpu_model || "";
  var n = _num(s.cpu_cores);                 // 숫자로 강제 → HTML 주입 여지 제거
  var cores = n ? n + "C" : "";
  if (model && cores) return escHtml(model) + " <span style='color:#64748b'>(" + cores + ")</span>";
  return escHtml(model) || cores || "-";
}
// DB/JSON에서 문자열로 올 수도 있으므로 항상 숫자로 강제한다.
// (표기 함수가 예외를 던지면 서버 표 전체가 렌더되지 않는다)
function _num(v) {
  var n = Number(v);
  return isFinite(n) ? n : 0;
}
// 장착 구성(JSON 문자열) → 배열. 깨진 값이 표 전체 렌더를 막지 않도록 항상 배열 반환.
function _hwList(v) {
  if (Array.isArray(v)) return v;
  try {
    var a = JSON.parse(v || "[]");
    return Array.isArray(a) ? a : [];
  } catch (e) { return []; }
}
function _sizeLabel(mb) {
  mb = _num(mb);
  if (!mb) return "-";
  if (mb >= 1048576) return (mb / 1048576).toFixed(1) + " TB";
  return mb >= 1024 ? (mb / 1024).toFixed(mb % 1024 ? 1 : 0) + " GB" : mb + " MB";
}
// 요약용 압축 라벨(공백 없음) — 좁은 셀용이자 CSV(백엔드 summarize_modules)와 표기 통일
function _sizeLabelCompact(mb) {
  mb = _num(mb);
  if (!mb) return "-";
  if (mb >= 1048576) return +(mb / 1048576).toFixed(1) + "TB";
  return mb >= 1024 ? +(mb / 1024).toFixed(mb % 1024 ? 1 : 0) + "GB" : mb + "MB";
}
// 모듈 목록 → '16GB×4 (DDR4)' 요약 (백엔드 summarize_modules와 같은 규칙)
// core/server_collector.py `_unknown_to_blank()`와 같은 목록. 화면 요약은 규격을
// 그대로 쓰고 CSV는 걸러내서 'DDR4 (Unknown)' vs 'DDR4'로 표기가 갈렸었다.
var _HW_PLACEHOLDERS = ["unknown", "not specified", "none", "no module installed",
                        "to be filled by o.e.m.", "n/a", "[empty]", "other"];
function _hwPlaceholder(v) {
  var s = String(v == null ? "" : v).trim();
  return _HW_PLACEHOLDERS.indexOf(s.toLowerCase()) >= 0 ? "" : s;
}
function summarizeModules(mods, slotsTotal) {
  if (!mods.length) return "";
  var counts = {}, order = [];
  mods.forEach(function (m) {
    var k = _num(m.size_mb);
    if (!(k in counts)) { counts[k] = 0; order.push(k); }
    counts[k]++;
  });
  order.sort(function (a, b) { return b - a; });
  var parts = order.map(function (k) { return _sizeLabelCompact(k) + "×" + counts[k]; });
  var types = [];
  mods.forEach(function (m) {
    var t = _hwPlaceholder(m.type);   // 'Unknown' 등은 CSV와 같은 규칙으로 제외
    if (t && types.indexOf(t) < 0) types.push(t);
  });
  var out = parts.join(" + ");
  if (types.length) out += " (" + types.sort().join(", ") + ")";
  slotsTotal = _num(slotsTotal);
  if (slotsTotal > mods.length) out += " · " + mods.length + "/" + slotsTotal + " 슬롯";
  return out;
}
function summarizeDisks(disks) {
  if (!disks.length) return "";
  var counts = {}, order = [];
  disks.forEach(function (d) {
    var k = d.kind || "디스크";
    if (!(k in counts)) { counts[k] = 0; order.push(k); }
    counts[k]++;
  });
  return order.sort().map(function (k) { return k + " " + counts[k]; }).join(" · ");
}
function fmtMem(mb) {
  mb = _num(mb);
  if (!mb) return "-";
  return mb >= 1024 ? (mb / 1024).toFixed(mb % 1024 ? 1 : 0) + " GB" : mb + " MB";
}
function fmtSize(gb) {
  gb = _num(gb);
  return gb >= 1024 ? (gb / 1024).toFixed(1) + " TB" : gb.toFixed(gb < 10 ? 1 : 0) + " GB";
}
// 주의: fmtDisk는 **HTML**을 돌려준다(사용률 색상 span 포함).
// escHtml()로 감싸는 자리에는 쓰면 안 된다 — 태그가 글자로 그대로 보인다.
// 그런 자리에는 fmtDiskText()를 쓴다.
function fmtDisk(s) {
  var total = _num(s.disk_total_gb);
  if (!total) return "-";
  var used = _num(s.disk_used_gb);
  var pct = Math.round((used / total) * 100);
  var color = pct >= 90 ? "#dc2626" : (pct >= 80 ? "#d97706" : "#64748b");
  return fmtSize(used) + " / " + fmtSize(total) +
    " <span style='color:" + color + "'>(" + pct + "%)</span>";
}
function fmtDiskText(s) {
  var total = _num(s.disk_total_gb);
  if (!total) return "-";
  var used = _num(s.disk_used_gb);
  return fmtSize(used) + " / " + fmtSize(total) +
    " (" + Math.round((used / total) * 100) + "%)";
}

// 표 셀 — 총량(굵게) + 장착 구성 요약. 구성이 있으면 클릭해 상세를 연다.
function memCell(s) {
  var mods = _hwList(s.mem_modules);
  var summary = summarizeModules(mods, s.mem_slots_total);
  var head = fmtMem(s.mem_total_mb);
  if (!summary) return head;
  return "<a href='#' data-action='hw-detail' data-id='" + s.id + "' data-hw='mem' " +
    "title='메모리 모듈 상세 보기' style='color:inherit;text-decoration:none'>" + head +
    "<div style='color:#2563eb'>" + escHtml(summary) + " ▸</div></a>";
}
function diskCell(s) {
  var disks = _hwList(s.disk_devices);
  var summary = summarizeDisks(disks);
  var head = fmtDisk(s);
  if (!summary) return head;
  return "<a href='#' data-action='hw-detail' data-id='" + s.id + "' data-hw='disk' " +
    "title='물리 디스크 상세 보기' style='color:inherit;text-decoration:none'>" + head +
    "<div style='color:#2563eb'>" + escHtml(summary) + " ▸</div></a>";
}

// 사양 셀 — CPU·메모리·디스크를 한 칸에 세 줄로 묶는다.
// 3개 컬럼으로 나눠 두면 폭이 좁아 내용이 잘려 안 보였다.
// 장착 구성(메모리 모듈·물리 디스크)이 있으면 그 줄을 클릭해 상세 팝업을 연다.
function specCell(s) {
  function row(label, valueHtml, hw) {
    var body = valueHtml;
    if (hw) {
      body = "<a href='#' data-action='hw-detail' data-id='" + s.id + "' data-hw='" + hw +
        "' title='장착 구성 상세 보기' style='color:inherit;text-decoration:none'>" +
        valueHtml + " <span style='color:#2563eb'>▸</span></a>";
    }
    return "<div><span class='cell-spec__k'>" + label + "</span>" + body + "</div>";
  }
  var mods = _hwList(s.mem_modules), disks = _hwList(s.disk_devices);
  var cpu = fmtCpu(s);
  var mem = escHtml(fmtMem(s.mem_total_mb));
  var memSum = summarizeModules(mods, s.mem_slots_total);
  if (memSum) mem += " <span style='color:#64748b'>(" + escHtml(memSum) + ")</span>";
  var disk = fmtDisk(s);
  var diskSum = summarizeDisks(disks);
  if (diskSum) disk += " <span style='color:#64748b'>(" + escHtml(diskSum) + ")</span>";
  if (!_num(s.cpu_cores) && !_num(s.mem_total_mb) && !_num(s.disk_total_gb)) {
    return "<span class='cell-none' title='계정을 입력해 수집하면 채워집니다'>미수집</span>";
  }
  return "<div class='cell-spec'>" +
    row("CPU", cpu, null) +
    row("MEM", mem, mods.length ? "mem" : null) +
    row("DISK", disk, disks.length ? "disk" : null) +
    "</div>";
}

// 장착 구성 상세 팝업 — 메모리 모듈 / 물리 디스크 목록
function showHwDetail(id, which) {
  var s = (_servers || []).find(function (x) { return x.id === id; });
  if (!s) return;
  var mods = _hwList(s.mem_modules), disks = _hwList(s.disk_devices);
  var t = document.getElementById("hw-detail-title");
  if (t) t.textContent = "장착 구성 — " + s.name + " (" + s.ip + ")";
  var html = "";

  html += "<h4 style='margin:0 0 6px;font-size:13px'>메모리 " +
    escHtml(fmtMem(s.mem_total_mb)) +
    (_num(s.mem_slots_total) ? " · " + mods.length + "/" + _num(s.mem_slots_total) + " 슬롯 사용" : "") +
    "</h4>";
  if (mods.length) {
    html += "<table class='data-table' style='font-size:12px;margin-bottom:14px'><thead><tr>" +
      "<th>슬롯</th><th>용량</th><th>규격</th><th>속도</th><th>제조사</th><th>파트번호</th>" +
      "</tr></thead><tbody>" +
      mods.map(function (m) {
        return "<tr><td>" + escHtml(m.locator || "-") + "</td>" +
          "<td>" + escHtml(_sizeLabel(m.size_mb)) + "</td>" +
          "<td>" + escHtml(_hwPlaceholder(m.type) || "-") + "</td>" +
          "<td>" + escHtml(_hwPlaceholder(m.speed) || "-") + "</td>" +
          "<td>" + escHtml(_hwPlaceholder(m.maker) || "-") + "</td>" +
          "<td>" + escHtml(_hwPlaceholder(m.part) || "-") + "</td></tr>";
      }).join("") + "</tbody></table>";
  } else {
    html += "<p style='font-size:12px;color:#64748b;margin:0 0 14px'>" +
      "모듈 정보가 없습니다. 리눅스는 <code>dmidecode</code>가 <b>root 권한</b>을 요구하므로 " +
      "일반 계정으로 수집하면 총량만 보입니다.</p>";
  }

  html += "<h4 style='margin:0 0 6px;font-size:13px'>디스크 " + escHtml(fmtDiskText(s)) +
    (disks.length ? " · " + disks.length + "개 장착" : "") + "</h4>";
  if (disks.length) {
    html += "<table class='data-table' style='font-size:12px'><thead><tr>" +
      "<th>장치</th><th>모델</th><th>용량</th>" +
      "<th title='SSD / HDD / NVMe'>종류</th>" +
      "<th title='연결 버스(SCSI·IDE·USB) — 저장매체 종류가 아님'>인터페이스</th>" +
      "</tr></thead><tbody>" +
      disks.map(function (d) {
        return "<tr><td>" + escHtml(d.name || "-") + "</td>" +
          "<td>" + escHtml(d.model || "-") + "</td>" +
          "<td>" + escHtml(_num(d.size_gb) >= 1024
            ? (_num(d.size_gb) / 1024).toFixed(1) + " TB"
            : _num(d.size_gb) + " GB") + "</td>" +
          "<td>" + escHtml(d.kind || "-") + "</td>" +
          "<td>" + escHtml(d.bus || "-") + "</td></tr>";
      }).join("") + "</tbody></table>";
  } else {
    html += "<p style='font-size:12px;color:#64748b;margin:0'>" +
      "물리 디스크 목록이 없습니다. 위 용량은 마운트된 파일시스템 합계입니다.</p>";
  }

  var box = document.getElementById("hw-detail-body");
  if (box) box.innerHTML = html;
  openModal("modal-hw-detail");
  // 클릭한 쪽으로 스크롤
  if (which === "disk" && box) {
    var hs = box.querySelectorAll("h4");
    if (hs.length > 1) hs[1].scrollIntoView({ block: "start" });
  }
}

function renderServers() {
  var body = document.getElementById("server-table-body");
  if (!body) return;
  var q = (document.getElementById("server-search") || {}).value;
  q = (q || "").trim().toLowerCase();
  var rows = _byStatusSel(_servers, "status-filter-srv").filter(function (s) {
    if (!q) return true;
    return [s.name, s.ip, s.hostname, s.mac, s.cpu_model].some(function (v) {
      return (v || "").toLowerCase().indexOf(q) >= 0;
    });
  });
  if (!rows.length) {
    body.innerHTML = "<tr><td colspan='13' style='color:#64748b'>" +
      (_servers.length ? "검색 결과가 없습니다." : "등록된 서버가 없습니다. [+ 서버 추가]로 추가하세요.") + "</td></tr>";
    return;
  }
  body.innerHTML = rows.map(function (s) {
    var kind = s.is_vm ? "<span style='color:#8b5cf6'>VM</span>"
                       : "<span style='color:#2563eb'>물리</span>";
    return "<tr>" +
      "<td style='text-align:center'><input type='checkbox' class='srv-check' value='" + s.id + "'></td>" +
      // 구분을 맨 앞에, 그다음 호스트네임(이름 컬럼 제거 — 대부분 같은 값이었다)
      "<td>" + kind + "</td>" +
      "<td>" + hostnameCell(s) + "</td>" +
      "<td><code>" + escHtml(s.ip) + "</code></td>" +
      "<td><code style='font-size:11px'>" + escHtml(s.mac || "-") + "</code></td>" +
      "<td>" + escHtml(s.os_info || s.os_type || "-") + "</td>" +
      // 사양: CPU·메모리·디스크를 한 칸에 모았다(3컬럼이라 내용이 잘려 안 보였다)
      "<td>" + specCell(s) + "</td>" +
      "<td style='font-size:11px;max-width:180px'>" + escHtml(s.open_ports || "-") + "</td>" +
      "<td>" + escHtml(s.switch_name || "-") + "</td>" +
      "<td>" + escHtml(s.switch_port || "-") + "</td>" +
      "<td>" + locationCell(s) + "</td>" +
      "<td>" + statusBadge(s.status, s.last_error) + "</td>" +
      // 작업 — 스위치 현황과 같은 구성(수집·수정·진단·터미널·삭제)
      "<td style='white-space:nowrap'>" +
        "<button class='btn btn--primary' style='font-size:11px;padding:2px 8px' " +
        "title='계정을 입력해 이 서버를 재수집' data-action='collect-server' data-id='" + s.id + "'>수집</button> " +
        "<button class='btn btn--secondary' style='font-size:11px;padding:2px 8px' " +
        "data-action='edit-server' data-id='" + s.id + "'>수정</button> " +
        "<button class='btn btn--secondary' style='font-size:11px;padding:2px 8px' " +
        "title='계정 없이 도달성·열린 포트·hostname·연결 스위치를 확인' " +
        "data-action='diagnose-server' data-id='" + s.id + "'>진단</button> " +
        "<button class='btn btn--ghost' style='font-size:11px;padding:2px 8px' " +
        "data-action='delete-server' data-id='" + s.id + "'>삭제</button>" +
      "</td></tr>";
  }).join("");
  // 재렌더로 체크가 풀렸는데 버튼 라벨이 "(3)"으로 남아 있으면, 눌러도 아무 일이
  // 안 일어난다(대상 0건). 표를 다시 그릴 때마다 선택 개수를 맞춘다.
  _updateSrvSelBtns();
  var allChk = document.getElementById("srv-check-all");
  if (allChk) allChk.checked = false;
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

  // 서버 전체선택 체크박스 + 선택 카운트
  var srvAll = document.getElementById("srv-check-all");
  if (srvAll) srvAll.addEventListener("change", function () {
    Array.prototype.forEach.call(document.querySelectorAll("#server-table-body .srv-check"),
      function (c) { c.checked = srvAll.checked; });
    _updateSrvSelBtns();
  });
  var srvBody = document.getElementById("server-table-body");
  if (srvBody) srvBody.addEventListener("change", function (e) {
    if (e.target && e.target.classList.contains("srv-check")) _updateSrvSelBtns();
  });

  // 서버 선택 삭제
  var srvDel = document.getElementById("btn-server-bulk-delete");
  if (srvDel) srvDel.addEventListener("click", function () {
    var ids = _selectedServerIds();
    if (!ids.length) return;
    if (!confirm(ids.length + "대 서버를 삭제할까요?")) return;
    Promise.all(ids.map(function (id) {
      return fetch("/api/servers/" + id, { method: "DELETE" }).catch(function () {});
    })).then(loadServers);
  });

  // 서버 전체 진단 — 계정 없이 도달성·포트·hostname·연결 스위치 확인
  var srvDiag = document.getElementById("btn-server-diagnose");
  if (srvDiag) srvDiag.addEventListener("click", function () {
    if (!(_servers || []).length) { alert("등록된 서버가 없습니다."); return; }
    if (!confirm("계정 없이 전 서버의 도달성·열린 포트·hostname·연결 스위치를 확인합니다.\n" +
                 "SSH 접속은 하지 않으므로 OS·CPU·메모리·디스크는 갱신되지 않습니다.\n계속할까요?")) return;
    // 예전엔 collect-all을 호출해 세션·저장 계정으로 실제 SSH 접속을 했다(안내와 다름)
    fetch("/api/servers/diagnose-all", { method: "POST" })
      .then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (!res.ok) { alert((res.b && res.b.error) || "진단 시작 실패"); return; }
        pollProgress("/api/servers/collect-all/status", "server-progress", loadServers,
          "/api/servers/collect-all/stop", loadServers);   // 수집 중에도 표 갱신
      }).catch(function (e) { console.error(e); alert("진단 오류"); });
  });

  var allBtn = document.getElementById("btn-server-collect-all");
  if (allBtn) allBtn.addEventListener("click", function () {
    if (!_servers.length) { alert("등록된 서버가 없습니다."); return; }
    // 체크된 서버만(없으면 전체) — 계정은 팝업에서만 입력받는다(툴바 노출 제거)
    var ids = _selectedServerIds();
    _srvCollectIds = ids;                       // 일괄 대상(빈 배열이면 전체)
    _srvCollectId = null;
    var t = document.getElementById("srv-collect-title");
    if (t) t.textContent = "서버 수집 — " + (ids.length ? (ids.length + "대 선택") : "전체");
    var u = document.getElementById("srv-username"); if (u) u.value = "";
    var p = document.getElementById("srv-password"); if (p) p.value = "";
    var pe = document.getElementById("srv-persist"); if (pe) pe.checked = false;
    openModal("modal-server-collect");
  });

  // 일괄 수집 실행(모달에서 계정 입력 후 호출) — 진행바 폴링 공용
  window._runServerCollectAll = function (body) {
    fetch("/api/servers/collect-all", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json(); })
      .then(function () {
        pollProgress("/api/servers/collect-all/status", "server-progress", loadServers,
          "/api/servers/collect-all/stop", loadServers);   // 수집 중에도 표 갱신
      }).catch(function (e) { console.error(e); alert("수집 오류"); });
  };

  // 방화벽 전체 수집 — 진행바 폴링
  var fwAllBtn = document.getElementById("btn-firewall-collect-all");
  if (fwAllBtn) fwAllBtn.addEventListener("click", function () {
    var ids = Object.keys(_fwSel).map(function (x) { return parseInt(x, 10); });
    // 방화벽 계정은 스위치·서버와 다르다 → 이 화면에서 직접 입력받는다.
    // (저장 계정이 있거나 방화벽 세션 계정이 살아 있으면 팝업에서 빈칸으로 두면 된다)
    _openFwBulkCollect(ids);
  });

  // 방화벽 일괄 수집 — 개별 수집 팝업을 재사용해 계정을 입력받는다
  function _openFwBulkCollect(ids) {
    _selectedFirewall = null;            // 개별이 아니라 일괄
    _fwBulkIds = ids;
    var t = document.getElementById("modal-fw-collect-title");
    if (t) t.textContent = "방화벽 정보 수집 — " + (ids.length ? (ids.length + "대 선택") : "전체");
    var info = document.getElementById("modal-fw-collect-info");
    if (info) {
      info.innerHTML = _fwTargetInfo(ids);
    }
    var hint = document.getElementById("fw-cred-hint");
    if (hint) {
      hint.textContent = "비워두면 각 방화벽에 저장된 계정(또는 이 세션의 방화벽 계정)을 사용합니다. " +
        "FortiGate는 API 토큰, Palo Alto는 아이디/패스워드가 필요합니다.";
    }
    ["fw-token", "fw-username", "fw-password"].forEach(function (id) {
      var el = document.getElementById(id); if (el) el.value = "";
    });
    var rm = document.getElementById("fw-remember"); if (rm) rm.checked = false;
    var tr = document.getElementById("fw-test-result"); if (tr) tr.textContent = "";
    openModal("modal-fw-collect");
  }
  window._openFwBulkCollect = _openFwBulkCollect;

  function _fwTargetInfo(ids) {
    if (!ids.length) {
      return "<strong>등록된 전체</strong> 방화벽";
    }
    var names = ids.map(function (id) {
      var f = (_firewalls || []).find(function (x) { return String(x.id) === String(id); });
      return f ? (f.name + " (" + f.host + ")") : ("#" + id);
    });
    var head = "<strong>" + ids.length + "대</strong> 선택됨";
    if (names.length <= 5) {
      return head + "<div style='margin-top:4px;color:var(--text-2)'>" +
        names.map(escHtml).join(", ") + "</div>";
    }
    return head + "<div style='margin-top:4px;color:var(--text-2)'>" +
      names.slice(0, 5).map(escHtml).join(", ") +
      " <span style='color:var(--text-faint)'>외 " + (names.length - 5) + "대</span></div>" +
      "<details class='target-list' style='margin-top:6px'>" +
      "<summary>대상 " + names.length + "대 전체 보기</summary>" +
      "<div class='target-list__items'>" + names.map(escHtml).join("<br>") + "</div></details>";
  }

  function _fwRunBulk(ids, token, username, password) {
    var body = ids.length ? {ids: ids} : {};
    if (token) body.token = token;
    if (username) body.username = username;
    if (password) body.password = password;
    fetch("/api/firewalls/collect-all", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    })
      .then(function (r) { return r.json().then(function (b) { return {ok: r.ok, b: b}; }); })
      .then(function (res) {
        if (!res.ok) { alert((res.b && res.b.error) || "일괄 수집 시작 실패"); return; }
        pollProgress("/api/firewalls/collect-all/status", "firewall-progress", loadFirewalls,
          "/api/firewalls/collect-all/stop", loadFirewalls);   // 수집 중에도 표 갱신
      }).catch(function (e) { console.error(e); alert("수집 오류"); });
  }
  window._fwRunBulk = _fwRunBulk;

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
    var body = {
      username: document.getElementById("srv-username").value.trim(),
      password: document.getElementById("srv-password").value,
      persist: document.getElementById("srv-persist").checked,
    };
    var srem = document.getElementById("srv-remember");
    if (srem && srem.checked && body.username && body.password) {
      sessCredRemember(body.username, body.password, "server");
    }
    // 일괄 경로(정보 수집 버튼): 선택분 또는 전체를 계정과 함께 수집
    if (_srvCollectId == null) {
      if (_srvCollectIds && _srvCollectIds.length) body.ids = _srvCollectIds;
      closeModal("modal-server-collect");
      document.getElementById("srv-password").value = "";   // 화면 잔류 방지
      _srvCollectIds = null;
      window._runServerCollectAll(body);
      return;
    }
    fetch("/api/servers/" + _srvCollectId + "/collect", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) {
        closeModal("modal-server-collect");
        // 예전엔 6초 뒤 딱 한 번만 갱신해서, SSH 상세 수집이 그보다 오래 걸리면
        // 탭을 다시 누르기 전까지 행이 계속 '수집중'으로 남았다.
        _watchServerCollecting();
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
  // 방화벽 이벤트는 백엔드가 실제로 발생시키는데(core/reachability.py) 여기에
  // 없어 알람 목록에 영문 키 그대로 노출됐다(관제 월보드에는 한글이 있었다).
  firewall_unreachable: "방화벽 연결 실패", firewall_recovered: "방화벽 복구",
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
// 관제 대시보드에서 스위치를 클릭하면 /#switch=<id> 로 열린다 — 목록이 로드된 뒤
// 한 번만 해당 스위치의 상세 패널을 연다(해시는 지워 새로고침 시 재열림 방지).
var _hashDetailDone = false;
function _openHashDetail() {
  if (_hashDetailDone) return;
  var m = (location.hash || "").match(/^#switch=(\d+)$/);
  if (!m) { _hashDetailDone = true; return; }
  var id = parseInt(m[1], 10);
  var sw = (_switches || []).find(function (s) { return s.id === id; });
  if (!sw) return;                        // 아직 로드 전이면 다음 폴링에서 재시도
  _hashDetailDone = true;
  try { history.replaceState(null, "", location.pathname); } catch (e) {}
  openDetailPanel(sw);
}

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
      _openHashDetail();      // 관제 Top10 클릭 등 #switch=<id> 딥링크 처리

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
// 표시 시간대 — 설정에서 고를 수 있고, 서버가 알려준 값으로 채워진다.
// (기본 America/New_York = 미국 동부. 'local'이면 이 브라우저 PC 기준)
var _TZ = { zone: "America/New_York", label: "미국 동부", srvOffsetMin: null };

var _TZ_CHOICES = [
  { zone: "America/New_York", label: "미국 동부 (EST/EDT)" },
  { zone: "Asia/Seoul", label: "한국 (KST)" },
  { zone: "UTC", label: "UTC" },
  { zone: "local", label: "이 PC의 시간대" },
];

// 서버가 알려준 표시 시간대·오프셋을 적용한다.
function _applyTimezone(d) {
  if (!d) return;
  if (d.display_timezone) _TZ.zone = d.display_timezone;
  if (typeof d.server_tz_offset_min === "number") _TZ.srvOffsetMin = d.server_tz_offset_min;
  _TZ.label = _tzLabel(_TZ.zone);
}

// 기동 시 1회 — 시간대 설정을 받아 첫 렌더부터 올바른 시각이 나오게 한다.
function loadTimezone() {
  return fetch("/api/settings/auto_collect").then(function (r) { return r.json(); })
    .then(function (d) { _applyTimezone(d); }).catch(function () {});
}

function _tzLabel(zone) {
  for (var i = 0; i < _TZ_CHOICES.length; i++) {
    if (_TZ_CHOICES[i].zone === zone) return _TZ_CHOICES[i].label;
  }
  return zone;
}

// 시각 문자열 → 선택한 시간대 표기.
//
// DB는 `datetime('now','localtime')` 즉 **서버 PC의 로컬 시각**을 시간대 표기 없이
// 저장한다. 예전 코드는 이 값을 UTC로 가정해 'Z'를 붙인 뒤 미국 동부로 변환해서,
// 서버가 EDT(UTC-4)일 때 **4시간 이르게** 표시됐다("수집 시간이 안 맞는다").
// 서버의 UTC 오프셋을 받아 실제 순간을 복원한 뒤 선택 시간대로 표기한다.
function fmtTime(ts) {
  if (!ts) return "-";
  try {
    var raw = String(ts).trim();
    var s = raw.replace(" ", "T");
    var d;
    if (/[zZ]|[+\-]\d\d:?\d\d$/.test(s)) {
      d = new Date(s);                       // 이미 시간대가 명시된 값
    } else if (_TZ.srvOffsetMin == null) {
      d = new Date(s);                       // 오프셋 미확보 → 브라우저 로컬로 해석
    } else {
      // 서버 로컬 벽시계 → UTC 순간으로 환산
      var m = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/);
      if (!m) return raw;
      var utcMs = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
      d = new Date(utcMs - _TZ.srvOffsetMin * 60000);
    }
    if (isNaN(d.getTime())) return raw;
    var opt = { year: "numeric", month: "2-digit", day: "2-digit",
                hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false };
    if (_TZ.zone && _TZ.zone !== "local") opt.timeZone = _TZ.zone;
    var out = d.toLocaleString("sv-SE", opt).replace("T", " ");
    return out + (_TZ.zone === "local" ? "" : " " + _tzAbbr(d));
  } catch (e) { return String(ts); }
}

// 표기용 시간대 약어(EDT/KST/UTC …) — 브라우저가 계산해 주므로 DST도 맞는다.
function _tzAbbr(d) {
  if (_TZ.zone === "UTC") return "UTC";
  try {
    var p = new Intl.DateTimeFormat("en-US", {
      timeZone: _TZ.zone, timeZoneName: "short",
    }).formatToParts(d);
    for (var i = 0; i < p.length; i++) {
      if (p[i].type === "timeZoneName") return p[i].value;
    }
  } catch (e) { /* 무시 */ }
  return "";
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

// ─── 세션 수집 계정 (메모리 전용·TTL) ─────────────────────────────
// 계정을 화면에 상시 노출하지 않으면서 수집 때마다 재입력하는 불편을 없앤다.
// 비밀번호는 서버 메모리에만 있고, 여기서는 활성 여부와 남은 시간만 받아 표시한다.
// 장비 종류별로 따로 보관한다 — 스위치·서버·방화벽은 계정 체계가 대개 다르고,
// 하나로 공유하면 스위치 계정이 전 서버에 SSH로 시도돼 계정이 잠길 수 있다.
window._sessCredActive = false;              // (하위호환) 아무 종류나 하나라도 활성
window._sessCredKinds = {};                  // {switch|server|firewall: true}
var SESS_KIND_LABEL = { switch: "스위치", server: "서버", firewall: "방화벽" };

function sessCredActive(kind) {
  return !!window._sessCredKinds[kind];
}

function sessCredRemember(username, password, kind) {
  return fetch("/api/session/credential", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username, password: password,
                           kind: kind || "switch" }),
  }).then(function (r) { return r.json(); })
    .then(function () { refreshSessCred(); })
    .catch(function () { /* 실패해도 이번 수집은 입력한 계정으로 진행됨 */ });
}

function refreshSessCred() {
  var box = document.getElementById("sess-cred");
  if (!box) return;
  fetch("/api/session/credential").then(function (r) { return r.json(); })
    .then(function (s) {
      var kinds = (s && s.kinds) || {};
      window._sessCredKinds = {};
      var parts = [];
      Object.keys(SESS_KIND_LABEL).forEach(function (k) {
        if (kinds[k] && kinds[k].active) {
          window._sessCredKinds[k] = true;
          parts.push(SESS_KIND_LABEL[k] + " " + (kinds[k].username || "") +
                     "(" + Math.max(1, Math.ceil((kinds[k].remaining || 0) / 60)) + "분)");
        }
      });
      window._sessCredActive = parts.length > 0;
      if (!window._sessCredActive) { box.classList.add("hidden"); return; }
      var t = document.getElementById("sess-cred-text");
      if (t) t.textContent = "🔓 수집 계정 " + parts.join(" · ");
      box.classList.remove("hidden");
    })
    .catch(function () { /* 상태 조회 실패는 무시 */ });
}

(function () {
  var lock = document.getElementById("btn-sess-lock");
  if (lock) lock.addEventListener("click", function () {
    fetch("/api/session/credential/lock", { method: "POST" })
      .then(function () {
        window._sessCredActive = false;
        var box = document.getElementById("sess-cred");
        if (box) box.classList.add("hidden");
      });
  });
  refreshSessCred();
  setInterval(refreshSessCred, 30000);   // 남은 시간 갱신·만료 시 자동 숨김
})();

// ─── 새로고침 복구 ───────────────────────────────────────────────
// 백그라운드 작업(일괄 수집·진단)은 서버에서 계속 도는데 화면을 새로고침하면
// 진행바가 사라져 "멈춘 건지 도는 건지" 알 수 없었다. 시작 시 상태를 한 번
// 조회해 running이면 진행 표시를 다시 붙인다.
(function () {
  var JOBS = [
    ["/api/servers/collect-all/status", "server-progress", loadServers,
     "/api/servers/collect-all/stop"],
    ["/api/firewalls/collect-all/status", "firewall-progress", loadFirewalls,
     "/api/firewalls/collect-all/stop"],
    ["/api/switches/bulk-collect/status", "sw-bulk-progress", pollState,
     "/api/switches/bulk-collect/stop"],
  ];
  JOBS.forEach(function (j) {
    fetch(j[0]).then(function (r) { return r.json(); }).then(function (st) {
      if (st && st.running) pollProgress(j[0], j[1], j[2], j[3]);
    }).catch(function () {});
  });
})();

// ─── 초기화 ──────────────────────────────────────────────────────
// 시간대를 먼저 받아야 첫 렌더부터 수집 시각이 올바르게 표시된다.
loadTimezone().then(function () { pollState(); loadServers(); });
loadNetInfo();
pollState();
loadFirewalls();  // 서버실 현황에 방화벽을 표시하려면 시작 시 방화벽 목록도 로드
_pollTimer = setInterval(pollState, 5000);
