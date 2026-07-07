/* NetDash — 메인 UI 스크립트 */

"use strict";

// ─── 전역 상태 ────────────────────────────────────────────────────
let _switches = [];
let _firewalls = [];
let _currentSwitchId = null;
let _pollTimer = null;

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
    case "edit-switch": editSwitch(obj); break;
    case "diagnose-switch": diagnoseSwitch(nid); break;
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

// ─── M14: 자동 수집 설정 ─────────────────────────────────────────
(function () {
  var btn = document.getElementById("btn-auto-collect");
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

// 테이블 검색창 HTML 생성 헬퍼
function _searchBox(targetId, placeholder) {
  return "<input class='tbl-search' data-target='" + targetId + "' placeholder='" +
    placeholder + "' style='margin-bottom:8px;padding:5px 9px;width:240px;" +
    "border:1px solid #cbd5e1;border-radius:4px;font-size:13px'>";
}

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
    if (btn.dataset.tab === "room") { loadFirewalls(); renderRoom(_switches); }
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
    document.querySelectorAll(".modal:not(.hidden)").forEach(m => closeModal(m.id));
  });
});

function openModal(id) { document.getElementById(id).classList.remove("hidden"); }
function closeModal(id) { document.getElementById(id).classList.add("hidden"); }

// ─── 상세 패널 ───────────────────────────────────────────────────
document.getElementById("detail-close").addEventListener("click", closeDetailPanel);
document.getElementById("detail-overlay").addEventListener("click", closeDetailPanel);

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

function renderEventsTab(events) {
  var el = document.getElementById("dtab-events");
  if (!events.length) { el.innerHTML = "<p style='color:#64748b'>감지된 이벤트 없음</p>"; return; }
  el.innerHTML = "<table class='data-table'><thead><tr><th>포트</th><th>유형</th><th>횟수</th><th>최초</th><th>최근</th></tr></thead><tbody>" +
    events.map(function(e) {
      return "<tr><td>" + escHtml(e.port_name) + "</td><td><span class='status-badge status-badge--" +
        (e.event_type === "looping" ? "critical" : "warning") + "'>" + escHtml(e.event_type) + "</span></td><td>" +
        e.count + "</td><td>" + fmtTime(e.first_seen) + "</td><td>" + fmtTime(e.last_seen) + "</td></tr>";
    }).join("") + "</tbody></table>";
}

// ─── 스위치 카드 렌더링 ──────────────────────────────────────────
var _viewMode = "card";  // card | rack
var _bulkSel = {};        // 일괄 수집 선택 집합 {switch_id: true} — 재렌더에도 유지
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
      document.querySelectorAll(".dash-sfilter").forEach(function (b) {
        b.className = "btn dash-sfilter " +
          (b === btn ? "btn--primary" : "btn--secondary");
        b.style.fontSize = "12px";
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

// 장비(스위치/방화벽)의 랙뷰 그룹/랙 키 결정.
// TPS 호스트네임 → 공장/건물/층. 아니면 서버실 랙(A09U27). 아니면 위치 텍스트. 없으면 미지정.
function _deviceRackKeys(dev) {
  if (dev.tps_group) return { group: dev.tps_group, rack: dev.tps_num || "기타" };
  if (dev.room_rack) return { group: "서버실", rack: dev.room_rack + " 랙" };
  if (dev.location) return { group: dev.location, rack: "기타" };
  return { group: "위치 미상(미지정)", rack: "기타" };
}

function renderRackView(switches) {
  var host = document.getElementById("rack-view");
  if (!host) return;
  switches = _applyStatusFilter(_applyLocFilter(switches, "loc-filter-dash"));
  var fws = _dashStatusFilter === "all"
    ? _applyLocFilter(_firewalls || [], "loc-filter-dash") : [];
  // 스위치 + 방화벽을 하나의 위치 맵으로. 그룹 → 랙 → 유닛
  var devices = switches.map(function (s) { return { k: "sw", o: s }; })
    .concat(fws.map(function (f) { return { k: "fw", o: f }; }));
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
    rkeys.forEach(function (t) {
      racks[t].forEach(function (d) { if (d.k !== "fw") gIds.push(d.o.id); });
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
          " data-action='detail-switch' data-payload='" + encodeURIComponent(JSON.stringify(sw)) + "'>" +
          "<span class='rack-unit__name'>" + escHtml(sw.name) + "</span>" +
          "<span class='rack-unit__ip'>" + escHtml(sw.ip) + "</span></div>";
      }).join("");
      return "<div class='rack'><div class='rack__label'>" + escHtml(t) + "</div>" +
        "<div class='rack__units'>" + units + "</div></div>";
    }).join("");
    return "<div class='rack-group'><div class='rack-group__title'>📍 " + escHtml(g) + selBtn + "</div>" +
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
})();

function renderRoom(switches) {
  // 서버실 소속 = location이 "A09U27" 형식(room_rack 주입됨). 스위치 + 방화벽 모두.
  var roomSw = (switches || _switches || []).filter(function (sw) { return sw.room_rack; });
  var roomFw = (_firewalls || []).filter(function (f) { return f.room_rack; });
  if (_roomViewMode === "rack") renderRoomRackView(roomSw, roomFw);
  else renderRoomGrid(roomSw, roomFw);
}

var _ROOM_EMPTY = "서버실 위치(A09U27 형식)가 지정된 장비가 없습니다. 스위치/방화벽 수정 → 위치에 A09U27처럼 입력하세요.";

// 방화벽 카드 — 스위치 카드(swCardHTML)와 동일한 골격으로 통일(현황판·서버실 공용).
function _fwCardHTML(f) {
  // 도달성 감시에서 끊김이면 카드 전체를 위험 상태로 표시(현황판/서버실 공통)
  var sc = f.reachable === false ? "critical" : (_fwStatusMeta[f.status] || "new");
  var reachBadge = f.reachable === false
    ? "<span class='sw-card__alert-badge badge--critical' title='도달성 감시: 관리 포트 TCP 응답 없음'>🔴 연결 끊김</span>"
    : "";
  var locLine = f.tps_location ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>📍 " + escHtml(f.tps_location) + "</span>"
    : f.room_label ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>🗄 " + escHtml(f.room_label) + "</span>"
    : f.location ? "<span style='font-size:10px'>" + escHtml(f.location) + "</span>" : "";
  return "<div class='sw-card sw-card--" + sc + "'>" + reachBadge +
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

function renderRoomGrid(switches, firewalls) {
  switches = _applyLocFilter(switches, "loc-filter-room");
  firewalls = _applyLocFilter(firewalls || [], "loc-filter-room");
  var grid = document.getElementById("room-grid");
  if (!grid) return;
  if (!switches.length && !firewalls.length) {
    grid.innerHTML = "<p class='placeholder'>" + _ROOM_EMPTY + "</p>";
    return;
  }
  // 현황판 카드뷰와 동일한 평면 그리드(랙 오름차순 → U 내림차순 정렬만 적용)
  switches = switches.slice().sort(_roomSort);
  firewalls = firewalls.slice().sort(_roomSort);
  grid.innerHTML = switches.map(function (sw) { return swCardHTML(sw, false); }).join("") +
                   firewalls.map(_fwCardHTML).join("");
  switches.forEach(function (sw) {
    var card = document.getElementById("swcard-" + sw.id);
    if (!card) return;
    card.addEventListener("click", function (e) {
      if (e.target.closest("[data-action]")) return;
      openCredentialModal(sw);
    });
  });
}

function _roomSort(a, b) {
  if (a.room_rack !== b.room_rack) return a.room_rack < b.room_rack ? -1 : 1;
  return (b.room_unit || 0) - (a.room_unit || 0);  // 유닛 높은 번호가 위(실제 랙과 동일)
}

function renderRoomRackView(switches, firewalls) {
  var host = document.getElementById("room-rack-view");
  if (!host) return;
  switches = _applyLocFilter(switches, "loc-filter-room");
  firewalls = _applyLocFilter(firewalls || [], "loc-filter-room");
  if (!switches.length && !firewalls.length) {
    host.innerHTML = "<p class='placeholder'>" + _ROOM_EMPTY + "</p>";
    return;
  }
  // 랙(room_rack) → 유닛 목록 (스위치 + 방화벽)
  var racks = {};
  switches.forEach(function (sw) { (racks[sw.room_rack] = racks[sw.room_rack] || []).push({ k: "sw", o: sw }); });
  firewalls.forEach(function (f) { (racks[f.room_rack] = racks[f.room_rack] || []).push({ k: "fw", o: f }); });

  // 열(A/B/...) 단위로 줄을 나눔: A01 A02...가 한 줄, B01 B02...가 다음 줄.
  // 각 랙 안은 U 내림차순(U42→U41→U40 — 실제 랙 상단부터).
  var rows = {};
  Object.keys(racks).forEach(function (rk) {
    var m = rk.match(/^[A-Za-z]+/);
    var letter = m ? m[0].toUpperCase() : "#";
    (rows[letter] = rows[letter] || []).push(rk);
  });

  function _rackHtml(rk) {
    var units = racks[rk].slice().sort(function (a, b) { return (b.o.room_unit || 0) - (a.o.room_unit || 0); });
    var unitsHtml = units.map(function (u) {
      if (u.k === "fw") {
        var f = u.o, fsc = f.reachable === false ? "critical" : (_fwStatusMeta[f.status] || "new");
        return "<div class='rack-unit rack-unit--" + fsc + "' data-action='detail-fw' data-id='" + f.id + "'>" +
          "<span class='rack-unit__u'>U" + escHtml(String(f.room_unit)) + "</span>" +
          "<span class='rack-unit__name'>🛡 " + escHtml(f.name) + "</span>" +
          "<span class='rack-unit__ip'>" + escHtml(f.host) + "</span></div>";
      }
      var sw = u.o, cls = swStatusClass(sw);
      return "<div class='rack-unit rack-unit--" + cls + "' " +
        "data-action='detail-switch' data-payload='" + encodeURIComponent(JSON.stringify(sw)) + "'>" +
        "<span class='rack-unit__u'>U" + escHtml(String(sw.room_unit)) + "</span>" +
        "<span class='rack-unit__name'>" + escHtml(sw.name) + "</span>" +
        "<span class='rack-unit__ip'>" + escHtml(sw.ip) + "</span></div>";
    }).join("");
    return "<div class='rack'><div class='rack__label'>🗄 " + escHtml(rk) + "</div>" +
      "<div class='rack__units'>" + unitsHtml + "</div></div>";
  }

  host.innerHTML = Object.keys(rows).sort().map(function (letter) {
    var racksHtml = rows[letter].sort().map(_rackHtml).join("");
    return "<div class='rack-group'><div class='rack-group__title'>🗄 " + escHtml(letter) +
      " 열</div><div class='rack-row'>" + racksHtml + "</div></div>";
  }).join("");
}

function renderSwitchGrid(switches) {
  _updateStatusCounts(_applyLocFilter(switches, "loc-filter-dash"));
  switches = _applyStatusFilter(_applyLocFilter(switches, "loc-filter-dash"));
  // 상태 필터가 걸려 있으면 방화벽 카드는 숨김(스위치 재수집 목적 화면)
  var fws = _dashStatusFilter === "all"
    ? _applyLocFilter(_firewalls || [], "loc-filter-dash") : [];
  var grid = document.getElementById("switch-grid");
  if (!switches.length && !fws.length) {
    grid.innerHTML = "<p class='placeholder'>" +
      (_dashStatusFilter === "all"
        ? "표시할 장비가 없습니다. (위치 필터를 확인하거나 스위치/방화벽을 추가하세요)"
        : "해당 상태의 스위치가 없습니다.") + "</p>";
    return;
  }
  grid.innerHTML = switches.map(function (sw) { return swCardHTML(sw, true); }).join("") +
                   fws.map(_fwCardHTML).join("");
  switches.forEach(function(sw) {
    var card = document.getElementById("swcard-" + sw.id);
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
       ? "<span class='sw-card__alert-badge badge--critical' title='도달성 감시(TCP-22)에서 응답 없음'>🔴 도달불가</span>"
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

  var swJson = encodeURIComponent(JSON.stringify(sw));

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
    (sw.location ? "<span style='font-size:10px'>" + escHtml(sw.location) + "</span>" : "") +
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

// 구분 인라인 변경(위임) — 선택 즉시 저장
document.addEventListener("change", function (e) {
  var t = e.target;
  if (!t || !t.classList || !t.classList.contains("sw-type-sel")) return;
  var id = parseInt(t.getAttribute("data-id"), 10);
  fetch("/api/switches/" + id, {
    method: "PUT", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({device_type: t.value}),
  }).then(function (r) { return r.json(); }).then(function (res) {
    if (!res.ok) alert(res.error || "구분 변경 실패");
    else pollState();
  }).catch(function (err) { console.error(err); });
});

// 구분 일괄 변경(체크된 항목에 적용)
(function () {
  var sel = document.getElementById("sw-bulk-type");
  var btn = document.getElementById("btn-sw-apply-type");
  if (!sel || !btn) return;
  sel.addEventListener("change", function () { btn.disabled = !sel.value; });
  btn.addEventListener("click", function () {
    var ids = Array.prototype.map.call(
      document.querySelectorAll("#switch-table-body .sw-check:checked"),
      function (c) { return parseInt(c.value, 10); });
    if (!ids.length) { alert("먼저 변경할 스위치를 체크하세요."); return; }
    if (!sel.value) return;
    fetch("/api/switches/bulk-set-type", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids: ids, device_type: sel.value}),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) { alert(res.updated + "대 구분을 '" + sel.value + "'로 변경했습니다."); pollState(); }
      else alert(res.error || "일괄 변경 실패");
    }).catch(function (e) { console.error(e); alert("일괄 변경 오류"); });
  });
})();

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
  switches = _applySwSearch(switches);
  var tbody = document.getElementById("switch-table-body");
  if (tbody && !switches.length) {
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
    // 구분(장비 유형) — 인라인 드롭다운(변경 즉시 저장). 이름은 카드/검색에서 사용.
    var typeSel = "<select class='sw-type-sel' data-id='" + sw.id + "' style='font-size:12px;padding:3px'>" +
      "<option value=''" + (!sw.device_type ? " selected" : "") + ">미지정</option>" +
      _DEVICE_TYPES.map(function (t) {
        return "<option" + (sw.device_type === t ? " selected" : "") + ">" + escHtml(t) + "</option>";
      }).join("") + "</select>";
    // 모델·버전(수집 시 show version에서 자동 추출) — 별도 컬럼
    return "<tr>" +
      "<td style='text-align:center'><input type='checkbox' class='sw-check' value='" + sw.id + "'></td>" +
      "<td>" + typeSel + "</td><td><code>" + escHtml(sw.ip) + "</code></td><td>" +
      escHtml(sw.hostname || "-") + "</td><td>" + escHtml(_vendorLabel(sw.vendor)) + "</td><td>" +
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
      (sw.alert && sw.alert !== "none" ? "<span class='status-badge status-badge--" + sw.alert + "'>" + sw.alert + "</span>" : "-") +
      "</td><td>" + fmtTime(sw.last_collected) + "</td>" +
      "<td>" +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "data-action='edit-switch' data-payload='" + encodeURIComponent(JSON.stringify(sw)) + "'>수정</button> " +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "title='실제 배너/프롬프트/show version 응답을 확인(벤더 미인식 원인 파악)' " +
      "data-action='diagnose-switch' data-id='" + sw.id + "'>진단</button> " +
      "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' " +
      "data-action='delete-switch' data-id='" + sw.id + "'>삭제</button></td></tr>";
  }).join("");
  var allChk = document.getElementById("sw-check-all");
  if (allChk) allChk.checked = false;
  _updateBulkDeleteBtn();
}

// 선택 삭제 버튼 상태(개수) 갱신
function _updateBulkDeleteBtn() {
  var btn = document.getElementById("btn-sw-bulk-delete");
  if (!btn) return;
  var n = document.querySelectorAll("#switch-table-body .sw-check:checked").length;
  btn.textContent = "선택 삭제 (" + n + ")";
  btn.disabled = n === 0;
}

(function () {
  // 전체 선택 체크박스
  var allChk = document.getElementById("sw-check-all");
  if (allChk) allChk.addEventListener("change", function () {
    document.querySelectorAll("#switch-table-body .sw-check").forEach(function (c) {
      // 검색 필터로 숨겨진 행은 선택 제외
      if (c.closest("tr").style.display !== "none") c.checked = allChk.checked;
    });
    _updateBulkDeleteBtn();
  });
  // 개별 체크박스 변경 위임
  var tbody = document.getElementById("switch-table-body");
  if (tbody) tbody.addEventListener("change", function (e) {
    if (e.target && e.target.classList.contains("sw-check")) _updateBulkDeleteBtn();
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
  }).catch(function(e) { console.error("vlan load:", e); });
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
    sel.innerHTML = "<option value=''>스위치 선택</option>" +
      (_switches || []).map(function (s) {
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

function renderFacilityProgress(st) {
  var el = document.getElementById("fac-progress");
  if (!el) return;
  if (!st || (!st.running && !st.message)) { el.textContent = ""; return; }
  if (st.running) {
    var pct = st.total ? Math.round(st.done / st.total * 100) : 0;
    el.innerHTML = "<strong>수집 중</strong> — " + escHtml(st.subnet || "") + " · " +
      st.done + "/" + st.total + " (" + pct + "%) · " + escHtml(st.message || "");
  } else {
    el.textContent = st.message || "";
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
             (h.port_desc || ""), (h.via || "")].join(" ").toLowerCase();
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
    tbody.innerHTML = "<tr><td colspan=6 style='color:#64748b'>" + emptyMsg + "</td></tr>";
    return;
  }
  tbody.innerHTML = rows.map(function (h) {
    var swCell, portCell, descCell;
    if (_facIsDirect(h) && !h.online) {
      // 오프라인이지만 마지막 관측 위치는 유지 — '직접'처럼 보이지 않게 회색 표기
      swCell = "<span style='color:#94a3b8'>" + escHtml(h.switch_name) +
        "</span> <span class='status-badge status-badge--new' title='연결이 끊기기 전 마지막으로 관측된 위치'>마지막 관측</span>";
      portCell = "<code style='color:#94a3b8'>" + escHtml(h.port || "-") + "</code>";
      descCell = "<span style='color:#94a3b8'>" + escHtml(h.port_desc || "-") + "</span>";
    } else if (_facIsDirect(h)) {
      swCell = "<span style='font-weight:600'>" + escHtml(h.switch_name) +
        "</span> <span class='status-badge status-badge--ok'>직접</span>";
      portCell = "<code>" + escHtml(h.port || "-") + "</code>";
      // 연결 스위치가 수집한 포트 Description — 설비 정체 파악용
      descCell = h.port_desc
        ? "<span title='연결 스위치에서 수집한 포트 설명'>" + escHtml(h.port_desc) + "</span>"
        : "<span style='color:#cbd5e1'>-</span>";
    } else {
      // Po/Vl 등 업링크 경유 상세는 툴팁으로만(표는 깔끔하게)
      var tip = h.via ? " title='업링크 경유 관측: " + escHtml(h.via) + "'" : "";
      swCell = "<span style='color:#b45309;cursor:help'" + tip + ">직접 연결 미확인 ⓘ</span>";
      portCell = "<span style='color:#94a3b8'>—</span>";
      descCell = "<span style='color:#94a3b8'>—</span>";
    }
    // 상태 컬럼 제거 — 오프라인(연결 실패)은 행 배경(빨강)으로만 신호
    var trStyle = h.online ? "" : " style='background:#fef2f2'" +
      " title='마지막 수집에서 응답 없음(오프라인)'";
    return "<tr" + trStyle + "><td>" + escHtml(h.subnet || "-") + "</td><td><code>" + escHtml(h.ip) + "</code></td>" +
      "<td><code>" + escHtml(h.mac || "-") + "</code></td><td>" + swCell + "</td><td>" +
      portCell + "</td><td>" + descCell + "</td></tr>";
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
    var fjson = encodeURIComponent(JSON.stringify(f));
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
        "data-action='edit-fw' data-payload='" + encodeURIComponent(JSON.stringify(f)) + "'>수정</button> " +
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
        ? "<table class='data-table'><thead><tr><th>인터페이스</th><th>IP</th><th>마스크</th><th>VDOM/Zone</th></tr></thead><tbody>" +
          ifaces.map(function(i) {
            // secondary IP 행은 파란 뱃지로 구분(2nd)
            var isSec = i.type === "secondary" || /\(2nd\)/.test(i.name || "");
            var nameCell = escHtml(i.name) + (isSec
              ? " <span class='status-badge status-badge--new' style='font-size:10px'>2nd</span>" : "");
            return "<tr" + (isSec ? " style='background:#f0f9ff'" : "") + "><td>" + nameCell +
              "</td><td><code>" + escHtml(i.ip || "-") + "</code></td><td>" +
              escHtml(i.mask || "-") + "</td><td>" + escHtml(i.vdom_zone || "-") + "</td></tr>";
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
  openModal("modal-credential");
}

document.getElementById("btn-collect").addEventListener("click", function() {
  if (!_selectedSwitch) return;
  var username = document.getElementById("cred-username").value.trim();
  var password = document.getElementById("cred-password").value;
  if (!username || !password) { alert("아이디와 패스워드를 입력하세요."); return; }
  var persist = document.getElementById("cred-persist");
  closeModal("modal-credential");
  collectSwitch(_selectedSwitch.id, username, password, persist && persist.checked);
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

function collectSwitch(switchId, username, password, persist) {
  fetch("/api/switches/" + switchId + "/collect", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: username, password: password, persist: !!persist}),
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

  // 일괄 수집 실행(공통) — 성공 시 선택 해제 + 안내
  function _runBulkCollect(ids, username, password, persist) {
    fetch("/api/switches/bulk-collect", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids: ids, username: username, password: password,
                            persist: !!persist}),
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
    var bp = document.getElementById("bulk-persist"); if (bp) bp.checked = false;
    openModal("modal-bulk-collect");
  });

  // "수집 시작" → 일괄 수집 요청(팝업 경로)
  var start = document.getElementById("btn-bulk-start");
  if (start) start.addEventListener("click", function () {
    var ids = Object.keys(_bulkSel).map(function (x) { return parseInt(x, 10); });
    if (!ids.length) { closeModal("modal-bulk-collect"); return; }
    var username = document.getElementById("bulk-username").value.trim();
    var password = document.getElementById("bulk-password").value;
    if (!username || !password) { alert("아이디와 패스워드를 입력하세요."); return; }
    var persist = document.getElementById("bulk-persist");
    _runBulkCollect(ids, username, password, persist && persist.checked);
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
    }),
  }).then(function(r) { return r.json(); }).then(function(data) {
    if (data.ok) { closeModal("modal-add-switch"); _editSwitchId = null; pollState(); }
    else alert(data.error || "저장 실패");
  }).catch(function(e) { console.error(e); alert("서버 오류"); });
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

// ─── 토폴로지(구역 집계 맵 ↔ 구역 상세 — 스위치·방화벽 전용) ─────────
var _topoData = null;    // {nodes, links} 서버 응답 보관
var _topoZone = null;    // null=구역 맵, "구역명"=해당 구역 상세
var _topoFocus = null;   // 검색으로 지정한 노드 id(상세에서 주황 링 강조)

function loadTopology() {
  fetch("/api/topology").then(function (r) { return r.json(); }).then(function (data) {
    _topoData = { nodes: data.nodes || [], links: data.links || [] };
    renderTopology();
  }).catch(function (e) { console.error("topology:", e); });
}

function _topoZoneOf(n) {
  if (n.depth === 0) return "🏢 백본";      // 링크 최다 루트 = 백본 구역
  return (n.group || "").trim() || "미지정";
}

function _topoColor(n) {
  if (!n) return "#64748b";
  if (n.alert === "critical" || n.status === "failed" || n.reachable === false) return "#ef4444";
  if (n.alert === "warning") return "#f59e0b";
  if (n.status === "done") return "#22c55e";
  return "#64748b";
}

// 공통 툴바(빵부스러기 + 검색) — 두 뷰 모두 상단에 표시
function _topoToolbarHTML() {
  var crumb = _topoZone
    ? "<a href='#' id='topo-crumb-root' style='color:#38bdf8;text-decoration:none'>전체</a>" +
      "<span style='color:#475569'> &gt; </span><b style='color:#e2e8f0'>" + escHtml(_topoZone) + "</b>"
    : "<b style='color:#e2e8f0'>전체 구역</b> <span style='color:#64748b;font-size:11px'>(구역 클릭 = 내부 장비 보기)</span>";
  return "<div style='display:flex;gap:12px;align-items:center;padding:8px 14px;border-bottom:1px solid #1e293b'>" +
    "<span style='font-size:13px'>" + crumb + "</span>" +
    "<input id='topo-search' placeholder='장비 검색 (이름·IP) 후 Enter' " +
    "style='margin-left:auto;padding:4px 10px;border:1px solid #334155;border-radius:4px;" +
    "background:#0f172a;color:#e2e8f0;font-size:12px;width:220px'>" +
    "</div>";
}

function _topoBindToolbar(host) {
  var crumbRoot = host.querySelector("#topo-crumb-root");
  if (crumbRoot) crumbRoot.addEventListener("click", function (e) {
    e.preventDefault(); _topoZone = null; _topoFocus = null; renderTopology();
  });
  var search = host.querySelector("#topo-search");
  if (search) search.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    var q = search.value.trim().toLowerCase();
    if (!q || !_topoData) return;
    var hit = _topoData.nodes.find(function (n) {
      return ((n.name || "") + " " + (n.ip || "")).toLowerCase().indexOf(q) >= 0;
    });
    if (!hit) { alert("'" + q + "' 장비를 찾지 못했습니다."); return; }
    _topoZone = _topoZoneOf(hit);
    _topoFocus = hit.id;
    renderTopology();
  });
}

function renderTopology() {
  var host = document.getElementById("topology-canvas");
  if (!host || !_topoData) return;
  var nodes = _topoData.nodes, links = _topoData.links;
  if (!nodes.length) {
    host.innerHTML = "<p style='color:#94a3b8;padding:20px'>표시할 장비가 없습니다. 스위치를 수집하면 연결 관계가 그려집니다.</p>";
    return;
  }
  if (_topoZone === null) _renderZoneMap(host, nodes, links);
  else _renderZoneDetail(host, nodes, links, _topoZone);
}

// ── 1단계: 구역 집계 맵 — 구역 카드 + 구역 간 링크 수 ──────────────
function _renderZoneMap(host, nodes, links) {
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  var zones = {};   // {zone: {sw,fw,bad,warn,ok,total}}
  nodes.forEach(function (n) {
    var z = _topoZoneOf(n);
    var e = zones[z] = zones[z] || { sw: 0, fw: 0, bad: 0, warn: 0, ok: 0, total: 0 };
    e.total++;
    if (n.kind === "fw") e.fw++; else e.sw++;
    var c = _topoColor(n);
    if (c === "#ef4444") e.bad++;
    else if (c === "#f59e0b") e.warn++;
    else if (c === "#22c55e") e.ok++;
  });
  // 구역 간 링크 집계(호버 시 실제 장비 쌍 표시)
  var inter = {};   // {"A||B": {count, pairs[]}}
  links.forEach(function (l) {
    var za = _topoZoneOf(byId[l.a] || {}), zb = _topoZoneOf(byId[l.b] || {});
    if (za === zb) return;
    var key = [za, zb].sort().join("||");
    var e = inter[key] = inter[key] || { count: 0, pairs: [] };
    e.count++;
    if (e.pairs.length < 6) {
      e.pairs.push(((byId[l.a] || {}).name || "?") + " ↔ " + ((byId[l.b] || {}).name || "?"));
    }
  });

  var zkeys = Object.keys(zones).sort(function (a, b) {
    if (a === "🏢 백본") return -1;
    if (b === "🏢 백본") return 1;
    return a.localeCompare(b);
  });
  var CARD_W = 200, CARD_H = 84, GX = 40, GY = 90;
  var others = zkeys.filter(function (z) { return z !== "🏢 백본"; });
  var cols = Math.max(1, Math.min(5, Math.ceil(Math.sqrt(others.length || 1)) + 1));
  var rows = Math.ceil(others.length / cols) || 1;
  var width = Math.max(940, cols * (CARD_W + GX) + 80);
  var height = 160 + rows * (CARD_H + GY) + 20;

  var pos = {};
  if (zones["🏢 백본"]) pos["🏢 백본"] = { x: width / 2 - CARD_W / 2, y: 30 };
  others.forEach(function (z, i) {
    var r = Math.floor(i / cols), c = i % cols;
    var rowCount = (r === rows - 1) ? (others.length - r * cols) : cols;
    var rowW = rowCount * (CARD_W + GX) - GX;
    pos[z] = { x: (width - rowW) / 2 + c * (CARD_W + GX), y: 190 + r * (CARD_H + GY) };
  });

  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='" +
             Math.max(420, Math.min(height, 720)) + "' viewBox='0 0 " + width + " " + height + "'>"];

  // 구역 간 링크(집계 라벨)
  Object.keys(inter).forEach(function (key) {
    var zs = key.split("||");
    var pa = pos[zs[0]], pb = pos[zs[1]];
    if (!pa || !pb) return;
    var top = (pa.y <= pb.y) ? pa : pb;
    var bot = (top === pa) ? pb : pa;
    var x1 = top.x + CARD_W / 2, y1 = top.y + CARD_H;
    var x2 = bot.x + CARD_W / 2, y2 = bot.y;
    var mid = (y1 + y2) / 2;
    var tip = zs[0] + " ↔ " + zs[1] + " · 링크 " + inter[key].count + "개\n" +
              inter[key].pairs.join("\n");
    svg.push("<path class='topo-zedge' data-tip=\"" + escHtml(tip) + "\" d='M" + x1 + "," + y1 +
      " C" + x1 + "," + mid + " " + x2 + "," + mid + " " + x2 + "," + y2 +
      "' fill='none' stroke='#64748b' stroke-width='2'/>");
    svg.push("<rect x='" + ((x1 + x2) / 2 - 18) + "' y='" + (mid - 9) + "' width='36' height='16' rx='8' fill='#1e293b'/>" +
      "<text x='" + ((x1 + x2) / 2) + "' y='" + (mid + 3) + "' fill='#94a3b8' font-size='10' text-anchor='middle'>" +
      inter[key].count + "링크</text>");
  });

  // 구역 카드
  zkeys.forEach(function (z) {
    var p = pos[z], e = zones[z];
    if (!p) return;
    var border = e.bad ? "#ef4444" : e.warn ? "#f59e0b" : e.ok ? "#22c55e" : "#64748b";
    var tip = z + " · 스위치 " + e.sw + (e.fw ? " · 방화벽 " + e.fw : "") +
      (e.bad ? " · 문제 " + e.bad + "대" : "") + "\n클릭하면 내부 장비 연결이 열립니다";
    svg.push("<g class='topo-zone' data-zone=\"" + escHtml(z) + "\" data-tip=\"" + escHtml(tip) + "\" style='cursor:pointer'>");
    svg.push("<rect x='" + p.x + "' y='" + p.y + "' width='" + CARD_W + "' height='" + CARD_H +
      "' rx='10' fill='" + (z === "🏢 백본" ? "#27314a" : "#1e293b") + "' stroke='" + border + "' stroke-width='2.5'/>");
    svg.push("<text x='" + (p.x + CARD_W / 2) + "' y='" + (p.y + 26) +
      "' fill='#e2e8f0' font-size='13' font-weight='700' text-anchor='middle'>" +
      escHtml(z.slice(0, 20)) + "</text>");
    svg.push("<text x='" + (p.x + CARD_W / 2) + "' y='" + (p.y + 46) +
      "' fill='#94a3b8' font-size='11' text-anchor='middle'>스위치 " + e.sw +
      (e.fw ? " · 🛡 " + e.fw : "") + "</text>");
    var badge = e.bad ? ("🔴 문제 " + e.bad) : e.warn ? ("⚠ 경보 " + e.warn) : "✅ 정상";
    svg.push("<text x='" + (p.x + CARD_W / 2) + "' y='" + (p.y + 66) +
      "' fill='" + border + "' font-size='11' font-weight='600' text-anchor='middle'>" + badge + "</text>");
    svg.push("</g>");
  });
  svg.push("</svg>");

  host.innerHTML = _topoToolbarHTML() + svg.join("") +
    "<div id='topo-tip' style='position:fixed;display:none;background:#0b1220;color:#e2e8f0;border:1px solid #334155;" +
    "border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;z-index:500;max-width:420px;white-space:pre-line'></div>";
  _topoBindToolbar(host);
  _topoBindTips(host);
  host.querySelectorAll(".topo-zone").forEach(function (g) {
    g.addEventListener("click", function () {
      _topoZone = g.getAttribute("data-zone");
      _topoFocus = null;
      renderTopology();
    });
  });
}

// ── 2단계: 구역 상세 — 그 구역 장비 + 외부 직결(고스트) 트리 ─────────
function _renderZoneDetail(host, allNodes, allLinks, zone) {
  var byId = {};
  allNodes.forEach(function (n) { byId[n.id] = n; });
  var inZone = {};
  allNodes.forEach(function (n) { if (_topoZoneOf(n) === zone) inZone[n.id] = true; });
  // 구역 밖이지만 직결된 이웃 = 고스트(업링크 방향 표시용)
  var ghost = {};
  allLinks.forEach(function (l) {
    if (inZone[l.a] && !inZone[l.b]) ghost[l.b] = true;
    if (inZone[l.b] && !inZone[l.a]) ghost[l.a] = true;
  });
  var nodes = allNodes.filter(function (n) { return inZone[n.id] || ghost[n.id]; });
  var links = allLinks.filter(function (l) {
    return (inZone[l.a] || inZone[l.b]) && (inZone[l.a] || ghost[l.a]) && (inZone[l.b] || ghost[l.b]);
  });

  var adj = {};
  links.forEach(function (l) {
    (adj[l.a] = adj[l.a] || []).push(l.b);
    (adj[l.b] = adj[l.b] || []).push(l.a);
  });

  // 스패닝 트리(BFS): 루트 = 고스트(외부 업링크) 우선, 없으면 링크 최다
  var parent = {}, children = {}, depth = {}, roots = [], visited = {};
  var ids = Object.keys(adj);
  ids.sort(function (a, b) {
    var ga = ghost[a] ? 1 : 0, gb = ghost[b] ? 1 : 0;
    if (ga !== gb) return gb - ga;
    return (adj[b] || []).length - (adj[a] || []).length;
  });
  ids.forEach(function (rid) {
    if (visited[rid]) return;
    roots.push(rid);
    visited[rid] = true; depth[rid] = 0;
    var q = [rid];
    while (q.length) {
      var cur = q.shift();
      var nbrs = (adj[cur] || []).slice().sort(function (a, b) {
        return ((byId[a] || {}).name || "").localeCompare(((byId[b] || {}).name || ""));
      });
      nbrs.forEach(function (nx) {
        if (visited[nx]) return;
        visited[nx] = true;
        parent[nx] = cur;
        (children[cur] = children[cur] || []).push(nx);
        depth[nx] = depth[cur] + 1;
        q.push(nx);
      });
    }
  });
  var orphans = nodes.filter(function (n) { return !(String(n.id) in visited) && inZone[n.id]; });

  var NODE_W = 160, NODE_H = 46, GAP_X = 26, GAP_Y = 110;
  var slot = { v: 0 };
  var xIndex = {};
  function assignX(id) {
    var ch = children[id] || [];
    if (!ch.length) { xIndex[id] = slot.v++; return xIndex[id]; }
    var xs = ch.map(assignX);
    xIndex[id] = (xs[0] + xs[xs.length - 1]) / 2;
    return xIndex[id];
  }
  roots.forEach(function (r) { assignX(r); slot.v += 0.6; });

  var maxDepth = 0;
  Object.keys(depth).forEach(function (k) { if (depth[k] > maxDepth) maxDepth = depth[k]; });
  var width = Math.max(900, (slot.v + 1) * (NODE_W + GAP_X) + 60);
  var height = (maxDepth + 1) * (NODE_H + GAP_Y) + 80;

  var pos = {};
  Object.keys(xIndex).forEach(function (k) {
    pos[k] = { x: 30 + xIndex[k] * (NODE_W + GAP_X), y: 40 + depth[k] * (NODE_H + GAP_Y) };
  });

  var svg = ["<svg id='topo-svg' xmlns='http://www.w3.org/2000/svg' width='100%' height='" +
             Math.max(520, Math.min(height, 760)) + "' viewBox='0 0 " + width + " " + height +
             "' style='cursor:grab'>"];

  links.forEach(function (l) {
    var a = pos[l.a], b = pos[l.b];
    if (!a || !b) return;
    var top = (depth[l.a] <= depth[l.b]) ? l.a : l.b;
    var bot = (top === l.a) ? l.b : l.a;
    var x1 = pos[top].x + NODE_W / 2, y1 = pos[top].y + NODE_H;
    var x2 = pos[bot].x + NODE_W / 2, y2 = pos[bot].y;
    var mid = (y1 + y2) / 2;
    var portA = (top === l.a) ? l.a_port : l.b_port;
    var portB = (top === l.a) ? l.b_port : l.a_port;
    var tip = escHtml((byId[top] || {}).name || "") + (portA ? " [" + escHtml(portA) + "]" : "") +
      "  ↕  " + escHtml((byId[bot] || {}).name || "") + (portB ? " [" + escHtml(portB) + "]" : "") +
      (l.mutual ? "  (양방향 확인)" : "  (한쪽만 관측)");
    svg.push("<path class='topo-edge' data-ea='" + l.a + "' data-eb='" + l.b + "' data-tip=\"" + tip + "\" d='M" +
      x1 + "," + y1 + " C" + x1 + "," + mid + " " + x2 + "," + mid + " " + x2 + "," + y2 +
      "' fill='none' stroke='#64748b' stroke-width='2'" + (l.mutual ? "" : " stroke-dasharray='6 4'") + "/>");
  });

  nodes.forEach(function (n) {
    var p = pos[n.id];
    if (!p) return;
    var isGhost = !!ghost[n.id];
    var isFocus = _topoFocus != null && String(_topoFocus) === String(n.id);
    var tip = escHtml(n.name || "") + " · " + escHtml(n.ip || "") +
      " · " + escHtml(n.vendor || "") + (n.group ? " · " + escHtml(n.group) : "") +
      (isGhost ? "\n(다른 구역 장비 — 클릭하면 그 구역으로 이동)" : "");
    svg.push("<g class='topo-node' data-swid='" + n.id + "' data-kind='" + (n.kind || "sw") +
      "' data-ghost='" + (isGhost ? 1 : 0) + "' data-tip=\"" + tip + "\" style='cursor:pointer'" +
      (isGhost ? " opacity='0.65'" : "") + ">");
    if (isFocus) {
      svg.push("<rect x='" + (p.x - 5) + "' y='" + (p.y - 5) + "' width='" + (NODE_W + 10) +
        "' height='" + (NODE_H + 10) + "' rx='11' fill='none' stroke='#f59e0b' stroke-width='3'/>");
    }
    svg.push("<rect x='" + p.x + "' y='" + p.y + "' width='" + NODE_W + "' height='" + NODE_H +
      "' rx='8' fill='" + (isGhost ? "#111827" : "#1e293b") + "' stroke='" + _topoColor(n) +
      "' data-basestroke='" + _topoColor(n) + "' stroke-width='2'" +
      (isGhost ? " stroke-dasharray='5 4'" : "") + "/>");
    svg.push("<circle cx='" + (p.x + NODE_W - 12) + "' cy='" + (p.y + 12) + "' r='4' fill='" +
      _topoColor(n) + "'/>");
    svg.push("<text x='" + (p.x + NODE_W / 2) + "' y='" + (p.y + 19) +
      "' fill='#e2e8f0' font-size='11' font-weight='700' text-anchor='middle'>" +
      (n.kind === "fw" ? "🛡 " : "") + escHtml((n.name || "").slice(0, 20)) + "</text>");
    svg.push("<text x='" + (p.x + NODE_W / 2) + "' y='" + (p.y + 35) +
      "' fill='#94a3b8' font-size='10' text-anchor='middle'>" + escHtml(n.ip || "") + "</text>");
    svg.push("</g>");
  });
  svg.push("</svg>");

  var legend =
    "<div style='display:flex;gap:16px;align-items:center;padding:6px 14px;color:#94a3b8;font-size:11px;border-bottom:1px solid #1e293b'>" +
    "<span>점선 테두리 = 다른 구역 장비(클릭=그 구역으로)</span>" +
    "<span style='color:#22c55e'>● 정상</span><span style='color:#ef4444'>● 실패/도달불가</span><span style='color:#f59e0b'>● 경보</span>" +
    "<span style='margin-left:auto'>휠=확대/축소 · 드래그=이동 · 호버=직결 하이라이트</span></div>";
  var orphanHtml = "";
  if (orphans.length) {
    orphanHtml = "<div style='border-top:1px solid #1e293b;padding:8px 14px'>" +
      "<span style='color:#94a3b8;font-size:11px'>이 구역 연결 미발견 " + orphans.length + "대: </span>" +
      orphans.map(function (n) {
        return "<span class='topo-orphan' data-swid='" + n.id + "' data-kind='" + (n.kind || "sw") +
          "' style='display:inline-block;margin:2px 4px;padding:2px 8px;" +
          "background:#1e293b;border:1px solid " + _topoColor(n) + ";border-radius:4px;color:#cbd5e1;" +
          "font-size:11px;cursor:pointer'>" + (n.kind === "fw" ? "🛡 " : "") + escHtml(n.name || "") + "</span>";
      }).join("") + "</div>";
  }
  host.innerHTML = _topoToolbarHTML() + legend + svg.join("") + orphanHtml +
    "<div id='topo-tip' style='position:fixed;display:none;background:#0b1220;color:#e2e8f0;border:1px solid #334155;" +
    "border-radius:6px;padding:6px 10px;font-size:12px;pointer-events:none;z-index:500;max-width:420px;white-space:pre-line'></div>";
  _topoBindToolbar(host);
  _topoBindTips(host);

  // 클릭: 고스트=그 구역으로 이동, 방화벽=방화벽 상세, 스위치=스위치 상세
  function _open(g) {
    var id = g.getAttribute("data-swid");
    if (g.getAttribute("data-ghost") === "1") {
      var n = byId[id] || byId[parseInt(id, 10)];
      if (n) { _topoZone = _topoZoneOf(n); _topoFocus = n.id; renderTopology(); }
      return;
    }
    if (g.getAttribute("data-kind") === "fw") {
      showFirewallDetail(parseInt(id.slice(1), 10));
      return;
    }
    var sw = (_switches || []).find(function (s) { return String(s.id) === String(id); });
    if (sw) openDetailPanel(sw);
  }
  host.querySelectorAll(".topo-node, .topo-orphan").forEach(function (g) {
    g.addEventListener("click", function () { _open(g); });
  });

  // 자비스식 호버: 직결 라인 글로우 + 무관 요소 페이드 + 이웃 강조
  host.querySelectorAll(".topo-node").forEach(function (g) {
    var id = g.getAttribute("data-swid");
    g.addEventListener("mouseenter", function () {
      var neighbors = {};
      neighbors[id] = true;
      host.querySelectorAll(".topo-edge").forEach(function (p2) {
        var ea = p2.getAttribute("data-ea"), eb = p2.getAttribute("data-eb");
        var on = ea === id || eb === id;
        if (on) { neighbors[ea] = true; neighbors[eb] = true; }
        p2.setAttribute("stroke", on ? "#38bdf8" : "#334155");
        p2.setAttribute("stroke-width", on ? "3.5" : "1");
        p2.style.opacity = on ? "1" : "0.12";
        p2.style.filter = on ? "drop-shadow(0 0 4px #38bdf8)" : "";
      });
      host.querySelectorAll(".topo-node").forEach(function (n) {
        var nid = n.getAttribute("data-swid");
        var hot = !!neighbors[nid];
        n.style.opacity = hot ? "1" : "0.15";
        var rects = n.querySelectorAll("rect");
        var rect = rects[rects.length - 1];
        if (rect) {
          if (hot && nid !== id) rect.setAttribute("stroke", "#38bdf8");
          if (nid === id) rect.setAttribute("stroke-width", "3.5");
        }
      });
    });
    g.addEventListener("mouseleave", function () {
      host.querySelectorAll(".topo-edge").forEach(function (p2) {
        p2.setAttribute("stroke", "#64748b");
        p2.setAttribute("stroke-width", "2");
        p2.style.opacity = "1";
        p2.style.filter = "";
      });
      host.querySelectorAll(".topo-node").forEach(function (n) {
        n.style.opacity = n.getAttribute("data-ghost") === "1" ? "0.65" : "1";
        var rects = n.querySelectorAll("rect");
        var rect = rects[rects.length - 1];
        if (rect) {
          rect.setAttribute("stroke", rect.getAttribute("data-basestroke") || "#64748b");
          rect.setAttribute("stroke-width", "2");
        }
      });
    });
  });

  _topoBindZoomPan(host, width, height);
}

// 툴팁 공통 바인딩
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

// 줌/팬 공통(구역 상세)
function _topoBindZoomPan(host, width, height) {
  var svgEl = host.querySelector("#topo-svg");
  if (!svgEl) return;
  var vb = { x: 0, y: 0, w: width, h: height };
  function applyVB() { svgEl.setAttribute("viewBox", vb.x + " " + vb.y + " " + vb.w + " " + vb.h); }
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
    vb.w = nw; vb.h = nh;
    applyVB();
  }, { passive: false });
  var drag = null;
  svgEl.addEventListener("mousedown", function (e) {
    drag = { sx: e.clientX, sy: e.clientY, vx: vb.x, vy: vb.y };
    svgEl.style.cursor = "grabbing";
  });
  window.addEventListener("mousemove", function (e) {
    if (!drag) return;
    var rect = svgEl.getBoundingClientRect();
    vb.x = drag.vx - (e.clientX - drag.sx) / rect.width * vb.w;
    vb.y = drag.vy - (e.clientY - drag.sy) / rect.height * vb.h;
    applyVB();
  });
  window.addEventListener("mouseup", function () {
    drag = null;
    if (svgEl) svgEl.style.cursor = "grab";
  });
}

(function () {
  var b = document.getElementById("btn-topo-refresh");
  if (b) b.addEventListener("click", function () { _topoZone = null; _topoFocus = null; loadTopology(); });
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

// ─── config 일괄 다운로드(ZIP) ───────────────────────────────────
(function () {
  var btn = document.getElementById("btn-configs-export");
  if (btn) btn.addEventListener("click", function () {
    window.location = "/api/configs/export-all";
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
    })
    .catch(function(e) { console.error("poll error:", e); });
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
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function fmtTime(ts) {
  if (!ts) return "-";
  try { return new Date(ts).toLocaleString("ko-KR"); } catch(e) { return String(ts); }
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
