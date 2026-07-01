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
  // 위치(location) + TPS 위치 라벨(건물명/공장/층) + hostname 모두에서 필터
  return list.filter(function (s) {
    var hay = ((s.location || "") + " " + (s.tps_location || "") + " " + (s.hostname || "")).toLowerCase();
    return hay.indexOf(q) >= 0;
  });
}

// ─── M14: 자동 수집 설정 ─────────────────────────────────────────
(function () {
  var btn = document.getElementById("btn-auto-collect");
  if (btn) btn.addEventListener("click", function () {
    fetch("/api/settings/auto_collect").then(function (r) { return r.json(); }).then(function (d) {
      document.getElementById("ac-enabled").checked = !!d.enabled;
      document.getElementById("ac-times").value = d.times || "06:00,18:00";
      openModal("modal-auto-collect");
    }).catch(function (e) { console.error(e); });
  });
  var save = document.getElementById("btn-ac-save");
  if (save) save.addEventListener("click", function () {
    var body = {
      enabled: document.getElementById("ac-enabled").checked,
      times: document.getElementById("ac-times").value,
    };
    fetch("/api/settings/auto_collect", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res.ok) { closeModal("modal-auto-collect"); alert("자동 수집 설정이 저장되었습니다. (시각: " + res.times + ")"); }
      else alert(res.error || "저장 실패");
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
  });
});

// ─── 상세 패널 탭 ────────────────────────────────────────────────
document.querySelectorAll(".detail-tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".detail-tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".dtab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("dtab-" + btn.dataset.dtab).classList.add("active");
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
  switches = _applyLocFilter(switches, "loc-filter-dash");
  var fws = _applyLocFilter(_firewalls || [], "loc-filter-dash");
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
    var racksHtml = rkeys.map(function (t) {
      var units = racks[t].map(function (d) {
        if (d.k === "fw") {
          var f = d.o, fsc = _fwStatusMeta[f.status] || "new";
          return "<div class='rack-unit rack-unit--" + fsc + "' data-action='detail-fw' data-id='" + f.id + "'>" +
            "<span class='rack-unit__name'>🛡 " + escHtml(f.name) + "</span>" +
            "<span class='rack-unit__ip'>" + escHtml(f.host) + "</span></div>";
        }
        var sw = d.o, cls = swStatusClass(sw);
        return "<div class='rack-unit rack-unit--" + cls + "' " +
          "data-action='detail-switch' data-payload='" + encodeURIComponent(JSON.stringify(sw)) + "'>" +
          "<span class='rack-unit__name'>" + escHtml(sw.name) + "</span>" +
          "<span class='rack-unit__ip'>" + escHtml(sw.ip) + "</span></div>";
      }).join("");
      return "<div class='rack'><div class='rack__label'>" + escHtml(t) + "</div>" +
        "<div class='rack__units'>" + units + "</div></div>";
    }).join("");
    return "<div class='rack-group'><div class='rack-group__title'>📍 " + escHtml(g) + "</div>" +
      "<div class='rack-row'>" + racksHtml + "</div></div>";
  }).join("");
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
  var sc = _fwStatusMeta[f.status] || "new";
  var locLine = f.tps_location ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>📍 " + escHtml(f.tps_location) + "</span>"
    : f.room_label ? "<span style='font-size:10px;color:#2563eb;font-weight:600'>🗄 " + escHtml(f.room_label) + "</span>"
    : f.location ? "<span style='font-size:10px'>" + escHtml(f.location) + "</span>" : "";
  return "<div class='sw-card sw-card--" + sc + "'>" +
    "<div class='sw-card__icon'><div class='sw-icon' style='display:flex;align-items:center;justify-content:center;font-size:30px'>🛡</div></div>" +
    "<div class='sw-card__name'>" + escHtml(f.name) + "</div>" +
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
  var rkeys = Object.keys(racks).sort();
  host.innerHTML = "<div class='rack-row'>" + rkeys.map(function (rk) {
    var units = racks[rk].slice().sort(function (a, b) { return (b.o.room_unit || 0) - (a.o.room_unit || 0); });
    var unitsHtml = units.map(function (u) {
      if (u.k === "fw") {
        var f = u.o, fsc = _fwStatusMeta[f.status] || "new";
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
    return "<div class='rack'><div class='rack__label'>🗄 " + escHtml(rk) + " 랙</div>" +
      "<div class='rack__units'>" + unitsHtml + "</div></div>";
  }).join("") + "</div>";
}

function renderSwitchGrid(switches) {
  switches = _applyLocFilter(switches, "loc-filter-dash");
  var fws = _applyLocFilter(_firewalls || [], "loc-filter-dash");
  var grid = document.getElementById("switch-grid");
  if (!switches.length && !fws.length) {
    grid.innerHTML = "<p class='placeholder'>표시할 장비가 없습니다. (위치 필터를 확인하거나 스위치/방화벽을 추가하세요)</p>";
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
    : "";

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
    "</div>" +
    "<div class='sw-card__status'>" +
    "<span class='dot " + dotClass + "'></span>" +
    "<span>" + escHtml(sw.vendor || "unknown") + " · " + statusLabel + "</span>" +
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

// ─── 스위치 테이블 (스위치 현황 탭) ─────────────────────────────
function renderSwitchTable(switches) {
  switches = _applyLocFilter(switches, "loc-filter-sw");
  var tbody = document.getElementById("switch-table-body");
  tbody.innerHTML = switches.map(function(sw) {
    var sc = swStatusClass(sw);
    var locCell = sw.tps_location
      ? "<span style='color:#2563eb;font-weight:600'>📍 " + escHtml(sw.tps_location) + "</span>" +
        (sw.location ? "<br><span style='font-size:11px;color:#64748b'>" + escHtml(sw.location) + "</span>" : "")
      : escHtml(sw.location || "-");
    return "<tr>" +
      "<td style='text-align:center'><input type='checkbox' class='sw-check' value='" + sw.id + "'></td>" +
      "<td>" + escHtml(sw.name) + "</td><td><code>" + escHtml(sw.ip) + "</code></td><td>" +
      escHtml(sw.hostname || "-") + "</td><td>" + escHtml(sw.vendor || "-") + "</td><td>" +
      locCell + "</td><td><span class='status-badge status-badge--" + sc + "'>" +
      escHtml(sw.status) + "</span></td><td>" +
      (sw.alert && sw.alert !== "none" ? "<span class='status-badge status-badge--" + sw.alert + "'>" + sw.alert + "</span>" : "-") +
      "</td><td>" + fmtTime(sw.last_collected) + "</td>" +
      "<td>" +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "data-action='edit-switch' data-payload='" + encodeURIComponent(JSON.stringify(sw)) + "'>수정</button> " +
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
  document.getElementById("add-vendor").value = sw.vendor || "unknown";
  document.getElementById("add-location").value = sw.location || "";
  document.getElementById("add-note").value = sw.note || "";
  openModal("modal-add-switch");
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
  _renderFacilityRows();
}

function _renderFacilityRows() {
  var tbody = document.getElementById("facility-table-body");
  if (!tbody) return;
  var all = _facHosts;
  var directCount = all.filter(_facIsDirect).length;

  var sum = document.getElementById("fac-summary");
  if (sum) {
    sum.innerHTML = all.length
      ? ("전체 <b>" + all.length + "</b>건 · 직접 연결 <b style='color:#15803d'>" + directCount +
         "</b>건 · 미확인 <b style='color:#b45309'>" + (all.length - directCount) + "</b>건" +
         "  <span style='color:#94a3b8'>(미확인 = 업링크 Po/Vl 경유로만 관측 — 직접 연결된 액세스 스위치 미수집일 수 있음)</span>")
      : "";
  }

  var onlyDirect = document.getElementById("fac-only-direct");
  var rows = (onlyDirect && onlyDirect.checked) ? all.filter(_facIsDirect) : all;
  if (!rows.length) {
    tbody.innerHTML = "<tr><td colspan=6 style='color:#64748b'>" +
      (all.length ? "직접 연결로 확인된 설비가 없습니다. ('직접 연결만' 해제 시 전체 표시)"
                  : "수집된 설비가 없습니다. '대역 수집(ping)'을 실행하세요.") +
      "</td></tr>";
    return;
  }
  tbody.innerHTML = rows.map(function (h) {
    var swCell, portCell;
    if (_facIsDirect(h)) {
      swCell = "<span style='font-weight:600'>" + escHtml(h.switch_name) +
        "</span> <span class='status-badge status-badge--ok'>직접</span>";
      portCell = "<code>" + escHtml(h.port || "-") + "</code>";
    } else {
      // Po/Vl 등 업링크 경유 상세는 툴팁으로만(표는 깔끔하게)
      var tip = h.via ? " title='업링크 경유 관측: " + escHtml(h.via) + "'" : "";
      swCell = "<span style='color:#b45309;cursor:help'" + tip + ">직접 연결 미확인 ⓘ</span>";
      portCell = "<span style='color:#94a3b8'>—</span>";
    }
    var on = h.online ? "<span class='status-badge status-badge--ok'>온라인</span>"
                      : "<span class='status-badge status-badge--critical'>연결 실패</span>";
    var trStyle = h.online ? "" : " style='background:#fef2f2'";
    return "<tr" + trStyle + "><td>" + escHtml(h.subnet || "-") + "</td><td><code>" + escHtml(h.ip) + "</code></td>" +
      "<td><code>" + escHtml(h.mac || "-") + "</code></td><td>" + swCell + "</td><td>" +
      portCell + "</td><td>" + on + "</td></tr>";
  }).join("");
}

// "직접 연결만" 토글 + "새로고침(재매칭)" 버튼
(function () {
  var only = document.getElementById("fac-only-direct");
  if (only) only.addEventListener("change", _renderFacilityRows);
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
    tbody.innerHTML = "<tr><td colspan=8 style='color:#64748b'>등록된 방화벽이 없습니다. '+ 방화벽 추가'로 등록하세요.</td></tr>";
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
      "<td>" + (f.interface_count != null ? f.interface_count : "-") + "</td>" +
      "<td>" + (f.arp_count != null ? f.arp_count : "-") + "</td>" +
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
            return "<tr><td>" + escHtml(i.name) + "</td><td>" + escHtml(i.ip || "-") + "</td><td>" +
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
  document.getElementById("cred-username").value = "";
  document.getElementById("cred-password").value = "";
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
  var btn = document.getElementById("btn-bulk-collect");
  if (!btn) return;
  var n = Object.keys(_bulkSel).length;
  btn.textContent = "정보 수집 (" + n + ")";
  btn.disabled = n === 0;
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

  // "정보 수집(N)" → 계정 입력 팝업
  var open = document.getElementById("btn-bulk-collect");
  if (open) open.addEventListener("click", function () {
    var ids = Object.keys(_bulkSel);
    if (!ids.length) { alert("먼저 수집할 스위치를 선택하세요."); return; }
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

  // "수집 시작" → 일괄 수집 요청
  var start = document.getElementById("btn-bulk-start");
  if (start) start.addEventListener("click", function () {
    var ids = Object.keys(_bulkSel).map(function (x) { return parseInt(x, 10); });
    if (!ids.length) { closeModal("modal-bulk-collect"); return; }
    var username = document.getElementById("bulk-username").value.trim();
    var password = document.getElementById("bulk-password").value;
    if (!username || !password) { alert("아이디와 패스워드를 입력하세요."); return; }
    var persist = document.getElementById("bulk-persist");
    fetch("/api/switches/bulk-collect", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids: ids, username: username, password: password,
                            persist: persist && persist.checked}),
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
  });
})();

// ─── 수동 추가 모달 ──────────────────────────────────────────────
document.getElementById("btn-add-manual").addEventListener("click", function() {
  _editSwitchId = null;  // 신규 추가 모드
  ["add-name","add-ip","add-hostname","add-location","add-note"].forEach(function(id) {
    document.getElementById(id).value = "";
  });
  document.getElementById("add-vendor").value = "unknown";
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

// ─── 알람(변경 이벤트) ───────────────────────────────────────────
var _ALERT_KIND = {
  new_device: "새 설비", device_offline: "설비 연결 끊김", device_online: "설비 복구",
  switch_unreachable: "스위치 연결 실패", switch_recovered: "스위치 복구",
  flapping: "포트 flapping", looping: "포트 looping",
};

function loadAlerts(renderList) {
  fetch("/api/alerts").then(function (r) { return r.json(); }).then(function (data) {
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
