/* NetDash — 메인 UI 스크립트 */

"use strict";

// ─── 전역 상태 ────────────────────────────────────────────────────
let _switches = [];
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
  }
});

// ─── 탭 전환 ─────────────────────────────────────────────────────
document.querySelectorAll(".tab-nav__btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-nav__btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "vlan") loadVlans();
    if (btn.dataset.tab === "switch") renderSwitchTable(_switches);
    if (btn.dataset.tab === "reconcile") loadReconcile();
    if (btn.dataset.tab === "firewall") loadFirewalls();
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
    sw.ip + (sw.hostname ? " · " + sw.hostname : "");
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
  Promise.all([
    fetch("/api/switches/" + switchId + "/detail").then(r => r.json()),
    fetch("/api/switches/" + switchId + "/events").then(r => r.json()),
  ]).then(function(results) {
    var detail = results[0], evts = results[1];
    renderPortsTab(detail.ports || []);
    renderMacsTab(detail.macs || []);
    renderArpsTab(detail.arps || []);
    renderEventsTab(evts.events || []);
  }).catch(function(e) { console.error("detail load error:", e); });
}

function renderPortsTab(ports) {
  var el = document.getElementById("dtab-ports");
  if (!ports.length) { el.innerHTML = "<p style='color:#64748b'>포트 정보 없음</p>"; return; }
  el.innerHTML = "<table class='data-table'><thead><tr><th>포트</th><th>상태</th><th>VLAN</th><th>속도</th><th>설명</th></tr></thead><tbody>" +
    ports.map(function(p) {
      return "<tr><td>" + escHtml(p.name) + "</td><td><span class='status-badge status-badge--" +
        (p.status === "up" ? "ok" : "critical") + "'>" + escHtml(p.status || "-") + "</span></td><td>" +
        (p.vlan != null ? p.vlan : "-") + "</td><td>" + escHtml(p.speed || "-") + "</td><td>" + escHtml(p.description || "-") + "</td></tr>";
    }).join("") + "</tbody></table>";
}

function renderMacsTab(macs) {
  var el = document.getElementById("dtab-macs");
  if (!macs.length) { el.innerHTML = "<p style='color:#64748b'>MAC 정보 없음</p>"; return; }
  el.innerHTML = "<table class='data-table'><thead><tr><th>VLAN</th><th>MAC 주소</th><th>포트</th><th>타입</th></tr></thead><tbody>" +
    macs.map(function(m) {
      return "<tr><td>" + (m.vlan != null ? m.vlan : "-") + "</td><td><code>" + escHtml(m.mac) + "</code></td><td>" + escHtml(m.port) + "</td><td>" + escHtml(m.entry_type || "-") + "</td></tr>";
    }).join("") + "</tbody></table>";
}

function renderArpsTab(arps) {
  var el = document.getElementById("dtab-arps");
  if (!arps.length) { el.innerHTML = "<p style='color:#64748b'>ARP 정보 없음</p>"; return; }
  el.innerHTML = "<table class='data-table'><thead><tr><th>IP</th><th>MAC 주소</th><th>인터페이스</th></tr></thead><tbody>" +
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
function renderSwitchGrid(switches) {
  var grid = document.getElementById("switch-grid");
  if (!switches.length) {
    grid.innerHTML = "<p class='placeholder'>스위치를 추가하거나 엑셀 파일을 가져오세요.</p>";
    return;
  }
  grid.innerHTML = switches.map(swCardHTML).join("");
  switches.forEach(function(sw) {
    var card = document.getElementById("swcard-" + sw.id);
    if (!card) return;
    card.addEventListener("click", function() { openCredentialModal(sw); });
  });
}

function swCardHTML(sw) {
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
    alertBadge +
    "<div class='sw-card__icon'><div class='sw-icon'><div class='sw-icon__ports'>" +
    renderMiniPorts(sw) +
    "</div></div></div>" +
    "<div class='sw-card__name'>" + escHtml(sw.name) + "</div>" +
    "<div class='sw-card__meta'>" +
    "<span>" + escHtml(sw.ip) + "</span>" +
    (sw.hostname ? "<span>" + escHtml(sw.hostname) + "</span>" : "") +
    (sw.location ? "<span style='font-size:10px'>" + escHtml(sw.location) + "</span>" : "") +
    "</div>" +
    "<div class='sw-card__status'>" +
    "<span class='dot " + dotClass + "'></span>" +
    "<span>" + escHtml(sw.vendor || "unknown") + " · " + statusLabel + "</span>" +
    "</div>" +
    "<div class='sw-card__actions'>" +
    "<button class='btn btn--primary' style='font-size:12px;padding:4px 10px' " +
    "data-action='detail-switch' data-payload='" + swJson + "'>상세보기</button>" +
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
  var tbody = document.getElementById("switch-table-body");
  tbody.innerHTML = switches.map(function(sw) {
    var sc = swStatusClass(sw);
    return "<tr><td>" + escHtml(sw.name) + "</td><td><code>" + escHtml(sw.ip) + "</code></td><td>" +
      escHtml(sw.hostname || "-") + "</td><td>" + escHtml(sw.vendor || "-") + "</td><td>" +
      escHtml(sw.location || "-") + "</td><td><span class='status-badge status-badge--" + sc + "'>" +
      escHtml(sw.status) + "</span></td><td>" +
      (sw.alert && sw.alert !== "none" ? "<span class='status-badge status-badge--" + sw.alert + "'>" + sw.alert + "</span>" : "-") +
      "</td><td>" + fmtTime(sw.last_collected) + "</td>" +
      "<td>" +
      "<button class='btn btn--secondary' style='font-size:12px;padding:4px 10px' " +
      "data-action='edit-switch' data-payload='" + encodeURIComponent(JSON.stringify(sw)) + "'>수정</button> " +
      "<button class='btn btn--ghost' style='font-size:12px;padding:4px 10px' " +
      "data-action='delete-switch' data-id='" + sw.id + "'>삭제</button></td></tr>";
  }).join("");
}

var _editSwitchId = null;

function editSwitch(sw) {
  _editSwitchId = sw.id;
  document.getElementById("add-name").value = sw.name || "";
  document.getElementById("add-ip").value = sw.ip || "";
  document.getElementById("add-hostname").value = sw.hostname || "";
  document.getElementById("add-vendor").value = sw.vendor || "unknown";
  document.getElementById("add-location").value = sw.location || "";
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

// ─── VLAN 탭 ─────────────────────────────────────────────────────
function loadVlans() {
  fetch("/api/vlans").then(function(r) { return r.json(); }).then(function(data) {
    var tbody = document.getElementById("vlan-table-body");
    var vlans = data.vlans || [];
    if (!vlans.length) {
      tbody.innerHTML = "<tr><td colspan=4 style='color:#64748b'>VLAN 정보 없음</td></tr>";
      return;
    }
    tbody.innerHTML = vlans.map(function(v) {
      return "<tr><td><strong>VLAN " + v.vlan + "</strong></td><td>" + escHtml(v.switch_name) +
        "</td><td><code>" + escHtml(v.switch_ip) + "</code></td><td>" + v.mac_count + "</td></tr>";
    }).join("");
  }).catch(function(e) { console.error("vlan load:", e); });
}

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
    .then(function(data) { renderFirewalls(data.firewalls || []); })
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
    return "<tr><td>" + escHtml(f.name) + "</td>" +
      "<td>" + escHtml(f.vendor) + "</td>" +
      "<td><code>" + escHtml(f.host) + "</code></td>" +
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
        ? "<table class='data-table'><thead><tr><th>IP</th><th>MAC</th><th>인터페이스</th></tr></thead><tbody>" +
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
  ["fw-name", "fw-host", "fw-port", "fw-add-token", "fw-add-username", "fw-add-password"].forEach(function(id) {
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
  closeModal("modal-credential");
  collectSwitch(_selectedSwitch.id, username, password);
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

function collectSwitch(switchId, username, password) {
  fetch("/api/switches/" + switchId + "/collect", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: username, password: password}),
  }).then(function(r) { return r.json(); }).then(function() {
    pollState();
  }).catch(function(e) { console.error("collect error:", e); });
}

// ─── 수동 추가 모달 ──────────────────────────────────────────────
document.getElementById("btn-add-manual").addEventListener("click", function() {
  _editSwitchId = null;  // 신규 추가 모드
  ["add-name","add-ip","add-hostname","add-location"].forEach(function(id) {
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
        var totalImported = (data.imported_switch_ids ? data.imported_switch_ids.length : 0) +
                           (data.imported_host_ids ? data.imported_host_ids.length : 0);
        alert(totalImported + "개 항목 임포트 완료 (스위치: " +
              (data.imported_switch_ids ? data.imported_switch_ids.length : 0) + ", " +
              "호스트: " + (data.imported_host_ids ? data.imported_host_ids.length : 0) + ")");
        pollState();
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
      if (data.found && data.result) {
        var r = data.result;
        body.innerHTML =
          "<p><strong>IP:</strong> " + escHtml(r.ip) + "</p>" +
          "<p><strong>MAC:</strong> " + escHtml(r.mac || "-") + "</p>" +
          "<p><strong>연결 스위치:</strong> " + escHtml(r.switch_name || "-") + " (" + escHtml(r.switch_ip || "-") + ")</p>" +
          "<p><strong>포트:</strong> " + escHtml(r.port || "-") + "</p>" +
          "<p><strong>신뢰도:</strong> " + (r.confidence ? (r.confidence * 100).toFixed(0) + "%" : "-") + "</p>" +
          (r.reason ? "<p style='margin-top:8px;color:#64748b;font-size:12px'>" + escHtml(r.reason) + "</p>" : "");
      } else {
        body.innerHTML = "<p style='color:#64748b'>IP <strong>" + escHtml(ip) + "</strong> 의 위치 정보가 없습니다. 해당 스위치의 정보를 먼저 수집하세요.</p>";
      }
      openModal("modal-search-result");
    })
    .catch(function(e) { console.error(e); alert("검색 오류"); });
}

// ─── 폴링 ────────────────────────────────────────────────────────
function pollState() {
  fetch("/api/state")
    .then(function(r) { return r.json(); })
    .then(function(data) {
      _switches = data.switches || [];
      renderSwitchGrid(_switches);
      renderSwitchTable(_switches);

      if (_currentSwitchId) {
        var sw = _switches.find(function(s) { return s.id === _currentSwitchId; });
        if (sw) {
          document.getElementById("detail-title").textContent = sw.name;
          document.getElementById("detail-subtitle").textContent =
            sw.ip + (sw.hostname ? " · " + sw.hostname : "");
        }
      }
      document.getElementById("last-updated").textContent = "갱신: " + new Date().toLocaleTimeString("ko-KR");
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
_pollTimer = setInterval(pollState, 5000);
