/* NetDash 관제(월보드) — 10초 자동 새로고침, 읽기 전용 */
"use strict";

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
  });
}

var KIND_KO = {
  new_device: "새 설비", device_offline: "설비 연결 끊김", device_online: "설비 복구",
  device_moved: "설비 이동", config_changed: "설정 변경",
  switch_unreachable: "스위치 연결 실패", switch_recovered: "스위치 복구",
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

function refresh() {
  fetch("/api/wall").then(function (r) { return r.json(); }).then(function (d) {
    setTile("t-total", d.total_switches || 0, false);
    setTile("t-unreach", d.unreachable || 0, true);
    setTile("t-failed", d.failed || 0, true);
    setTile("t-alert", d.alert_switches || 0, true);
    setTile("t-facoff", d.facility_offline || 0, true);
    setTile("t-unack", d.unacked_alerts || 0, true);

    var host = document.getElementById("wall-problems");
    var problems = d.problems || [];
    if (!problems.length) {
      host.innerHTML = "<div class='wall-ok'>✓ 이상 없음<small>모든 장비 정상 · " +
        (d.total_switches || 0) + "대 감시 중</small></div>";
    } else {
      host.innerHTML = problems.map(function (p) {
        return "<div class='pcard'><div class='pcard__name'>" + esc(p.name) + "</div>" +
          "<div class='pcard__ip'>" + esc(p.ip) + "</div>" +
          "<div class='pcard__why'>⚠ " + esc(p.why) + "</div></div>";
      }).join("");
    }

    var tick = document.getElementById("wall-events");
    tick.innerHTML = (d.recent_events || []).map(function (ev) {
      var kind = KIND_KO[ev.kind] || ev.kind || "-";
      var where = [ev.label, ev.ip].filter(Boolean).join(" ");
      return "<span>" + esc((ev.ts || "").replace("T", " ").slice(5, 16)) +
        " <b>" + esc(kind) + "</b> " + esc(where) + "</span>";
    }).join("");
  }).catch(function (e) { console.error(e); });
}

function clock() {
  var el = document.getElementById("wall-clock");
  if (el) el.textContent = new Date().toLocaleString("ko-KR");
}

refresh();
clock();
setInterval(refresh, 10000);
setInterval(clock, 1000);
