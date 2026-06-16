(function () {
  "use strict";

  var POLL_INTERVAL_MS = 3000;

  function statusLabel(status) {
    var map = {
      done: "완료",
      failed: "실패",
      collecting: "수집 중",
      pending: "대기",
      unsupported: "미지원",
    };
    return map[status] || status;
  }

  function renderSwitches(switches) {
    var container = document.getElementById("switch-list");
    if (!switches || switches.length === 0) {
      container.innerHTML = '<p class="loading">스위치 없음</p>';
      return;
    }

    var html = switches
      .map(function (sw) {
        var cls = "switch-card switch-card--" + (sw.status || "pending");
        return (
          '<div class="' + cls + '">' +
          '<div class="switch-card__name">' + escapeHtml(sw.name || "") + "</div>" +
          '<div class="switch-card__ip">' + escapeHtml(sw.ip || "") + "</div>" +
          '<div class="switch-card__meta">' +
          '<div class="switch-card__stat">포트 <span>' + (sw.port_count || 0) + "</span></div>" +
          '<div class="switch-card__stat">MAC <span>' + (sw.mac_count || 0) + "</span></div>" +
          '<div class="switch-card__stat">벤더 <span>' + escapeHtml(sw.vendor || "-") + "</span></div>" +
          "</div>" +
          '<span class="switch-card__status">' + statusLabel(sw.status) + "</span>" +
          "</div>"
        );
      })
      .join("");

    container.innerHTML = html;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function updateTimestamp(ts) {
    var el = document.getElementById("last-updated");
    if (el && ts) {
      el.textContent = "갱신: " + ts.replace("T", " ").slice(0, 19) + " UTC";
    }
  }

  function poll() {
    fetch("/api/state")
      .then(function (res) {
        if (!res.ok) {
          throw new Error("HTTP " + res.status);
        }
        return res.json();
      })
      .then(function (data) {
        renderSwitches(data.switches);
        updateTimestamp(data.timestamp);
      })
      .catch(function (err) {
        var container = document.getElementById("switch-list");
        container.innerHTML = '<p class="error-msg">서버 연결 실패: ' + escapeHtml(err.message) + "</p>";
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    poll();
    setInterval(poll, POLL_INTERVAL_MS);
  });
})();
