// app.js의 사양 표기 헬퍼(fmtCpu/fmtMem/fmtSize/fmtDisk)를 실제 소스에서 떼어내
// 엣지 케이스로 두들긴다. 렌더 중 예외가 나면 서버 표 전체가 안 그려지므로 중요.
// 실행: node scripts/verify_fmt_helpers.js   → 전부 통과 시 exit 0
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "web", "static", "app.js"), "utf8");
const start = src.indexOf("function fmtCpu(");
const end = src.indexOf("function renderServers(");
if (start < 0 || end < 0 || end <= start) {
  console.error("FAIL: app.js에서 fmtCpu~renderServers 구간을 못 찾음 (함수명 변경?)");
  process.exit(1);
}
// escHtml은 app.js 상단에 정의돼 있으므로 동일 동작으로 주입
const escHtml = function (s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
};
const ctx = { escHtml: escHtml, Math: Math };
const fn = new Function("escHtml", src.slice(start, end) + "\nreturn {fmtCpu, fmtMem, fmtSize, fmtDisk};");
const H = fn(escHtml);

let fails = 0;
function check(name, cond, got) {
  console.log((cond ? "  [OK]   " : "  [FAIL] ") + name + (got !== undefined ? " — " + JSON.stringify(got) : ""));
  if (!cond) fails++;
}
function noThrow(name, f) {
  try {
    const v = f();
    check(name + " (예외 없음)", true, v);
    return v;
  } catch (e) {
    check(name + " (예외 없음)", false, String(e));
    return null;
  }
}

console.log("\n[fmtCpu]");
check("모델+코어", H.fmtCpu({ cpu_model: "Intel Xeon Silver 4210", cpu_cores: 8 }).indexOf("Intel Xeon Silver 4210") >= 0);
check("모델만", H.fmtCpu({ cpu_model: "AMD EPYC" }) === "AMD EPYC", H.fmtCpu({ cpu_model: "AMD EPYC" }));
check("코어만", H.fmtCpu({ cpu_cores: 4 }) === "4C", H.fmtCpu({ cpu_cores: 4 }));
check("둘 다 없음 → '-'", H.fmtCpu({}) === "-", H.fmtCpu({}));
check("null 필드 → '-'", H.fmtCpu({ cpu_model: null, cpu_cores: null }) === "-");
const xss = H.fmtCpu({ cpu_model: "<img src=x onerror=alert(1)>", cpu_cores: 2 });
check("XSS 이스케이프(원문 태그 없음)", xss.indexOf("<img") < 0, xss);
check("XSS 이스케이프(&lt; 로 변환)", xss.indexOf("&lt;img") >= 0);
const xss2 = H.fmtCpu({ cpu_model: "Xeon", cpu_cores: "<b>8" });
check("cpu_cores 주입 차단(비숫자는 무시)", xss2.indexOf("<b>") < 0, xss2);
check("cpu_cores 숫자문자열은 정상 표기", H.fmtCpu({ cpu_cores: "16" }) === "16C", H.fmtCpu({ cpu_cores: "16" }));

console.log("\n[fmtMem]");
check("0/누락 → '-'", H.fmtMem(0) === "-" && H.fmtMem(null) === "-" && H.fmtMem(undefined) === "-");
check("1024MB → 1 GB", H.fmtMem(1024) === "1 GB", H.fmtMem(1024));
check("512MB → 512 MB", H.fmtMem(512) === "512 MB", H.fmtMem(512));
check("32174MB → 소수 1자리 GB", H.fmtMem(32174) === "31.4 GB", H.fmtMem(32174));
check("65536MB → 64 GB(정수)", H.fmtMem(65536) === "64 GB", H.fmtMem(65536));
noThrow("문자열 입력", () => H.fmtMem("16384"));

console.log("\n[fmtDisk]");
check("총량 0 → '-'", H.fmtDisk({ disk_total_gb: 0 }) === "-");
check("필드 없음 → '-'", H.fmtDisk({}) === "-");
const d1 = H.fmtDisk({ disk_total_gb: 200, disk_used_gb: 100 });
check("200/100 → 50%", d1.indexOf("(50%)") >= 0, d1);
const d2 = H.fmtDisk({ disk_total_gb: 2048, disk_used_gb: 1843 });
check("2048GB → TB 표기", d2.indexOf("TB") >= 0, d2);
check("90% 초과 → 빨강", d2.indexOf("#dc2626") >= 0, d2);
const d3 = H.fmtDisk({ disk_total_gb: 100, disk_used_gb: 85 });
check("85% → 주황", d3.indexOf("#d97706") >= 0, d3);
noThrow("used 누락", () => H.fmtDisk({ disk_total_gb: 50 }));
noThrow("아주 작은 디스크(0.1GB)", () => H.fmtDisk({ disk_total_gb: 0.1, disk_used_gb: 0.05 }));
noThrow("used > total(비정상)", () => H.fmtDisk({ disk_total_gb: 10, disk_used_gb: 99 }));
noThrow("문자열 값", () => H.fmtDisk({ disk_total_gb: "200", disk_used_gb: "100" }));

console.log("\n" + "=".repeat(60));
if (fails) {
  console.log("FAILED " + fails + "건");
  process.exit(1);
}
console.log("ALL PASS — 사양 표기 헬퍼 엣지케이스 통과");
