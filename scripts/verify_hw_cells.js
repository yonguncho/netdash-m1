// app.js의 장착 구성 표기 함수(memCell/diskCell/summarize*)를 실제 소스에서 떼어내
// 실행해 본다. 표 렌더 중 예외가 나면 서버 표 전체가 안 그려지므로 중요.
// 실행: node scripts/verify_hw_cells.js
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "web", "static", "app.js"), "utf8");
const start = src.indexOf("// 장착 구성(JSON 문자열) → 배열");
const end = src.indexOf("function renderServers(");
if (start < 0 || end < 0) {
  console.error("FAIL: app.js에서 장착 구성 헬퍼 구간을 못 찾음");
  process.exit(1);
}
const escHtml = function (s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
};
// memCell/diskCell은 fmtMem/fmtDisk/fmtSize/_num에 의존한다 → 그 구간부터 함께 가져온다
const helperStart = src.indexOf("function fmtCpu(");
const body = src.slice(helperStart, end);
const F = new Function("escHtml", "openModal", "document", "_servers",
  body + "\nreturn {memCell, diskCell, summarizeModules, summarizeDisks, _hwList, _sizeLabel, _sizeLabelCompact, showHwDetail};"
)(escHtml, function () {}, undefined, []);

let fails = 0;
function check(name, cond, got) {
  console.log((cond ? "  [OK]   " : "  [FAIL] ") + name + (got !== undefined ? " — " + JSON.stringify(got) : ""));
  if (!cond) fails++;
}
function noThrow(name, f) {
  try { const v = f(); check(name + " (예외 없음)", true, v); return v; }
  catch (e) { check(name + " (예외 없음)", false, String(e)); return null; }
}

const MODS = JSON.stringify([
  { size_mb: 16384, locator: "DIMM_A1", type: "DDR4", speed: "2400 MT/s", maker: "Samsung", part: "M393" },
  { size_mb: 16384, locator: "DIMM_A2", type: "DDR4", speed: "2400 MT/s", maker: "Samsung", part: "M393" },
]);
const DISKS = JSON.stringify([
  { name: "sda", model: "SAMSUNG MZ7LH960", size_gb: 894.3, kind: "SSD", bus: "" },
  { name: "sdb", model: "ST2000NM0055", size_gb: 1843.2, kind: "HDD", bus: "" },
]);

console.log("\n[JSON 파싱 방어]");
check("정상 배열", F._hwList(MODS).length === 2);
check("깨진 JSON → 빈 배열", F._hwList("{not json").length === 0);
check("null 문자열 → 빈 배열", F._hwList("null").length === 0);
check("undefined → 빈 배열", F._hwList(undefined).length === 0);
check("이미 배열이면 그대로", F._hwList([1, 2]).length === 2);

console.log("\n[요약]");
// 백엔드 summarize_modules(CSV)와 글자 하나까지 같아야 화면·엑셀이 어긋나지 않는다
check("모듈 요약", F.summarizeModules(JSON.parse(MODS), 4) === "16GB×2 (DDR4) · 2/4 슬롯",
  F.summarizeModules(JSON.parse(MODS), 4));
check("TB 단위 모듈", F._sizeLabelCompact(1048576) === "1TB", F._sizeLabelCompact(1048576));
check("슬롯 꽉 참 → 슬롯 표기 생략", F.summarizeModules(JSON.parse(MODS), 2) === "16GB×2 (DDR4)",
  F.summarizeModules(JSON.parse(MODS), 2));
check("디스크 요약", F.summarizeDisks(JSON.parse(DISKS)) === "HDD 1 · SSD 1",
  F.summarizeDisks(JSON.parse(DISKS)));
check("빈 목록 → 빈 문자열", F.summarizeModules([], 0) === "" && F.summarizeDisks([]) === "");

console.log("\n[표 셀]");
const s = { id: 1, mem_total_mb: 32768, mem_slots_total: 4, mem_modules: MODS,
            disk_total_gb: 2737.5, disk_used_gb: 1200, disk_devices: DISKS };
const mc = F.memCell(s), dc = F.diskCell(s);
check("메모리 셀에 총량", mc.indexOf("32 GB") >= 0, mc);
check("메모리 셀에 구성 요약", mc.indexOf("16GB×2") >= 0);
check("메모리 셀이 상세로 연결", mc.indexOf("data-action='hw-detail'") >= 0);
check("디스크 셀에 사용량", dc.indexOf("1.2 TB") >= 0, dc);
check("디스크 셀에 구성 요약", dc.indexOf("HDD 1 · SSD 1") >= 0);

console.log("\n[구성이 없을 때 — 기존 동작 유지]");
const bare = { id: 2, mem_total_mb: 8192, disk_total_gb: 100, disk_used_gb: 50 };
check("구성 없으면 링크 없음", F.memCell(bare).indexOf("hw-detail") < 0, F.memCell(bare));
check("총량은 그대로 표시", F.memCell(bare) === "8 GB", F.memCell(bare));
check("디스크도 링크 없음", F.diskCell(bare).indexOf("hw-detail") < 0);

console.log("\n[깨진 데이터 방어]");
noThrow("mem_modules가 깨진 JSON", () => F.memCell({ id: 3, mem_total_mb: 1024, mem_modules: "{x" }));
noThrow("disk_devices가 숫자", () => F.diskCell({ id: 4, disk_total_gb: 10, disk_devices: 5 }));
noThrow("size_mb가 문자열", () => F.summarizeModules([{ size_mb: "16384", type: "DDR4" }], 1));
const xss = F.memCell({ id: 5, mem_total_mb: 1024, mem_slots_total: 1,
  mem_modules: JSON.stringify([{ size_mb: 1024, type: "<img src=x onerror=alert(1)>" }]) });
check("구성 요약 XSS 이스케이프", xss.indexOf("<img") < 0, xss);

console.log("\n" + "=".repeat(60));
if (fails) { console.log("FAILED " + fails + "건"); process.exit(1); }
console.log("ALL PASS — 장착 구성 표기 함수 검증 통과");
