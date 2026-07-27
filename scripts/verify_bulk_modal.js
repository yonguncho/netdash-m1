// 일괄 수집 팝업 — 대상이 아주 많을 때도 계정 입력칸과 '수집 시작'이 화면에 남는가.
// app.js의 _bulkTargetInfo를 실제 소스에서 떼어내 실행하고, CSS 규칙도 함께 확인한다.
// 실행: node scripts/verify_bulk_modal.js
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const src = fs.readFileSync(path.join(root, "web", "static", "app.js"), "utf8");
const css = fs.readFileSync(path.join(root, "web", "static", "style.css"), "utf8");

let fails = 0;
function check(name, cond, got) {
  console.log((cond ? "  [OK]   " : "  [FAIL] ") + name + (got !== undefined ? " — " + JSON.stringify(got).slice(0, 160) : ""));
  if (!cond) fails++;
}

// _bulkTargetInfo 추출
const s = src.indexOf("var _BULK_PREVIEW");
const e = src.indexOf("function _updateBulkCollectBtn(");
if (s < 0 || e < 0) { console.error("FAIL: _bulkTargetInfo 구간을 못 찾음"); process.exit(1); }
const escHtml = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const mk = (n) => Array.from({ length: n }, (_, i) => ({ id: i + 1, name: "TPS-SW-" + (i + 1), ip: "10.0.0." + (i + 1) }));
function build(n) {
  const _switches = mk(n);
  const F = new Function("escHtml", "_switches",
    src.slice(s, e) + "\nreturn _bulkTargetInfo;")(escHtml, _switches);
  return F(_switches.map(x => x.id));
}

console.log("\n[대상 수에 따른 요약]");
const few = build(3);
check("3대 — 전부 나열", (few.match(/TPS-SW-/g) || []).length === 3, few);
check("3대 — 접기 없음", few.indexOf("target-list") < 0);

const many = build(300);
check("300대 — 개수 표시", many.indexOf("<strong>300대</strong>") >= 0);
check("300대 — 미리보기 5대만 본문에 노출", (many.split("details")[0].match(/TPS-SW-/g) || []).length === 5,
  many.split("details")[0]);
check("300대 — '외 295대' 표기", many.indexOf("외 295대") >= 0);
check("300대 — 전체는 접어 둠(details)", many.indexOf("<details class='target-list'") >= 0);
check("300대 — 접힌 상태(open 아님)", many.indexOf("<details class='target-list' open") < 0);
check("300대 — 전체 목록은 스크롤 박스 안", many.indexOf("target-list__items") >= 0);

console.log("\n[XSS]");
const _switches = [{ id: 1, name: "<img src=x onerror=alert(1)>", ip: "10.0.0.1" }];
const F = new Function("escHtml", "_switches", src.slice(s, e) + "\nreturn _bulkTargetInfo;")(escHtml, _switches);
const xss = F([1]);
check("스위치 이름 이스케이프", xss.indexOf("<img") < 0, xss);

console.log("\n[CSS — 팝업이 화면을 넘어가지 않는가]");
const box = css.slice(css.indexOf(".modal__box {"), css.indexOf(".modal__header {"));
check(".modal__box 높이 제한", /max-height:\s*100%/.test(box), box.trim().slice(0, 120));
check(".modal__box 세로 플렉스", /flex-direction:\s*column/.test(box));
// 기본 규칙만 본다 — '#modal-auto-collect .modal__body'(그리드 전용)를 집으면 무의미
const baseBody = /\n\.modal__body\s*\{([^}]*)\}/.exec(css);
check(".modal__body 기본 규칙 존재", !!baseBody);
const body = baseBody ? baseBody[1] : "";
check(".modal__body 스크롤", /overflow-y:\s*auto/.test(body), body.trim());
check(".modal__body 축소 허용(min-height:0)", /min-height:\s*0/.test(body));
check(".modal__body 남는 공간 차지(flex:1 1 auto)", /flex:\s*1 1 auto/.test(body));
const footer = css.slice(css.indexOf(".modal__footer {"), css.indexOf(".required"));
check(".modal__footer 고정(축소 안 됨)", /flex:\s*0 0 auto/.test(footer), footer.trim());
const infobox = css.slice(css.indexOf(".switch-info-box {"), css.indexOf(".target-list > summary"));
check(".switch-info-box 높이 제한 + 스크롤",
  /max-height/.test(infobox) && /overflow-y:\s*auto/.test(infobox), infobox.trim());

console.log("\n" + "=".repeat(60));
if (fails) { console.log("FAILED " + fails + "건"); process.exit(1); }
console.log("ALL PASS — 대량 선택에서도 팝업 조작이 가능하다");
