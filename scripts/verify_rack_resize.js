// 서버실 랙뷰의 '높이(U) 드래그 조절'을 실제 DOM에서 돌려본다.
// 실행: node scripts/verify_rack_resize.js   → 전부 통과 시 exit 0
//
// 사용자 보고(2026-07-28):
//   "랙뷰에서 장비 랙 사이즈를 아래로 늘리면 숫자가 늘어난다. 늘리는 기능이 잘 안된다.
//    갑자기 장비가 삭제되기도 한다. 아래로 내리면 U 숫자가 감소해야 하는데 증가한다."
//
// 랙은 위가 U42, 아래가 U1이다. 손잡이는 장비 아래쪽에 있으므로 아래로 끌면
// **아래 유닛(= 더 작은 번호)** 을 차지해야 한다. 예전에는 시작 유닛을 고정한 채
// 높이만 키워서, 화면은 아래로 늘어나는데 저장은 위쪽(U13→U15)으로 됐다.
// 그 결과 새로고침하면 장비가 위로 튀고, 위 장비와 겹치면 랙뷰에서 사라졌다.
const fs = require("fs");
const path = require("path");
const { JSDOM } = require(process.env.ND_JSDOM ||
  "C:/Users/yongu/AppData/Local/Temp/nd/node_modules/jsdom");

const src = fs.readFileSync(path.join(__dirname, "..", "web", "static", "app.js"), "utf8");

let fails = 0;
function check(name, cond, got) {
  console.log((cond ? "  [OK]   " : "  [FAIL] ") + name +
    (got !== undefined ? " — " + JSON.stringify(got) : ""));
  if (!cond) fails++;
}

// app.js에서 필요한 두 조각만 떼어낸다(전체 로드는 fetch/타이머까지 끌고 온다)
function slice(from, to, label) {
  const a = src.indexOf(from), b = src.indexOf(to);
  if (a < 0 || b < 0 || b <= a) {
    console.error("FAIL: app.js에서 " + label + " 구간을 못 찾음 (함수명 변경?)");
    process.exit(1);
  }
  return src.slice(a, b);
}
const renderSrc = slice("function renderRoomRackView(", "// ─── 랙 실장 높이(U) 드래그 조절",
  "renderRoomRackView");
const dragSrc = slice("var _RU_H = 21;", "function renderSwitchGrid(", "드래그 핸들러");
// jsdom은 레이아웃을 계산하지 않아 offsetWidth/elementFromPoint가 0/null이다.
// 좌표 → 칸 매핑을 테스트가 직접 쥐도록 스텁을 심는다(아래 dropAt 참고).

const dom = new JSDOM("<div id='room-rack-view'></div>", { pretendToBeVisual: true });
const { window } = dom;
const doc = window.document;

// app.js가 기대하는 최소 전역
const escHtml = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const saved = [];                       // PUT으로 저장된 location 기록
const stub = {
  document: doc, window: window, escHtml: escHtml,
  _num: (v) => (v == null || v === "" ? 0 : (isNaN(+v) ? 0 : +v)),
  _applyLocFilter: (a) => a,
  _ROOM_EMPTY: "비어 있음",
  _RACK_KIND: { Server: { c: "#3b82f6", t: "서버" }, _: { c: "#94a3b8", t: "" } },
  _roomInferDT: () => "Server",
  _roomKind: () => ({ c: "#3b82f6", t: "서버" }),
  payloadAttr: (o) => escHtml(JSON.stringify(o)),
  fetch: (url, opt) => {
    saved.push({ url: url, body: JSON.parse(opt.body) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({ ok: true }) });
  },
  loadFirewalls: () => {}, loadServers: () => {}, pollState: () => {},
  alert: (m) => { lastAlert = m; }, console: console,
};
let lastAlert = null;

const names = Object.keys(stub);
const api = new Function(...names,
  renderSrc + "\n" + dragSrc + "\nreturn {renderRoomRackView: renderRoomRackView};")
  (...names.map((k) => stub[k]));

function srv(id, name, unit, height, rack) {
  rack = rack || "A09";
  return { id: id, name: name, ip: "10.0.0." + id, room_rack: rack,
           room_unit: unit, room_height: height, location: rack + "U" + unit,
           status: "done" };
}
function render(servers) {
  api.renderRoomRackView([], [], servers);
}
function cellOf(name) {
  return [...doc.querySelectorAll(".ru--dev")]
    .find((c) => c.querySelector(".ru__name").textContent.indexOf(name) >= 0);
}
function drag(cell, dyPx) {
  const grip = cell.querySelector(".ru__grip");
  grip.dispatchEvent(new window.MouseEvent("mousedown",
    { bubbles: true, clientY: 500 }));
  doc.dispatchEvent(new window.MouseEvent("mousemove",
    { bubbles: true, clientY: 500 + dyPx }));
  doc.dispatchEvent(new window.MouseEvent("mouseup", { bubbles: true }));
}

// ── ① 아래로 끌면 U 숫자가 내려간다 ──────────────────────────────
console.log("\n[아래로 드래그 = 아래 유닛 차지]");
render([srv(1, "SRV-A", 20, 1)]);
let c = cellOf("SRV-A");
check("1U 장비가 U20에 그려짐", c && c.getAttribute("data-unit") === "20",
  c && c.getAttribute("data-unit"));
drag(c, 21 * 2);                                   // 두 칸 아래로
check("드래그 중 라벨이 아래로 확장(U18-U20)",
  c.querySelector(".ru__u").textContent === "U18-U20",
  c.querySelector(".ru__u").textContent);
check("저장된 위치도 U18-U20", saved.length === 1 && saved[0].body.location === "A09U18-U20",
  saved.map((s) => s.body.location));
check("서버 엔드포인트로 저장", saved[0].url === "/api/servers/1", saved[0].url);

// ── ② 위로 끌면 다시 줄어든다 ────────────────────────────────────
console.log("\n[위로 드래그 = 축소]");
saved.length = 0;
render([srv(2, "SRV-B", 18, 3)]);                  // U18-U20 (3U)
c = cellOf("SRV-B");
check("3U 장비 라벨", c.querySelector(".ru__u").textContent === "U18-U20",
  c.querySelector(".ru__u").textContent);
drag(c, -21 * 2);                                  // 두 칸 위로 = 1U로
check("축소 시 윗변 유지(U20)", saved[0].body.location === "A09U20",
  saved[0].body.location);

// ── ③ 아래 장비를 침범하지 않는다 ────────────────────────────────
console.log("\n[겹침 방지]");
saved.length = 0;
render([srv(3, "SRV-TOP", 20, 1), srv(4, "SRV-LOW", 18, 1)]);
c = cellOf("SRV-TOP");
drag(c, 21 * 10);                                  // 열 칸 아래로 세게 끈다
check("아래 빈 칸(U19)까지만 늘어남", saved[0].body.location === "A09U19-U20",
  saved[0].body.location);
check("아래 장비(U18)를 덮지 않음", saved[0].body.location.indexOf("U18") < 0);

// ── ④ 겹쳐 저장돼도 장비가 사라지지 않는다 ──────────────────────
console.log("\n[겹쳐도 사라지지 않는다]");
render([srv(5, "SRV-BIG", 18, 4), srv(6, "SRV-HIDDEN", 20, 1)]);
const html = doc.getElementById("room-rack-view").innerHTML;
check("겹친 장비가 화면 어딘가에 남아 있다", html.indexOf("SRV-HIDDEN") >= 0);
check("겹침 안내가 보인다", html.indexOf("위치 겹침") >= 0 || html.indexOf("⚠") >= 0);

// ── ⑤ 랙 밖(U1 아래)으로는 못 내린다 ────────────────────────────
console.log("\n[랙 경계]");
saved.length = 0;
render([srv(7, "SRV-BOTTOM", 1, 1)]);
c = cellOf("SRV-BOTTOM");
drag(c, 21 * 5);
check("U1에서 더 못 내려감(저장 없음)", saved.length === 0, saved.map((s) => s.body.location));

// ── ⑥ 손잡이 드래그가 상세를 열지 않는다 ────────────────────────
console.log("\n[상세 팝업 간섭]");
let detailOpened = false;
doc.addEventListener("click", () => { detailOpened = true; });
render([srv(8, "SRV-C", 30, 1)]);
c = cellOf("SRV-C");
drag(c, 21);
check("드래그로 상세가 열리지 않음", detailOpened === false);

// ── ⑦ 장비 드래그 이동 ──────────────────────────────────────────
// jsdom은 레이아웃이 없으므로 elementFromPoint가 항상 null이다.
// '커서 아래 칸'을 테스트가 지정할 수 있게 스텁을 심는다.
let _under = null;
doc.elementFromPoint = () => _under;

function moveTo(cell, rack, unit) {
  _under = doc.querySelector('.ru[data-rack="' + rack + '"][data-unit="' + unit + '"]');
  cell.dispatchEvent(new window.MouseEvent("mousedown",
    { bubbles: true, button: 0, clientX: 100, clientY: 100 }));
  doc.dispatchEvent(new window.MouseEvent("mousemove",
    { bubbles: true, clientX: 140, clientY: 140 }));   // 임계값(4px) 넘김
  doc.dispatchEvent(new window.MouseEvent("mouseup", { bubbles: true }));
}

console.log("\n[장비 드래그 이동]");
saved.length = 0;
render([srv(10, "SRV-MOVE", 20, 1), srv(11, "SRV-STAY", 10, 1)]);
let mv = cellOf("SRV-MOVE");
moveTo(mv, "A09", 30);
check("빈 유닛으로 옮기면 위치가 저장된다", saved.length === 1 &&
  saved[0].body.location === "A09U30", saved.map((s) => s.body.location));
check("옮긴 장비의 엔드포인트", saved[0].url === "/api/servers/10", saved[0].url);

saved.length = 0;
render([srv(12, "SRV-A2", 20, 1), srv(13, "SRV-B2", 10, 1)]);
moveTo(cellOf("SRV-A2"), "A09", 10);
check("다른 장비가 쓰는 칸에는 못 놓는다(저장 없음)", saved.length === 0,
  saved.map((s) => s.body.location));

saved.length = 0;
render([srv(14, "SRV-3U", 18, 3)]);                 // U18-U20
moveTo(cellOf("SRV-3U"), "A09", 30);
check("3U 장비는 커서 칸이 윗변 → U28-U30", saved[0].body.location === "A09U28-U30",
  saved[0].body.location);

saved.length = 0;
render([srv(15, "SRV-EDGE", 20, 3)]);               // U20-U22
moveTo(cellOf("SRV-EDGE"), "A09", 2);               // 아래가 U1 밖으로 넘어감
check("랙 아래로 삐져나가는 자리에는 못 놓는다", saved.length === 0,
  saved.map((s) => s.body.location));

saved.length = 0;
render([srv(18, "SRV-CROSS", 20, 1), srv(19, "SRV-OTHER", 5, 1, "B12")]);
moveTo(cellOf("SRV-CROSS"), "B12", 30);
check("다른 랙으로도 옮길 수 있다", saved.length === 1 &&
  saved[0].body.location === "B12U30", saved.map((s) => s.body.location));

saved.length = 0;
render([srv(16, "SRV-SAME", 20, 1)]);
moveTo(cellOf("SRV-SAME"), "A09", 20);              // 제자리
check("제자리에 놓으면 저장하지 않는다", saved.length === 0);

// 클릭(이동 없음)은 상세를 막지 않아야 한다
saved.length = 0;
render([srv(17, "SRV-CLICK", 25, 1)]);
mv = cellOf("SRV-CLICK");
mv.dispatchEvent(new window.MouseEvent("mousedown",
  { bubbles: true, button: 0, clientX: 100, clientY: 100 }));
doc.dispatchEvent(new window.MouseEvent("mouseup", { bubbles: true }));
let clicked = false;
doc.addEventListener("click", () => { clicked = true; });
mv.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
check("이동 없이 클릭하면 상세가 열린다", clicked === true);

console.log("\n" + "=".repeat(60));
if (fails) { console.log("FAILED " + fails + "건"); process.exit(1); }
console.log("ALL PASS — 랙 높이 드래그 + 장비 이동 검증 통과");
