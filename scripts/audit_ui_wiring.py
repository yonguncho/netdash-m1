# -*- coding: utf-8 -*-
"""UI 배선 감사 — '클릭해도 아무 일 없는 버튼'을 기계적으로 찾는다.

세 가지를 교차 검증한다:
  ① index.html/wall.html의 버튼 id 중 JS가 한 번도 참조하지 않는 것(죽은 버튼)
  ② JS가 getElementById로 찾는 id 중 HTML에 없는 것(항상 null → 기능 없음)
  ③ JS가 fetch하는 /api/ 경로 중 app.py에 라우트가 없는 것(404)
  ④ data-action 값 중 어떤 핸들러에도 없는 것(무반응)

읽기 전용. 실행: python scripts/audit_ui_wiring.py
"""
import re
import sys
from pathlib import Path

# 한국어 콘솔(cp949)에서 em-dash 등 비-cp949 문자를 print할 때
# UnicodeEncodeError로 죽지 않도록 stdout을 utf-8로 재설정한다.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent
APP_PY = (ROOT / "app.py").read_text(encoding="utf-8")
APP_JS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
WALL_JS = (ROOT / "web" / "static" / "wall.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")
WALL_HTML = (ROOT / "web" / "templates" / "wall.html").read_text(encoding="utf-8")
JS_ALL = APP_JS + "\n" + WALL_JS
HTML_ALL = HTML + "\n" + WALL_HTML

issues = []      # 사용자에게 실제 영향 있는 것
notes = []       # 잔재·정보(빌드 실패 아님)


def report(kind, item, detail=""):
    issues.append((kind, item, detail))


def note(kind, item, detail=""):
    notes.append((kind, item, detail))


# ── ① HTML 버튼 id 중 JS가 안 쓰는 것 ─────────────────────────────
btn_ids = set(re.findall(r'<button[^>]*\bid="([^"]+)"', HTML_ALL))
# 모달 닫기(data-close)로 동작하는 버튼은 id 없이도 동작하므로 제외 대상 아님
for bid in sorted(btn_ids):
    if bid not in JS_ALL:
        report("죽은 버튼(JS가 id를 참조하지 않음)", bid)

# ── ② JS가 찾는 id 중 HTML에 없는 것 ──────────────────────────────
js_ids = set(re.findall(r'getElementById\("([^"+]+)"\)', JS_ALL))
html_ids = set(re.findall(r'\bid="([^"]+)"', HTML_ALL))
# JS가 직접 만들어 넣는 엘리먼트(배너 등)는 HTML에 없는 게 정상
dyn_ids = set(re.findall(r'\.id\s*=\s*"([^"]+)"', JS_ALL))
dyn_ids |= set(re.findall(r'''id=[\\]?["']([a-z0-9-]+)[\\]?["']''', JS_ALL))
for jid in sorted(js_ids):
    if jid in html_ids or jid in dyn_ids:
        continue
    # `getElementById(a) || getElementById(b)` 폴백의 두 번째 항목은 구 id 호환용
    if re.search(r'getElementById\("[^"]+"\)\s*\|\|\s*document\.getElementById\("%s"\)'
                 % re.escape(jid), JS_ALL):
        continue
    # if (el) 가드가 있으면 기능이 깨지지 않는다 → 잔재로만 기록
    guarded = re.search(
        r'(\w+)\s*=\s*document\.getElementById\("%s"\)[\s\S]{0,120}?if\s*\(!?\1' % re.escape(jid),
        JS_ALL)
    if guarded:
        note("제거된 UI의 잔재(가드 있어 무해)", jid)
    else:
        report("없는 엘리먼트를 가드 없이 참조(런타임 오류 위험)", jid)

# ── ③ JS가 부르는 API 경로가 실제 라우트에 있는가 ────────────────
routes = re.findall(r'@app\.route\("([^"]+)"', APP_PY)
sock_routes = re.findall(r'@sock\.route\("([^"]+)"', APP_PY)


def route_to_regex(r):
    # /api/servers/<int:server_id>/collect → ^/api/servers/[^/]+/collect$
    pat = re.sub(r"<[^>]+>", "[^/]+", r)
    return re.compile("^" + pat + "$")


route_res = [route_to_regex(r) for r in routes + sock_routes]

# fetch("/api/..." + var + "/collect") 형태를 경로 패턴으로 환원
fetch_raw = re.findall(r'fetch\(\s*"([^"]+)"', JS_ALL)
fetch_concat = re.findall(r'fetch\(\s*"(/api/[^"]*)"\s*\+', JS_ALL)
ws_urls = re.findall(r'"(/ws/[^"]*)"', JS_ALL)

concat_prefixes = set(fetch_concat)
checked = set()
for raw in fetch_raw:
    path = raw.split("?")[0]
    if not path.startswith("/api/") or path in checked:
        continue
    checked.add(path)
    # fetch("/api/x/" + id + "/y") 형태는 완전한 경로가 아니다 → 접두사 검사로 넘긴다
    if raw in concat_prefixes:
        continue
    if not any(rx.match(path) for rx in route_res):
        report("존재하지 않는 API 호출", path)

for pref in set(fetch_concat):
    # 접두사 뒤에 무언가가 붙는 형태 → 접두사로 시작하는 라우트가 하나라도 있어야 한다
    if not any(r.startswith(pref.rstrip("/")) or pref.rstrip("/").startswith(
            r.split("<")[0].rstrip("/")) for r in routes):
        report("존재하지 않는 API 접두사", pref)

# ── ④ data-action 값이 핸들러에 있는가 ───────────────────────────
actions_html = set(re.findall(r"data-action=[\"']([a-z0-9-]+)[\"']", HTML_ALL))
actions_js = set(re.findall(r"data-action='([a-z0-9-]+)'", JS_ALL))
actions_js |= set(re.findall(r'data-action="([a-z0-9-]+)"', JS_ALL))
handled = set(re.findall(r'case\s+"([a-z0-9-]+)":', JS_ALL))
handled |= set(re.findall(r'action\s*===\s*"([a-z0-9-]+)"', JS_ALL))
handled |= set(re.findall(r'getAttribute\("data-action"\)\s*===\s*"([a-z0-9-]+)"', JS_ALL))
for a in sorted((actions_html | actions_js)):
    if a not in handled:
        report("처리되지 않는 data-action(클릭 무반응)", a)

# ── 결과 ─────────────────────────────────────────────────────────
print("라우트 %d개 / 버튼 id %d개 / data-action %d종 검사"
      % (len(routes) + len(sock_routes), len(btn_ids), len(actions_html | actions_js)))


def _dump(title, rows):
    by_kind = {}
    for kind, item, detail in rows:
        by_kind.setdefault(kind, []).append((item, detail))
    print("\n%s %d건" % (title, len(rows)))
    for kind, items in by_kind.items():
        print("  [%s] %d건" % (kind, len(items)))
        for item, detail in items:
            print("     -", item, ("— " + detail) if detail else "")


if notes:
    _dump("참고(기능 영향 없음)", notes)
if not issues:
    print("\n배선 문제 없음 — 클릭 가능한 모든 버튼·액션이 핸들러와 실제 API에 연결돼 있다")
    sys.exit(0)
_dump("발견", issues)
sys.exit(1)
