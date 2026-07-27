# -*- coding: utf-8 -*-
"""UI 배선 회귀 — '클릭해도 아무 일 없는 버튼'이 생기지 않게 고정한다.

이 프로젝트에서 반복된 실패 유형: 화면을 개편하면서 버튼은 남았는데 핸들러가
빠지거나, 핸들러가 부르는 API 경로가 바뀌어 클릭이 무반응이 되는 것.
scripts/audit_ui_wiring.py 를 그대로 돌려 한 곳에서 판정한다.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
AUDIT = ROOT / "scripts" / "audit_ui_wiring.py"


def test_no_dead_buttons_or_missing_apis():
    r = subprocess.run([sys.executable, str(AUDIT)], capture_output=True,
                       cwd=str(ROOT), timeout=120)
    out = (r.stdout or b"").decode("utf-8", "replace") + \
          (r.stderr or b"").decode("utf-8", "replace")
    assert r.returncode == 0, "UI 배선 문제 발견:\n" + out


def test_audit_covers_meaningful_surface():
    """감사가 실제로 무언가를 검사하고 있는지(정규식이 깨져 0건이 아닌지) 확인."""
    r = subprocess.run([sys.executable, str(AUDIT)], capture_output=True,
                       cwd=str(ROOT), timeout=120)
    out = (r.stdout or b"").decode("utf-8", "replace")
    import re
    m = re.search(r"라우트 (\d+)개 / 버튼 id (\d+)개 / data-action (\d+)종", out)
    assert m, out
    routes, buttons, actions = (int(x) for x in m.groups())
    assert routes >= 80, routes
    assert buttons >= 50, buttons
    assert actions >= 15, actions
