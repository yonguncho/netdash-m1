# -*- coding: utf-8 -*-
"""랙뷰 높이(U) 드래그 — 아래로 끌면 U 번호가 내려간다 (v6.7.1).

사용자 보고: "랙뷰에서 장비 크기를 아래로 늘리면 U 숫자가 늘어난다. 늘리는 기능이
잘 안 되고, 갑자기 장비가 삭제되기도 한다. 아래로 내리면 U 숫자가 감소해야 한다."

랙은 위가 U42, 아래가 U1이다. 손잡이는 장비 **아래쪽**에 있으므로 아래로 끌면
아래 유닛(= 더 작은 번호)을 차지해야 한다. 예전에는 시작 유닛을 고정한 채 높이만
키워서, 화면은 아래로 늘어나는데 저장은 위쪽(U20→U22)으로 됐다. 그래서
새로고침하면 장비가 위로 튀고, 위 장비와 겹치면 랙뷰에서 사라졌다.

DOM 동작 검증은 scripts/verify_rack_resize.js(jsdom)에서 실제로 드래그해 본다.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import serverroom  # noqa: E402

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")


def _drag_block():
    i = APPJS.index('.closest(".ru__grip")')
    return APPJS[i:i + 2600]


def test_top_edge_is_the_anchor():
    """윗변(topU)을 고정하고 시작 유닛을 내려야 아래로 늘어난다."""
    b = _drag_block()
    assert "var topU = unit + startH - 1;" in b
    assert "topU - h + 1" in b, "아래로 끌 때 시작 유닛이 내려가지 않는다"
    assert "_ruLocation(rack, topU - curH + 1, curH)" in b, "저장 위치가 위로 간다"


def test_growth_is_capped_by_free_space_below():
    """아래 장비를 덮으면 저장 후 한쪽이 화면에서 사라진다."""
    b = _drag_block()
    assert "freeBelow" in b and 'classList.contains("ru--empty")' in b
    assert "Math.min(42, topU, startH + freeBelow)" in b, "랙 바닥·아래 장비 한계가 없다"


def test_label_shows_range_downward():
    b = _drag_block()
    assert '"U" + base + "-U" + topU' in b, "라벨이 아래로 확장된 범위를 못 보여준다"


def test_saved_location_roundtrips_through_parser():
    """화면이 만드는 문자열을 백엔드가 그대로 해석해야 한다."""
    # U20 1U 장비를 두 칸 아래로 → U18-U20
    loc = serverroom.format_rack("A09", 18, 3)
    assert loc == "A09U18-U20"
    info = serverroom.parse_rack(loc)
    assert info["unit"] == 18 and info["unit_end"] == 20 and info["height"] == 3
    assert serverroom.occupied_units(info) == [18, 19, 20]


def test_overlap_keeps_device_visible():
    i = APPJS.index("function _put(d)")
    b = APPJS[i:i + 1200]
    assert "conflicts.push(d)" in b
    assert "d.clipped = fit < h;" in b, "들어가는 만큼이라도 그려야 한다"
    assert "rack-conflicts" in APPJS, "겹친 장비를 알려주는 안내가 없다"


@pytest.mark.skipif(not shutil.which("node"), reason="node 없음")
def test_jsdom_drag_behaviour():
    """실제 DOM에서 드래그해 라벨·저장값·겹침 처리를 확인한다."""
    script = ROOT / "scripts" / "verify_rack_resize.js"
    p = subprocess.run([shutil.which("node"), str(script)],
                       cwd=str(ROOT), capture_output=True, timeout=180)
    out = (p.stdout or b"").decode("utf-8", "replace")
    if "Cannot find module" in out + (p.stderr or b"").decode("utf-8", "replace"):
        pytest.skip("jsdom 미설치")
    assert p.returncode == 0, out[-2000:]
    assert "ALL PASS" in out
