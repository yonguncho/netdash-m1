"""서버실 랙 뷰 — TPS 그룹핑 키 주입 + UI 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"
CSS = ROOT / "web" / "static" / "style.css"
HTML = ROOT / "web" / "templates" / "index.html"


def test_state_injects_rack_group(client):
    client.post("/api/switches/manual",
                json={"ip": "10.8.8.1", "name": "FA_SW1", "vendor": "cisco",
                      "hostname": "TPS-F1B02_1F01_FA_SW1"})
    sw = next(x for x in client.get("/api/state").get_json()["switches"] if x["ip"] == "10.8.8.1")
    assert "tps_group" in sw
    assert "1공장" in sw["tps_group"]
    assert "Assembly" in sw["tps_group"]
    assert sw["tps_num"] == "TPS01"


def test_rack_view_ui():
    js = APP_JS.read_text(encoding="utf-8")
    assert "function renderRackView" in js
    assert "_viewMode" in js
    assert "tps_group" in js and "tps_num" in js
    css = CSS.read_text(encoding="utf-8")
    assert ".rack-unit" in css
    html = HTML.read_text(encoding="utf-8")
    assert 'id="btn-view-rack"' in html
    assert 'id="rack-view"' in html
