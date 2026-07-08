# -*- coding: utf-8 -*-
"""네트워크 구성도 PPTX 자동 생성 테스트."""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, pptx_report

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def _seed(dbp):
    db.save_firewall(dbp, "SKBA_F1_FA_FW", "fortigate", "10.92.186.1", port=443)
    bb = db.save_switch(dbp, "SKBA_F1_FABB", "10.92.0.1", "cisco_nxos")
    db.update_switch(dbp, bb, device_type="BackBone")
    a1 = db.save_switch(dbp, "SKBA_F1_FASW1", "10.92.174.11", "cisco_nxos")
    db.update_switch(dbp, a1, hostname="1공장A동")
    db.set_switch_status(dbp, bb, "done"); db.set_switch_status(dbp, a1, "done")
    db.save_neighbors(dbp, bb, [{"local_port": "Eth1/9", "remote_name": "SKBA_F1_FASW1",
                                 "remote_port": "Eth1/48", "remote_ip": "10.92.174.11", "platform": "N9K"}])
    return bb, a1


def test_build_pptx(temp_db):
    _seed(temp_db)
    data, fname = pptx_report.build_pptx(temp_db, customer="OO전자", generated="2026-07-08")
    assert data[:2] == b"PK"                       # zip/pptx 시그니처
    assert fname == "OO전자_네트워크구성도_20260708.pptx"
    zf = zipfile.ZipFile(io.BytesIO(data))
    slides = [n for n in zf.namelist() if n.startswith("ppt/slides/slide") and n.endswith(".xml")]
    assert len(slides) >= 4                        # 표지+서버실+구역개요+구역상세
    # 로고 이미지가 슬라이드에 포함(표지/헤더)
    media = [n for n in zf.namelist() if n.startswith("ppt/media/")]
    assert len(media) >= 1


def test_pptx_default_date(temp_db):
    _seed(temp_db)
    data, fname = pptx_report.build_pptx(temp_db, customer="고객A")
    assert data[:2] == b"PK" and fname.startswith("고객A_네트워크구성도_")


def test_pptx_render_png(temp_db):
    _seed(temp_db)
    topo = pptx_report.topology.build_topology(temp_db)
    buf = pptx_report._render_layered_png(topo["nodes"], topo["links"], "테스트")
    assert buf.getvalue()[:8] == b"\x89PNG\r\n\x1a\n"   # PNG 시그니처


def test_pptx_endpoint(client):
    from config import get_config
    _seed(get_config(demo_mode=True).get_db_path())
    r = client.get("/api/report/pptx?customer=테스트사&date=2026-07-08")
    assert r.status_code == 200
    assert r.data[:2] == b"PK"
    assert "presentationml" in r.headers.get("Content-Type", "")


def test_pptx_ui():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="btn-pptx-report"' in html and 'id="modal-pptx"' in html
    assert 'id="pptx-customer"' in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "/api/report/pptx?customer=" in js


def test_logo_bundled():
    assert (ROOT / "web" / "static" / "brand" / "skax_logo.png").exists()
