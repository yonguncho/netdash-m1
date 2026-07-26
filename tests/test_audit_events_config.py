# -*- coding: utf-8 -*-
"""접근로그 이더넷 IP + 루프/플래핑 포트 표기 + config 선택 다운로드 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, collector

ROOT = Path(__file__).parent.parent
HTML = ROOT / "web" / "templates" / "index.html"
APP_JS = ROOT / "web" / "static" / "app.js"


def test_client_ip_loopback_uses_eth(client, monkeypatch):
    """루프백 접속이면 접근 로그에 서버 이더넷 IP로 표기."""
    import app as _app
    _app._SERVER_ETH_IP = None
    from core import netinfo
    monkeypatch.setattr(netinfo, "_primary_ip", lambda: "10.92.170.5")
    ctx_app = client.application
    with ctx_app.test_request_context(environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert _app._client_ip() == "10.92.170.5"
    # XFF가 있으면 그것이 우선
    with ctx_app.test_request_context(headers={"X-Forwarded-For": "10.1.2.3"},
                                      environ_base={"REMOTE_ADDR": "127.0.0.1"}):
        assert _app._client_ip() == "10.1.2.3"


def test_extract_event_ports():
    events = [
        {"type": "flapping", "detail": "Eth1/9: link up/down 5회", "count": 5},
        {"type": "flapping", "detail": "Gi1/0/24: link up/down 3회", "count": 3},
    ]
    ports = collector._extract_event_ports(events, "flapping")
    assert "Eth1/9" in ports and "Gi1/0/24" in ports
    loop = [{"type": "looping", "detail": "%SPANNING-TREE loop guard blocking Ethernet1/5"}]
    assert collector._extract_event_ports(loop, "looping") == ["Ethernet1/5"]


def test_config_export_selected(client):
    a = client.post("/api/switches/manual", json={"ip": "10.60.0.1", "name": "SWA", "vendor": "cisco"}).get_json()["switch_id"]
    b = client.post("/api/switches/manual", json={"ip": "10.60.0.2", "name": "SWB", "vendor": "cisco"}).get_json()["switch_id"]
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    db.save_config_backup(dbp, a, "hostname SWA\nversion 15.2")
    db.save_config_backup(dbp, b, "hostname SWB\nversion 15.2")
    # 선택(a만) → ZIP에 1개
    r = client.get("/api/configs/export-all?ids=%d" % a)
    assert r.status_code == 200 and r.data[:2] == b"PK"
    import io, zipfile
    names = zipfile.ZipFile(io.BytesIO(r.data)).namelist()
    assert len(names) == 1 and "SWA" in names[0]
    # 전체
    r2 = client.get("/api/configs/export-all")
    names2 = zipfile.ZipFile(io.BytesIO(r2.data)).namelist()
    assert len(names2) == 2


def test_config_download_ui():
    html = HTML.read_text(encoding="utf-8")
    # v5.4 툴바 통일: 라벨이 '⬇ 설정 다운로드'로 변경(버튼 id·동작은 동일)
    assert 'id="btn-configs-export"' in html
    assert "설정 다운로드</button>" in html
    assert "config 일괄 다운로드" not in html
    js = APP_JS.read_text(encoding="utf-8")
    assert "export-all?ids=" in js
