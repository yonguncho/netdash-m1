# -*- coding: utf-8 -*-
"""2026-07-12 3차 감사(런타임 통합 검증) 수정 회귀 테스트."""
import sys
import io
import warnings
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

warnings.filterwarnings("ignore")


@pytest.fixture
def demo_client():
    with redirect_stderr(io.StringIO()):
        from app import create_app
        app = create_app(demo_mode=True)
        return app.test_client()


# ── malformed JSON은 500이 아니라 정상 처리(400/202) ──
def test_malformed_json_not_500(demo_client):
    r = demo_client.post("/api/switches/1/collect", data="{bad",
                         content_type="application/json")
    assert r.status_code != 500
    r2 = demo_client.post("/api/switches/bulk-collect", data="{bad",
                          content_type="application/json")
    assert r2.status_code != 500  # ids 누락 → 400


def test_all_get_json_silent():
    """모든 request.get_json은 silent=True (malformed JSON 500 방지)."""
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    # 비-silent get_json()이 남아있지 않아야
    assert "request.get_json() or" not in src
    assert src.count("request.get_json(silent=True)") >= 18


# ── 없는 스위치 collect → 404 (이전 202) ──
def test_collect_nonexistent_switch_404(demo_client):
    r = demo_client.post("/api/switches/999999/collect",
                         json={"username": "a", "password": "b"})
    assert r.status_code == 404


# ── 주요 라우트 200 (런타임 스키마) ──
def test_core_routes_ok(demo_client):
    for p, keys in [
        ("/api/state", ("switches", "snapshots")),
        ("/api/switches", ("switches",)),
        ("/api/firewalls", ("firewalls",)),
        ("/api/vlans", ("vlans",)),
        ("/api/topology", ("nodes", "links")),
        ("/api/reconcile", ("hosts", "summary")),
        ("/api/alerts", ("events", "unacked")),
    ]:
        r = demo_client.get(p)
        assert r.status_code == 200, p
        data = r.get_json()
        for k in keys:
            assert k in data, "%s missing %s" % (p, k)


# ── 없는 스위치 detail → 404 ──
def test_detail_nonexistent_404(demo_client):
    assert demo_client.get("/api/switches/999999/detail").status_code == 404


# ── cred_blob 마이그레이션(레거시 DB diagnose 500 방지) ──
def test_switches_cred_blob_migration():
    import tempfile, os, sqlite3
    from core import db
    d = tempfile.mkdtemp()
    p = os.path.join(d, "legacy.db")
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE switches (id INTEGER PRIMARY KEY, name TEXT, ip TEXT, vendor TEXT)")
    conn.commit(); conn.close()
    db.init_schema(p)
    conn = sqlite3.connect(p)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(switches)").fetchall()]
    conn.close()
    assert "cred_blob" in cols
    sid = db.save_switch(p, "SW1", "10.0.0.1", "cisco_ios")
    assert db.get_switch_credential(p, sid) is None  # 500 없이 None


# ── 스냅샷 세대 정리(무한 누적 방지) ──
def test_snapshot_generation_cap():
    import tempfile, os, sqlite3
    from core import db
    d = tempfile.mkdtemp(); p = os.path.join(d, "t.db")
    db.init_schema(p)
    sid = db.save_switch(p, "SW1", "10.0.0.1", "cisco_ios")
    for _ in range(db._SNAPSHOT_KEEP + 15):
        db.save_snapshot(p, sid, {"ports": [{"name": "Gi1/0/1", "status": "up", "vlan": 1}]})
    conn = sqlite3.connect(p)
    n = conn.execute("SELECT COUNT(*) FROM snapshots WHERE switch_id=?", (sid,)).fetchone()[0]
    latest = db.latest_snapshot_id(p, sid)
    np = conn.execute("SELECT COUNT(*) FROM ports WHERE snapshot_id=?", (latest,)).fetchone()[0]
    conn.close()
    assert n == db._SNAPSHOT_KEEP        # 초과분 정리
    assert np == 1                        # 최신 스냅샷 데이터 온전


# ── 파서 방어 ──
def test_ios_status_name_column_down_token():
    from core.parsers import cisco_ios
    st = "Gi1/0/3   link down bkp      connected    300       a-full  1000\n"
    r = cisco_ios._parse_ports(st, {}, 1)
    assert r[0]["status"] == "up" and r[0]["vlan"] == 300


def test_arista_lldp_bullet_port_id():
    from core.parsers import neighbors
    ar = ('Interface Ethernet1 detected 1 LLDP neighbors:\n'
          '  - Port ID     : "Ethernet1"\n  - System Name: "peer"\n')
    nb = neighbors.parse_lldp_detail(ar)
    assert nb and nb[0]["remote_port"] == "Ethernet1"


def test_normalize_mac_rejects_nonhex():
    from core.parsers import utils
    assert utils.normalize_mac("ZZZZ.ZZZZ.ZZZZ") is None
    assert utils.normalize_mac("0050.56a1.b2c3") == "00:50:56:a1:b2:c3"
