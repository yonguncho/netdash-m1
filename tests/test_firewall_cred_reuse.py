"""방화벽 자격증명 재사용(매번 토큰 입력 방지) 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db

APP_JS = Path(__file__).parent.parent / "web" / "static" / "app.js"


def test_list_firewalls_has_credential_flag(temp_db):
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.1", 443)
    f = next(x for x in db.list_firewalls(temp_db) if x["id"] == fid)
    assert f["has_credential"] is False
    assert "cred_blob" not in f  # blob 자체는 절대 노출 안 함

    db.save_firewall_credential(temp_db, fid, b"encrypted-blob")
    f = next(x for x in db.list_firewalls(temp_db) if x["id"] == fid)
    assert f["has_credential"] is True
    assert "cred_blob" not in f  # 여전히 노출 안 함


def test_appjs_collect_direct_reuse():
    src = APP_JS.read_text(encoding="utf-8")
    assert "collectFirewallDirect" in src
    assert "has_credential" in src
