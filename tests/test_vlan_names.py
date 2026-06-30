"""VLAN 이름(show vlan brief) 파싱 + 저장 + 요약 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from core.parsers import cisco_ios

SH_VLAN_BRIEF = """
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/4, Gi1/0/5
100  SERVER_FARM                      active    Gi1/0/1
200  DMZ                              active    Gi1/0/2
999  MGMT                             act/lshut
"""


def test_parse_vlans():
    vlans = cisco_ios.parse_vlans(SH_VLAN_BRIEF, 1)
    by = {v["vlan"]: v for v in vlans}
    assert by[1]["name"] == "default"
    assert by[100]["name"] == "SERVER_FARM"
    assert by[200]["name"] == "DMZ"
    assert by[999]["name"] == "MGMT"
    assert by[100]["status"] == "active"


def test_save_and_summary_with_name(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    vlans = cisco_ios.parse_vlans(SH_VLAN_BRIEF, sid)
    db.save_vlan_names(temp_db, sid, vlans)
    summary = db.get_vlan_summary(temp_db)
    names = {r["vlan"]: r.get("vlan_name") for r in summary}
    assert names.get(100) == "SERVER_FARM"
    assert names.get(200) == "DMZ"


def test_save_vlan_names_replaces(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.save_vlan_names(temp_db, sid, [{"vlan": 10, "name": "OLD", "status": "active"}])
    db.save_vlan_names(temp_db, sid, [{"vlan": 10, "name": "NEW", "status": "active"}])
    summary = db.get_vlan_summary(temp_db)
    rows = [r for r in summary if r["vlan"] == 10]
    assert len(rows) == 1 and rows[0]["vlan_name"] == "NEW"


def test_appjs_vlan_name_column():
    src = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "vlan_name" in src
