"""포트 CRC/errors 파싱 (show interfaces) 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import cisco_ios

SH_INTERFACES = """\
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aabb.cc00.0101
  MTU 1500 bytes, BW 1000000 Kbit/sec
     5 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored
     3 output errors, 0 collisions, 1 interface resets
GigabitEthernet1/0/2 is down, line protocol is down (notconnect)
  Hardware is Gigabit Ethernet
     0 input errors, 0 CRC, 0 frame
     0 output errors, 0 collisions
"""

SH_STATUS = """\
Port      Name      Status       Vlan    Duplex  Speed Type
Gi1/0/1   SVR       connected    100     a-full a-1000 10/100/1000BaseTX
Gi1/0/2             notconnect   1         auto   auto 10/100/1000BaseTX
"""


def test_parse_interface_errors():
    e = cisco_ios.parse_interface_errors(SH_INTERFACES)
    # 키는 약어로 통일됨(GigabitEthernet1/0/1 → Gi1/0/1)
    g1 = e.get("Gi1/0/1")
    assert g1["in_errors"] == 5
    assert g1["crc"] == 2
    assert g1["out_errors"] == 3


def test_ports_merge_errors():
    r = cisco_ios.parse({"status": SH_STATUS, "errors": SH_INTERFACES, "description": "", "mac": "", "arp": ""}, 1)
    g1 = next(p for p in r["ports"] if p["name"].endswith("1/0/1"))
    assert g1["crc_errors"] == 2
    assert g1["in_errors"] == 5
    assert g1["out_errors"] == 3
    g2 = next(p for p in r["ports"] if p["name"].endswith("1/0/2"))
    assert g2["crc_errors"] == 0


def test_db_saves_port_errors(temp_db):
    from core import db
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    snap = db.save_snapshot(temp_db, sid)
    db.save_ports(temp_db, snap, sid, [
        {"name": "Gi1/0/1", "status": "up", "vlan": 100, "speed": "a-1000",
         "description": "", "crc_errors": 2, "in_errors": 5, "out_errors": 3}])
    ports = db.get_ports_by_switch(temp_db, sid)
    assert ports[0]["crc_errors"] == 2
    assert ports[0]["in_errors"] == 5


def test_appjs_port_errors_column():
    src = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "crc_errors" in src
    assert "In/Out" in src
