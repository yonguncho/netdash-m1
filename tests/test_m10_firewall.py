"""M10 1단계: 방화벽 코어 (파서 + DB + 디스패치) 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db
from core.firewall import fortigate, paloalto
import core.firewall as fw


# ── Palo Alto 파서 ─────────────────────────────────────────────────
PA_ARP = """address          hw address        port             status   ttl
192.168.1.1      00:11:22:33:44:55 ethernet1/1      c        1750
192.168.1.2      aa:bb:cc:dd:ee:ff ethernet1/2      c        1200
10.0.0.9         00:00:00:00:00:00 ethernet1/3      i        10
"""

PA_INTERFACES = """name                 id    speed/duplex/state   mac-address
-------------------- ----- -------------------- -----------------
ethernet1/1          16    1000/full/up         00:11:22:33:44:55
ethernet1/2          17    unknown/unknown/down aa:bb:cc:dd:ee:ff
management           1     1000/full/up         ff:ee:dd:cc:bb:aa
"""


def test_paloalto_parse_arp():
    arp = paloalto.parse_arp(PA_ARP)
    ips = {a["ip"] for a in arp}
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips
    # all-zero MAC은 제외
    assert "10.0.0.9" not in ips
    e = [a for a in arp if a["ip"] == "192.168.1.1"][0]
    assert e["mac"] == "00:11:22:33:44:55"
    assert e["interface"] == "ethernet1/1"


def test_paloalto_parse_interfaces():
    ifaces = paloalto.parse_interfaces(PA_INTERFACES)
    names = {i["name"] for i in ifaces}
    assert {"ethernet1/1", "ethernet1/2", "management"} <= names


def test_paloalto_parse_empty():
    assert paloalto.parse_arp("") == []
    assert paloalto.parse_interfaces("") == []


# ── FortiGate CLI 파서 ─────────────────────────────────────────────
FG_ARP_CLI = """Address          Age(min)   Hardware Addr      Interface
10.0.0.100       0          00:50:56:a1:b2:c3  port3
10.0.0.101       5          00:50:56:a1:b2:c4  port2
10.0.0.102       1          00:00:00:00:00:00  port2
"""


def test_fortigate_parse_arp_cli():
    arp = fortigate.parse_arp_cli(FG_ARP_CLI)
    ips = {a["ip"] for a in arp}
    assert "10.0.0.100" in ips
    assert "10.0.0.101" in ips
    assert "10.0.0.102" not in ips  # all-zero MAC 제외
    e = [a for a in arp if a["ip"] == "10.0.0.100"][0]
    assert e["mac"] == "00:50:56:A1:B2:C3"
    assert e["interface"] == "port3"


# ── DB CRUD ────────────────────────────────────────────────────────
def test_save_and_list_firewall(temp_db):
    fid = db.save_firewall(temp_db, "FW-01", "fortigate", "10.0.0.1", 443, "token")
    fws = db.list_firewalls(temp_db)
    assert len(fws) == 1
    assert fws[0]["name"] == "FW-01"
    assert fws[0]["vendor"] == "fortigate"
    got = db.get_firewall(temp_db, fid)
    assert got["host"] == "10.0.0.1"


def test_save_firewall_upsert_by_host(temp_db):
    fid1 = db.save_firewall(temp_db, "FW-01", "fortigate", "10.0.0.1")
    fid2 = db.save_firewall(temp_db, "FW-01-renamed", "paloalto", "10.0.0.1", 22, "password")
    assert fid1 == fid2  # 동일 host → upsert
    fws = db.list_firewalls(temp_db)
    assert len(fws) == 1
    assert fws[0]["vendor"] == "paloalto"


def test_firewall_status(temp_db):
    fid = db.save_firewall(temp_db, "FW", "paloalto", "10.0.0.2", 22)
    db.set_firewall_status(temp_db, fid, "done")
    assert db.get_firewall(temp_db, fid)["status"] == "done"


def test_save_and_get_interfaces_arp(temp_db):
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.3")
    db.save_firewall_interfaces(temp_db, fid, [
        {"name": "port1", "ip": "10.1.0.1", "mask": "255.255.255.0", "vdom_zone": "root"},
        {"name": "port2", "ip": "10.2.0.1", "mask": "255.255.255.0", "vdom_zone": "root"},
    ])
    db.save_firewall_arp(temp_db, fid, [
        {"ip": "10.1.0.50", "mac": "AA:BB:CC:DD:EE:01", "interface": "port1"},
    ])
    ifaces = db.get_firewall_interfaces(temp_db, fid)
    assert len(ifaces) == 2
    assert ifaces[0]["ip"] == "10.1.0.1"
    arp = db.get_firewall_arp(temp_db, fid)
    assert len(arp) == 1
    assert arp[0]["mac"] == "AA:BB:CC:DD:EE:01"


def test_save_interfaces_replaces(temp_db):
    fid = db.save_firewall(temp_db, "FW", "fortigate", "10.0.0.4")
    db.save_firewall_interfaces(temp_db, fid, [{"name": "port1", "ip": "1.1.1.1"}])
    db.save_firewall_interfaces(temp_db, fid, [{"name": "port2", "ip": "2.2.2.2"}])
    ifaces = db.get_firewall_interfaces(temp_db, fid)
    assert len(ifaces) == 1  # 교체됨
    assert ifaces[0]["name"] == "port2"


# ── 디스패치 (네트워크 mock) ───────────────────────────────────────
def test_collect_firewall_fortigate(monkeypatch):
    monkeypatch.setattr(fortigate, "get_interfaces",
                        lambda *a, **k: [{"name": "port1", "ip": "10.0.0.1", "mask": "", "vdom_zone": "root"}])
    monkeypatch.setattr(fortigate, "get_arp_table",
                        lambda *a, **k: [{"ip": "10.0.0.50", "mac": "AA:BB", "interface": "port1"}])
    result = fw.collect_firewall("fortigate", "10.0.0.1", token="tok")
    assert len(result["interfaces"]) == 1
    assert len(result["arp"]) == 1


def test_collect_firewall_paloalto(monkeypatch):
    monkeypatch.setattr(paloalto, "collect",
                        lambda *a, **k: {"interfaces": [{"name": "ethernet1/1"}], "arp": []})
    result = fw.collect_firewall("paloalto", "10.0.0.2", username="admin", password="pw")
    assert result["interfaces"][0]["name"] == "ethernet1/1"


def test_collect_firewall_paloalto_requires_creds():
    with pytest.raises(ValueError, match="username/password"):
        fw.collect_firewall("paloalto", "10.0.0.2")


def test_collect_firewall_unsupported_vendor():
    with pytest.raises(ValueError, match="지원하지 않는"):
        fw.collect_firewall("checkpoint", "10.0.0.3")
