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


def test_save_firewall_upsert_by_name_host(temp_db):
    # 같은 name+host → upsert(1개)
    fid1 = db.save_firewall(temp_db, "FW-01", "fortigate", "10.0.0.1")
    fid2 = db.save_firewall(temp_db, "FW-01", "paloalto", "10.0.0.1", 22, "password")
    assert fid1 == fid2
    fws = db.list_firewalls(temp_db)
    assert len(fws) == 1
    assert fws[0]["vendor"] == "paloalto"


def test_save_firewall_ha_same_vip_diff_name(temp_db):
    """HA/VRRP: 같은 VIP라도 hostname이 다르면 Active/Backup 각각 등록."""
    a = db.save_firewall(temp_db, "FW_ACTIVE", "fortigate", "10.92.1.1", 443)
    b = db.save_firewall(temp_db, "FW_BACKUP", "fortigate", "10.92.1.1", 443)
    assert a != b
    fws = db.list_firewalls(temp_db)
    assert len(fws) == 2
    assert {f["name"] for f in fws} == {"FW_ACTIVE", "FW_BACKUP"}
    assert all(f["host"] == "10.92.1.1" for f in fws)
    # HA 쌍 각각에 인터페이스 저장 → FK 정상(FOREIGN KEY constraint 회귀 방지)
    db.save_firewall_interfaces(temp_db, a, [{"name": "port1", "ip": "10.92.1.1"}])
    db.save_firewall_interfaces(temp_db, b, [{"name": "port1", "ip": "10.92.1.1"}])


def test_firewalls_unique_migration_preserves_fk(tmp_path):
    """구버전(host UNIQUE) DB 마이그레이션 후 FK가 firewalls를 참조하고 인터페이스 저장 가능."""
    import sqlite3
    p = str(tmp_path / "old.db")
    c = sqlite3.connect(p)
    c.execute("""CREATE TABLE firewalls (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                 vendor TEXT NOT NULL, host TEXT NOT NULL UNIQUE, port INTEGER, auth_type TEXT DEFAULT 'token',
                 status TEXT DEFAULT 'new', last_collected TIMESTAMP,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, cred_blob TEXT, location TEXT)""")
    c.execute("""CREATE TABLE firewall_interfaces (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 firewall_id INTEGER NOT NULL, name TEXT, ip TEXT, mask TEXT, vdom_zone TEXT,
                 FOREIGN KEY (firewall_id) REFERENCES firewalls(id))""")
    c.execute("INSERT INTO firewalls (name,vendor,host,port) VALUES ('FW_BACKUP','fortigate','10.92.1.1',443)")
    c.commit(); c.close()
    db.init_schema(p)
    c = sqlite3.connect(p)
    assert not c.execute("SELECT name FROM sqlite_master WHERE name='firewalls_old'").fetchone()
    assert not c.execute("SELECT name FROM sqlite_master WHERE sql LIKE '%firewalls_old%'").fetchall()
    assert c.execute("PRAGMA foreign_key_check").fetchall() == []
    c.close()
    # ACTIVE 등록 + 인터페이스 저장(사용자가 겪은 FOREIGN KEY constraint 시나리오)
    a = db.save_firewall(p, "FW_ACTIVE", "fortigate", "10.92.1.1", 443)
    db.save_firewall_interfaces(p, a, [{"name": "port1", "ip": "10.92.1.1"}])
    assert len(db.list_firewalls(p)) == 2


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
    # v3.38.1: 디스패처가 세션 1개 재사용하는 fortigate.collect 사용(429 방지)
    monkeypatch.setattr(fortigate, "collect",
                        lambda *a, **k: {"interfaces": [{"name": "port1", "ip": "10.0.0.1",
                                                         "mask": "", "vdom_zone": "root"}],
                                         "arp": [{"ip": "10.0.0.50", "mac": "AA:BB",
                                                  "interface": "port1"}]})
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
