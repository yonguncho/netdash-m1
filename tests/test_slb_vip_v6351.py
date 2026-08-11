# -*- coding: utf-8 -*-
"""v6.35.1 — L4 SLB VIP를 설비 수집에서 제외(사용자 신고).

설비 대역을 스캔하면 L4의 SLB VIP가 ping에 응답해 설비로 잡히고, 포트에 물린
실체가 없으니 '연결 안 됨'으로 목록을 오염시켰다. VIP는 이미 수집된 L4 config
(/cfg/dump 등)에 정의가 있으므로 그걸 근거로 저장·재매칭 시점에 걸러낸다.
"""
from core import db

_ALTEON_CFG = """/c/sys
        hprompt ena
/c/slb/virt 1
        ena
        vip 10.92.140.88
/c/slb/virt 2
        ena
        vip 10.92.140.89
/c/slb/real 1
        rip 10.92.140.10
"""

_OTHER_CFG = """hostname L4-B
virtual-ip 10.92.141.50
interface vlan10
 description link to 10.92.141.99
virtual ip address 10.92.141.51
"""


def _sw(p, name="L4-01", ip="10.92.140.5"):
    return db.save_switch(p, name, ip, "alteon")


def test_slb_vip_ips_from_configs(temp_db):
    sid = _sw(temp_db)
    db.save_config_backup(temp_db, sid, _ALTEON_CFG)
    sid2 = _sw(temp_db, "L4-02", "10.92.141.5")
    db.save_config_backup(temp_db, sid2, _OTHER_CFG)
    db._vip_cache.clear()
    vips = db.slb_vip_ips(temp_db)
    assert vips == {"10.92.140.88", "10.92.140.89", "10.92.141.50", "10.92.141.51"}
    # real 서버(rip)·설명문 속 IP는 VIP가 아니다 — 오제외 금지
    assert "10.92.140.10" not in vips and "10.92.141.99" not in vips


def test_save_facility_drops_vips(temp_db):
    sid = _sw(temp_db)
    db.save_config_backup(temp_db, sid, _ALTEON_CFG)
    db._vip_cache.clear()
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.88", "mac": "",
         "online": 1, "direct": 0},                       # VIP — 저장 금지
        {"subnet": "10.92.140.0/24", "ip": "10.92.140.20", "mac": "aa:20",
         "online": 1, "direct": 1, "switch_name": "SW", "port": "Gi1/0/2"}])
    ips = {h["ip"] for h in db.get_facility_hosts(temp_db)}
    assert ips == {"10.92.140.20"}, "VIP가 설비로 저장되면 안 된다"


def test_purge_removes_existing_vip_rows(temp_db):
    """예전에 수집돼 남아 있던 VIP 행도 재매칭 때 청소된다."""
    with db.get_db(temp_db) as conn:
        conn.execute("INSERT INTO facility_hosts (subnet, ip, online, direct) "
                     "VALUES ('10.92.140.0/24','10.92.140.88',0,0)")
        conn.execute("INSERT INTO facility_hosts (subnet, ip, online, direct) "
                     "VALUES ('10.92.140.0/24','10.92.140.21',1,1)")
    sid = _sw(temp_db)
    db.save_config_backup(temp_db, sid, _ALTEON_CFG)
    db._vip_cache.clear()
    assert db.purge_registered_devices_from_facility(temp_db) == 1
    ips = {h["ip"] for h in db.get_facility_hosts(temp_db)}
    assert ips == {"10.92.140.21"}


def test_no_configs_no_exclusion(temp_db):
    """config가 없으면 VIP 제외는 조용히 무동작 — 설비 저장을 막지 않는다."""
    db._vip_cache.clear()
    assert db.slb_vip_ips(temp_db) == frozenset()
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.1.0.0/24", "ip": "10.1.0.5", "mac": "aa:05",
         "online": 1, "direct": 1}])
    assert {h["ip"] for h in db.get_facility_hosts(temp_db)} == {"10.1.0.5"}
