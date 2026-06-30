# -*- coding: utf-8 -*-
"""설비 현황 수집 — 11번 TPS 스위치가 대역 전체에 ping → ARP 학습 → MAC 대조.

흐름:
  1) 지정한 게이트웨이 스위치(각 대역 11번, 보통 L2)에 SSH
  2) 대역(subnet) 전체에 ping(스위치가 직접) → 스위치 ARP 테이블 채움
  3) show ip arp 수집 → IP/MAC
  4) 등록된 모든 스위치의 최신 MAC 테이블과 대조 → 어느 스위치 어느 포트인지
  5) facility_hosts에 저장

성능: ping은 1개씩이라 /23(≈510개)은 수~십 분. 백그라운드 + 진행률로 처리한다.
"""
import ipaddress
import threading

from . import db, utils
from . import collector as _collector

# 진행 상태(메모리). {"running","subnet","done","total","message"}
_status = {"running": False, "subnet": None, "done": 0, "total": 0, "message": ""}
_lock = threading.Lock()


def get_status():
    with _lock:
        return dict(_status)


def _set(**kw):
    with _lock:
        _status.update(kw)


def collect_band(db_path, switch_id, subnet, username, password, source_ip=None):
    """동기 수집(백그라운드 스레드에서 호출). 진행 상태는 _status로 갱신."""
    from netmiko import ConnectHandler
    from . import netbind
    from .parsers import cisco_ios

    sw = db.get_switch(db_path, switch_id)
    if not sw:
        raise ValueError("switch not found")
    net = ipaddress.IPv4Network(subnet, strict=False)
    ips = [str(h) for h in net.hosts()]
    _set(running=True, subnet=subnet, done=0, total=len(ips), message="연결 중")

    device = {
        "device_type": _collector._norm_vendor(sw.get("vendor")),
        "ip": sw["ip"], "username": username, "password": password,
        "secret": password, "conn_timeout": 30, "fast_cli": False,
    }
    if source_ip:
        device["sock"] = netbind.bind_socket(sw["ip"], 22, source_ip, 30)

    arp_out = ""
    with ConnectHandler(**device) as conn:
        try:
            if hasattr(conn, "check_enable_mode") and not conn.check_enable_mode():
                conn.enable()
        except Exception:
            pass
        try:
            conn.send_command("terminal length 0", read_timeout=10)
        except Exception:
            pass
        _set(message="대역 ping 중")
        for i, ip in enumerate(ips):
            try:
                conn.send_command("ping %s repeat 1 timeout 1" % ip, read_timeout=5)
            except Exception:
                pass
            if i % 20 == 0:
                _set(done=i)
        _set(done=len(ips), message="ARP 수집 중")
        arp_out = conn.send_command("show ip arp", read_timeout=60)

    arp = cisco_ios._parse_arps(arp_out, switch_id)  # [{ip, mac, interface}]
    mac_map = db.get_mac_to_switchport(db_path)       # {mac: [(sid, sname, port)]}

    hosts = []
    for a in arp:
        mac = (a.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        if matches:
            for (sid, sname, port) in matches:
                hosts.append({"subnet": subnet, "ip": a["ip"], "mac": a["mac"],
                              "switch_id": sid, "switch_name": sname, "port": port, "online": 1})
        else:
            # ARP엔 있으나 어느 스위치 포트인지 미상(해당 스위치 MAC 미수집 등)
            hosts.append({"subnet": subnet, "ip": a["ip"], "mac": a["mac"],
                          "switch_id": None, "switch_name": None, "port": None, "online": 1})

    db.save_facility_hosts(db_path, hosts)
    utils.log_event("info", "facility_collected", subnet=subnet,
                    pinged=len(ips), arp=len(arp), saved=len(hosts))
    _set(running=False, message="완료(%d개 설비)" % len(hosts))
    return {"subnet": subnet, "pinged": len(ips), "arp": len(arp), "saved": len(hosts)}


def start_collect_band(db_path, switch_id, subnet, username, password, source_ip=None):
    """백그라운드 스레드로 대역 수집 시작. 이미 실행 중이면 거부."""
    with _lock:
        if _status["running"]:
            return False
    def _run():
        try:
            collect_band(db_path, switch_id, subnet, username, password, source_ip)
        except Exception as e:
            _set(running=False, message="실패: " + _collector._sanitize_error_msg(str(e)))
            utils.log_event("error", "facility_collect_error",
                            error=_collector._sanitize_error_msg(str(e)))
    threading.Thread(target=_run, daemon=True).start()
    return True
