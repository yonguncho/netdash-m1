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
import re
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


# 논리(가상) 인터페이스 접두어 — 이 포트의 MAC은 업링크/트렁크를 경유한 것이라
# 설비가 "직접" 붙은 곳이 아니다. (Po=포트채널, Vl=VLAN/SVI, Lo=루프백, Tu=터널, ae=Juniper 본딩)
_LOGICAL_PREFIXES = ("po", "port-channel", "vl", "vlan", "lo", "loopback",
                     "tu", "tunnel", "ae", "bundle", "irb")
# 물리 액세스 포트로 인정할 MAC 수 상한. 이보다 많으면 트렁크/업링크로 간주(직접연결 불확실).
_EDGE_MAC_MAX = 4


def _is_physical_port(port):
    """Gi/Te/Fa/Eth 등 물리 포트면 True, Po/Vl 등 논리 포트면 False."""
    p = (port or "").strip().lower()
    if not p:
        return False
    return not p.startswith(_LOGICAL_PREFIXES)


def _choose_attachment(matches, port_counts):
    """여러 스위치 MAC 테이블 매치 중 설비가 '직접' 붙은 스위치/포트를 선택.

    matches: [(switch_id, switch_name, port), ...]
    port_counts: {(switch_id, port소문자): 해당 포트 MAC 수}
    반환: (switch_id, switch_name, port, direct(bool), via(list[str]))
      - direct=True : 물리 액세스 포트(소수 MAC)에서 관측 → 직접 연결로 확신
      - direct=False: 논리 포트(Po/Vl)뿐이거나 트렁크(다수 MAC)만 → 업링크 경유, 직접연결 불확실
      - via: 선택된 곳을 제외한 나머지 관측 위치("SW:port") 목록(진단용)
    """
    if not matches:
        return None, None, None, False, []

    def _cnt(m):
        return port_counts.get((m[0], (m[2] or "").lower()), 9999)

    physical = sorted([m for m in matches if _is_physical_port(m[2])], key=_cnt)
    if physical:
        best = physical[0]           # MAC 수가 가장 적은 물리 포트 = 액세스(엣지) 포트
        best_cnt = _cnt(best)
        if len(physical) == 1:
            # 물리 포트로 관측된 '유일한' 위치 → 그 스위치에 직접 연결.
            # (백본/서버처럼 포트가 MAC을 많이 학습해도, 다른 스위치는 Po/Vl 업링크로만
            #  보이므로 물리 관측이 하나뿐이면 그곳이 직접 연결 지점이다 — 임계값 무관)
            direct = True
        elif best_cnt <= _EDGE_MAC_MAX:
            direct = True            # 명확한 액세스 포트(소수 MAC)
        else:
            # 여러 물리 포트 모두 MAC 많음 → 최소가 나머지보다 뚜렷이 적으면 엣지로 확신
            direct = best_cnt * 2 <= _cnt(physical[1])
    else:
        # 물리 포트 관측이 없음 → 업링크(Po/Vl) 경유로만 보임 → 직접연결 미확인
        best = matches[0]
        direct = False

    via = ["%s:%s" % (m[1], m[2]) for m in matches if m is not best]
    return best[0], best[1], best[2], direct, via


def _parse_connected_subnets(route_out, iface_out):
    """show ip route connected / show interface 출력에서 directly-connected 대역 추출.

    Returns: ["10.92.174.0/23", ...] (중복 제거, /22 이하만)
    """
    found = []
    # show ip route: "C  10.92.174.0/23 is directly connected, Vlan100"
    for line in (route_out or "").splitlines():
        m = re.search(r"([\d.]+/\d{1,2})\s+is\s+directly\s+connected", line)
        if m:
            found.append(m.group(1))
    # show interface: "Internet address is 10.92.174.11/23"
    for line in (iface_out or "").splitlines():
        m = re.search(r"Internet address is\s+([\d.]+)/(\d{1,2})", line)
        if m:
            try:
                net = ipaddress.IPv4Network("%s/%s" % (m.group(1), m.group(2)), strict=False)
                found.append(str(net))
            except (ipaddress.AddressValueError, ValueError):
                pass
    # 정규화 + 중복 제거 + 크기 제한(/22 이하 = num_addresses<=1024)
    out, seen = [], set()
    for s in found:
        try:
            net = ipaddress.IPv4Network(s, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            continue
        key = str(net)
        if key in seen or net.num_addresses > 1024 or net.num_addresses < 4:
            continue
        if net.is_loopback or net.is_link_local:
            continue
        seen.add(key)
        out.append(key)
    return out


def detect_subnets(db_path, switch_id, username, password, source_ip=None):
    """11번 스위치에 접속해 directly-connected 대역을 자동 도출."""
    from netmiko import ConnectHandler
    from . import netbind
    sw = db.get_switch(db_path, switch_id)
    if not sw:
        raise ValueError("switch not found")
    device = {
        "device_type": _collector._norm_vendor(sw.get("vendor")),
        "ip": sw["ip"], "username": username, "password": password,
        "secret": password, "conn_timeout": 30, "fast_cli": False,
    }
    if source_ip:
        device["sock"] = netbind.bind_socket(sw["ip"], 22, source_ip, 30)
    route_out, iface_out = "", ""
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
        try:
            route_out = conn.send_command("show ip route connected", read_timeout=30)
        except Exception:
            pass
        try:
            iface_out = conn.send_command("show ip interface", read_timeout=30)
        except Exception:
            pass
    return _parse_connected_subnets(route_out, iface_out)


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
    port_counts = db.get_port_mac_counts(db_path)     # {(sid, port_lower): MAC수}

    # IP별 1행: 같은 MAC이 여러 스위치/포트에 보일 때 "직접 연결된 스위치"를 가려낸다.
    #  - Po(포트채널)·Vl(VLAN/SVI) 등 논리 인터페이스는 업링크 경유 → 직접 연결 아님
    #  - 물리 포트 중 MAC 수가 가장 적은 포트 = 액세스(엣지) 포트 → 직접 연결
    by_ip = {}
    for a in arp:
        mac = (a.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        sid, sname, port, direct, via = _choose_attachment(matches, port_counts)
        by_ip[a["ip"]] = {"subnet": subnet, "ip": a["ip"], "mac": a["mac"],
                          "switch_id": sid, "switch_name": sname, "port": port,
                          "online": 1, "direct": 1 if direct else 0,
                          "via": "; ".join(via) if via else None}

    saved_hosts = list(by_ip.values())
    db.clear_facility_subnet(db_path, subnet)  # 재수집 시 기존 대역 결과 비우기
    db.save_facility_hosts(db_path, saved_hosts)
    utils.log_event("info", "facility_collected", subnet=subnet,
                    pinged=len(ips), arp=len(arp), saved=len(saved_hosts))
    _set(running=False, message="완료(%d개 설비)" % len(saved_hosts))
    return {"subnet": subnet, "pinged": len(ips), "arp": len(arp), "saved": len(saved_hosts)}


_EXPORT_COLS = ["대역", "IP", "MAC", "연결 스위치", "포트", "직접연결", "그 외 관측", "상태"]


def _export_rows(db_path):
    """설비 현황을 추출용 행 목록(dict)으로 변환."""
    rows = []
    for h in db.get_facility_hosts(db_path):
        direct = h.get("direct", 1) and h.get("switch_name")
        rows.append({
            "대역": h.get("subnet") or "",
            "IP": h.get("ip") or "",
            "MAC": h.get("mac") or "",
            "연결 스위치": (h.get("switch_name") or "") if direct else "직접 연결 미확인",
            "포트": (h.get("port") or "") if direct else "",
            "직접연결": "직접" if direct else "미확인",
            "그 외 관측": h.get("via") or "",
            "상태": "온라인" if h.get("online") else "오프라인",
        })
    return rows


def export_xlsx(db_path):
    """설비 현황 전체를 엑셀(xlsx) 바이트로 반환."""
    from io import BytesIO
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "설비 현황"
    ws.append(_EXPORT_COLS)
    for r in _export_rows(db_path):
        ws.append([r[c] for c in _EXPORT_COLS])
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def export_txt(db_path):
    """설비 현황 전체를 탭 구분 TXT 바이트로 반환(UTF-8 BOM — 엑셀 한글 정상)."""
    lines = ["\t".join(_EXPORT_COLS)]
    for r in _export_rows(db_path):
        lines.append("\t".join(
            str(r[c]).replace("\t", " ").replace("\n", " ") for c in _EXPORT_COLS))
    return ("﻿" + "\r\n".join(lines)).encode("utf-8")


def rematch(db_path):
    """기존 설비(facility_hosts)의 MAC을 '최신' MAC 스냅샷 기준으로 재대조.

    ping/ARP 재수집 없이(빠름) 연결 스위치·포트·직접여부만 최신화한다.
    TPS 스위치를 다시 일반 수집한 뒤 설비 현황 '새로고침'에 사용.
    반환: 갱신된 설비 개수.
    """
    hosts = db.get_facility_hosts(db_path)
    if not hosts:
        return 0
    mac_map = db.get_mac_to_switchport(db_path)
    port_counts = db.get_port_mac_counts(db_path)
    updated = []
    for h in hosts:
        mac = (h.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        sid, sname, port, direct, via = _choose_attachment(matches, port_counts)
        updated.append({
            "subnet": h.get("subnet"), "ip": h.get("ip"), "mac": h.get("mac"),
            "switch_id": sid, "switch_name": sname, "port": port,
            "online": h.get("online", 1), "direct": 1 if direct else 0,
            "via": "; ".join(via) if via else None})
    db.save_facility_hosts(db_path, updated)  # subnet+ip UNIQUE → 제자리 갱신
    utils.log_event("info", "facility_rematched", count=len(updated))
    return len(updated)


def start_collect_band(db_path, switch_id, subnet, username, password, source_ip=None):
    """백그라운드 스레드로 대역 수집 시작. 이미 실행 중이면 거부.

    TOCTOU 방지: running 플래그를 같은 lock 구간에서 즉시 True로 set한다.
    """
    with _lock:
        if _status["running"]:
            return False
        _status["running"] = True
        _status["message"] = "시작 중"
    def _run():
        try:
            collect_band(db_path, switch_id, subnet, username, password, source_ip)
        except Exception as e:
            _set(running=False, message="실패: " + _collector._sanitize_error_msg(str(e)))
            utils.log_event("error", "facility_collect_error",
                            error=_collector._sanitize_error_msg(str(e)))
    threading.Thread(target=_run, daemon=True).start()
    return True
