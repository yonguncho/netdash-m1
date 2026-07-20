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

# 청크 스윕 파라미터: ping N개마다 ARP 중간 수집(부분 결과 확보) + ping 간격(부담 완화)
_SWEEP_CHUNK = 32
_SWEEP_PING_GAP = 0.05   # 초 — /23(510개) 기준 총 +26초, 제어평면 여유 확보

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


def _choose_attachment(matches, port_counts, pc_map=None):
    """여러 스위치 MAC 테이블 매치 중 설비가 '직접' 붙은 스위치/포트를 선택.

    matches: [(switch_id, switch_name, port), ...]
    port_counts: {(switch_id, port소문자): 해당 포트 MAC 수}
    pc_map: {(switch_id, po소문자): [member_port, ...]}  # NX-OS 포트채널 → 물리 멤버
    반환: (switch_id, switch_name, port, direct(bool), via(list[str]))
      - 물리 액세스 포트(소수 MAC) → 직접
      - 포트채널(Po)이 멤버로 해석되면 실제 물리 멤버포트로 표시하고 직접으로 승격
        (TPS가 백본에 Po로 직결된 경우: Po10 → "Eth1/1, Eth1/2 (Po10)")
      - 해석 불가 논리포트뿐이면 미확인
    """
    if not matches:
        return None, None, None, False, []
    pc_map = pc_map or {}

    def _cnt(sid, port):
        return port_counts.get((sid, (port or "").lower()), 9999)

    physical, pchan, logical = [], [], []
    for orig in matches:                       # orig = (sid, name, port)
        sid, name, port = orig
        if _is_physical_port(port):
            physical.append(orig)
        else:
            members = pc_map.get((sid, (port or "").lower()))
            if members:                        # 포트채널 → 물리 멤버로 해석(직결 승격)
                disp = "%s (%s)" % (", ".join(members), port)
                pchan.append((orig, disp))
            else:
                logical.append(orig)

    physical.sort(key=lambda m: _cnt(m[0], m[2]))
    if physical:
        best = physical[0]                     # MAC 수가 가장 적은 물리 포트 = 액세스 포트
        disp_port = best[2]
        best_cnt = _cnt(best[0], best[2])
        if len(physical) == 1:
            direct = True                      # 물리 관측이 유일 → 그곳이 직접 연결
        elif best_cnt <= _EDGE_MAC_MAX:
            direct = True                      # 명확한 액세스 포트(소수 MAC)
        else:
            direct = best_cnt * 2 <= _cnt(physical[1][0], physical[1][2])
        chosen = best
    elif pchan:
        chosen, disp_port = pchan[0]           # 물리 직결 없지만 포트채널이 멤버로 해석됨
        direct = True
    else:
        chosen = logical[0] if logical else matches[0]
        disp_port = chosen[2]
        direct = False

    via = ["%s:%s" % (m[1], m[2]) for m in matches if m is not chosen]
    return chosen[0], chosen[1], disp_port, direct, via


def _parse_connected_subnets(route_out, iface_out, cfg_out=""):
    """directly-connected 대역 추출 — 3개 소스의 합집합.

    ① show ip route connected: "C 10.92.174.0/23 is directly connected, Vlan100"
    ② show ip interface: "Internet address is 10.92.174.11/23"
    ③ running-config의 "ip address 10.92.174.11 255.255.254.0" (L2 SVI/VRF에서도 확실)
    Returns: ["10.92.174.0/23", ...] (중복 제거, /22 이하만)
    """
    found = []
    # ① show ip route connected
    for line in (route_out or "").splitlines():
        m = re.search(r"([\d.]+/\d{1,2})\s+is\s+directly\s+connected", line)
        if m:
            found.append(m.group(1))
    # ② show ip interface (슬래시 표기 + 구형 '주소 마스크' 표기 모두)
    for line in (iface_out or "").splitlines():
        m = re.search(r"Internet address is\s+([\d.]+)/(\d{1,2})", line)
        if m:
            try:
                net = ipaddress.IPv4Network("%s/%s" % (m.group(1), m.group(2)), strict=False)
                found.append(str(net))
            except (ipaddress.AddressValueError, ValueError):
                pass
    # ③ running-config: "ip address <ip> <netmask>" (dhcp/no ip address 제외)
    for line in (cfg_out or "").splitlines():
        m = re.search(r"^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            try:
                net = ipaddress.IPv4Network("%s/%s" % (m.group(1), m.group(2)), strict=False)
                found.append(str(net))
            except (ipaddress.AddressValueError, ValueError):
                pass
    return _finalize_subnets(found)


def _finalize_subnets(found):
    """대역 후보 리스트 → 정규화 + 중복 제거 + 크기 제한(/22 이하 = num_addresses<=1024).
    루프백/링크로컬 제외. 벤더 무관(IOS·EXOS 공용)."""
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


def _extract_exos_subnets(text):
    """EXOS 출력 한 덩어리에서 대역 후보 추출(버전별 표기 편차 흡수).

    EXOS는 마스크를 버전/명령에 따라 CIDR('/24')로도, 점표기('Netmask: 255.255.255.0')로도
    출력한다. 두 형태 모두 잡는다.
    """
    out = []
    t = text or ""

    def _add(ip, mask):
        try:
            out.append(str(ipaddress.IPv4Network("%s/%s" % (ip, mask), strict=False)))
        except (ipaddress.AddressValueError, ValueError):
            pass

    # ① CIDR: 'a.b.c.d/nn' 또는 'a.b.c.d /nn' (show vlan, show iproute)
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})", t):
        _add(m.group(1), m.group(2))
    # ② 점표기 마스크: 'IP Address: a.b.c.d ... Netmask: 255.x.x.x'
    for m in re.finditer(
            r"(\d{1,3}(?:\.\d{1,3}){3})\D{0,40}?(255\.\d{1,3}\.\d{1,3}\.\d{1,3})", t):
        _add(m.group(1), m.group(2))
    # ③ EXOS 'show ipconfig' 줄바꿈 형태(31.x): IP와 프리픽스가 다른 줄에 있음
    #      ip address: 10.92.152.11
    #      flags: /23 EUf--R--g---
    #    'ip address:' 뒤 IP → 다음 숫자가 나오기 전 첫 '/nn'(flags 줄의 프리픽스)와 페어링.
    for m in re.finditer(
            r"ip\s*address:\s*(\d{1,3}(?:\.\d{1,3}){3})[^\d/]{0,60}?/\s*(\d{1,2})",
            t, re.IGNORECASE):
        _add(m.group(1), m.group(2))
    return out


def _detect_subnets_exos(conn):
    """EXOS: 라우터 인터페이스(SVI) 대역 자동 도출.

    IOS의 'show ip route connected'/'show ip interface'/'show running-config'는 미지원.
    로컬 인터페이스가 나오는 여러 EXOS 명령을 함께 시도해 버전별 출력 편차를 흡수한다.
    반환: (대역리스트, 진단용 원문 샘플)
    """
    cmds = ["show vlan", "show ipconfig", "show iproute"]
    outs = {}
    for c in cmds:
        try:
            outs[c] = conn.send_command(c, read_timeout=45)
        except Exception:
            outs[c] = ""
    found = []
    for text in outs.values():
        found.extend(_extract_exos_subnets(text))
    sample = " | ".join(
        "%s=%r" % (c, (outs[c] or "").strip()[:150]) for c in cmds)
    return _finalize_subnets(found), sample


def detect_subnets(db_path, switch_id, username, password, source_ip=None):
    """스위치에 접속해 directly-connected 대역을 자동 도출(벤더별 명령)."""
    from netmiko import ConnectHandler
    from . import netbind
    sw = db.get_switch(db_path, switch_id)
    if not sw:
        raise ValueError("switch not found")
    vendor = _collector._norm_vendor(sw.get("vendor"))
    device = {
        "device_type": vendor,
        "ip": sw["ip"], "username": username, "password": password,
        "secret": password, "conn_timeout": 30, "fast_cli": False,
    }
    if source_ip:
        device["sock"] = netbind.bind_socket(sw["ip"], 22, source_ip, 30)
    route_out, iface_out, cfg_out = "", "", ""
    with ConnectHandler(**device) as conn:
        try:
            if hasattr(conn, "check_enable_mode") and not conn.check_enable_mode():
                conn.enable()
        except Exception:
            pass
        # 페이징 비활성(EXOS는 'disable clipaging', IOS류는 'terminal length 0')
        paging = _collector._PAGING_CMD.get(vendor, "terminal length 0")
        try:
            conn.send_command(paging, read_timeout=10)
        except Exception:
            pass
        # EXOS는 IOS 명령을 지원하지 않으므로 전용 경로로 분기
        if vendor == "extreme_exos":
            subnets, sample = _detect_subnets_exos(conn)
            if not subnets:
                # 원문 샘플(3개 명령)을 로그로 — 형식 편차를 정확히 추적
                utils.log_event("warning", "detect_subnets_empty_exos",
                                switch_id=switch_id, sample=sample)
            return subnets
        try:
            route_out = conn.send_command("show ip route connected", read_timeout=30)
        except Exception:
            pass
        try:
            iface_out = conn.send_command("show ip interface", read_timeout=30)
        except Exception:
            pass
        # ③ running-config의 ip address 줄 — L2 SVI/VRF 환경에서도 확실한 소스
        try:
            cfg_out = conn.send_command(
                "show running-config | include ip address", read_timeout=30)
        except Exception:
            pass
        subnets = _parse_connected_subnets(route_out, iface_out, cfg_out)
        if not subnets:
            # 안전망: 벤더가 EXOS인데 cisco 등으로 잘못 등록됐으면 IOS 명령이 전부
            # 빈손이 된다. 연결이 살아있는 동안 EXOS 명령으로 한 번 더 시도.
            exos_subnets, exos_sample = _detect_subnets_exos(conn)
            if exos_subnets:
                utils.log_event("info", "detect_subnets_exos_fallback",
                                switch_id=switch_id, count=len(exos_subnets))
                return exos_subnets
    # 저장된 벤더 드라이버로 전부 빈손 — 대표 사례: EXOS를 cisco 드라이버로 접속하면
    # 프롬프트 불일치로 모든 명령이 실패(빈 응답)한다. 실제 OS를 프로브해 올바른
    # 드라이버로 재접속 후 재시도한다(성공 시 벤더도 교정).
    if not subnets:
        subnets = _detect_subnets_probe_retry(
            db_path, switch_id, sw, vendor, username, password, source_ip)
    return subnets


def _detect_subnets_probe_retry(db_path, switch_id, sw, cur_vendor,
                                username, password, source_ip):
    """저장 벤더 드라이버로 빈손일 때: 드라이버 무관 프로브로 실제 OS를 알아내
    올바른 드라이버로 재접속해 대역 도출. 성공하면 벤더도 교정(다음 수집부터 정상)."""
    from netmiko import ConnectHandler
    from . import netbind
    try:
        probed, _ver = _collector._probe_os(sw, username, password, source_ip=source_ip)
    except Exception:
        probed = None
    if not probed or probed == cur_vendor:
        utils.log_event("warning", "detect_subnets_empty", switch_id=switch_id,
                        note="probe_failed_or_same", probed=probed or "")
        return []
    device = {
        "device_type": probed, "ip": sw["ip"], "username": username,
        "password": password, "secret": password, "conn_timeout": 30, "fast_cli": False,
    }
    if source_ip:
        device["sock"] = netbind.bind_socket(sw["ip"], 22, source_ip, 30)
    subnets = []
    try:
        with ConnectHandler(**device) as conn:
            try:
                if hasattr(conn, "check_enable_mode") and not conn.check_enable_mode():
                    conn.enable()
            except Exception:
                pass
            paging = _collector._PAGING_CMD.get(probed, "terminal length 0")
            try:
                conn.send_command(paging, read_timeout=10)
            except Exception:
                pass
            if probed == "extreme_exos":
                subnets, _s = _detect_subnets_exos(conn)
            else:
                r = i = c = ""
                try:
                    r = conn.send_command("show ip route connected", read_timeout=30)
                except Exception:
                    pass
                try:
                    i = conn.send_command("show ip interface", read_timeout=30)
                except Exception:
                    pass
                try:
                    c = conn.send_command(
                        "show running-config | include ip address", read_timeout=30)
                except Exception:
                    pass
                subnets = _parse_connected_subnets(r, i, c)
    except Exception as e:
        utils.log_event("warning", "detect_subnets_probe_reconnect_failed",
                        switch_id=switch_id, probed=probed,
                        error=_collector._sanitize_error_msg(str(e)))
        return []
    if subnets:
        utils.log_event("info", "detect_subnets_probe_success",
                        switch_id=switch_id, probed=probed, count=len(subnets))
        # 벤더 교정 — 다음 수집·대역수집(ARP)도 올바른 드라이버/명령을 쓰게 된다
        try:
            db.update_switch(db_path, switch_id, vendor=probed)
        except Exception:
            pass
    else:
        utils.log_event("warning", "detect_subnets_empty", switch_id=switch_id,
                        note="probe_reconnect_empty", probed=probed)
    return subnets


def _list_vrfs(conn):
    """장비의 VRF 이름 목록(IOS/IOS-XE/NX-OS). 실패·미지원이면 빈 리스트."""
    try:
        vrf_out = conn.send_command("show vrf", read_timeout=15)
    except Exception:
        return []
    names = []
    for line in (vrf_out or "").splitlines():
        m = re.match(r"^\s{0,2}(\S+)\s+", line)
        if not m:
            continue
        name = m.group(1)
        if name.lower() in ("name", "vrf", "%", "---", "") or name.startswith("-"):
            continue
        if "invalid" in line.lower():
            return []
        names.append(name)
    return names


def _ping_tpl(vendor, vrf):
    """벤더별 단발 ping 템플릿(%s=IP). ping은 ARP 채우기용 — 실패해도 치명적 아님.

    NX-OS는 'ping <ip> vrf X' 어순, IOS/Arista는 'ping vrf X <ip>' 어순으로 다르다.
    """
    if vendor == "cisco_nxos":
        return ("ping %s vrf " + vrf + " count 1 timeout 1") if vrf \
               else "ping %s count 1 timeout 1"
    if vendor == "extreme_exos":
        return "ping count 1 %s"        # EXOS 어순: ping [count N] <host> (VRF 개념 다름)
    return ("ping vrf " + vrf + " %s repeat 1 timeout 1") if vrf \
           else "ping %s repeat 1 timeout 1"


def _find_vrf_for_subnet(conn, net):
    """대상 대역이 어느 VRF에 속하는지 탐지(IOS/IOS-XE/NX-OS). 글로벌이면 None.

    관리 IP와 다른 대역(예: 172.27.x)이 VRF에 있으면 일반 ping은 글로벌로 나가
    실패하고 show ip arp에도 안 보여 '완료인데 0대'가 된다 → vrf 키워드 필요.
    """
    names = _list_vrfs(conn)
    for name in names[:10]:
        try:
            out = conn.send_command("show ip route vrf %s connected" % name,
                                    read_timeout=20)
        except Exception:
            continue
        # connected 대역들과 비교 — 수집 대역이 그 안(하위 대역 포함)이면 해당 VRF.
        # 'show ip route vrf X connected'는 연결 라우트만 나열하므로 출력의 모든 CIDR가
        # 곧 connected 대역이다. IOS는 'X/Y is directly connected', NX-OS는 'X/Y, attached',
        # Arista도 표기가 달라 문구 대신 CIDR를 직접 대조한다(벤더 무관).
        for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", out or ""):
            try:
                route_net = ipaddress.IPv4Network(m.group(1), strict=False)
                if net.subnet_of(route_net):
                    utils.log_event("info", "facility_vrf_detected",
                                    vrf=name, subnet=str(net))
                    return name
            except (ipaddress.AddressValueError, ValueError):
                continue
    return None


def collect_band(db_path, switch_id, subnet, username, password, source_ip=None):
    """동기 수집(백그라운드 스레드에서 호출). 진행 상태는 _status로 갱신."""
    from netmiko import ConnectHandler
    from . import netbind
    from . import parsers

    sw = db.get_switch(db_path, switch_id)
    if not sw:
        raise ValueError("switch not found")
    # 벤더별 파서·ARP 명령 선택. 이전엔 cisco_ios 하드코딩 → 비-IOS 장비에서
    # ARP 파싱이 0건이 되어 '완료인데 0대'가 나던 원인. VRF는 IOS/NX-OS/Arista만 지원.
    vendor = _collector._norm_vendor(sw.get("vendor"))
    try:
        parser = parsers.get_parser(vendor)
    except ValueError:
        vendor = "cisco_ios"
        parser = parsers.get_parser("cisco_ios")   # 미지원 벤더는 IOS로 시도(fallback)
    # 파서의 명령 딕셔너리는 COMMANDS(전 벤더 공통). 이전엔 CMDS로 잘못 참조해
    # 항상 'show ip arp'(IOS)로 폴백 → EXOS('show iparp')·Alteon에서 0대였다.
    arp_base_cmd = getattr(parser, "COMMANDS", {}).get("arp", "show ip arp")
    vrf_capable = vendor in ("cisco_ios", "cisco_nxos", "arista_eos")
    net = ipaddress.IPv4Network(subnet, strict=False)
    ips = [str(h) for h in net.hosts()]
    _set(running=True, subnet=subnet, done=0, total=len(ips), message="연결 중")

    # keepalive: 긴 ping 스윕(/23=~510회, 15분+) 중 방화벽/장비의 유휴 세션 정리로
    # TCP가 끊겨 'socket is closed'가 나던 문제 완화.
    device = {
        "device_type": _collector._norm_vendor(sw.get("vendor")),
        "ip": sw["ip"], "username": username, "password": password,
        "secret": password, "conn_timeout": 30, "fast_cli": False,
        "keepalive": 15,
    }

    def _connect():
        conn_device = dict(device)
        if source_ip:
            conn_device["sock"] = netbind.bind_socket(sw["ip"], 22, source_ip, 30)
        c = ConnectHandler(**conn_device)
        try:
            if hasattr(c, "check_enable_mode") and not c.check_enable_mode():
                c.enable()
        except Exception:
            pass
        try:
            c.send_command("terminal length 0", read_timeout=10)
        except Exception:
            pass
        return c

    def _is_conn_dead(err):
        m = str(err).lower()
        return ("socket" in m and "closed" in m) or "not connected" in m or \
               isinstance(err, (OSError, EOFError))

    _MAX_RECONNECT = 5
    reconnects = 0
    # ── 청크 스윕: ping 32개마다 그 자리에서 ARP를 중간 수집(부분 결과 즉시 확보) ──
    #  · /24+ 대규모 대역에서 "완료인데 빈 결과"가 나던 문제의 근본 대책:
    #    맨 끝 1회 ARP에 전부를 걸지 않고, 청크마다 작게 읽어 누적한다.
    #  · ping 사이 짧은 간격(pacing)으로 스위치 제어평면 부담 완화.
    #  · 중간에 복구 불가 오류가 나도 그때까지의 청크 결과는 저장(부분 완료).
    import time as _t
    arp_union = {}      # {ip: {ip, mac, interface}} — 청크 ARP 누적(뒤 결과 우선)
    arp_reads = 0
    partial_error = None

    vrf = None            # 대역이 VRF 소속이면 ping/ARP에 vrf 키워드 적용
    arp_cmd = arp_base_cmd
    last_arp_sample = ""  # 0대 완료 시 진단용 원문 샘플

    def _read_arp():
        """작게 자주 읽는 ARP — 끊겼으면 1회 재접속 재시도."""
        nonlocal conn, arp_reads, last_arp_sample
        try:
            out = conn.send_command(arp_cmd, read_timeout=60)
        except Exception as e:
            if not _is_conn_dead(e):
                raise
            utils.log_event("warning", "facility_arp_reconnect", subnet=subnet)
            try:
                conn.disconnect()
            except Exception:
                pass
            _t.sleep(3)
            conn = _connect()
            out = conn.send_command(arp_cmd, read_timeout=60)
        arp_reads += 1
        last_arp_sample = (out or "")[:300]
        for a in parser._parse_arps(out, switch_id):
            try:
                if ipaddress.IPv4Address(a["ip"]) in net:   # 대역 밖 ARP는 제외
                    arp_union[a["ip"]] = a
            except (ipaddress.AddressValueError, ValueError):
                continue

    conn = _connect()
    try:
        # 대역이 VRF에 속하면 ping/ARP에 vrf 적용(관리대역≠수집대역 환경 대응)
        if vrf_capable:
            _set(message="VRF 확인 중")
            vrf = _find_vrf_for_subnet(conn, net)
        if vrf:
            arp_cmd = "%s vrf %s" % (arp_base_cmd, vrf)
        ping_tpl = _ping_tpl(vendor, vrf)
        _set(message="대역 ping 중" + ((" (VRF %s)" % vrf) if vrf else ""))
        i = 0
        try:
            while i < len(ips):
                ip = ips[i]
                try:
                    conn.send_command(ping_tpl % ip, read_timeout=5)
                except Exception as e:
                    # 세션 끊김이면 재접속 후 같은 IP부터 재개. 그 외는 해당 IP만 건너뜀.
                    if _is_conn_dead(e) and reconnects < _MAX_RECONNECT:
                        reconnects += 1
                        utils.log_event("warning", "facility_session_reconnect",
                                        subnet=subnet, attempt=reconnects, progress=i)
                        _set(message="세션 끊김 — 재접속 %d/%d (진행 %d/%d)" % (
                            reconnects, _MAX_RECONNECT, i, len(ips)))
                        try:
                            conn.disconnect()
                        except Exception:
                            pass
                        _t.sleep(3)
                        conn = _connect()
                        _set(message="대역 ping 중 (재개)")
                        continue  # 같은 IP 재시도
                i += 1
                _t.sleep(_SWEEP_PING_GAP)          # 스위치 부담 완화(pacing)
                if i % _SWEEP_CHUNK == 0:
                    _set(done=i, message="대역 ping 중 (%d/%d · ARP 중간수집 %d회 · 확보 %d대)"
                         % (i, len(ips), arp_reads, len(arp_union)))
                    _read_arp()                    # 청크마다 ARP 중간 수집
            _set(done=len(ips), message="ARP 최종 수집 중")
            _read_arp()                            # 마지막 잔여분
        except Exception as e:
            # 복구 불가 오류 — 지금까지 확보한 청크 결과라도 저장(부분 완료)
            if not arp_union:
                raise
            partial_error = _collector._sanitize_error_msg(str(e))
            utils.log_event("warning", "facility_partial", subnet=subnet,
                            collected=len(arp_union), error=partial_error)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

    # 0대 폴백: VRF 자동탐지가 실장비 출력 포맷과 어긋나 못 잡았을 수 있다.
    # 재접속해 모든 VRF의 ARP를 훑어 대역에 드는 항목을 건진다(정탐 보정).
    if not arp_union and vrf_capable:
        try:
            conn = _connect()
            try:
                for vname in _list_vrfs(conn)[:10]:
                    try:
                        out = conn.send_command("%s vrf %s" % (arp_base_cmd, vname),
                                                read_timeout=60)
                    except Exception:
                        continue
                    for a in parser._parse_arps(out or "", switch_id):
                        try:
                            if ipaddress.IPv4Address(a["ip"]) in net:
                                arp_union[a["ip"]] = a
                        except (ipaddress.AddressValueError, ValueError):
                            continue
                    if arp_union:
                        vrf = vname
                        utils.log_event("info", "facility_vrf_fallback_hit",
                                        subnet=subnet, vrf=vname,
                                        collected=len(arp_union))
                        break
            finally:
                try:
                    conn.disconnect()
                except Exception:
                    pass
        except Exception:
            pass

    arp = list(arp_union.values())  # [{ip, mac, interface}]
    mac_map = db.get_mac_to_switchport(db_path)       # {mac: [(sid, sname, port)]}
    port_counts = db.get_port_mac_counts(db_path)     # {(sid, port_lower): MAC수}
    pc_map = db.get_port_channel_members(db_path)     # {(sid, po_lower): [members]}
    port_descs = db.get_port_descriptions(db_path)    # {(sid, port_lower): Description}

    # IP별 1행: 같은 MAC이 여러 스위치/포트에 보일 때 "직접 연결된 스위치"를 가려낸다.
    #  - Po(포트채널)·Vl(VLAN/SVI) 등 논리 인터페이스는 업링크 경유 → 직접 연결 아님
    #  - 물리 포트 중 MAC 수가 가장 적은 포트 = 액세스(엣지) 포트 → 직접 연결
    by_ip = {}
    for a in arp:
        mac = (a.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        sid, sname, port, direct, via = _choose_attachment(matches, port_counts, pc_map)
        by_ip[a["ip"]] = {"subnet": subnet, "ip": a["ip"], "mac": a["mac"],
                          "switch_id": sid, "switch_name": sname, "port": port,
                          "online": 1, "direct": 1 if direct else 0,
                          "via": "; ".join(via) if via else None,
                          "port_desc": port_descs.get((sid, (port or "").lower()))}

    saved, new_cnt, off_cnt = _apply_scan(db_path, subnet, by_ip)
    utils.log_event("info", "facility_collected", subnet=subnet, pinged=len(ips),
                    arp=len(arp), saved=saved, new=new_cnt, offline=off_cnt,
                    arp_reads=arp_reads, vrf=vrf or "(global)",
                    partial=bool(partial_error))
    if not by_ip:
        # 0대 완료 — VRF/ARP 형식 진단을 위해 원문 샘플을 로그로
        utils.log_event("warning", "facility_zero_result", subnet=subnet,
                        vrf=vrf or "(global)", arp_sample=last_arp_sample)
    done_msg = "완료(설비 %d · 새 %d · 오프라인 %d)" % (len(by_ip), new_cnt, off_cnt)
    if partial_error:
        done_msg = "부분 완료(설비 %d 확보 — 중단 사유: %s)" % (len(by_ip), partial_error[:80])
    _set(running=False, message=done_msg)
    return {"subnet": subnet, "pinged": len(ips), "arp": len(arp),
            "saved": saved, "new": new_cnt, "offline": off_cnt,
            "partial": bool(partial_error)}


_KEEP_COLS = ("subnet", "ip", "mac", "switch_id", "switch_name", "port", "direct", "via", "port_desc")


def _apply_scan(db_path, subnet, by_ip):
    """대역 스캔 결과(by_ip: {ip: host})를 이전 상태와 비교해 저장 + 변경 이벤트 기록.

    - 새 IP → new_device 이벤트
    - 이전 online인데 이번에 없음 → device_offline 이벤트 + online=0으로 '유지'(삭제 안 함)
    - 이전 offline인데 이번에 응답 → device_online(복구) 이벤트
    반환: (저장 개수, 새 설비 수, 오프라인 전환 수)
    """
    existing = {h["ip"]: h for h in db.get_facility_hosts(db_path) if h.get("subnet") == subnet}
    merged = list(by_ip.values())   # 이번에 응답한 설비(online=1)
    new_cnt = off_cnt = 0
    for ip, host in by_ip.items():
        ex = existing.get(ip)
        if ex is None:
            db.save_device_event(db_path, "new_device", "warning", subnet=subnet, ip=ip,
                                 mac=host.get("mac"), switch_id=host.get("switch_id"),
                                 label=host.get("switch_name"), message="새 설비 감지: " + ip)
            new_cnt += 1
        else:
            if not ex.get("online"):
                db.save_device_event(db_path, "device_online", "info", subnet=subnet, ip=ip,
                                     mac=host.get("mac"), message="설비 복구(온라인): " + ip)
            # 설비 이동 감지: 같은 MAC이 다른 스위치/포트(직접 관측)로 옮겨짐 → 무단 이설 의심
            _mac_same = (ex.get("mac") or "").lower() == (host.get("mac") or "").lower()
            if (_mac_same and ex.get("switch_name") and host.get("switch_name")
                    and ex.get("direct") and host.get("direct")
                    and (ex.get("switch_name"), ex.get("port")) !=
                        (host.get("switch_name"), host.get("port"))):
                db.save_device_event(
                    db_path, "device_moved", "warning", subnet=subnet, ip=ip,
                    mac=host.get("mac"), switch_id=host.get("switch_id"),
                    label=host.get("switch_name"),
                    message="설비 이동 감지: %s (%s:%s → %s:%s)" % (
                        ip, ex.get("switch_name"), ex.get("port"),
                        host.get("switch_name"), host.get("port")))
    for ip, ex in existing.items():
        if ip in by_ip:
            continue
        off = {k: ex.get(k) for k in _KEEP_COLS}
        off["online"] = 0
        merged.append(off)                       # 삭제하지 않고 오프라인으로 유지
        if ex.get("online"):                     # 온라인→사라짐 = 연결 끊김(신규 이벤트)
            # 마지막 확인 위치(오프라인 시 MAC이 테이블에서 빠져 재조회 불가)를 메시지에
            # 병기 — 어느 스위치/포트에 붙어 있던 설비인지 알람만으로 특정 가능.
            _loc = ""
            if ex.get("switch_name") and ex.get("port"):
                _loc = " (마지막 위치: %s %s)" % (ex["switch_name"], ex["port"])
            elif ex.get("switch_name"):
                _loc = " (마지막 스위치: %s, 포트 미확인)" % ex["switch_name"]
            db.save_device_event(db_path, "device_offline", "warning", subnet=subnet, ip=ip,
                                 mac=ex.get("mac"), switch_id=ex.get("switch_id"),
                                 label=ex.get("switch_name"),
                                 message="설비 연결 끊김: " + ip + _loc)
            off_cnt += 1

    db.clear_facility_subnet(db_path, subnet)
    db.save_facility_hosts(db_path, merged)
    return len(merged), new_cnt, off_cnt


_EXPORT_COLS = ["대역", "IP", "MAC", "연결 스위치", "포트", "포트 설명", "직접연결", "그 외 관측", "상태"]


def _export_rows(db_path):
    """설비 현황을 추출용 행 목록(dict)으로 변환."""
    rows = []
    for h in db.get_facility_hosts(db_path):
        direct = h.get("direct", 1) and h.get("switch_name")
        online = bool(h.get("online"))
        # 오프라인이면 '직접'이 아니라 '마지막 관측'으로 표기(Opus 검증 반영)
        if direct and online:
            label = "직접"
        elif direct:
            label = "마지막 관측"
        else:
            label = "미확인"
        rows.append({
            "대역": h.get("subnet") or "",
            "IP": h.get("ip") or "",
            "MAC": h.get("mac") or "",
            "연결 스위치": (h.get("switch_name") or "") if direct else "직접 연결 미확인",
            "포트": (h.get("port") or "") if direct else "",
            "포트 설명": (h.get("port_desc") or "") if direct else "",
            "직접연결": label,
            "그 외 관측": h.get("via") or "",
            "상태": "온라인" if online else "연결 실패",
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
    pc_map = db.get_port_channel_members(db_path)
    port_descs = db.get_port_descriptions(db_path)
    updated = []
    for h in hosts:
        mac = (h.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        sid, sname, port, direct, via = _choose_attachment(matches, port_counts, pc_map)
        updated.append({
            "subnet": h.get("subnet"), "ip": h.get("ip"), "mac": h.get("mac"),
            "switch_id": sid, "switch_name": sname, "port": port,
            "online": h.get("online", 1), "direct": 1 if direct else 0,
            "via": "; ".join(via) if via else None,
            "port_desc": port_descs.get((sid, (port or "").lower()))})
    db.save_facility_hosts(db_path, updated)  # subnet+ip UNIQUE → 제자리 갱신
    utils.log_event("info", "facility_rematched", count=len(updated))
    return len(updated)


def remember_band(db_path, subnet, switch_id):
    """자동 스캔용: 대역→수집 스위치 매핑 기억(마지막 수동 수집 기준)."""
    import json
    try:
        m = json.loads(db.get_setting(db_path, "facility_subnet_map", "{}") or "{}")
    except (ValueError, TypeError):
        m = {}
    m[str(subnet)] = int(switch_id)
    db.set_setting(db_path, "facility_subnet_map", json.dumps(m))


def get_band_map(db_path):
    """{subnet: switch_id} — 자동 스캔 대상 목록."""
    import json
    try:
        m = json.loads(db.get_setting(db_path, "facility_subnet_map", "{}") or "{}")
        return {str(k): int(v) for k, v in m.items()}
    except (ValueError, TypeError):
        return {}


def run_auto_scan(db_path):
    """기억된 모든 대역을 '순차'로 자동 스캔(부하 분산 — 동시에 1개 대역만).

    각 대역의 스위치에 저장된 계정(DPAPI)이 있어야 한다. 없으면 그 대역은 건너뜀.
    스케줄러 스레드에서 동기 호출된다. 반환: {"scanned": n, "skipped": n}
    """
    from . import credentials
    from . import pcprofile
    band_map = get_band_map(db_path)
    scanned = skipped = 0
    src = pcprofile.get_source_ip(db_path)
    for subnet, switch_id in band_map.items():
        if _status.get("running"):
            # 수동 수집과 겹치면 대기(최대 30분) 후 재확인
            for _ in range(180):
                import time as _t
                _t.sleep(10)
                if not _status.get("running"):
                    break
        blob = db.get_switch_credential(db_path, switch_id)
        if not blob:
            utils.log_event("warning", "facility_auto_skip_no_cred",
                            subnet=subnet, switch_id=switch_id)
            skipped += 1
            continue
        dec = credentials.decrypt_credential(blob)   # "username|password"
        if not dec or "|" not in dec:
            skipped += 1
            continue
        username, password = dec.split("|", 1)
        try:
            with _lock:
                if _status["running"]:
                    skipped += 1
                    continue
                _status["running"] = True
                _status["message"] = "자동 스캔: " + subnet
            collect_band(db_path, switch_id, subnet, username, password, src)
            scanned += 1
        except Exception as e:
            _set(running=False, message="자동 스캔 실패: " + subnet)
            utils.log_event("error", "facility_auto_scan_error", subnet=subnet,
                            error=_collector._sanitize_error_msg(str(e)))
        finally:
            dec = username = password = None
    utils.log_event("info", "facility_auto_scan_done", scanned=scanned, skipped=skipped)
    return {"scanned": scanned, "skipped": skipped}


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
