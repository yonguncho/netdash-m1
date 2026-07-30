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
import time

from . import db, utils
from . import collector as _collector

# 청크 스윕 파라미터: ping N개마다 ARP 중간 수집(부분 결과 확보) + ping 간격(부담 완화)
_SWEEP_CHUNK = 32
_SWEEP_PING_GAP = 0.05   # 초 — /23(510개) 기준 총 +26초, 제어평면 여유 확보

# 진행 상태(메모리). {"running","subnet","done","total","message"}
_status = {"running": False, "subnet": None, "done": 0, "total": 0, "message": "",
           "started_at": None}
_lock = threading.Lock()
_stop_requested = False   # 사용자 '수집 중지' 요청 플래그
_worker = None            # 진행 중인 수집 스레드 — 죽었는데 running이 남는 것 방지


def _reap_dead_worker():
    """수집 스레드가 죽었는데 running 플래그만 남은 상태를 스스로 푼다.

    이 플래그가 한 번 걸리면 재수집이 전부 409로 막히고, 되돌릴 방법이 exe 재시작
    뿐이었다. 스레드가 이미 끝났다면 '수집 중'이라고 우길 근거가 없다.
    호출자는 _lock을 잡은 상태여야 한다.
    """
    global _worker
    if not _status.get("running"):
        return False
    if _worker is None or _worker.is_alive():
        # 등록된 스레드가 없으면 판단 근거가 없다 — 함부로 풀면 진행 중인
        # 수집을 '끝났다'고 단정해 두 개가 동시에 돌 수 있다.
        return False
    _worker = None
    _status["running"] = False
    _status["message"] = "이전 수집이 비정상 종료되어 상태를 초기화했습니다"
    utils.log_event("warning", "facility_stale_running_cleared",
                    subnet=_status.get("subnet"))
    return True


def get_status():
    with _lock:
        _reap_dead_worker()
        st = dict(_status)
        # 중지 요청이 접수됐음을 화면이 알 수 있게 노출한다.
        # 이게 없으면 진행바가 1.5초마다 '⏹ 수집 중지' 버튼을 새로 그려서,
        # 사용자는 중지가 안 먹은 것으로 오해한다(실제로는 마무리 중).
        st["stopping"] = bool(_stop_requested and _status.get("running"))
        st["elapsed_sec"] = (int(time.time() - st["started_at"])
                             if st.get("started_at") and st.get("running") else 0)
        return st


def busy_reason():
    """수집 중이면 '무엇이 얼마나 진행됐는지' 한 줄로. 아니면 빈 문자열.

    409를 그냥 '이미 수집 중입니다'로만 돌려주면, 사용자는 무엇이 왜 막는지
    알 수 없어 '버튼이 고장났다'로 받아들인다.
    """
    st = get_status()
    if not st.get("running"):
        return ""
    parts = []
    if st.get("subnet"):
        parts.append("%s 대역" % st["subnet"])
    if st.get("total"):
        parts.append("%d/%d" % (st.get("done") or 0, st["total"]))
    if st.get("elapsed_sec"):
        m, s = divmod(st["elapsed_sec"], 60)
        parts.append("%d분 %d초 경과" % (m, s) if m else "%d초 경과" % s)
    return " · ".join(parts)


def request_stop():
    """진행 중인 대역 스캔/전체 스캔에 중지 요청. 다음 체크 지점에서 부분 저장 후 종료."""
    global _stop_requested
    with _lock:
        if not _status.get("running"):
            return False
        _stop_requested = True
        _status["message"] = "중지 요청됨 — 마무리 중…"
    return True


def _is_stop_requested():
    with _lock:
        return _stop_requested


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


def _norm_dev_id(name):
    """CDP device-id를 비교용으로 정규화 — FQDN 꼬리·시리얼 괄호 제거 후 소문자.

    'SKBA_F1_C9300(FDO1234X0AB).example.com' → 'skba_f1_c9300'
    """
    n = (name or "").strip()
    n = re.sub(r"\(.*?\)", "", n)      # Cisco가 device-id에 붙이는 (시리얼)
    n = n.split(".")[0]                # FQDN 꼬리
    return n.strip().lower()


def uplink_ports(db_path):
    """{(switch_id, port소문자)} — '그 너머에 등록된 다른 스위치가 있는' 포트.

    MAC 개수만으로 액세스/트렁크를 가르면 오판이 남는다. 업링크라도 그 뒤 장비가
    대부분 조용하거나 꺼져 있으면 학습된 MAC이 몇 개뿐이라 액세스 포트처럼 보인다.
    (실제 사례: 백본 Po124가 TPS 스위치로 가는 업링크인데 설비 하나가 '백본에 직접
    연결'로 표시됨.) 스위치가 그 포트 너머에 있다는 건 개수와 무관한 확정 근거이므로
    여기서 따로 모아 _choose_attachment가 직접연결 후보에서 제외하게 한다.

    근거 두 가지 — 둘 다 '등록된 스위치'로 확인될 때만 인정한다(IP전화·AP를
    업링크로 오인하지 않기 위해):
      ① CDP/LLDP 이웃의 remote_ip/remote_name이 등록 스위치와 일치
      ② 그 포트에서 학습된 MAC이 등록 스위치가 소유한 MAC(관리/인터페이스)과 일치
    포트채널은 멤버↔Po 양방향으로 전파한다(한쪽만 알면 다른 쪽도 업링크).
    """
    up = set()
    try:
        switches = db.get_switches(db_path)
    except Exception:
        return up
    if not switches:
        return up

    by_ip, by_name = {}, {}
    for s in switches:
        if s.get("ip"):
            by_ip[str(s["ip"]).strip()] = s["id"]
        for key in (s.get("name"), s.get("hostname")):
            k = _norm_dev_id(key)
            if k:
                by_name[k] = s["id"]

    # ① CDP/LLDP 이웃
    try:
        for n in db.get_all_neighbors(db_path):
            rip = (n.get("remote_ip") or "").strip()
            peer = by_ip.get(rip) or by_name.get(_norm_dev_id(n.get("remote_name")))
            if peer and peer != n.get("switch_id") and n.get("local_port"):
                up.add((n["switch_id"], str(n["local_port"]).strip().lower()))
    except Exception:
        pass

    # ② 등록 스위치가 소유한 MAC이 학습된 포트
    try:
        from . import topology
        dev_macs = topology._device_macs(db_path, switches)
        owner = {}
        for sid, macs in dev_macs.items():
            for m in macs:
                owner[(m or "").lower()] = sid
        if owner:
            for mac, locs in db.get_mac_to_switchport(db_path).items():
                peer = owner.get((mac or "").lower())
                if not peer:
                    continue
                for sid, _sname, port in locs:
                    if sid != peer and port:
                        up.add((sid, str(port).strip().lower()))
    except Exception:
        pass

    # 포트채널 ↔ 물리 멤버 전파
    try:
        pc_map = db.get_port_channel_members(db_path)
    except Exception:
        pc_map = {}
    for (sid, po), members in (pc_map or {}).items():
        mem = {(sid, str(m).strip().lower()) for m in (members or []) if m}
        if (sid, po) in up:
            up |= mem
        elif mem & up:
            up.add((sid, po))
    return up


def _choose_attachment(matches, port_counts, pc_map=None, uplinks=None):
    """여러 스위치 MAC 테이블 매치 중 설비가 '직접' 붙은 스위치/포트를 선택.

    matches: [(switch_id, switch_name, port), ...]
    port_counts: {(switch_id, port소문자): 해당 포트 MAC 수}
    pc_map: {(switch_id, po소문자): [member_port, ...]}  # NX-OS 포트채널 → 물리 멤버
    uplinks: {(switch_id, port소문자)}  # 너머에 등록 스위치가 있는 포트(uplink_ports())
    반환: (switch_id, switch_name, port, direct(bool), via(list[str]))
      - 물리 액세스 포트(소수 MAC) → 직접
      - 포트채널(Po)이 멤버로 해석되면 실제 물리 멤버포트로 표시하고 직접으로 승격
        (TPS가 백본에 Po로 직결된 경우: Po10 → "Eth1/1, Eth1/2 (Po10)")
      - 단, 그 포트 너머에 등록된 스위치가 있으면(uplinks) MAC 수와 무관하게 직접 아님
      - 해석 불가 논리포트뿐이면 미확인
    """
    if not matches:
        return None, None, None, False, []
    pc_map = pc_map or {}
    uplinks = uplinks or set()

    def _cnt(sid, port):
        return port_counts.get((sid, (port or "").lower()), 9999)

    def _is_uplink(sid, port):
        """이 포트 너머에 등록된 다른 스위치가 있는가(개수 휴리스틱보다 우선)."""
        return (sid, (port or "").strip().lower()) in uplinks

    # 스위치가 너머에 있는 포트를 먼저 걷어낸다. 전부 업링크면(=설비가 붙은 액세스
    # 스위치를 아직 수집 못 했거나 MAC이 에이징된 경우) 원래 목록으로 되돌아가되
    # 직접연결로는 승격하지 않는다.
    edge = [m for m in matches if not _is_uplink(m[0], m[2])]
    all_uplink = not edge
    scan = matches if all_uplink else edge

    physical, pchan, logical = [], [], []
    for orig in scan:                          # orig = (sid, name, port)
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
        # 포트채널이 물리 멤버로 풀렸다고 무조건 '직접'은 아니다. 백본↔액세스
        # 스위치 간 업링크 트렁크(예: 백본의 Po124가 TPS 스위치로 올라가는 길목)도
        # pc_map에 물리 멤버가 있어 여기로 들어온다 — 그 뒤에 있는 장비 전부의 MAC이
        # 이 Po 하나로 몰려 학습되므로, 물리 포트와 똑같이 MAC 개수로 걸러야 한다.
        # (실제 사례: TPS 스위치 1/0/25에 물린 장비가 오프라인이 되어 그 스위치의
        #  MAC 항목은 에이징으로 지워졌는데, 백본은 Po124의 오래된 관측치를 아직
        #  갖고 있어 '백본에 직접 연결'로 잘못 표시됐다)
        pchan.sort(key=lambda pc: _cnt(pc[0][0], pc[0][2]))
        best_orig, best_disp = pchan[0]
        pc_cnt = _cnt(best_orig[0], best_orig[2])
        if pc_cnt <= _EDGE_MAC_MAX:
            chosen, disp_port, direct = best_orig, best_disp, True
        else:
            # 트렁크로 판단 — 물리 멤버로 풀어 보여주면 '거기 꽂혀 있다'는 오해를
            # 준다. 원래 포트채널 이름 그대로 두고 경유로 남긴다.
            chosen, disp_port, direct = best_orig, best_orig[2], False
    else:
        chosen = logical[0] if logical else matches[0]
        disp_port = chosen[2]
        direct = False

    # 최종 안전장치 — 고른 포트 자체가 업링크면 어떤 분기를 거쳐 왔든 직접연결이 아니다.
    # (MAC 개수가 적어도 마찬가지: 업링크 뒤 장비가 대부분 꺼져 있으면 개수는 얼마든
    #  작아질 수 있다.) 멤버로 풀어 보여주면 '거기 꽂혀 있다'는 오해를 주므로 원래
    # 포트 이름 그대로 되돌린다.
    if _is_uplink(chosen[0], chosen[2]):
        direct, disp_port = False, chosen[2]

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


def new_hosts_expected(db_path, subnet):
    """이 대역에 아직 등록된 설비가 없는가(=0건이 정상일 수 있는 신규 대역인가)."""
    try:
        return not any(h.get("subnet") == subnet for h in db.get_facility_hosts(db_path))
    except Exception:
        return False


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
    global _stop_requested
    # 중지 플래그는 여기서 초기화하지 않는다.
    # 예전에는 워커 스레드가 이 지점에서 False로 되돌려서, 사용자가 '시작 직후'
    # 누른 중지가 통째로 지워졌다(요청은 True로 접수되는데 스캔은 끝까지 진행 —
    # /23 대역이면 15분+ 동안 "중지가 안 된다"). 초기화는 **스캔을 시작하는 쪽**
    # (start_collect_band / run_auto_scan)이 스레드를 띄우기 전에 한다.
    # 새 스캔 시작 시 이전 diff 배너 초기화(직전 결과가 무기한 남지 않도록)
    _set(running=True, subnet=subnet, done=0, total=len(ips), message="연결 중",
         last_subnet=subnet, last_added=[], last_removed=[])

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
    i = 0               # ping 진행 인덱스(= 실제 스캔한 IP 수)
    stopped_at = None   # 중지 지점 — 이후 IP는 미스캔이므로 오프라인 판정에서 제외
    unscanned = set()   # ping을 실제로 보내지 못한 IP — 오프라인 판정에서 제외

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
        try:
            while i < len(ips):
                if _is_stop_requested():
                    stopped_at = i
                    _set(message="사용자 중지 — 그때까지 확보한 결과 저장 중")
                    break
                ip = ips[i]
                try:
                    conn.send_command(ping_tpl % ip, read_timeout=5)
                except Exception as e:
                    # 세션 끊김이면 재접속 후 같은 IP부터 재개. 그 외는 해당 IP만 건너뜀.
                    if _is_conn_dead(e):
                        if reconnects < _MAX_RECONNECT:
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
                        # 재접속 상한 초과 — 남은 IP는 확인 자체가 불가능하다.
                        # 예전엔 예외를 삼키고 계속 진행해서, ping도 못 해본 IP가
                        # 전부 '연결 끊김'으로 오탐되고 로그엔 '정상 완료'로 남았다.
                        partial_error = ("세션 재접속 %d회 실패 — 남은 %d개 IP 미확인"
                                         % (reconnects, len(ips) - i))
                        utils.log_event("warning", "facility_scan_aborted_session",
                                        subnet=subnet, progress=i, total=len(ips))
                        break
                    # 개별 IP 오류(타임아웃 등) — 이 IP는 '확인 못 함'으로 남긴다.
                    # 오프라인 판정 대상에 넣으면 멀쩡한 설비가 끊김으로 찍힌다.
                    unscanned.add(ip)
                i += 1
                _t.sleep(_SWEEP_PING_GAP)          # 스위치 부담 완화(pacing)
                if i % _SWEEP_CHUNK == 0:
                    _set(done=i, message="대역 ping 중 (%d/%d · ARP 중간수집 %d회 · 확보 %d대)"
                         % (i, len(ips), arp_reads, len(arp_union)))
                    _read_arp()                    # 청크마다 ARP 중간 수집
            if stopped_at is None:
                _set(done=len(ips), message="ARP 최종 수집 중")
            else:
                _set(done=stopped_at, message="ARP 최종 수집 중(중지)")
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
    uplinks = uplink_ports(db_path)                   # {(sid, port_lower)} 스위치가 너머에 있는 포트

    # IP별 1행: 같은 MAC이 여러 스위치/포트에 보일 때 "직접 연결된 스위치"를 가려낸다.
    #  - 너머에 등록 스위치가 있는 포트(CDP/LLDP·스위치 MAC)는 업링크 → 직접 연결 아님
    #  - Po(포트채널)·Vl(VLAN/SVI) 등 논리 인터페이스는 업링크 경유 → 직접 연결 아님
    #  - 물리 포트 중 MAC 수가 가장 적은 포트 = 액세스(엣지) 포트 → 직접 연결
    by_ip = {}
    for a in arp:
        mac = (a.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        sid, sname, port, direct, via = _choose_attachment(matches, port_counts, pc_map, uplinks)
        by_ip[a["ip"]] = {"subnet": subnet, "ip": a["ip"], "mac": a["mac"],
                          "switch_id": sid, "switch_name": sname, "port": port,
                          "online": 1, "direct": 1 if direct else 0,
                          "via": "; ".join(via) if via else None,
                          "port_desc": port_descs.get((sid, (port or "").lower()))}

    # 중지·부분중단 시엔 '실제로 ping한 IP'만 오프라인 판정 대상으로 넘긴다.
    # (미스캔 IP를 끊김으로 처리하면 대량 허위 '설비 연결 끊김' 알람이 발생)
    scanned_ips = None
    if stopped_at is not None:
        scanned_ips = set(ips[:stopped_at]) | set(by_ip.keys())
    elif partial_error:
        scanned_ips = set(ips[:i]) | set(by_ip.keys())
    if unscanned:
        # ping을 못 보낸 IP는 '끊김'이 아니라 '확인 못 함'이다 → 이전 상태를 보존
        if scanned_ips is None:
            scanned_ips = (set(ips) - unscanned) | set(by_ip.keys())
        else:
            scanned_ips -= (unscanned - set(by_ip.keys()))
    # ARP 결과가 0건이면 스캔 자체가 실패한 것으로 본다(VRF 오지정, 벤더별 명령
    # 형식 차이, 권한 부족 등). 예전엔 이걸 '정상 완료'로 적용해 **그 대역 설비
    # 전부를 연결 끊김으로 바꾸고 대량 오탐 알람을 보냈다.** 기존 상태를 보존한다.
    # (이미 등록된 설비가 있는 대역에 한함 — 신규 대역의 0건은 정상일 수 있다)
    if not by_ip and not new_hosts_expected(db_path, subnet):
        utils.log_event("warning", "facility_zero_arp_kept_previous", subnet=subnet,
                        vrf=vrf or "(global)", arp_sample=last_arp_sample)
        with _lock:
            _stop_requested = False
        _set(running=False,
             message="ARP 정보를 얻지 못해 이전 상태를 유지했습니다(대역: %s). "
                     "스위치 계정 권한과 VRF 설정을 확인하세요." % subnet)
        return {"subnet": subnet, "pinged": len(ips), "arp": 0, "saved": 0,
                "new": 0, "offline": 0, "partial": True, "stopped": False,
                "unscanned": len(unscanned), "zero_arp": True}
    saved, new_cnt, off_cnt = _apply_scan(db_path, subnet, by_ip, scanned_ips=scanned_ips)
    utils.log_event("info", "facility_collected", subnet=subnet, pinged=len(ips),
                    arp=len(arp), saved=saved, new=new_cnt, offline=off_cnt,
                    arp_reads=arp_reads, vrf=vrf or "(global)",
                    partial=bool(partial_error), stopped=stopped_at is not None)
    if not by_ip:
        # 0대 완료 — VRF/ARP 형식 진단을 위해 원문 샘플을 로그로
        utils.log_event("warning", "facility_zero_result", subnet=subnet,
                        vrf=vrf or "(global)", arp_sample=last_arp_sample)
    done_msg = "완료(설비 %d · 새 %d · 오프라인 %d)" % (len(by_ip), new_cnt, off_cnt)
    if stopped_at is not None:
        done_msg = "중지됨(스캔한 %d개 IP만 반영 · 설비 %d · 새 %d · 끊김 %d)" % (
            stopped_at, len(by_ip), new_cnt, off_cnt)
    elif partial_error:
        done_msg = "부분 완료(설비 %d 확보 — 중단 사유: %s)" % (len(by_ip), partial_error[:80])
    # 중지 플래그는 이 스캔에서 소비 완료 — 반드시 해제해야 다음 스캔(전체 대역·
    # 매일 자동 스캔)이 정상 동작한다(잔류 시 즉시 break되어 무력화됨).
    with _lock:
        _stop_requested = False
    _set(running=False, message=done_msg)
    return {"subnet": subnet, "pinged": len(ips), "arp": len(arp),
            "saved": saved, "new": new_cnt, "offline": off_cnt,
            "partial": bool(partial_error),
            "stopped": stopped_at is not None,   # 전체 대역 스캔이 남은 대역을 멈추는 근거
            "unscanned": len(unscanned)}


def gateway_credential(db_path, switch_id):
    """게이트웨이 스위치의 계정 — 저장 계정 우선, 없으면 PC 프로필 공통 계정.

    app.py가 예전엔 이 로직을 자기 안에 따로 갖고 있었다(관제 개별 재수집 전용).
    같은 계산이 두 곳에 있으면 한쪽만 고쳐져 어긋난다 — 이 모듈 하나로 모은다.
    반환: (username, password) | (None, None)."""
    from . import credentials, pcprofile
    blob = db.get_switch_credential(db_path, switch_id)
    username = password = ""
    if blob:
        dec = credentials.decrypt_credential(blob)
        if dec and "|" in dec:
            username, password = dec.split("|", 1)
    if not (username and password):
        cred = pcprofile.get_credential(db_path)
        if cred:
            username, password = cred
    return (username, password) if (username and password) else (None, None)


def _gateway_connect(sw, username, password, source_ip=None, timeout=20):
    """게이트웨이 스위치에 SSH 연결 + enable + 페이징 해제. 반환: (conn, vendor, parser)."""
    from netmiko import ConnectHandler
    from . import netbind, parsers

    vendor = _collector._norm_vendor(sw.get("vendor"))
    try:
        parser = parsers.get_parser(vendor)
    except ValueError:
        vendor = "cisco_ios"
        parser = parsers.get_parser("cisco_ios")
    device = {
        "device_type": vendor, "ip": sw["ip"], "username": username,
        "password": password, "secret": password, "conn_timeout": timeout,
        "fast_cli": False,
    }
    if source_ip:
        device["sock"] = netbind.bind_socket(sw["ip"], 22, source_ip, timeout)
    conn = ConnectHandler(**device)
    try:
        if hasattr(conn, "check_enable_mode") and not conn.check_enable_mode():
            conn.enable()
    except Exception:
        pass
    try:
        conn.send_command("terminal length 0", read_timeout=10)
    except Exception:
        pass
    return conn, vendor, parser


def _probe_ips(conn, vendor, parser, switch_id, net, ips):
    """이미 연결된 세션으로 **지정한 IP들만** ping 후 ARP를 한 번 읽는다.

    대역 전체를 스윕하지 않는다 — 확인하려는 IP만큼만 ping을 보낸다.
    반환: {ip: arp_entry} (응답 없는 IP는 키 자체가 없다).
    """
    vrf_capable = vendor in ("cisco_ios", "cisco_nxos", "arista_eos")
    vrf = _find_vrf_for_subnet(conn, net) if vrf_capable else None
    arp_base_cmd = getattr(parser, "COMMANDS", {}).get("arp", "show ip arp")
    arp_cmd = ("%s vrf %s" % (arp_base_cmd, vrf)) if vrf else arp_base_cmd
    ping_tpl = _ping_tpl(vendor, vrf)
    for ip in ips:
        try:
            conn.send_command(ping_tpl % ip, read_timeout=8)
        except Exception:
            pass   # ping 실패는 곧 '오프라인'으로 해석되므로 여기서 죽지 않는다
    out = conn.send_command(arp_cmd, read_timeout=30)
    want = set(ips)
    found = {}
    for a in parser._parse_arps(out or "", switch_id):
        if a.get("ip") in want:
            found[a["ip"]] = a
    return found


def _apply_host_results(db_path, subnet, ip_results):
    """probe 결과를 facility_hosts에 반영. ip_results: {ip: arp_entry|None}.

    같은 대역의, 결과에 없는(=대상 아니었던) 행은 그대로 둔다. 위치를 새로
    못 찾은 IP는 이전 연결 위치를 보존한다(마지막 위치 참고용으로 남긴다).
    반환: [(ip, now_online, was_online), ...] — 이벤트 기록·집계용.
    """
    hosts = db.get_facility_hosts(db_path)
    rows, changed = [], []
    seen_ips = set()
    mac_map = port_counts = pc_map = port_descs = None   # 필요할 때만 조회(성능)

    for h in hosts:
        if h.get("subnet") != subnet or h.get("ip") not in ip_results:
            rows.append(h)
            continue
        seen_ips.add(h["ip"])
        found = ip_results[h["ip"]]
        now_online = bool(found)
        was_online = bool(h.get("online"))
        updated = dict(h)
        updated["mac"] = (found or {}).get("mac") or h.get("mac")
        updated["online"] = 1 if now_online else 0
        mac = (updated["mac"] or "").lower()
        if mac:
            if mac_map is None:
                mac_map = db.get_mac_to_switchport(db_path)
                port_counts = db.get_port_mac_counts(db_path)
                pc_map = db.get_port_channel_members(db_path)
            sid, sname, port, direct, via = _choose_attachment(
                mac_map.get(mac, []), port_counts, pc_map)
            if sname:   # 새로 찾았을 때만 덮는다 — 못 찾았으면 이전 위치 보존
                if port_descs is None:
                    port_descs = db.get_port_descriptions(db_path)
                updated["switch_id"] = sid
                updated["switch_name"] = sname
                updated["port"] = port
                updated["direct"] = 1 if direct else 0
                updated["via"] = "; ".join(via) if via else None
                updated["port_desc"] = port_descs.get((sid, (port or "").lower()))
        rows.append(updated)
        changed.append((h["ip"], now_online, was_online))

    # 요청받은 IP인데 facility_hosts에 행이 아예 없던 경우(드묾) — 새로 만든다.
    for ip, found in ip_results.items():
        if ip in seen_ips:
            continue
        rows.append({"subnet": subnet, "ip": ip,
                     "mac": (found or {}).get("mac") or "",
                     "online": 1 if found else 0})
        changed.append((ip, bool(found), False))

    db.replace_facility_subnet(db_path, subnet, rows)
    return changed


def recollect_single_host(db_path, subnet, ip, username, password, source_ip=None):
    """설비 하나만 재확인 — 그 설비가 속한 대역 전체를 다시 스캔하지 않는다.

    관제에서 '연결 실패' 설비의 재수집을 누르면, 예전에는 그 설비가 속한 대역
    전체를 처음부터 다시 스캔했다(대역이 /23이면 15분+, 확인하려는 건 그 설비
    하나뿐인데 나머지 수백 개 IP까지 다시 ping했다). 이 함수는 게이트웨이
    스위치에 붙어 **그 IP 하나만** ping하고 ARP를 한 번 읽어, 그 설비의 온라인
    여부·연결 위치만 갱신한다. 같은 대역의 다른 설비 행은 건드리지 않는다.

    전체 대역 스캔(_status.running)과는 별도의 짧은 세션이라 서로를 막지 않는다
    — 스위치는 보통 여러 개의 관리 세션을 동시에 받는다(vty 여러 개).

    반환: (ok: bool, message: str).
    """
    band_map = get_band_map(db_path)
    switch_id = band_map.get(subnet)
    if not switch_id:
        return False, "이 대역의 게이트웨이 스위치가 기억되지 않았습니다"
    sw = db.get_switch(db_path, switch_id)
    if not sw:
        return False, "게이트웨이 스위치를 찾을 수 없습니다"
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        if ipaddress.IPv4Address(ip) not in net:
            return False, "이 IP는 해당 대역에 속하지 않습니다"
    except (ipaddress.AddressValueError, ValueError):
        return False, "IP/대역 형식이 올바르지 않습니다"

    conn = None
    try:
        conn, vendor, parser = _gateway_connect(sw, username, password, source_ip)
        found_map = _probe_ips(conn, vendor, parser, switch_id, net, [ip])
    except Exception as e:
        err = _collector._sanitize_error_msg(str(e))
        utils.log_event("warning", "facility_single_recollect_error", ip=ip,
                        subnet=subnet, error=err)
        return False, "스위치 접속 실패: %s" % err
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

    try:
        changed = _apply_host_results(db_path, subnet, {ip: found_map.get(ip)})
    except Exception as e:
        return False, "결과 저장 실패: %s" % _collector._sanitize_error_msg(str(e))
    _, now_online, was_online = changed[0]
    updated = next((h for h in db.get_facility_hosts(db_path)
                   if h.get("subnet") == subnet and h.get("ip") == ip), {})

    if now_online and not was_online:
        db.save_device_event(db_path, "device_online", "info", subnet=subnet, ip=ip,
                             mac=updated.get("mac"),
                             message="설비 복구(개별 재확인): " + ip)
    elif not now_online and was_online:
        db.save_device_event(db_path, "device_offline", "warning", subnet=subnet, ip=ip,
                             mac=updated.get("mac"), switch_id=updated.get("switch_id"),
                             label=updated.get("switch_name"),
                             message="설비 연결 끊김(개별 재확인): " + ip)
    utils.log_event("info", "facility_single_recollect", ip=ip, subnet=subnet,
                    online=now_online, switch=updated.get("switch_name"))
    return True, ("온라인 확인됨" + (" (%s %s)" % (updated["switch_name"], updated.get("port") or "")
                                   if updated.get("switch_name") else "")
                  if now_online else "오프라인 — 응답 없음")


def recollect_offline_facility(db_path, source_ip=None, switch_filter=None):
    """관제의 '설비 연결 실패' 카테고리 전체를 대역별로 묶어 일괄 재확인.

    개별 재수집(recollect_single_host)과 원리는 같지만, 여러 설비를 한 번에
    처리할 때 설비마다 새로 접속하면 대역이 여러 개일 때 시간이 그만큼 배로
    든다. 대역(=게이트웨이 스위치) 하나당 세션을 한 번만 열어 재사용하고,
    그 대역에서 오프라인인 IP들만 ping한다(대역 전체 스윕이 아니다).

    switch_filter를 주면 그 연결 스위치의 오프라인 설비만 대상으로 한다
    (관제 화면의 스위치별 칩 필터와 대응).

    반환: {"checked", "online", "still_offline", "no_gateway": [subnet,...],
           "no_cred": [subnet,...], "errors": {subnet: msg}}
    """
    hosts = [h for h in db.get_facility_hosts(db_path) if not h.get("online")]
    if switch_filter:
        hosts = [h for h in hosts if (h.get("switch_name") or "미확인") == switch_filter]
    result = {"checked": 0, "online": 0, "still_offline": 0,
              "no_gateway": [], "no_cred": [], "errors": {}}
    if not hosts:
        return result

    by_subnet = {}
    for h in hosts:
        by_subnet.setdefault(h.get("subnet"), []).append(h["ip"])
    band_map = get_band_map(db_path)

    for subnet, ips in by_subnet.items():
        switch_id = band_map.get(subnet)
        sw = db.get_switch(db_path, switch_id) if switch_id else None
        if not switch_id or not sw:
            result["no_gateway"].append(subnet)
            continue
        username, password = gateway_credential(db_path, switch_id)
        if not username:
            result["no_cred"].append(subnet)
            continue
        try:
            net = ipaddress.IPv4Network(subnet, strict=False)
        except (ipaddress.AddressValueError, ValueError):
            result["errors"][subnet] = "잘못된 대역 형식"
            continue

        conn = None
        try:
            conn, vendor, parser = _gateway_connect(sw, username, password, source_ip)
            found_map = _probe_ips(conn, vendor, parser, switch_id, net, ips)
        except Exception as e:
            err = _collector._sanitize_error_msg(str(e))
            result["errors"][subnet] = err
            utils.log_event("warning", "facility_bulk_recollect_error",
                            subnet=subnet, error=err)
            continue
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass

        try:
            changed = _apply_host_results(
                db_path, subnet, {ip: found_map.get(ip) for ip in ips})
        except Exception as e:
            result["errors"][subnet] = "결과 저장 실패: %s" % _collector._sanitize_error_msg(str(e))
            continue

        for ip, now_online, was_online in changed:
            result["checked"] += 1
            if now_online:
                result["online"] += 1
                if not was_online:
                    row = next((h for h in db.get_facility_hosts(db_path)
                               if h.get("subnet") == subnet and h.get("ip") == ip), {})
                    db.save_device_event(db_path, "device_online", "info", subnet=subnet,
                                         ip=ip, mac=row.get("mac"),
                                         message="설비 복구(일괄 재확인): " + ip)
            else:
                result["still_offline"] += 1

    utils.log_event("info", "facility_bulk_recollect", checked=result["checked"],
                    online=result["online"], still_offline=result["still_offline"],
                    no_gateway=len(result["no_gateway"]), no_cred=len(result["no_cred"]))
    return result


_KEEP_COLS = ("subnet", "ip", "mac", "switch_id", "switch_name", "port", "direct", "via", "port_desc")


def _apply_scan(db_path, subnet, by_ip, scanned_ips=None):
    """대역 스캔 결과(by_ip: {ip: host})를 이전 상태와 비교해 저장 + 변경 이벤트 기록.

    - 새 IP → new_device 이벤트
    - 이전 online인데 이번에 없음 → device_offline 이벤트 + online=0으로 '유지'(삭제 안 함)
    - 이전 offline인데 이번에 응답 → device_online(복구) 이벤트
    scanned_ips: 중지·부분중단으로 대역 일부만 ping한 경우 '실제 스캔한 IP' 집합.
      이 집합 밖의 기존 설비는 확인되지 않았으므로 상태·이벤트를 그대로 보존한다
      (미스캔 IP를 끊김으로 처리해 대량 허위 알람이 나가던 문제 방지).
    반환: (저장 개수, 새 설비 수, 오프라인 전환 수)
    """
    existing = {h["ip"]: h for h in db.get_facility_hosts(db_path) if h.get("subnet") == subnet}
    merged = list(by_ip.values())   # 이번에 응답한 설비(online=1)
    new_cnt = off_cnt = 0
    added_ips, removed_ips = [], []   # 이번 스캔 diff(추가/끊김) — 완료 배너용
    # MAC 생존 신호: ping(ICMP)에 응답 안 해 ARP에 없더라도, 그 MAC이 아직
    # 스위치 MAC 테이블(최신 스냅샷)에 살아 있으면 '연결됨'으로 본다. ICMP 차단
    # 장비(윈도우 서버·보안장비 등)가 포트 UP·MAC 학습 상태인데 오프라인으로
    # 오탐되던 문제 해결. MAC 테이블은 L2 프레임 기준이라 ARP보다 생존을 잘 반영.
    try:
        mac_alive = set(db.get_mac_to_switchport(db_path).keys())
    except Exception:
        mac_alive = set()
    for ip, host in by_ip.items():
        ex = existing.get(ip)
        if ex is None:
            db.save_device_event(db_path, "new_device", "warning", subnet=subnet, ip=ip,
                                 mac=host.get("mac"), switch_id=host.get("switch_id"),
                                 label=host.get("switch_name"), message="새 설비 감지: " + ip)
            new_cnt += 1
            added_ips.append(ip)
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
        # 중지·부분중단: 실제로 ping하지 않은 IP는 '확인 불가' → 이전 상태 그대로 보존
        if scanned_ips is not None and ip not in scanned_ips:
            merged.append({k: ex.get(k) for k in _KEEP_COLS + ("online",)})
            continue
        # ARP엔 없지만 MAC 테이블에 살아있으면 online 유지(ICMP 차단 장비 오탐 방지)
        ex_mac = (ex.get("mac") or "").lower()
        if ex_mac and ex_mac in mac_alive:
            keep = {k: ex.get(k) for k in _KEEP_COLS}
            keep["online"] = 1
            merged.append(keep)
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
            removed_ips.append(ip)

    # 삭제+저장을 한 트랜잭션으로 — 중간 실패 시 대역이 통째로 사라지던 것 방지
    db.replace_facility_subnet(db_path, subnet, merged)
    # 완료 배너용 diff 스냅샷(설비 페이지에서 추가/끊김을 한눈에)
    _set(last_subnet=subnet, last_added=added_ips[:50], last_removed=removed_ips[:50])
    return len(merged), new_cnt, off_cnt


def reconcile_online_by_mac(db_path):
    """오프라인 설비 중 그 MAC이 스위치 MAC 테이블(최신 스냅샷)에 살아 있으면 online 복원.

    설비 online/offline은 대역 스캔 때만 갱신돼, 스캔을 안 하면 '연결 실패'가 계속 남는다.
    도달성 감시(60초 주기)에서 이 함수를 호출하면, ping/ARP 없이도 스위치 MAC 테이블만
    대조해 '실제로 포트에 살아있는' 설비의 오프라인 오탐을 주기적으로 해소한다.
    스위치 재수집으로 MAC 테이블이 갱신될수록 정확해진다. 반환: 복원한 설비 수.
    """
    try:
        mac_alive = set(db.get_mac_to_switchport(db_path).keys())
    except Exception:
        return 0
    if not mac_alive:
        return 0
    restored = 0
    try:
        hosts = db.get_facility_hosts(db_path)
    except Exception:
        return 0
    changed_by_subnet = {}
    for h in hosts:
        if h.get("online"):
            continue
        mac = (h.get("mac") or "").lower()
        if mac and mac in mac_alive:
            changed_by_subnet.setdefault(h.get("subnet"), []).append(h)
    for subnet, items in changed_by_subnet.items():
        # 해당 대역 전체를 다시 저장하되 대상 호스트만 online=1로
        try:
            allh = [dict(x) for x in hosts if x.get("subnet") == subnet]
            ids = {id(x): x for x in items}
            for x in allh:
                if any(x.get("ip") == it.get("ip") for it in items):
                    x["online"] = 1
            db.replace_facility_subnet(db_path, subnet, allh)
            for it in items:
                restored += 1
                db.save_device_event(db_path, "device_online", "info", subnet=subnet,
                                     ip=it.get("ip"), mac=it.get("mac"),
                                     message="설비 복구(MAC 테이블 확인): " + (it.get("ip") or ""))
        except Exception as e:
            utils.log_event("warning", "facility_reconcile_skip", subnet=subnet,
                            error=_collector._sanitize_error_msg(str(e)))
    if restored:
        utils.log_event("info", "facility_reconciled_online", restored=restored)
    return restored


# 자주 모니터링용 상태 — '서로 다른 MAC 스냅샷에서 연속 실종'을 셈한다.
#
# 예전엔 60초 감시 '주기 횟수'를 셌는데, 판정 입력인 MAC 스냅샷은 스위치를
# 재수집할 때만 갱신된다. 같은 스냅샷을 두 번 본 것뿐인데 2분 만에 오프라인으로
# 넘어가 조용한 설비(PLC 등)의 MAC이 aging되면 곧바로 끊김 알람이 떴다.
# 스냅샷 세대가 실제로 바뀐 경우에만 카운트해야 디바운스 의미가 생긴다.
_MISS_THRESHOLD = 2      # 서로 다른 MAC 스냅샷에서 N회 연속 실종 시 오프라인 전환
_miss_counts = {}        # {(subnet, ip): (연속 실종 횟수, 마지막으로 센 스냅샷 세대)}


def _mac_generation(db_path):
    """MAC 스냅샷 세대 — 스위치별 '최신 MAC 스냅샷 id'의 조합.

    이 값이 그대로면 판정 입력이 바뀌지 않은 것이므로 실종 횟수를 세지 않는다.
    """
    try:
        with db.get_db(db_path) as conn:
            rows = conn.execute(
                "SELECT switch_id, MAX(snapshot_id) m FROM mac_entries "
                "GROUP BY switch_id ORDER BY switch_id").fetchall()
        return tuple((r[0], r[1]) for r in rows)
    except Exception:
        return ()


def monitor_known_hosts(db_path):
    """이미 수집된 설비를 '자주'(도달성 감시 60초 주기) 재판정 — 대역 재스캔 없이.

    대역 전체 ping 스윕은 하루 1회지만, 그 사이 연결 끊김/복구를 빨리 알기 위해
    스위치 MAC 테이블(최신 스냅샷)만으로 online↔offline을 양방향 갱신한다.
      - 오프라인인데 MAC 살아있음 → online 복구(+ device_online)
      - 온라인인데 MAC 실종이 연속 _MISS_THRESHOLD회 → offline(+ device_offline)
    순간적인 MAC aging 오탐을 막기 위해 연속 실종 횟수로 디바운스한다.
    스위치 재수집으로 MAC 테이블이 자주 갱신될수록 정확해진다.
    대역 수집이 진행 중이면 건너뛴다(스캔이 곧 정확히 갱신). 반환: (복구수, 끊김수).
    """
    if get_status().get("running"):
        return (0, 0)
    try:
        mac_map = db.get_mac_to_switchport(db_path)
        mac_alive = set(mac_map.keys())
    except Exception:
        return (0, 0)
    if not mac_alive:
        return (0, 0)   # MAC 스냅샷이 아예 없으면(수집 전) 판단 보류
    try:
        hosts = db.get_facility_hosts(db_path)
        port_counts = db.get_port_mac_counts(db_path)
        pc_map = db.get_port_channel_members(db_path)
        port_descs = db.get_port_descriptions(db_path)
    except Exception:
        return (0, 0)
    changed = {}        # {subnet: True} — 저장 필요 대역
    online_now, offline_now = [], []
    relinked = 0        # 연결 스위치를 새로 찾아 채운 설비 수
    seen_keys = set()
    generation = _mac_generation(db_path)   # 판정 입력이 실제로 바뀌었는지 구분
    for h in hosts:
        subnet = h.get("subnet")
        ip = h.get("ip")
        key = (subnet, ip)
        seen_keys.add(key)
        mac = (h.get("mac") or "").lower()
        if not mac:
            continue
        alive = mac in mac_alive
        # 연결 스위치/포트는 지금까지 '대역 스캔' 때만 계산돼, 스캔 시점에 스위치가
        # 아직 수집 전이면 영영 빈칸으로 남았다(스위치를 나중에 수집해도 안 채워짐).
        # MAC이 살아 있으면 여기서 다시 대조해 채운다 — 재스캔 없이 자가 복구.
        if alive:
            sid, sname, port, direct, via = _choose_attachment(
                mac_map.get(mac, []), port_counts, pc_map)
            if sname and (h.get("switch_name") != sname or h.get("port") != port):
                if not h.get("switch_name"):
                    relinked += 1
                h["switch_id"] = sid
                h["switch_name"] = sname
                h["port"] = port
                h["direct"] = 1 if direct else 0
                h["via"] = "; ".join(via) if via else None
                h["port_desc"] = port_descs.get((sid, (port or "").lower()))
                changed[subnet] = True
        if h.get("online"):
            if alive:
                _miss_counts.pop(key, None)
            else:
                n, last_gen = _miss_counts.get(key, (0, None))
                if last_gen == generation:
                    continue      # 같은 MAC 스냅샷을 또 본 것뿐 — 새 근거가 아니다
                n += 1
                _miss_counts[key] = (n, generation)
                if n >= _MISS_THRESHOLD:
                    h["online"] = 0
                    changed[subnet] = True
                    offline_now.append(h)
                    _miss_counts.pop(key, None)
        else:
            if alive:
                h["online"] = 1
                changed[subnet] = True
                online_now.append(h)
                _miss_counts.pop(key, None)
    # 사라진 호스트의 miss 카운터 정리(메모리 누수 방지)
    for k in [k for k in _miss_counts if k not in seen_keys]:
        _miss_counts.pop(k, None)
    if not changed:
        return (0, 0)
    # 대역별로 다시 저장(현재 hosts 리스트에 online 필드가 갱신돼 있음)
    for subnet in changed:
        try:
            rows = [{k: x.get(k) for k in _KEEP_COLS + ("online",)}
                    for x in hosts if x.get("subnet") == subnet]
            db.replace_facility_subnet(db_path, subnet, rows)
        except Exception as e:
            utils.log_event("warning", "facility_monitor_save_skip", subnet=subnet,
                            error=_collector._sanitize_error_msg(str(e)))
    for h in online_now:
        db.save_device_event(db_path, "device_online", "info", subnet=h.get("subnet"),
                             ip=h.get("ip"), mac=h.get("mac"),
                             message="설비 복구(MAC 테이블 확인): " + (h.get("ip") or ""))
    for h in offline_now:
        _loc = ""
        if h.get("switch_name") and h.get("port"):
            _loc = " (마지막 위치: %s %s)" % (h["switch_name"], h["port"])
        elif h.get("switch_name"):
            _loc = " (마지막 스위치: %s, 포트 미확인)" % h["switch_name"]
        db.save_device_event(db_path, "device_offline", "warning", subnet=h.get("subnet"),
                             ip=h.get("ip"), mac=h.get("mac"), switch_id=h.get("switch_id"),
                             label=h.get("switch_name"),
                             message="설비 연결 끊김(MAC 실종): " + (h.get("ip") or "") + _loc)
    if online_now or offline_now or relinked:
        utils.log_event("info", "facility_monitor", restored=len(online_now),
                        dropped=len(offline_now), relinked=relinked)
    return (len(online_now), len(offline_now))


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


def explain_attachment(db_path, ip):
    """설비 하나의 '연결 스위치' 판정 근거를 사람이 읽을 수 있게 풀어서 반환.

    같은 장비를 두고 "왜 백본으로 나오냐"를 여러 번 확인하게 되는데, 판정에 쓰인
    입력(MAC 관측 위치·포트별 MAC 수·포트채널 멤버·CDP 이웃)이 화면에 없어서
    매번 장비에 직접 들어가 대조해야 했다. 그 입력을 그대로 보여준다.

    반환: {"ok": bool, "ip", "mac", "stored": {...}, "observations": [...],
           "decision": {...}, "hints": {...}}  (ok=False면 "error")
    """
    target = None
    for h in db.get_facility_hosts(db_path):
        if str(h.get("ip")) == str(ip):
            target = h
            break
    if not target:
        return {"ok": False, "error": "설비 목록에 없는 IP입니다: %s" % ip}

    mac = (target.get("mac") or "").lower()
    mac_map = db.get_mac_to_switchport(db_path)
    port_counts = db.get_port_mac_counts(db_path)
    pc_map = db.get_port_channel_members(db_path)
    port_descs = db.get_port_descriptions(db_path)
    uplinks = uplink_ports(db_path)
    matches = mac_map.get(mac, [])

    # 이웃 정보는 "왜 업링크로 봤는가"의 근거라 포트별로 붙여 준다.
    nbr_by_port = {}
    try:
        for n in db.get_all_neighbors(db_path):
            key = (n.get("switch_id"), str(n.get("local_port") or "").strip().lower())
            nbr_by_port.setdefault(key, []).append(n)
    except Exception:
        pass

    obs = []
    for sid, sname, port in matches:
        pl = str(port or "").strip().lower()
        members = pc_map.get((sid, pl)) or []
        nbrs = list(nbr_by_port.get((sid, pl), []))
        for m in members:                       # Po면 멤버 포트의 이웃도 근거
            nbrs.extend(nbr_by_port.get((sid, str(m).strip().lower()), []))
        cnt = port_counts.get((sid, pl))
        obs.append({
            "switch_id": sid, "switch_name": sname, "port": port,
            "mac_count": cnt,                   # None = 해당 포트 집계 없음(미상)
            "physical": _is_physical_port(port),
            "members": members,
            "is_uplink": (sid, pl) in uplinks,
            "port_desc": port_descs.get((sid, pl)),
            "neighbors": [{"remote_name": n.get("remote_name"),
                           "remote_ip": n.get("remote_ip"),
                           "remote_port": n.get("remote_port"),
                           "local_port": n.get("local_port")} for n in nbrs],
        })

    sid, sname, port, direct, via = _choose_attachment(matches, port_counts, pc_map, uplinks)
    if not matches:
        why = "최신 MAC 테이블 어디에서도 이 MAC이 보이지 않습니다(설비 오프라인 후 에이징이거나 연결 스위치 미수집)."
    elif direct:
        why = "액세스 포트로 판단했습니다 — 이 포트 너머에 등록된 스위치가 없고, 학습된 MAC도 소수입니다."
    else:
        upn = [o for o in obs if o["is_uplink"]]
        if upn:
            why = ("관측된 포트가 모두 업링크(트렁크)입니다 — 그 너머에 등록된 스위치가 있어 "
                   "설비가 실제로 꽂힌 지점이 아닙니다. 설비가 물린 액세스 스위치를 수집하면 정확해집니다.")
        else:
            why = "액세스 포트로 확정할 근거가 부족합니다(포트에 MAC이 많거나 논리 인터페이스로만 관측)."

    hints = {}
    try:
        hist = db.find_location_by_mac(db_path, mac) if mac else None
        if hist:
            hints["history"] = hist
    except Exception:
        pass
    try:
        d = db.find_port_by_description(db_path, str(ip))
        if d:
            hints["port_description"] = d
    except Exception:
        pass

    return {"ok": True, "ip": str(ip), "mac": target.get("mac"),
            "stored": {"switch_name": target.get("switch_name"), "port": target.get("port"),
                       "direct": target.get("direct"), "online": target.get("online"),
                       "updated": target.get("updated")},
            "observations": obs,
            "decision": {"switch_name": sname, "port": port, "direct": bool(direct),
                         "via": via, "why": why},
            "hints": hints}


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
    uplinks = uplink_ports(db_path)
    updated = []
    for h in hosts:
        mac = (h.get("mac") or "").lower()
        matches = mac_map.get(mac, [])
        sid, sname, port, direct, via = _choose_attachment(matches, port_counts, pc_map, uplinks)
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
    global _stop_requested, _worker
    with _lock:
        _stop_requested = False   # 새 전체 스캔 시작 — 이전 중지 요청 잔류 해제
    band_map = get_band_map(db_path)
    scanned = skipped = 0
    src = pcprofile.get_source_ip(db_path)
    for subnet, switch_id in band_map.items():
        if _is_stop_requested():   # 사용자 중지 → 남은 대역 스캔 취소
            utils.log_event("info", "facility_auto_scan_stopped", scanned=scanned)
            break
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
                _reap_dead_worker()
                if _status["running"]:
                    skipped += 1
                    continue
                _status["running"] = True
                _status["message"] = "자동 스캔: " + subnet
                _status["started_at"] = time.time()
                # 이 스레드를 주인으로 등록해야, 도중에 죽어도 다음 요청이
                # 잔류 플래그를 풀 수 있다(안 하면 재수집이 영영 409).
                _worker = threading.current_thread()
            _res = collect_band(db_path, switch_id, subnet, username, password, src)
            scanned += 1
            # collect_band는 중지 플래그를 '소비 완료'로 보고 스스로 해제한다.
            # 그래서 다음 대역에서 _is_stop_requested()를 물으면 이미 False라
            # 사용자가 중지를 눌러도 남은 대역이 계속 스캔됐다(대역당 수 분~수십 분).
            # 반환값으로 중지 여부를 직접 확인한다.
            if (_res or {}).get("stopped"):
                utils.log_event("info", "facility_auto_scan_stopped",
                                scanned=scanned, at=subnet)
                break
        except Exception as e:
            _set(running=False, message="자동 스캔 실패: " + subnet)
            utils.log_event("error", "facility_auto_scan_error", subnet=subnet,
                            error=_collector._sanitize_error_msg(str(e)))
        finally:
            dec = username = password = None
    with _lock:
        if _worker is threading.current_thread():
            _worker = None
    utils.log_event("info", "facility_auto_scan_done", scanned=scanned, skipped=skipped)
    return {"scanned": scanned, "skipped": skipped}


def start_collect_band(db_path, switch_id, subnet, username, password, source_ip=None):
    """백그라운드 스레드로 대역 수집 시작. 이미 실행 중이면 거부.

    TOCTOU 방지: running 플래그를 같은 lock 구간에서 즉시 True로 set한다.
    """
    global _stop_requested, _worker
    with _lock:
        # 죽은 스레드의 잔류 플래그면 여기서 푼다 — 아니면 재수집이 영영 409다.
        _reap_dead_worker()
        if _status["running"]:
            return False
        _status["running"] = True
        _status["message"] = "시작 중"
        _status["started_at"] = time.time()
        # 이전 스캔의 잔류 플래그를 여기서 해제한다(스레드 시작 전 = 경합 없음)
        _stop_requested = False
    def _run():
        global _worker
        try:
            collect_band(db_path, switch_id, subnet, username, password, source_ip)
        except Exception as e:
            _set(running=False, message="실패: " + _collector._sanitize_error_msg(str(e)))
            utils.log_event("error", "facility_collect_error",
                            error=_collector._sanitize_error_msg(str(e)))
        finally:
            # 어떤 경로로 끝나든 '수집 중'으로 남지 않게 한다. collect_band가
            # running=False를 놓치는 경로(중간 return 등)까지 여기서 덮는다.
            _set(running=False)
            # 끝난 스레드를 주인으로 남겨두면, 나중에 다른 경로가 running을 켰을 때
            # '죽은 주인'으로 보여 엉뚱하게 초기화된다.
            with _lock:
                if _worker is t:
                    _worker = None
    t = threading.Thread(target=_run, daemon=True)
    with _lock:
        _worker = t
    t.start()
    return True
