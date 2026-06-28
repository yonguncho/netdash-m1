import logging
import re
from collections import defaultdict
from . import db
from . import utils
from config import get_config

logger = logging.getLogger(__name__)


# ── M7: 장부(엑셀) vs 실측(수집) 대조 ─────────────────────────────
# 물리 이더넷 인터페이스 타입 (동등 비교를 위해 접두사 제거).
# 논리/특수 타입(po, mgmt, lo, vlan, port-channel 등)은 접두사를 보존해
# 물리 포트와의 오매칭(예: 'Po1' vs 물리 '1')을 방지한다.
_PHYSICAL_PORT_PREFIXES = {
    "", "gigabitethernet", "gi", "ge", "tengige", "tengigabitethernet", "te",
    "fortygige", "fo", "hundredgige", "hu", "twentyfivegige", "twentyfivegig",
    "fastethernet", "fa", "ethernet", "eth", "et",
    # Juniper 인터페이스 타입 (xe=10G, fe=fast, ge/et 공통, ce/xle)
    "xe", "fe", "ce", "xle", "me",
}


def normalize_port(p):
    """비교용 포트 표기 정규화: 장부 표기와 실측 표기를 맞비교하기 위해
    인터페이스 타입 접두사를 정규화한다.

    - 물리 이더넷('GigabitEthernet1/0/5','Gi1/0/5','Eth1/1')은 타입 접두사를
      제거해 동등 비교 가능하게: → '1/0/5', '1/1'.
    - 서브인터페이스('1/0/5.100')는 숫자부 전체를 보존(점 포함) → '1/0/5.100'.
    - Extreme 콜론('1:12') 보존, 단독 포트('5') 보존.
    - 논리/특수 포트('Po1','Mgmt0','Vlan10')는 타입 태그를 보존해 물리 포트와
      충돌하지 않게 → 'po1','mgmt0','vlan10'.
    - None/빈값 → "".

    parsers.utils.normalize_port 와는 목적이 다르다(파싱 표준화 vs 비교 정규화).
    """
    if not p:
        return ""
    p = str(p).strip().lower().replace(" ", "")
    # 알파벳 인터페이스 타입 접두사 + 숫자로 시작하는 식별자부 분리
    m = re.match(r"^([a-z\-]*?)(\d.*)$", p)
    if not m:
        return p  # 숫자가 없는 포트명은 원본 유지
    # trailing 하이픈 제거: Juniper 'xe-0/0/1' → prefix 'xe', num '0/0/1'
    prefix, num = m.group(1).rstrip("-"), m.group(2)
    if prefix in _PHYSICAL_PORT_PREFIXES:
        return num
    return f"{prefix}{num}"


def _switch_key(name):
    """스위치명 비교 키: 앞뒤 공백 제거 + 소문자 + FQDN 첫 레이블만.
    'ACC-SW01' 과 'acc-sw01.corp.local' 을 동일 스위치로 본다.
    """
    return (name or "").strip().lower().split(".")[0]


def reconcile(db_path):
    """장부 위치(ledger_switch/port) ↔ 실측 위치(switch_id/port) 비교.

    판정 6종:
      match           장부 = 실측 (스위치명 + 포트 일치)
      port_mismatch   스위치 같고 포트 다름
      switch_mismatch 실측 스위치가 장부와 다름
      ledger_only     장부엔 위치 있는데 실측 안 됨
      measured_only   실측됐는데 장부에 위치 없음
      no_data         장부도 실측도 위치 없음

    measured 판정은 located(측정 위치 유효성의 정답 신호)에 기반한다. switch_id가
    있어도 located=0이면 "위치 미확정"으로 보고 실측 없음으로 취급한다.

    반환: {"hosts": [판정 레코드...], "summary": {판정: 카운트}}
    """
    hosts = db.list_hosts(db_path)
    switches = {s["id"]: s["name"] for s in db.get_switches(db_path)}
    out = []
    counts = defaultdict(int)
    for h in hosts:
        led_sw = (h.get("ledger_switch") or "").strip()
        led_pt = normalize_port(h.get("ledger_port"))
        has_ledger = bool(led_sw)
        measured = bool(h.get("located"))
        actual_sw = switches.get(h.get("switch_id"), "") if h.get("switch_id") else ""
        actual_pt = normalize_port(h.get("port"))

        if has_ledger and measured:
            same_sw = _switch_key(led_sw) == _switch_key(actual_sw)
            same_pt = led_pt == actual_pt
            if same_sw and same_pt:
                verdict = "match"
            elif same_sw:
                verdict = "port_mismatch"
            else:
                verdict = "switch_mismatch"
        elif has_ledger and not measured:
            verdict = "ledger_only"
        elif not has_ledger and measured:
            verdict = "measured_only"
        else:
            verdict = "no_data"

        counts[verdict] += 1
        out.append({
            "ip": h["ip"],
            "hostname": h.get("hostname", ""),
            "verdict": verdict,
            "ledger_switch": led_sw,
            "ledger_port": h.get("ledger_port", ""),
            "actual_switch": actual_sw,
            "actual_port": h.get("port", ""),
        })
    utils.log_event("info", "reconcile_done", total=len(out), summary=dict(counts))
    return {"hosts": out, "summary": dict(counts)}


def correlate(db_path):
    utils.log_event("info", "correlate_start")

    config = get_config()
    uplink_threshold = config.get_uplink_threshold()

    arps = db.get_arp_entries(db_path)
    macs = db.get_mac_entries(db_path)

    uplink_ports = _identify_uplink_ports(macs, uplink_threshold)
    utils.log_event("info", "uplink_ports_identified", count=len(uplink_ports))

    hosts = _join_arp_mac(arps, macs, uplink_ports)

    db.save_hosts(db_path, hosts)

    utils.log_event("info", "correlate_done", total_ips=len(hosts))

    return {
        "hosts": hosts,
        "stats": {
            "total_ips": len(hosts),
            "located_ips": sum(1 for h in hosts.values() if h.get("located")),
            "accuracy": sum(1 for h in hosts.values() if h.get("located")) / len(hosts) if hosts else 0
        }
    }


def _identify_uplink_ports(macs, threshold):
    port_mac_count = defaultdict(int)

    for mac_entry in macs:
        port_key = (mac_entry.get("switch_id"), mac_entry.get("port"))
        port_mac_count[port_key] += 1

    uplink_ports = set()
    for port_key, count in port_mac_count.items():
        if count >= threshold:
            uplink_ports.add(port_key)
            utils.log_event("debug", "uplink_port_detected", switch_id=port_key[0], port=port_key[1], mac_count=count)

    return uplink_ports


def _join_arp_mac(arps, macs, uplink_ports):
    hosts = {}

    mac_to_port = {}
    for mac_entry in macs:
        mac = mac_entry.get("mac")
        switch_id = mac_entry.get("switch_id")
        port = mac_entry.get("port")

        port_key = (switch_id, port)
        if port_key not in uplink_ports:
            mac_to_port[mac] = (switch_id, port)

    for arp_entry in arps:
        ip = arp_entry.get("ip")
        mac = arp_entry.get("mac")

        if mac in mac_to_port:
            switch_id, port = mac_to_port[mac]
            hosts[ip] = {
                "mac": mac,
                "switch_id": switch_id,
                "port": port,
                "located": True,
                "confidence": 0.95,
                "reason": None
            }
        else:
            hosts[ip] = {
                "mac": mac,
                "switch_id": None,
                "port": None,
                "located": False,
                "confidence": 0.0,
                "reason": "MAC not found in any port"
            }

    return hosts
