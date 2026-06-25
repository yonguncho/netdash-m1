"""M3: 포트 Flapping / Looping 감지 모듈.

수집된 포트 상태 스냅샷을 이전 스냅샷과 비교해서
- 단시간(기본 5분) 내 N회(기본 3회) 이상 up↔down 전환 → flapping
- 업링크 아닌 포트에서 MAC 테이블 급증 → looping 의심
"""

import logging
from datetime import datetime, timezone
from . import db as _db
from .utils import log_event

logger = logging.getLogger(__name__)

FLAP_THRESHOLD = 3      # 이 횟수 이상이면 flapping 경보
LOOP_MAC_THRESHOLD = 50 # 단일 포트에서 이 수 이상 MAC → looping 의심


def analyze_flapping(db_path, switch_id, new_ports: list[dict]) -> list[dict]:
    """
    새 포트 목록과 이전 스냅샷 포트를 비교해 Flapping 이벤트를 기록.
    반환: 감지된 이벤트 목록 [{port_name, event_type, count}]
    """
    events = []
    prev_ports = _db.get_ports_by_switch(db_path, switch_id)
    prev_map = {p["name"]: p["status"] for p in prev_ports}

    for port in new_ports:
        name = port.get("name") or port.get("port")
        status = port.get("status") or port.get("link")
        prev_status = prev_map.get(name)

        if prev_status and prev_status != status:
            _db.upsert_port_event(db_path, switch_id, name, "flapping")
            port_events = _db.get_port_events(db_path, switch_id)
            for pe in port_events:
                if pe["port_name"] == name and pe["event_type"] == "flapping":
                    count = pe["count"]
                    if count >= FLAP_THRESHOLD:
                        events.append({"port_name": name, "event_type": "flapping", "count": count})
                        log_event("warning", "flapping_detected", switch_id=switch_id, port=name, count=count)

    return events


def analyze_looping(db_path, switch_id, new_macs: list[dict]) -> list[dict]:
    """
    포트별 MAC 주소 수를 확인해 Looping 의심 이벤트를 기록.
    반환: 감지된 이벤트 목록 [{port_name, event_type, mac_count}]
    """
    events = []
    port_mac_count: dict[str, int] = {}
    for mac in new_macs:
        port = mac.get("port", "")
        port_mac_count[port] = port_mac_count.get(port, 0) + 1

    for port, count in port_mac_count.items():
        if count >= LOOP_MAC_THRESHOLD:
            _db.upsert_port_event(db_path, switch_id, port, "looping")
            events.append({"port_name": port, "event_type": "looping", "mac_count": count})
            log_event("warning", "looping_suspected", switch_id=switch_id, port=port, mac_count=count)

    return events


def update_switch_alert(db_path, switch_id, flap_events: list, loop_events: list):
    """감지 결과에 따라 스위치 alert 상태를 업데이트."""
    if loop_events:
        alert = "critical"
    elif flap_events:
        alert = "warning"
    else:
        return
    _db.set_switch_alert(db_path, switch_id, alert)
    log_event("info", "switch_alert_updated", switch_id=switch_id, alert=alert)


def run_analysis(db_path, switch_id, parsed: dict):
    """수집 완료 후 호출: flapping + looping 분석을 한 번에 실행."""
    ports = parsed.get("ports", [])
    macs = parsed.get("macs", []) or parsed.get("mac_entries", [])

    flap_events = analyze_flapping(db_path, switch_id, ports)
    loop_events = analyze_looping(db_path, switch_id, macs)
    update_switch_alert(db_path, switch_id, flap_events, loop_events)

    return {"flapping": flap_events, "looping": loop_events}
