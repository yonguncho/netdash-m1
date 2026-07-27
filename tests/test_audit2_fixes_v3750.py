# -*- coding: utf-8 -*-
"""2026-07-11 2차 감사(수정분 회귀 + 미검토 영역 + 기능 완결성) 수정 회귀 테스트."""
import sys
import inspect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import neighbors
from core.firewall import fortigate


# ── 회귀 R1: NX-OS LLDP 다중 이웃 remote_port 밀림 ──
def test_nxos_lldp_multi_neighbor_no_shift():
    nxos = ("Chassis id: 00c1.6401.0a01\nPort id: Ethernet1/10\n"
            "Local Port id: Eth1/1\nSystem Name: leaf-a\n"
            "Chassis id: 00c1.6402.0b01\nPort id: Ethernet2/20\n"
            "Local Port id: Eth1/2\nSystem Name: leaf-b\n")
    nb = neighbors.parse_lldp_detail(nxos)
    by = {n["local_port"]: n for n in nb}
    assert by["Eth1/1"]["remote_port"] == "Ethernet1/10"
    assert by["Eth1/2"]["remote_port"] == "Ethernet2/20"


def test_ios_arista_lldp_still_ok():
    """NX-OS 분기 도입이 IOS/Arista를 깨지 않아야."""
    ios = "Local Intf: Gi1/0/1\nChassis id: y\nPort id: Gi0/1\nSystem Name: sw2\n"
    assert neighbors.parse_lldp_detail(ios)[0]["remote_port"] == "Gi0/1"
    ar = ('Interface Ethernet1 detected 1 LLDP neighbors:\n'
          '  System Name: "a2"\n  Port ID          : "Ethernet3"\n')
    assert neighbors.parse_lldp_detail(ar)[0]["remote_port"] == "Ethernet3"


# ── 회귀 R2: fortigate REST 세션 close ──
def test_fortigate_collect_closes_session():
    src = inspect.getsource(fortigate.collect)
    assert "finally" in src and "s.close()" in src


# ── 미검토: scheduler auto_collect 비블로킹 ──
def test_scheduler_auto_collect_threaded(monkeypatch):
    """자동 수집은 별도 스레드로 실행돼야 스케줄러 루프가 막히지 않는다.

    문자열 검사 대신 실제로 호출해 확인한다(스레드 생성 코드가 _fire로 옮겨졌다).
    """
    from datetime import datetime
    from core import scheduler
    started = {}

    class _FakeThread:
        def __init__(self, target=None, args=(), daemon=None, name=None):
            started["target"] = target
            started["args"] = args
            started["daemon"] = daemon

        def start(self):
            started["started"] = True

    monkeypatch.setattr(scheduler.threading, "Thread", _FakeThread)
    now = datetime(2026, 7, 27, 6, 0, 10)
    scheduler._fire("auto-collect", "auto_collect_trigger",
                    scheduler.collector.collect_all_registered,
                    "db.sqlite", "06:00", datetime(2026, 7, 27, 6, 0), now)
    assert started.get("started") is True
    assert started["target"] is scheduler.collector.collect_all_registered
    assert started["daemon"] is True


# ── 기능 완결: 방화벽 가드 잠금 누수(가드가 입력파싱 뒤에 위치) ──
def test_firewall_guard_after_input_parse():
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    # collect_firewall_endpoint에서 get_json이 add(fid)보다 먼저 나와야 누수 없음
    fn = src.split("def collect_firewall_endpoint", 1)[1].split("def get_switch_events", 1)[0]
    get_json_pos = fn.find("request.get_json")
    add_pos = fn.find("_collecting_firewalls.add")
    assert 0 < get_json_pos < add_pos, "get_json이 가드 add 뒤에 있어 malformed JSON 시 잠금 누수"


# ── 죽은 코드 제거 확인 ──
def test_dead_code_removed():
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "function renderEventsTab" not in js          # 죽은 함수 제거
    assert "툴바 미제공 — no-op" in js                    # topo 모드 바인딩 no-op화
