# -*- coding: utf-8 -*-
"""전체 코드 감사(v3.55.x) 확정 버그 회귀 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import arista_eos, cisco_nxos

ROOT = Path(__file__).parent.parent
APP_JS = ROOT / "web" / "static" / "app.js"


def test_arista_mac_dot_and_colon_formats():
    """Arista MAC 테이블: dot(0011.2233.44aa)·colon 형식 모두 파싱(콜론만 되던 버그)."""
    out = (
        "Vlan    Mac Address       Type        Ports\n"
        "100     0011.2233.44aa    DYNAMIC     Et1\n"
        "200     00:11:22:33:44:bb DYNAMIC     Et2\n"
    )
    macs = arista_eos._parse_macs(out, 1)
    ports = {m["port"] for m in macs}
    assert len(macs) == 2
    assert "Et1" in ports and "Et2" in ports


def test_arista_arp_dot_format():
    """Arista ARP: dot 형식 MAC 파싱."""
    out = (
        "Address         Age (min)  Hardware Addr   Interface\n"
        "10.0.0.1        0          0011.2233.44aa  Vlan100\n"
    )
    arps = arista_eos._parse_arps(out, 1)
    assert len(arps) == 1 and arps[0]["ip"] == "10.0.0.1"


def test_nxos_err_disabled_mapping():
    """NX-OS err-disabled가 'error-disabled'로 뭉개지지 않고 'err-disabled' 반환."""
    assert cisco_nxos._map_status("err-disabled") == "err-disabled"
    assert cisco_nxos._map_status("errdisabled") == "err-disabled"
    assert cisco_nxos._map_status("disabled") == "error-disabled"   # 순수 disabled는 유지
    assert cisco_nxos._map_status("connected") == "up"


def test_rate_limit_gc(client):
    """rate limit 딕셔너리가 만료 키를 정리(무한 누적 방지)."""
    import app as _app
    _app._rate_limit_tracker.clear()
    # 512 초과하도록 만료된 더미 키 삽입
    old = 0.0  # 아주 오래된 타임스탬프(항상 만료)
    for i in range(600):
        _app._rate_limit_tracker["ep:%d" % i] = [old]
    # rate_limit 데코레이터가 적용된 엔드포인트 호출 → gc 트리거
    client.post("/api/switches/manual", json={"ip": "10.0.0.1", "name": "X", "vendor": "cisco"})
    # 만료된 키들이 정리되어 크게 줄어야
    assert len(_app._rate_limit_tracker) < 300


def test_topo_window_listener_cleanup_present():
    js = APP_JS.read_text(encoding="utf-8")
    assert "_topoWinClear" in js and "_topoWinOn" in js
    assert "_topoWinClear();" in js                # renderTopology 진입 시 정리
    # galaxy/zoompan이 추적형 등록 사용(직접 window.addEventListener 잔존 최소화)
    assert 'window.addEventListener("mouseup", function () { drag = null; });' not in js


def test_webshell_no_query_credentials():
    """웹셸 WS가 쿼리 파라미터 u/p로 자격증명을 받지 않음(로그 노출 방지)."""
    import inspect
    import app as _app
    src = inspect.getsource(_app.create_app)
    assert 'request.args.get("u"' not in src
    assert 'request.args.get("p"' not in src
