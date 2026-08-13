# -*- coding: utf-8 -*-
"""v6.37.0 — FortiOS 버전 표기 통일 + 구버전 REST 미수집 사유 기록.

사용자 신고 2건:
① 어떤 장비는 'v7.4.6, build2726, 241210 (GA.M)', 어떤 장비는 'v7.4.6'으로 표시.
② 6.0/6.2 장비가 7.0 이상보다 덜 수집되는 것 같다 — 원인 파악.
"""
import os

import pytest

from core.firewall import fortigate, fortiperf


# ── ① 버전 표기 통일 ──────────────────────────────────────────────

@pytest.mark.parametrize("raw,want", [
    ("v7.4.6,build2726,241210 (GA.M)", "v7.4.6"),
    ("v7.4.6, build2726, 241210 (GA.M)", "v7.4.6"),   # 공백 있는 표기
    ("v7.4.6", "v7.4.6"),
    ("v6.0.14,build0632,220304 (GA)", "v6.0.14"),
    ("v7.2.5 (GA.F)", "v7.2.5"),                      # 콤마 없이 등급만
    ("FortiGate-1000D v6.0.14", "v6.0.14"),           # SNMP는 모델이 앞에 붙기도
    ("6.2.9", "v6.2.9"),                              # SNMP는 v 없이 주기도
    ("", ""),
    (None, ""),
])
def test_norm_version(raw, want):
    assert fortiperf.norm_version(raw) == want


def test_ssh_rest_snmp_agree_on_same_firmware():
    """세 경로가 같은 펌웨어를 같은 문자열로 표기해야 한다(사용자 신고의 핵심).

    예전엔 SNMP만 원문을 저장해 같은 화면에서 표기가 섞였다.
    """
    from core import snmp_fortigate
    ssh = fortiperf.parse_sys_status(
        "Version: FortiGate-1100E v7.4.6,build2726,241210 (GA.M)\n"
        "Serial-Number: FG1K1E0000000000\nHostname: FW-01")["version"]
    snmp = snmp_fortigate._norm_version("v7.4.6,build2726,241210 (GA.M)")
    rest = fortiperf.norm_version("v7.4.6,build2726,241210 (GA.M)")
    assert ssh == snmp == rest == "v7.4.6"


def test_parse_sys_status_keeps_other_fields():
    got = fortiperf.parse_sys_status(
        "Version: FortiGate-1000D v6.0.14,build0632,220304 (GA)\n"
        "Serial-Number: FG1K0D1234\nHostname: FW-OLD")
    assert got["version"] == "v6.0.14"
    assert got["model"] == "FortiGate-1000D"
    assert got["serial"] == "FG1K0D1234" and got["hostname"] == "FW-OLD"


# ── ② 미수집 사유 기록 ────────────────────────────────────────────

class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.headers = {}

    def json(self):
        return self._payload


class _Sess:
    """요청 URL별 응답을 미리 정해두는 가짜 세션."""

    def __init__(self, table, default=404):
        self.table = table
        self.default = default
        self.seen = []

    def get(self, url, timeout=None):
        self.seen.append(url)
        for key, resp in self.table.items():
            if key in url:
                return resp
        return _Resp(self.default)


def test_404_is_recorded_as_missing_api():
    """6.x에 없는 API는 '이 펌웨어에 없는 API'로 남아야 한다 —
    예전엔 except: pass 라 흔적이 없었다."""
    notes = {}
    s = _Sess({})                       # 전부 404
    assert fortigate._fetch_license(s, "https://fw", "fw", notes) is None
    assert "라이선스" in notes and "404" in notes["라이선스"]


def test_403_retries_with_vdom_then_succeeds():
    """403은 멀티 VDOM 장비에서 흔하다 — vdom=root로 한 번 더 시도한다."""
    calls = {"n": 0}

    class S:
        def get(self, url, timeout=None):
            calls["n"] += 1
            if "vdom=root" in url:
                return _Resp(200, {"results": {"forticare": {}}})
            return _Resp(403)

    notes = {}
    fortigate._fetch_license(S(), "https://fw", "fw", notes)
    assert calls["n"] == 2                      # 원 요청 + vdom 재시도
    assert "라이선스" not in notes              # 재시도가 성공하면 사유를 남기지 않는다


def test_403_without_vdom_success_is_recorded():
    notes = {}
    s = _Sess({}, default=403)
    fortigate._fetch_license(s, "https://fw", "fw", notes)
    assert "403" in notes["라이선스"]
    assert "VDOM" in notes["라이선스"] or "권한" in notes["라이선스"]


def test_partial_collection_records_only_failed_items():
    """성공한 항목은 사유에 남지 않는다 — 다 남기면 무엇이 문제인지 묻힌다."""
    notes = {}
    s = _Sess({
        "monitor/vpn/ipsec": _Resp(200, {"results": []}),
        "monitor/vpn/ssl": _Resp(404),
    })
    fortigate._fetch_vpn(s, "https://fw", "fw", notes)
    assert "VPN 터널" not in notes
    assert "SSL VPN" in notes


def test_policy_unused_counts_packets_field():
    """6.x는 hit_count 없이 packets/bytes만 주는 펌웨어가 있다 —
    그걸 못 보면 실제로 쓰는 정책이 '미사용'으로 잡힌다."""
    s = _Sess({
        "cmdb/firewall/policy": _Resp(200, {"results": [{"status": "enable"}] * 3}),
        "monitor/firewall/policy": _Resp(200, {"results": [
            {"packets": 100}, {"bytes": 50}, {"hit_count": 0, "packets": 0, "bytes": 0},
        ]}),
    })
    out = fortigate._fetch_policy_stats(s, "https://fw", "fw", {})
    assert out["total"] == 3
    assert out["unused"] == 1          # 셋 다 0인 한 건만


def test_collect_returns_notes_key():
    """수집 결과에 rest_notes가 실려야 저장·화면까지 이어진다."""
    import inspect
    src = inspect.getsource(fortigate.collect)
    assert "rest_notes" in src


def test_app_js_shows_missing_items():
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "web", "static", "app.js")
    with open(p, encoding="utf-8") as f:
        js = f.read()
    assert "rest_notes" in js
    assert "수집되지 않은 항목" in js


def test_collector_replaces_notes_each_run():
    """사유는 매 수집마다 교체돼야 한다 — 남겨두면 고친 뒤에도 계속 뜬다."""
    import inspect
    from core import collector
    src = inspect.getsource(collector.merge_fw_extra)
    assert 'cur["rest_notes"] = notes or None' in src
