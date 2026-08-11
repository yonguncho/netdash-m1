# -*- coding: utf-8 -*-
"""v6.33.2 — FortiOS 6.x 모델명 미수집(사용자 신고) 3중 수정.

① 6.x는 SSH exec 채널 미지원 → 대화형 셸 폴백(_shell_run, --More-- 처리)
② SNMP에 모델 OID(ENTITY-MIB) 추가 + FGT_ 표기 정규화
③ SNMP 지표 저장이 metrics_json을 통째로 덮어 SSH가 채운 모델을 지우던 것
"""
import sys
import types
from pathlib import Path

from core import db, snmp_fortigate
from core.firewall import fortisensor

ROOT = Path(__file__).parent.parent


# ── ② 모델 정규화·수집 ───────────────────────────────────────────

def test_norm_fgt_model():
    f = snmp_fortigate.norm_fgt_model
    assert f("FGT_1000D") == "FortiGate-1000D"
    assert f("FGT-1500D") == "FortiGate-1500D"
    assert f("FortiGate-1100E") == "FortiGate-1100E"
    assert f("fortigate 1000d") == "FortiGate-1000D"
    assert f("FWF_60D") == "FortiWiFi-60D"
    assert f("Fortinet security appliance") == "", "모델처럼 보일 때만 인정"
    assert f("") == "" and f(None) == ""


def test_collect_health_includes_model(monkeypatch):
    class _Sess:
        def __init__(self, *a, **k):
            pass

        def walk(self, *a, **k):
            return []

    monkeypatch.setattr(snmp_fortigate, "_Session", _Sess)
    monkeypatch.setattr(snmp_fortigate, "_scalars", lambda s: {
        snmp_fortigate._ENT_MODEL: b"FGT_1000D",
        snmp_fortigate._FG_VERSION: b"v6.0.14,build0489",
        snmp_fortigate._FG_CPU: b"12", snmp_fortigate._FG_MEM: b"40",
        snmp_fortigate._FG_SESSIONS: b"100"})
    out = snmp_fortigate.collect_health("10.0.0.1", "public")
    assert out["model"] == "FortiGate-1000D"
    assert out["cpu_pct"] == 12


def test_collect_health_model_from_sysdescr_fallback(monkeypatch):
    """ENTITY-MIB이 없으면 sysDescr — 단, 모델 형태일 때만."""
    class _Sess:
        def __init__(self, *a, **k):
            pass

        def walk(self, *a, **k):
            return []

    monkeypatch.setattr(snmp_fortigate, "_Session", _Sess)
    monkeypatch.setattr(snmp_fortigate, "_scalars", lambda s: {
        snmp_fortigate._SYS_DESCR: b"FGT_1500D",
        snmp_fortigate._FG_CPU: b"5"})
    assert snmp_fortigate.collect_health("h", "c")["model"] == "FortiGate-1500D"


# ── ① 6.x 대화형 셸 폴백 ────────────────────────────────────────

class FakeChan:
    """exec 미지원 장비의 대화형 셸 흉내 — --More-- 페이징 포함."""

    def __init__(self, outputs):
        # outputs: {cmd: (첫 청크 목록, --More-- 뒤 청크 목록)}
        self.outputs = outputs
        self.q = [b"Login banner\nFW-6X # "]
        self.after_more = []
        self.sent = []

    def settimeout(self, t):
        pass

    def recv_ready(self):
        return bool(self.q)

    def recv(self, n):
        return self.q.pop(0)

    def send(self, s):
        self.sent.append(s)
        if s == " ":
            self.q.extend(self.after_more)
            self.after_more = []
        else:
            first, rest = self.outputs.get(s.strip(), ([b""], []))
            self.q.extend(first)
            self.after_more = list(rest)

    def close(self):
        pass


class FakeClient:
    def __init__(self, chan, exec_out=b""):
        self._chan = chan
        self._exec_out = exec_out

    def connect(self, *a, **k):
        pass

    def exec_command(self, cmd, timeout=None):
        class _O:
            def __init__(self, b):
                self._b = b

            def read(self):
                return self._b
        return None, _O(self._exec_out), None

    def invoke_shell(self, **k):
        return self._chan

    def set_missing_host_key_policy(self, p):
        pass

    def close(self):
        pass


_STATUS_6X = (b"get system status\n"
              b"Version: FortiGate-1000D v6.0.14,build0489,220331 (GA)\n"
              b"Serial-Number: FG1K0D0000000001\n--More--")
_STATUS_REST = b"\x08\x08\x08Hostname: FW-6X-01\nOperation Mode: NAT\n\nFW-6X # "


def test_shell_run_handles_more_paging():
    chan = FakeChan({"get system status": ([_STATUS_6X], [_STATUS_REST])})
    out = fortisensor._shell_run(FakeClient(chan), ["get system status"], timeout=6)
    txt = out["get system status"]
    assert "Version: FortiGate-1000D v6.0.14" in txt
    assert "Hostname: FW-6X-01" in txt, "--More-- 뒤 내용도 이어 받아야 한다"
    assert "--More--" not in txt and "\x08" not in txt
    assert " " in chan.sent, "--More--에서 스페이스로 계속"
    # 파서까지 통과 — 모델·버전이 나온다
    from core.firewall import fortiperf
    parsed = fortiperf.parse_sys_status(txt)
    assert parsed["model"] == "FortiGate-1000D" and parsed["version"] == "v6.0.14"


def test_ssh_run_falls_back_to_shell_when_exec_empty(monkeypatch):
    """6.x: exec가 전부 빈 출력 → 셸 폴백으로 같은 명령을 다시 받는다."""
    chan = FakeChan({"get system status": ([_STATUS_6X], [_STATUS_REST]),
                     "get system performance status": ([b"CPU states: 3% user\nFW-6X # "], [])})
    client = FakeClient(chan, exec_out=b"")
    fake = types.SimpleNamespace(SSHClient=lambda: client,
                                 AutoAddPolicy=lambda: object())
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    out = fortisensor._ssh_run("10.0.0.1", "admin", "pw",
                               ["get system status", "get system performance status"],
                               timeout=6)
    assert "FortiGate-1000D" in out["get system status"]
    assert "CPU states" in out["get system performance status"]


def test_ssh_run_keeps_exec_when_it_works(monkeypatch):
    """7.x: exec가 출력을 주면 셸 폴백을 타지 않는다(빠른 경로 유지)."""
    chan = FakeChan({})
    client = FakeClient(chan, exec_out=b"Version: FortiGate-1100E v7.4.1,build2463 (GA)\n")
    fake = types.SimpleNamespace(SSHClient=lambda: client,
                                 AutoAddPolicy=lambda: object())
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    out = fortisensor._ssh_run("10.0.0.1", "admin", "pw", ["get system status"], timeout=6)
    assert "FortiGate-1100E" in out["get system status"]
    assert chan.sent == [], "셸 폴백 미사용"


# ── ③ SNMP 저장이 기존 모델·부가정보를 지우지 않는다 ─────────────

def _fw(p):
    with db.get_db(p) as conn:
        conn.execute("INSERT INTO firewalls (name, vendor, host, status) "
                     "VALUES ('FW6','fortigate','10.0.0.9','done')")
    return db.list_firewalls(p)[-1]["id"]


def test_snmp_save_preserves_ssh_model_and_extras(temp_db, monkeypatch):
    from core import collector
    fid = _fw(temp_db)
    db.save_device_metrics(temp_db, "firewall", fid, {
        "model": "FortiGate-1000D", "version": "v6.0.14",
        "vpn": {"tunnel_total": 2, "tunnel_up": 2},
        "policy": {"total": 100}})
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health",
                        lambda ip, c, **k: {"cpu_pct": 33, "mem_pct": 44,
                                            "sessions": 555,
                                            "model": "FortiGate-SNMP",
                                            "version": "v6.0.99"})
    collector.collect_fw_metrics_snmp(temp_db, db.get_firewall(temp_db, fid))
    m = db.get_device_env(temp_db, "firewall", fid)["metrics"]
    assert m["cpu_pct"] == 33 and m["sessions"] == 555, "지표는 SNMP가 갱신"
    assert m["model"] == "FortiGate-1000D", "SSH 모델이 표기 기준 — SNMP가 못 덮는다"
    assert m["version"] == "v6.0.14"
    assert m["vpn"]["tunnel_total"] == 2 and m["policy"]["total"] == 100, \
        "통째 덮어쓰기로 부가정보가 지워지던 회귀"


def test_snmp_fills_model_when_absent(temp_db, monkeypatch):
    """SSH·REST가 안 되는 장비 — SNMP 모델이 빈 곳을 채운다."""
    from core import collector
    fid = _fw(temp_db)
    monkeypatch.setattr(collector, "_snmp_community_if_enabled", lambda p: "public")
    monkeypatch.setattr(snmp_fortigate, "collect_health",
                        lambda ip, c, **k: {"cpu_pct": 10,
                                            "model": "FortiGate-1000D"})
    collector.collect_fw_metrics_snmp(temp_db, db.get_firewall(temp_db, fid))
    m = db.get_device_env(temp_db, "firewall", fid)["metrics"]
    assert m["model"] == "FortiGate-1000D"
