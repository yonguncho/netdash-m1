# -*- coding: utf-8 -*-
"""방화벽 수집 부가경로의 조용한 실패에 진단 로그/notes를 남기는지 고정한다.

배경: silent-failure 검토(2026-08-23)에서 fortigate `_fetch_ha`/`_fetch_sysinfo`/
`_fetch_objects` 와 fortisensor `_ssh_run` 폴백이 실패 사유를 아무 데도 안 남겨
"왜 장비 정보가 비었나"에 답할 수 없던 것을 발견. 동작은 그대로 두고 진단성만
추가했으며(부가정보 경로라 실패해도 수집 흐름은 유지), 이 테스트로 로그/notes를 고정.
"""
import logging

from core.firewall import fortigate, fortisensor
from core import utils, secpolicy


def _raise(*a, **k):
    raise RuntimeError("boom")


def test_fetch_ha_logs_on_error(monkeypatch, caplog):
    monkeypatch.setattr(fortigate, "_get_with_retry", _raise)
    caplog.set_level(logging.INFO)
    assert fortigate._fetch_ha(None, "http://b", "h1") is None
    assert "fortigate_ha_skip" in caplog.text


def test_fetch_sysinfo_records_reason_in_notes(monkeypatch, caplog):
    monkeypatch.setattr(fortigate, "_try_get", _raise)
    caplog.set_level(logging.INFO)
    notes = {}
    assert fortigate._fetch_sysinfo(None, "http://b", "h1", notes) is None
    assert "파싱 실패" in notes.get("장비 정보", "")
    assert "fortigate_sysinfo_parse_fail" in caplog.text


def test_fetch_objects_logs_partial(monkeypatch, caplog):
    monkeypatch.setattr(fortigate, "_get_with_retry", _raise)
    caplog.set_level(logging.INFO)
    assert fortigate._fetch_objects(None, "http://b", "h1") is None
    assert "fortigate_objects_partial" in caplog.text


def test_ssh_run_logs_shell_fallback(monkeypatch):
    """exec 채널이 전부 빈 출력이면 셸 폴백으로 넘어가며 그 사실을 로그한다."""
    events = []
    monkeypatch.setattr(utils, "log_event", lambda *a, **k: events.append((a, k)))
    monkeypatch.setattr(secpolicy, "apply_host_key_policy", lambda c: None)
    monkeypatch.setattr(fortisensor, "_shell_run",
                        lambda client, commands, timeout=20: {c: "fallback" for c in commands})

    class _Stdout:
        def read(self):
            return b""              # 빈 출력 → exec 채널 실패 모사 → 폴백 유발

    class _FakeClient:
        def connect(self, *a, **k):
            pass

        def exec_command(self, cmd, timeout=None):
            return None, _Stdout(), None

        def close(self):
            pass

    import paramiko
    monkeypatch.setattr(paramiko, "SSHClient", lambda: _FakeClient())
    out = fortisensor._ssh_run("10.0.0.1", "u", "p", ["get system status"])
    assert out == {"get system status": "fallback"}
    names = [e[0][1] for e in events if len(e[0]) >= 2]
    assert "fortisensor_exec_empty_shell_fallback" in names
