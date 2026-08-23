# -*- coding: utf-8 -*-
"""주기 지표 폴러(poll_once)가 SNMP 무응답은 조용히 넘기되, 코드 버그(시그니처
오류·오타 등)는 로그로 남기는지 고정한다.

배경: v6.39.0에서 `collect_env` 시그니처가 바뀌었는데 폴러의 광범위
`except: pass` 가 그 TypeError까지 먹어, 온도 지표가 **원인 로그 하나 없이**
조용히 사라진 적이 있다. 무응답(SnmpError 계열)은 폐쇄망에서 예상된 정상이라
조용히 넘기는 게 맞지만, 코드 버그까지 같은 except가 먹으면 재발한다.
이 테스트는 그 경계를 고정한다.
"""
from core import metrics_poller as mp
from core import snmp_fortigate, snmp_env, db
from core.snmp_collect import SnmpSilent


def _raise(exc):
    def _f(*a, **k):
        raise exc
    return _f


def _setup(monkeypatch, temp_db):
    """poll_once가 SNMP 단계까지 도달하도록 게이트를 열고 장비를 심는다."""
    events = []
    monkeypatch.setattr(mp.utils, "log_event", lambda *a, **k: events.append((a, k)))
    monkeypatch.setattr(mp, "bg_snmp_enabled", lambda p: True)
    monkeypatch.setattr(mp, "_snmp_community", lambda p: "public")
    monkeypatch.setattr(db, "list_firewalls",
                        lambda p: [{"id": 1, "vendor": "fortigate", "host": "10.0.0.1", "name": "FW"}])
    monkeypatch.setattr(db, "get_switches",
                        lambda p: [{"id": 2, "ip": "10.0.0.2", "name": "SW"}])
    monkeypatch.setattr(db, "save_metrics_point", lambda *a, **k: None)
    # 트래픽·포트에러 walk는 이 테스트 범위 밖 — 실제 네트워크 시도 방지.
    monkeypatch.setattr(mp, "collect_traffic", lambda *a, **k: 0)
    monkeypatch.setattr(mp, "collect_port_errors", lambda *a, **k: 0)
    return events


def _bug_events(events):
    names = {"metrics_poll_fw_snmp_bug", "metrics_poll_fw_env_bug", "metrics_poll_sw_snmp_bug"}
    return [e for e in events if len(e[0]) >= 2 and e[0][1] in names]


def test_snmp_no_response_is_silent(temp_db, monkeypatch):
    """SNMP 무응답(SnmpSilent)은 *_bug 로그를 남기지 않는다."""
    events = _setup(monkeypatch, temp_db)
    monkeypatch.setattr(snmp_fortigate, "collect_health", _raise(SnmpSilent("no resp")))
    monkeypatch.setattr(snmp_env, "collect_env", _raise(SnmpSilent("no resp")))
    mp.poll_once(str(temp_db), demo_mode=False)
    assert _bug_events(events) == []


def test_fw_health_code_bug_is_logged(temp_db, monkeypatch):
    """FortiGate collect_health의 코드 버그(TypeError)는 warning 로그로 남는다."""
    events = _setup(monkeypatch, temp_db)
    monkeypatch.setattr(snmp_fortigate, "collect_health", _raise(TypeError("bad signature")))
    monkeypatch.setattr(snmp_env, "collect_env", lambda *a, **k: {"max_temp_c": None})
    mp.poll_once(str(temp_db), demo_mode=False)
    names = [e[0][1] for e in events if len(e[0]) >= 2]
    assert "metrics_poll_fw_snmp_bug" in names


def test_switch_env_code_bug_is_logged(temp_db, monkeypatch):
    """스위치 온도 수집의 코드 버그(AttributeError)는 warning 로그로 남는다."""
    events = _setup(monkeypatch, temp_db)
    monkeypatch.setattr(snmp_fortigate, "collect_health", lambda *a, **k: {})
    monkeypatch.setattr(snmp_env, "collect_env", _raise(AttributeError("boom")))
    mp.poll_once(str(temp_db), demo_mode=False)
    names = [e[0][1] for e in events if len(e[0]) >= 2]
    assert "metrics_poll_sw_snmp_bug" in names
