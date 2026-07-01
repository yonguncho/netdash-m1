# -*- coding: utf-8 -*-
"""벤더 미지정(unknown) 스위치 수집 시 show version으로 벤더 학습 + DB 갱신."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, db, credentials


def test_detect_vendor_from_version():
    d = collector._detect_vendor_from_version
    assert d("Cisco Nexus Operating System (NX-OS) Software") == "cisco_nxos"
    assert d("Cisco IOS Software, Version 15.0") == "cisco_ios"
    assert d("Cisco IOS-XE Software, Version 17.3") == "cisco_ios"
    assert d("Arista DCS-7050 ... (EOS)") == "arista_eos"
    assert d("ExtremeXOS version 30.1") == "extreme_exos"
    assert d("JUNOS Software Release [18.4]") == "juniper_junos"
    assert d("random banner") is None
    assert d("") is None


def test_is_unknown_vendor():
    assert collector._is_unknown_vendor("unknown")
    assert collector._is_unknown_vendor("")
    assert collector._is_unknown_vendor(None)
    assert not collector._is_unknown_vendor("cisco")


def test_commands_for_falls_back_to_parser():
    # config에 있으면 config 우선
    assert collector._commands_for("cisco_nxos").get("port_channel")


class _FakeCfg:
    """워커가 데모 분기를 타지 않도록 non-demo 설정 스텁(전역 싱글턴 미변경)."""
    app = {"demo_mode": False}

    def get_max_concurrent(self):
        return 2


def test_worker_learns_vendor_and_updates_db(temp_db, monkeypatch):
    """unknown 스위치를 수집하면 학습된 벤더로 DB가 갱신된다(워커 흐름)."""
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    sid = db.save_switch(temp_db, "CORE-NX", "10.0.0.9", "unknown")
    credentials.save_credential(sid, "admin", "pw")

    # 실제 SSH 대신: detect_vendor=True로 호출되면 (outputs, 'cisco_nxos') 반환
    def fake_ssh(switch, username, password, vendor, source_ip=None, detect_vendor=False):
        assert detect_vendor is True  # unknown이라 학습 요청됨
        return ({"status": "", "mac": "", "arp": ""}, "cisco_nxos")
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    # 워커가 처리할 때까지 대기
    import time
    for _ in range(80):
        if db.get_switch(temp_db, sid)["vendor"] == "cisco_nxos":
            break
        time.sleep(0.1)
    assert db.get_switch(temp_db, sid)["vendor"] == "cisco_nxos"


def test_worker_keeps_known_vendor(temp_db, monkeypatch):
    """이미 벤더가 지정된 스위치는 detect_vendor=False로 호출(학습 안 함)."""
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    sid = db.save_switch(temp_db, "ACC-SW", "10.0.0.8", "cisco")
    credentials.save_credential(sid, "admin", "pw")

    seen = {}

    def fake_ssh(switch, username, password, vendor, source_ip=None, detect_vendor=False):
        seen["detect"] = detect_vendor
        return ({"status": "", "mac": "", "arp": ""}, vendor)
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(80):
        if "detect" in seen:
            break
        time.sleep(0.1)
    assert seen.get("detect") is False
