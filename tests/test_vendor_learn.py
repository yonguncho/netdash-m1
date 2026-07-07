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


def test_parse_os_version():
    p = collector._parse_os_version
    assert p("cisco_ios", "Cisco IOS XE Software, Version 17.03.05") == "IOS-XE 17.03.05"
    assert p("cisco_ios", "Cisco IOS Software, C2960X Software, Version 15.2(7)E3, RELEASE") == "IOS 15.2(7)E3"
    assert p("cisco_nxos", "  NXOS: version 9.3(5)") == "NX-OS 9.3(5)"
    assert p("extreme_exos", "ExtremeXOS version 22.7.1.2 by release-manager") == "EXOS 22.7.1.2"
    assert p("arista_eos", "Software image version: 4.25.4M") == "EOS 4.25.4M"
    assert p("juniper_junos", "Junos: 18.4R3.3") == "JUNOS 18.4R3.3"
    assert p("alteon", "Software Version 29.0.3.0 (FLASH image2)") == "Alteon 29.0.3.0"
    assert p("cisco_ios", "") is None


def test_parse_model():
    m = collector._parse_model
    assert m("cisco_ios", "Model Number                    : WS-C2960X-48TS-L") == "WS-C2960X-48TS-L"
    assert m("cisco_ios", "cisco C9300-48P (X86) processor with ...") == "C9300-48P"
    assert m("cisco_nxos", "  cisco Nexus9000 C93180YC-EX chassis") == "Nexus9000 C93180YC-EX"
    assert m("arista_eos", "Arista DCS-7050TX-64\nHardware version: 01.01") == "DCS-7050TX-64"
    assert m("extreme_exos", "System Type: X460G2-24t-10G4") == "X460G2-24t-10G4"
    assert m("juniper_junos", "Model: ex4300-48t") == "ex4300-48t"
    assert m("alteon", "Alteon Application Switch 6024") == "6024"
    assert m("cisco_ios", "no model here at all") is None


def test_parse_nxos_exos_variants():
    """v3.36.4: NX-OS kickstart/N9K 표기 + EXOS 모델은 show switch에서."""
    p, m = collector._parse_os_version, collector._parse_model
    # 구형 NX-OS(kickstart 표기만 있는 경우)
    old_nxos = "  kickstart: version 6.0(2)A8(11b)\n  system:    version 6.0(2)A8(11b)"
    assert p("cisco_nxos", old_nxos) == "NX-OS 6.0(2)A8(11b)"
    # N9K식 모델 표기
    assert m("cisco_nxos", "Hardware\n  cisco N9K-C93180YC-EX  supervisor") == "N9K-C93180YC-EX"
    # EXOS 모델: show switch의 System Type
    show_switch = ("SysName:          X460-STACK\n"
                   "System Type:      X460G2-24t-10G4\n"
                   "SysHealth check:  Enabled\n")
    assert m("extreme_exos", show_switch) == "X460G2-24t-10G4"
    # EXOS show version에는 모델이 없어도 크래시 없이 None
    assert m("extreme_exos", "Image : ExtremeXOS version 22.4.1.4 by release-manager") is None


def test_update_switch_version_model(temp_db):
    sid = db.save_switch(temp_db, "SW-V", "10.0.0.5", "cisco_ios")
    db.update_switch(temp_db, sid, os_version="IOS-XE 17.3.5", model="C9300-48P")
    sw = db.get_switch(temp_db, sid)
    assert sw["os_version"] == "IOS-XE 17.3.5" and sw["model"] == "C9300-48P"


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
    collector = {"hard_timeout": 5}

    def get_max_concurrent(self):
        return 2

    def get_raw_outputs_path(self):
        import tempfile
        return tempfile.mkdtemp(prefix="ndraw_")


def test_worker_learns_vendor_and_updates_db(temp_db, monkeypatch):
    """unknown 스위치를 수집하면 학습된 벤더로 DB가 갱신된다(워커 흐름)."""
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "CORE-NX", "10.0.0.9", "unknown")
    credentials.save_credential(sid, "admin", "pw")

    # 실제 SSH 대신: detect_vendor=True로 호출되면 (outputs, 'cisco_nxos') 반환
    def fake_ssh(switch, username, password, vendor, source_ip=None, detect_vendor=False):
        assert detect_vendor is True  # unknown이라 학습 요청됨
        return ({"status": "", "mac": "", "arp": ""}, "cisco_nxos")
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    # 워커가 DB 기록까지 마치도록 종료 상태까지 대기(임시폴더 삭제 경합 방지)
    import time
    for _ in range(100):
        sw = db.get_switch(temp_db, sid)
        if sw["status"] in ("done", "failed") and sw["vendor"] == "cisco_nxos":
            break
        time.sleep(0.1)
    assert db.get_switch(temp_db, sid)["vendor"] == "cisco_nxos"


def test_worker_always_verifies_vendor(temp_db, monkeypatch):
    """벤더가 지정돼 있어도 항상 show version으로 실제 OS 검증(detect_vendor=True)."""
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
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
    # 워커가 DB 기록까지 마치도록 종료 상태까지 대기(임시폴더 삭제 경합 방지)
    for _ in range(100):
        if db.get_switch(temp_db, sid)["status"] in ("done", "failed"):
            break
        time.sleep(0.1)
    assert seen.get("detect") is True


def test_worker_alteon_direct_fallback_no_probe(temp_db, monkeypatch):
    """프롬프트에서 Alteon 감지 시 프로브(추가 로그인) 없이 전용 수집 직행.

    구형 Alteon은 동시 관리 세션 제한이 있어 프로브 로그인이 거부될 수 있음.
    """
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "L4-DIRECT", "10.0.0.26", "unknown")
    credentials.save_credential(sid, "admin", "pw")

    def fake_ssh(*a, **k):
        raise collector._DriverMismatchError("alteon 메뉴형 프롬프트 감지")
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)

    def fail_probe(*a, **k):
        raise AssertionError("프로브가 호출되면 안 됨(직행 폴백)")
    monkeypatch.setattr(collector, "_probe_os", fail_probe)
    monkeypatch.setattr(collector, "_alteon_collect",
                        lambda switch, u, p, source_ip=None: {
                            "status": "", "mac": "", "arp": "",
                            "version": "Alteon Application Switch 5224\n"
                                       "Software Version 29.0.3.0"})

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(100):
        sw = db.get_switch(temp_db, sid)
        if sw["status"] in ("done", "failed") and sw["vendor"] == "alteon":
            break
        time.sleep(0.1)
    sw = db.get_switch(temp_db, sid)
    assert sw["vendor"] == "alteon" and sw["status"] == "done"
    assert sw["model"] == "5224"


def test_diagnose_endpoint(client, monkeypatch):
    """진단 API: 배너/프롬프트/버전 원문 반환(계정은 저장분 또는 입력)."""
    from core import collector as _col
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.88.0.1", "name": "DIAG", "vendor": "unknown"}).get_json()["switch_id"]
    monkeypatch.setattr(_col, "diagnose_switch",
                        lambda sw, u, p, source_ip=None: {
                            "tcp": True, "ssh_login": True,
                            "prompt": ">> Standalone SLB - Main#",
                            "banner_head": "Alteon Application Switch 5224",
                            "version_head": "Error: unknown command", "guess": "alteon",
                            "error": ""})
    r = client.post("/api/switches/%d/diagnose" % sid,
                    json={"username": "u", "password": "p"})
    body = r.get_json()
    assert body["ok"] and body["diag"]["guess"] == "alteon"
    # 계정 없으면 400
    sid2 = client.post("/api/switches/manual",
                       json={"ip": "10.88.0.2", "name": "DIAG2", "vendor": "unknown"}).get_json()["switch_id"]
    assert client.post("/api/switches/%d/diagnose" % sid2, json={}).status_code == 400


def test_prompt_looks_alteon():
    assert collector._prompt_looks_alteon(">> Standalone SLB - Main")
    assert collector._prompt_looks_alteon(">> Main#")
    assert collector._prompt_looks_alteon(">>ASw5224 - Main#")
    # 실장비(진단 원문): '>>'가 잘려 캡처돼도 '- Main#' 꼬리/Standard ADC로 인식
    assert collector._prompt_looks_alteon("SKBA_F1_OASVR_L4_1 - Standard ADC - Main#")
    assert collector._prompt_looks_alteon(">> SKBA_F1_OASVR_L4_1 - Standard ADC - Main#")
    assert not collector._prompt_looks_alteon("SW-A09#")
    assert not collector._prompt_looks_alteon("X460.1 #")
    assert not collector._prompt_looks_alteon("")


def test_diagnose_uses_info_cmd_for_alteon(monkeypatch):
    """진단: Alteon 프롬프트면 show version 대신 /info/sys/general 실행."""
    import types
    sent = []

    class FakeShell:
        def send(self, s):
            sent.append(s.strip())

    class FakeClient:
        def set_missing_host_key_policy(self, p):
            pass
        def connect(self, *a, **k):
            pass
        def invoke_shell(self, **k):
            return FakeShell()
        def close(self):
            pass

    import paramiko as _pk
    monkeypatch.setattr(_pk, "SSHClient", FakeClient)
    reads = {"n": 0}

    def fake_read(shell, timeout=5, **k):
        reads["n"] += 1
        if reads["n"] == 1:   # 배너
            return "Alteon Application Switch 5224\n>> L4-A - Standard ADC - Main#"
        return "Software Version 29.0.3.0\n>> L4-A - Standard ADC - Main#"
    monkeypatch.setattr(collector, "_alteon_read", fake_read)
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    import time as _time
    monkeypatch.setattr(_time, "sleep", lambda s: None)

    res = collector.diagnose_switch({"ip": "10.0.0.30", "name": "L4-A"}, "u", "p")
    assert res["probe_cmd"] == "/info/sys/general"
    assert "/info/sys/general" in sent
    assert res["guess"] == "alteon"


def test_detect_vendor_standard_adc():
    assert collector._detect_vendor_from_version(
        "SKBA_F1_OASVR_L4_1 - Standard ADC - Main#") == "alteon"


def test_diagnose_autocorrects_vendor(client, monkeypatch):
    """진단이 벤더를 알아내면 DB 자동 교정 → 다음 수집부터 올바른 경로."""
    from core import collector as _col, db as _db
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sid = client.post("/api/switches/manual",
                      json={"ip": "10.88.0.5", "name": "L4-AC", "vendor": "unknown"}).get_json()["switch_id"]
    monkeypatch.setattr(_col, "diagnose_switch",
                        lambda sw, u, p, source_ip=None: {
                            "tcp": True, "ssh_login": True,
                            "prompt": "SKBA_F1_OASVR_L4_1 - Standard ADC - Main#",
                            "banner_head": "", "version_head": "", "guess": "alteon",
                            "error": ""})
    r = client.post("/api/switches/%d/diagnose" % sid,
                    json={"username": "u", "password": "p"})
    assert r.get_json()["diag"]["vendor_corrected"] == "alteon"
    assert _db.get_switch(dbp, sid)["vendor"] == "alteon"


def test_worker_alteon_prompt_fallback(temp_db, monkeypatch):
    """netmiko 접속 시 Alteon 프롬프트 감지 → 프로브 → 전용 수집 폴백.

    실장비 증상: v3.39.0에서도 '알 수 없음' — netmiko가 출력에서 프롬프트를
    잘라내 시그니처가 안 남았음 → 프롬프트 자체 검사 + 프로브 프롬프트 판별.
    """
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "L4-PROMPT", "10.0.0.25", "unknown")
    credentials.save_credential(sid, "admin", "pw")

    def fake_ssh(switch, username, password, vendor, source_ip=None,
                 detect_vendor=False, max_retries=3):
        # 접속 직후 프롬프트 검사에서 Alteon으로 판정된 상황
        raise collector._DriverMismatchError("alteon 메뉴형 프롬프트 감지")
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)
    monkeypatch.setattr(collector, "_probe_os",
                        lambda switch, u, p, source_ip=None:
                        ("alteon", "Error: unknown command\n>> Standalone SLB - Main#"))
    monkeypatch.setattr(collector, "_alteon_collect",
                        lambda switch, u, p, source_ip=None: {
                            "status": "", "mac": "", "arp": "",
                            "version": "Alteon Application Switch 5224\n"
                                       "Software Version 29.0.3.0"})

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(100):
        sw = db.get_switch(temp_db, sid)
        if sw["status"] in ("done", "failed") and sw["vendor"] == "alteon":
            break
        time.sleep(0.1)
    sw = db.get_switch(temp_db, sid)
    assert sw["vendor"] == "alteon" and sw["status"] == "done"
    assert sw["model"] == "5224"
    assert (sw["os_version"] or "").startswith("Alteon 29")


def test_looks_like_alteon():
    assert collector._looks_like_alteon(
        {"status": "Error: unknown command\n>> Standalone SLB - Main#"})
    assert collector._looks_like_alteon(
        {"version": "Alteon Application Switch 5224"})
    assert not collector._looks_like_alteon(
        {"status": "Gi1/0/1 connected 1 a-full a-1000"})


def test_parse_nxos_model_from_inventory():
    inv = ('NAME: "Chassis",  DESCR: "Nexus9000 C93180YC-EX chassis"\n'
           'PID: N9K-C93180YC-EX     ,  VID: V02 ,  SN: FDO12345ABC\n')
    assert collector._parse_model("cisco_nxos", inv) == "N9K-C93180YC-EX"


def test_worker_alteon_signature_recollect(temp_db, monkeypatch):
    """cisco 접속이 '성공'해도 출력이 Alteon(>> Main#)이면 전용 수집으로 재수집.

    실장비 증상: Alteon 5224가 unknown으로 등록 → 수집은 완료인데 벤더 '알 수 없음'
    + 데이터 빈 채로 남음.
    """
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "L4-5224", "10.0.0.24", "unknown")
    credentials.save_credential(sid, "admin", "pw")

    def fake_ssh(switch, username, password, vendor, source_ip=None,
                 detect_vendor=False, max_retries=3):
        # cisco 드라이버 접속 '성공' — 그러나 전부 메뉴 CLI 오류 텍스트
        err = "Error: unknown command\n>> Standalone SLB - Main#"
        return ({"status": err, "mac": err, "arp": err, "version": err}, vendor)
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)
    monkeypatch.setattr(collector, "_alteon_collect",
                        lambda switch, u, p, source_ip=None: {
                            "status": "", "mac": "", "arp": "",
                            "version": "Alteon Application Switch 5224\n"
                                       "Software Version 29.0.3.0"})

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(100):
        sw = db.get_switch(temp_db, sid)
        if sw["status"] in ("done", "failed") and sw["vendor"] == "alteon":
            break
        time.sleep(0.1)
    sw = db.get_switch(temp_db, sid)
    assert sw["vendor"] == "alteon" and sw["status"] == "done"
    assert sw["model"] == "5224"                       # 모델까지 채워짐
    assert (sw["os_version"] or "").startswith("Alteon 29")


def test_worker_unknown_becomes_cisco_ios(temp_db, monkeypatch):
    """회귀: unknown 장비가 IOS-XE로 감지되면 DB가 cisco_ios로 갱신.

    (버그: unknown→cisco_ios 정규화 접속 벤더와 감지가 같으면 '변화 없음'으로
    보고 갱신을 건너뛰어 화면에 unknown이 남았음 — raw 벤더와 비교로 수정)
    """
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "IOSXE-UNK", "10.0.0.12", "unknown")
    credentials.save_credential(sid, "admin", "pw")

    def fake_ssh(switch, username, password, vendor, source_ip=None,
                 detect_vendor=False, max_retries=3):
        # 세션 감지 성공: show version 출력 포함, eff_vendor는 접속 벤더와 동일
        return ({"status": "", "mac": "", "arp": "",
                 "version": "Cisco IOS XE Software, Version 17.09.01"}, vendor)
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(100):
        sw = db.get_switch(temp_db, sid)
        if sw["status"] in ("done", "failed") and sw["vendor"] == "cisco_ios":
            break
        time.sleep(0.1)
    assert db.get_switch(temp_db, sid)["vendor"] == "cisco_ios"  # unknown 아님


def test_worker_probe_fallback_on_driver_mismatch(temp_db, monkeypatch):
    """netmiko 프롬프트 매칭 실패(EXOS 증가형 프롬프트) → 원시 셸 OS 탐지 → 재시도.

    실장비 증상: vendor_detect_failed 'pattern not detected' — cisco 드라이버가
    EXOS의 'SW.1 #'→'SW.2 #' 증가형 프롬프트를 못 따라감.
    """
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "EXOS-PROMPT", "10.0.0.10", "cisco")
    credentials.save_credential(sid, "admin", "pw")

    calls = {"n": 0}

    def fake_ssh(switch, username, password, vendor, source_ip=None,
                 detect_vendor=False, max_retries=3):
        calls["n"] += 1
        if calls["n"] == 1:
            assert vendor == "cisco_ios"
            raise collector._DriverMismatchError("pattern not detected")
        # 2차: 탐지된 벤더로 재시도
        assert vendor == "extreme_exos" and detect_vendor is False
        return ({"status": "", "mac": "", "arp": ""}, "extreme_exos")
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)
    monkeypatch.setattr(collector, "_probe_os",
                        lambda switch, u, p, source_ip=None: ("extreme_exos", "ExtremeXOS version 22.7.1.2"))

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(80):
        sw = db.get_switch(temp_db, sid)
        if sw["vendor"] == "extreme_exos" and sw["status"] == "done":
            break
        time.sleep(0.1)
    sw = db.get_switch(temp_db, sid)
    assert sw["vendor"] == "extreme_exos" and sw["status"] == "done"
    assert calls["n"] == 2


def test_worker_corrects_wrong_vendor(temp_db, monkeypatch):
    """cisco로 잘못 등록된 EXOS 장비 — show version으로 교정되어 DB 갱신.

    (실장비 증상: EXOS인데 cisco 명령 'show interfaces status'가 실행돼 command_failed)
    """
    monkeypatch.setattr(collector, "get_config", lambda *a, **k: _FakeCfg())
    monkeypatch.setattr(collector, "_tcp_precheck", lambda *a, **k: True)
    sid = db.save_switch(temp_db, "EXOS-MISREG", "10.0.0.9", "cisco")   # 잘못 등록
    credentials.save_credential(sid, "admin", "pw")

    def fake_ssh(switch, username, password, vendor, source_ip=None, detect_vendor=False):
        assert detect_vendor is True
        # show version에서 ExtremeXOS 판별됐다고 가정 → 실제 OS 반환
        return ({"status": "", "mac": "", "arp": ""}, "extreme_exos")
    monkeypatch.setattr(collector, "_ssh_collect", fake_ssh)

    collector.init_collector()
    collector.collect_switch(temp_db, sid, "admin", "pw")
    import time
    for _ in range(100):
        sw = db.get_switch(temp_db, sid)
        if sw["status"] in ("done", "failed") and sw["vendor"] == "extreme_exos":
            break
        time.sleep(0.1)
    assert db.get_switch(temp_db, sid)["vendor"] == "extreme_exos"
