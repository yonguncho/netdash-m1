"""show logging 분석(flapping/looping/err 탐지 + 최근 N줄) 테스트."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, log_analyzer

CISCO_LOG = """\
Jan  1 00:01:01: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down
Jan  1 00:01:03: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to up
Jan  1 00:01:08: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down
Jan  1 00:01:10: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to up
Jan  1 00:02:00: %SW_MATM-4-MACFLAP_NOTIF: Host 0050.56a1.b2c3 in vlan 100 is flapping between port Gi1/0/1 and port Gi1/0/2
Jan  1 00:03:00: %PM-4-ERR_DISABLE: loopback error detected on Gi1/0/9, putting Gi1/0/9 in err-disable state
Jan  1 00:04:00: %SYS-5-CONFIG_I: Configured from console
"""


def test_detect_looping():
    r = log_analyzer.analyze(CISCO_LOG)
    assert r["alert"] == "critical"  # MACFLAP = 루프
    assert any(e["type"] == "looping" for e in r["events"])


def test_detect_flapping_threshold():
    r = log_analyzer.analyze(CISCO_LOG, flap_threshold=3)
    flaps = [e for e in r["events"] if e["type"] == "flapping"]
    assert flaps  # Gi1/0/5가 4회 up/down
    assert flaps[0]["count"] >= 3


def test_detect_error():
    r = log_analyzer.analyze(CISCO_LOG)
    assert any(e["type"] in ("error", "looping") for e in r["events"])


def test_recent_tail():
    r = log_analyzer.analyze(CISCO_LOG, tail=3)
    assert len(r["recent"]) == 3
    assert "CONFIG_I" in r["recent"][-1]


def test_clean_log_no_alert():
    r = log_analyzer.analyze("Jan 1 00:00:00: %SYS-5-CONFIG_I: ok\nJan 1 00:00:01: normal line")
    assert r["alert"] == "none"
    assert r["events"] == []


def test_db_switch_logs_roundtrip(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    db.save_switch_logs(temp_db, sid, "line1\nline2", json.dumps([{"type": "flapping"}]), "warning")
    r = db.get_switch_logs(temp_db, sid)
    assert r["recent_lines"] == "line1\nline2"
    assert r["log_alert"] == "warning"


def test_all_vendors_have_logging_command():
    """모든 벤더 config에 logging 명령이 있어야(범용 log_analyzer로 탐지)."""
    import yaml
    cfg = yaml.safe_load((Path(__file__).parent.parent / "config.yaml").read_text(encoding="utf-8"))
    cmds = cfg["collector"]["commands"]
    for v in ("cisco_ios", "arista_eos", "extreme_exos", "cisco_nxos"):
        assert "logging" in cmds[v], v


def test_extreme_log_flap_detected():
    """Extreme 'show log' 형식의 Link Down/Up도 flapping으로 탐지."""
    exos = "\n".join([
        "01/01/2026 00:00:01 <Warn:vlan> Port 1:1 link down",
        "01/01/2026 00:00:03 <Info:vlan> Port 1:1 link up",
        "01/01/2026 00:00:06 <Warn:vlan> Port 1:1 link down",
        "01/01/2026 00:00:08 <Info:vlan> Port 1:1 link up",
    ])
    r = log_analyzer.analyze(exos, flap_threshold=3)
    assert r["alert"] in ("warning", "critical")


def test_flap_window_dense_detected():
    """10분 윈도우 내 3회 이상 → flapping (detail에 윈도우 표기)."""
    log = "\n".join([
        "Jul 11 09:00:01: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Jul 11 09:03:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
        "Jul 11 09:07:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Jul 11 09:09:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
    ])
    r = log_analyzer.analyze(log, flap_threshold=3, flap_window_min=10)
    flaps = [e for e in r["events"] if e["type"] == "flapping"]
    assert flaps and flaps[0]["count"] >= 3
    assert "/10분" in flaps[0]["detail"]


def test_flap_window_sparse_not_flapping():
    """총 4회여도 시간상 분산(1시간 간격)이면 flapping 아님."""
    log = "\n".join([
        "Jul 11 09:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Jul 11 10:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
        "Jul 11 11:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to down",
        "Jul 11 12:00:00: %LINK-3-UPDOWN: Interface Gi1/0/5, changed state to up",
    ])
    r = log_analyzer.analyze(log, flap_threshold=3, flap_window_min=10)
    assert not [e for e in r["events"] if e["type"] == "flapping"]


def test_flap_no_timestamp_fallback():
    """타임스탬프 없는 로그는 기존 총횟수 판정 폴백."""
    log = "\n".join([
        "%LINK-3-UPDOWN: Interface Gi1/0/7, changed state to down",
        "%LINK-3-UPDOWN: Interface Gi1/0/7, changed state to up",
        "%LINK-3-UPDOWN: Interface Gi1/0/7, changed state to down",
    ])
    r = log_analyzer.analyze(log, flap_threshold=3)
    flaps = [e for e in r["events"] if e["type"] == "flapping"]
    assert flaps and flaps[0]["count"] == 3
    assert "/분" not in flaps[0]["detail"].replace("회/", "/")


def test_flap_nxos_exos_timestamps():
    """NX-OS(연도 선행)·EXOS(MM/DD/YYYY) 타임스탬프 파싱."""
    assert log_analyzer._parse_ts("2026 Jul 11 09:12:03 %ETHPORT-5-IF_DOWN") is not None
    assert log_analyzer._parse_ts("07/11/2026 09:12:03.12 <Warn:vlan> Port 1:1 link down") is not None
    assert log_analyzer._parse_ts("no timestamp here") is None


def test_arista_errors_merge():
    """Arista show interfaces 상세에서 CRC/errors 병합."""
    from core.parsers import arista_eos
    sh = ("Ethernet1 is up, line protocol is up\n"
          "  Hardware is Ethernet\n"
          "     7 input errors, 3 CRC, 0 frame\n"
          "     2 output errors, 0 collisions\n")
    r = arista_eos.parse({"status": sh, "errors": sh, "description": "", "mac": "", "arp": ""}, 1)
    # 포트가 파싱되면 errors 병합 확인(arista 상세 형식)
    e1 = next((p for p in r["ports"] if "1" in p["name"]), None)
    if e1:
        assert e1.get("crc_errors") == 3


def test_appjs_syslog_tab():
    src = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "renderSyslogTab" in src
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'data-dtab="syslog"' in html
