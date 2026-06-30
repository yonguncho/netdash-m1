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


def test_appjs_syslog_tab():
    src = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    assert "renderSyslogTab" in src
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'data-dtab="syslog"' in html
