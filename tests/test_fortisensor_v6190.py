# -*- coding: utf-8 -*-
"""FortiGate `execute sensor list` 파싱 (v6.19.0).

사용자 요청: PSU·CPU·메모리 등 온도/암페어 상태를 이 명령으로 확인할 수 있으니
수집하게 해달라.
"""
from core.firewall import fortisensor as fs

# 실제 FortiGate 하드웨어 모델의 출력 형태(공백 폭은 모델마다 다르다)
SAMPLE = """
Fan 1            alarm=0 value=8100  rpm
Fan 2            alarm=0 value=7950  rpm
DTS CPU0         alarm=0 value=45    C
DTS CPU1         alarm=0 value=44    C
Temp SYS1        alarm=0 value=32    C
VCCP0            alarm=0 value=1.79  V
+3.3V            alarm=0 value=3.31  V
+12V             alarm=0 value=12.1  V
PS1 VIN          alarm=0 value=230   V
PS1 VOUT1        alarm=0 value=12.09 V
PS1 IOUT1        alarm=0 value=4.5   A
PS1 Temp1        alarm=0 value=35    C
PS1 Fan1         alarm=0 value=9000  rpm
PS1 Status       alarm=0 value=0
PS2 Status       alarm=1 value=1
"""


def test_parses_all_sensor_lines():
    s = fs.parse_sensor_list(SAMPLE)
    assert len(s) == 15
    by = {x["name"]: x for x in s}
    assert by["DTS CPU0"]["value"] == 45 and by["DTS CPU0"]["unit"] == "C"
    assert by["PS1 IOUT1"]["value"] == 4.5 and by["PS1 IOUT1"]["kind"] == "current"
    assert by["Fan 1"]["value"] == 8100 and by["Fan 1"]["kind"] == "fan"
    assert by["+3.3V"]["kind"] == "voltage"


def test_integer_values_stay_integers():
    """8100.0 rpm은 읽기 나쁘다."""
    by = {x["name"]: x for x in fs.parse_sensor_list(SAMPLE)}
    assert by["Fan 1"]["value"] == 8100 and isinstance(by["Fan 1"]["value"], int)
    assert isinstance(by["PS1 IOUT1"]["value"], float)


def test_alarm_flag_is_read():
    """장비가 준 alarm을 그대로 쓴다 — 우리가 전압 임계를 추측하지 않는다."""
    by = {x["name"]: x for x in fs.parse_sensor_list(SAMPLE)}
    assert by["PS2 Status"]["alarm"] is True
    assert by["PS1 Status"]["alarm"] is False


def test_grouping_by_component():
    by = {x["name"]: x["group"] for x in fs.parse_sensor_list(SAMPLE)}
    assert by["PS1 VOUT1"] == "PSU" and by["PS2 Status"] == "PSU"
    assert by["DTS CPU0"] == "CPU"
    assert by["Fan 1"] == "FAN"
    assert by["Temp SYS1"] == "SYSTEM"
    assert by["+12V"] == "POWER" and by["VCCP0"] == "POWER"


def test_summary_uses_device_alarm_for_level():
    out = fs.summarize(fs.parse_sensor_list(SAMPLE))
    assert out["level"] == "critical"           # PS2 Status alarm=1
    assert out["alarms"] == ["PS2 Status"]
    assert out["max_temp_c"] == 45
    assert out["fan_count"] == 3                # Fan 1, Fan 2, PS1 Fan1
    assert out["psu_names"] == ["PS1", "PS2"] and out["psu_count"] == 2


def test_zero_rpm_fan_is_flagged_even_without_alarm():
    """팬이 0 rpm이면 장비가 alarm을 안 올려도 이상 신호다."""
    out = fs.summarize(fs.parse_sensor_list(
        "Fan 1            alarm=0 value=0     rpm\n"
        "DTS CPU0         alarm=0 value=40    C\n"))
    assert out["dead_fans"] == ["Fan 1"] and out["level"] == "warning"


def test_normal_output_is_normal():
    out = fs.summarize(fs.parse_sensor_list(
        "Fan 1            alarm=0 value=8100  rpm\n"
        "DTS CPU0         alarm=0 value=40    C\n"))
    assert out["level"] == "normal" and not out["alarms"]


def test_vm_model_without_sensors():
    """VM 모델은 센서가 없다 — 오류가 아니라 빈 결과다."""
    out = fs.summarize(fs.parse_sensor_list(
        "Command fail. Return code -61\n"))
    assert out["sensors"] == [] and out["level"] is None
    assert out["max_temp_c"] is None


def test_ignores_noise_lines():
    """프롬프트·헤더가 섞여도 센서 줄만 골라낸다."""
    noisy = ("FW-01 # execute sensor list\n" + SAMPLE +
             "FW-01 # \n\n  \n")
    assert len(fs.parse_sensor_list(noisy)) == 15


def test_leading_whitespace_tolerated():
    """모델에 따라 들여쓰기가 붙는다."""
    s = fs.parse_sensor_list("      Fan 1            alarm=0 value=8100  rpm")
    assert len(s) == 1 and s[0]["name"] == "Fan 1"


def test_negative_and_decimal_values():
    s = fs.parse_sensor_list(
        "Temp Ambient     alarm=0 value=-3.5  C\n"
        "VBAT             alarm=0 value=3.05  V\n")
    by = {x["name"]: x["value"] for x in s}
    assert by["Temp Ambient"] == -3.5 and by["VBAT"] == 3.05


# --- REST 부가 수집(VPN·정책) ------------------------------------------------

def test_ipsec_tunnel_up_if_any_phase2_up():
    """phase2를 개별 터널로 세면 개수가 부풀고 지사 장애가 안 보인다."""
    from core.firewall import fortigate as fgw
    res = [
        {"name": "BRANCH-A", "rgwy": "203.0.113.5",
         "proxyid": [{"status": "down", "incoming_bytes": 0, "outgoing_bytes": 0},
                     {"status": "up", "incoming_bytes": 100, "outgoing_bytes": 50}]},
        {"name": "BRANCH-B", "rgwy": "203.0.113.9",
         "proxyid": [{"status": "down"}, {"status": "down"}]},
    ]
    t = fgw.parse_ipsec_tunnels(res)
    by = {x["name"]: x for x in t}
    assert len(t) == 2, "phase2가 아니라 터널 단위로 센다"
    assert by["BRANCH-A"]["status"] == "up" and by["BRANCH-A"]["incoming_bytes"] == 100
    assert by["BRANCH-B"]["status"] == "down"
    assert by["BRANCH-A"]["phase2_count"] == 2


def test_ipsec_tunnel_without_phase2_uses_phase1():
    from core.firewall import fortigate as fgw
    t = fgw.parse_ipsec_tunnels([{"name": "T1", "connection_count": 1}])
    assert t[0]["status"] == "up"
    t2 = fgw.parse_ipsec_tunnels([{"name": "T2", "connection_count": 0}])
    assert t2[0]["status"] == "down"


def test_ipsec_parser_survives_garbage():
    from core.firewall import fortigate as fgw
    assert fgw.parse_ipsec_tunnels(None) == []
    assert fgw.parse_ipsec_tunnels(["nope", 5]) == []


# --- 저장 경로 통합 ----------------------------------------------------------

def test_save_firewall_result_is_single_path(temp_db):
    """수집 호출부가 셋이라 저장은 한 곳이어야 한다 — v6.16.0의 온도·지표가
    자동 수집 경로에만 붙어 '수집' 버튼으로는 안 채워졌다."""
    from core import db, collector
    with db.get_db(temp_db) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                           ("FW-01", "fortigate", "10.0.0.1"))
        fid = cur.lastrowid
    fw = {"id": fid, "vendor": "fortigate", "host": "10.0.0.1"}
    res = {"interfaces": [{"name": "port1", "ip": "10.0.0.1", "mask": "255.255.255.0"}],
           "arp": [], "ha": None,
           "vpn": {"tunnel_total": 3, "tunnel_up": 2, "tunnels": []},
           "policy": {"total": 120, "unused": 14}}
    collector.save_firewall_result(temp_db, fw, res, {})
    assert len(db.get_firewall_interfaces(temp_db, fid)) == 1
    m = (db.get_device_env(temp_db, "firewall", fid) or {}).get("metrics") or {}
    assert m["vpn"]["tunnel_up"] == 2 and m["policy"]["total"] == 120


def test_merge_keeps_existing_snmp_metrics(temp_db):
    """REST 통계를 합칠 때 SNMP가 먼저 넣은 CPU·메모리를 지우면 안 된다."""
    from core import db, collector
    with db.get_db(temp_db) as conn:
        cur = conn.execute("INSERT INTO firewalls (name, vendor, host) VALUES (?,?,?)",
                           ("FW-01", "fortigate", "10.0.0.1"))
        fid = cur.lastrowid
    db.save_device_metrics(temp_db, "firewall", fid, {"cpu_pct": 11, "mem_pct": 40})
    collector.merge_fw_extra(temp_db, {"id": fid, "vendor": "fortigate", "host": "10.0.0.1"},
                             {"policy": {"total": 7}}, {})
    m = db.get_device_env(temp_db, "firewall", fid)["metrics"]
    assert m["cpu_pct"] == 11 and m["policy"]["total"] == 7


def test_merge_skips_non_fortigate(temp_db):
    from core import collector
    assert collector.merge_fw_extra(
        temp_db, {"id": 1, "vendor": "paloalto"}, {"policy": {"total": 5}}, {}) is None


# --- 대시보드 UI -------------------------------------------------------------

def test_dashboard_removed_from_firewall_page():
    """v6.25.0 사용자 지시: 방화벽 현황은 리스트만 — 통계는 관제 페이지 전담.

    v6.19.0에서 이 페이지에 넣었던 대시보드(fw-dashboard)는 제거됐다.
    상세보기의 부하 막대(fwBar/fwStatusHtml)는 유지된다.
    """
    from pathlib import Path
    root = Path(__file__).parent.parent
    js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")
    html = (root / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="fw-dashboard"' not in html
    assert "renderFirewallDashboard" not in js
    assert "function fwBar" in js and "function fwStatusHtml" in js
    assert "cdn." not in js
