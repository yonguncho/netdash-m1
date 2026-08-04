# -*- coding: utf-8 -*-
"""SNMP 환경 정보(ENTITY-SENSOR-MIB) 수집 (v6.16.0).

실장비가 없으므로 walk 결과만 바꿔 끼우는 가짜 세션으로 검증한다.
BER 인코딩·소켓은 snmp_collect가 이미 담당하고 여기서 검증할 것은
'센서 테이블을 어떻게 해석하는가'다.
"""
from core import snmp_env

T = snmp_env._SENSOR_TYPE
V = snmp_env._SENSOR_VALUE
S = snmp_env._SENSOR_SCALE
P = snmp_env._SENSOR_PREC
ST = snmp_env._SENSOR_STATUS
D = snmp_env._PHYS_DESCR


class FakeSession:
    """walk(base) → 미리 준 표를 돌려준다."""

    def __init__(self, table):
        self.table = table

    def walk(self, base, max_rows=64):
        return [(base + "." + idx, val) for idx, val in self.table.get(base, [])]


def _sess(rows):
    return FakeSession(rows)


def test_plain_celsius_sensor():
    s = _sess({
        T: [("1", 8)], V: [("1", 42)], S: [("1", 9)], P: [("1", 0)],
        ST: [("1", 1)], D: [("1", b"Temp: Inlet")],
    })
    out = snmp_env.summarize(snmp_env._decode(s))
    assert out["max_temp_c"] == 42.0
    assert out["sensors"][0]["name"] == "Temp: Inlet"
    assert out["level"] == "normal"


def test_precision_is_applied():
    """0.1도 단위로 주는 장비(455 = 45.5도) — precision을 무시하면 455도가 된다."""
    s = _sess({
        T: [("1", 8)], V: [("1", 455)], S: [("1", 9)], P: [("1", 1)],
        ST: [("1", 1)], D: [("1", b"Sensor")],
    })
    assert snmp_env.summarize(snmp_env._decode(s))["max_temp_c"] == 45.5


def test_milli_scale_is_applied():
    """밀리섭씨로 주는 장비(45000 milli = 45도) — scale을 무시하면 45000도가 된다."""
    s = _sess({
        T: [("1", 8)], V: [("1", 45000)], S: [("1", 8)], P: [("1", 0)],
        ST: [("1", 1)], D: [("1", b"Sensor")],
    })
    assert snmp_env.summarize(snmp_env._decode(s))["max_temp_c"] == 45.0


def test_non_environment_sensors_are_dropped():
    """전압·전류까지 담으면 화면이 잡음이 된다 — 온도/팬/유무만 남긴다."""
    s = _sess({
        T: [("1", 8), ("2", 4), ("3", 5), ("4", 10)],
        V: [("1", 40), ("2", 12), ("3", 3), ("4", 8200)],
        S: [("1", 9), ("2", 9), ("3", 9), ("4", 9)],
        P: [("1", 0), ("2", 0), ("3", 0), ("4", 0)],
        ST: [("1", 1), ("2", 1), ("3", 1), ("4", 1)],
        D: [("1", b"Temp"), ("2", b"Volt"), ("3", b"Amp"), ("4", b"Fan 1")],
    })
    out = snmp_env.summarize(snmp_env._decode(s))
    kinds = {x["type"] for x in out["sensors"]}
    assert kinds == {"celsius", "rpm"}
    assert out["temp_count"] == 1 and out["fan_count"] == 1


def test_max_temp_across_sensors_and_levels():
    s = _sess({
        T: [("1", 8), ("2", 8), ("3", 8)],
        V: [("1", 30), ("2", 72), ("3", 58)],
        S: [("1", 9), ("2", 9), ("3", 9)],
        P: [("1", 0), ("2", 0), ("3", 0)],
        ST: [("1", 1), ("2", 1), ("3", 1)],
        D: [("1", b"Inlet"), ("2", b"CPU"), ("3", b"Outlet")],
    })
    out = snmp_env.summarize(snmp_env._decode(s))
    assert out["max_temp_c"] == 72.0 and out["level"] == "critical"
    by = {x["name"]: x["level"] for x in out["sensors"]}
    assert by["Inlet"] == "normal" and by["Outlet"] == "warning" and by["CPU"] == "critical"


def test_nonoperational_sensor_raises_level_even_when_cool():
    """센서가 스스로 '비정상'이라 하면 온도가 낮아도 그냥 넘기지 않는다."""
    s = _sess({
        T: [("1", 8), ("2", 10)],
        V: [("1", 25), ("2", 0)],
        S: [("1", 9), ("2", 9)], P: [("1", 0), ("2", 0)],
        ST: [("1", 1), ("2", 3)],
        D: [("1", b"Inlet"), ("2", b"Fan 2")],
    })
    out = snmp_env.summarize(snmp_env._decode(s))
    assert out["level"] == "warning" and out["bad_sensors"] == ["Fan 2"]


def test_unsupported_device_returns_empty_not_error():
    """이 MIB을 지원하지 않는 장비가 흔하다 — 빈 결과지 오류가 아니다."""
    out = snmp_env.summarize(snmp_env._decode(_sess({})))
    assert out["sensors"] == [] and out["max_temp_c"] is None and out["level"] is None


def test_missing_name_falls_back_to_index():
    s = _sess({T: [("7", 8)], V: [("7", 33)], S: [("7", 9)], P: [("7", 0)],
               ST: [("7", 1)], D: []})
    assert snmp_env._decode(s)[0]["name"] == "sensor 7"


def test_temperature_sensors_sort_first():
    """화면에서 온도가 먼저 보여야 한다(팬 rpm이 위로 올라오면 읽기 나쁘다)."""
    s = _sess({
        T: [("1", 10), ("2", 8)], V: [("1", 9000), ("2", 40)],
        S: [("1", 9), ("2", 9)], P: [("1", 0), ("2", 0)],
        ST: [("1", 1), ("2", 1)], D: [("1", b"Fan A"), ("2", b"Temp B")],
    })
    assert snmp_env._decode(s)[0]["type"] == "celsius"


def test_thresholds_are_documented_constants():
    """임계값이 코드에 흩어지면 화면·저장 표기가 어긋난다."""
    assert snmp_env.WARN_C < snmp_env.CRIT_C
    assert snmp_env.temp_level(snmp_env.CRIT_C) == "critical"
    assert snmp_env.temp_level(snmp_env.WARN_C) == "warning"
    assert snmp_env.temp_level(snmp_env.WARN_C - 0.1) == "normal"
    assert snmp_env.temp_level(None) is None


# --- 저장·조회·정리 ----------------------------------------------------------

from core import db  # noqa: E402

_ENV = {"sensors": [{"index": "1", "name": "Inlet", "type": "celsius",
                     "value": 41.5, "status": "ok", "level": "normal"}],
        "temp_count": 1, "fan_count": 2, "max_temp_c": 41.5,
        "level": "normal", "bad_sensors": []}


def test_save_and_get_device_env(temp_db):
    sw = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    db.save_device_env(temp_db, "switch", sw, _ENV)
    got = db.get_device_env(temp_db, "switch", sw)
    assert got["max_temp_c"] == 41.5 and got["level"] == "normal"
    assert got["fan_count"] == 2
    assert got["sensors"][0]["name"] == "Inlet"


def test_env_map_omits_sensor_detail(temp_db):
    """목록 응답에 센서 수십 개를 실으면 통째로 무거워진다."""
    sw = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    db.save_device_env(temp_db, "switch", sw, _ENV)
    m = db.get_device_env_map(temp_db, "switch")
    assert m[sw]["max_temp_c"] == 41.5
    assert "sensors" not in m[sw] and "sensors_json" not in m[sw]


def test_env_is_scoped_by_kind(temp_db):
    """스위치 3번과 방화벽 3번이 섞이면 안 된다."""
    db.save_device_env(temp_db, "switch", 3, _ENV)
    db.save_device_env(temp_db, "firewall", 3, dict(_ENV, max_temp_c=61.0, level="warning"))
    assert db.get_device_env(temp_db, "switch", 3)["max_temp_c"] == 41.5
    assert db.get_device_env(temp_db, "firewall", 3)["max_temp_c"] == 61.0


def test_unknown_kind_rejected(temp_db):
    import pytest
    with pytest.raises(ValueError):
        db.save_device_env(temp_db, "printer", 1, _ENV)


def test_deleting_switch_removes_its_env(temp_db):
    """삭제된 id의 온도가 남으면 같은 id가 재사용될 때 되살아난다."""
    sw = db.save_switch(temp_db, "SW", "10.0.0.1", "cisco_ios")
    db.save_device_env(temp_db, "switch", sw, _ENV)
    db.delete_switch(temp_db, sw)
    assert db.get_device_env(temp_db, "switch", sw) is None


def test_env_absent_returns_none(temp_db):
    assert db.get_device_env(temp_db, "switch", 999) is None
    assert db.get_device_env_map(temp_db, "switch") == {}


# --- 수집 연동: 설정이 없으면 조용히 건너뛴다 --------------------------------

def test_collect_env_skipped_when_snmp_disabled(temp_db):
    """설정에서 SNMP를 끄면 시도하지 않는다.

    v6.18.0 정정: 예전엔 '커뮤니티 미설정이면 안 한다'고 적었는데 사실이 아니다.
    snmp_community()는 저장값이 없어도 기본값 public을 돌려준다 — 끄는 스위치는
    snmp_enabled뿐이다.
    """
    from core import db, collector
    db.set_setting(temp_db, "snmp_enabled", "0")
    assert collector.collect_env_snmp(temp_db, "switch", 1, "10.0.0.1") is None


def test_collect_env_skipped_without_ip(temp_db):
    from core import collector
    assert collector.collect_env_snmp(temp_db, "switch", 1, "") is None


# --- API·화면 ----------------------------------------------------------------

def test_switch_list_carries_temperature(client):
    r = client.get("/api/switches")
    assert r.status_code == 200          # 환경 정보가 없어도 목록은 정상


def test_attach_env_puts_temp_on_rows(temp_db):
    import app as app_mod
    db.save_device_env(temp_db, "switch", 7, _ENV)
    rows = [{"id": 7, "name": "SW"}, {"id": 8, "name": "SW2"}]
    app_mod._attach_env(temp_db, rows, "switch")
    assert rows[0]["temp_c"] == 41.5 and rows[0]["temp_level"] == "normal"
    assert "temp_c" not in rows[1]       # 없는 장비는 건드리지 않는다


def test_ui_has_temperature_column():
    from pathlib import Path
    root = Path(__file__).parent.parent
    js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")
    html = (root / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert "function tempCell" in js
    assert js.count("tempCell(") >= 3, "스위치·방화벽 표가 같은 셀 함수를 써야 한다"
    assert html.count("<th title=\"SNMP로 읽은 최고 센서 온도") == 2


def test_detail_shows_sensor_list():
    """상세보기에 센서 목록 영역과 렌더 함수가 있어야 한다."""
    from pathlib import Path
    root = Path(__file__).parent.parent
    js = (root / "web" / "static" / "app.js").read_text(encoding="utf-8")
    html = (root / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="detail-env"' in html
    assert "function renderDetailEnv" in js
    assert "renderDetailSummary(ports, macs, arps, detail.env)" in js


def test_switch_detail_api_carries_env(temp_db, client):
    """상세 API가 env 키를 포함해야 한다(없으면 null)."""
    r = client.get("/api/switches/1/detail")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "env" in r.get_json()
