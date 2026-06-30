"""TPS hostname → 위치 파싱 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import tps_location


def test_parse_example():
    r = tps_location.parse("TPS-F1B02_1F01_FA_SW1")
    assert r is not None
    assert r["phase"] == 1
    assert r["building_code"] == "B02"
    assert r["building_name"] == "Assembly"
    assert r["floor"] == 1
    assert r["tps"] == "01"
    assert "1공장" in r["label"]
    assert "Assembly" in r["label"]
    assert "1층" in r["label"]
    assert "TPS01" in r["label"]


def test_parse_phase1_buildings():
    assert tps_location.parse("TPS-F1B01_2F03_X_SW1")["building_name"] == "Electrode"
    assert tps_location.parse("TPS-F1B17_1F01_X_SW1")["building_name"] == "Utility"


def test_parse_phase2_building_alnum():
    # Phase2 건물코드는 영숫자(B1A 등)
    r = tps_location.parse("TPS-F2B1A_3F02_X_SW1")
    assert r["phase"] == 2
    assert r["building_code"] == "B1A"
    assert r["building_name"] == "Assembly"
    assert r["floor"] == 3
    assert r["tps"] == "02"


def test_parse_unknown_building_keeps_code():
    r = tps_location.parse("TPS-F1B99_1F01_X_SW1")
    assert r["building_name"] == "B99"  # 매핑 없으면 코드 그대로


def test_parse_prefix_independent():
    """접두가 TPS-/SKBA_ 등 무엇이든 F1B02_1F01 패턴을 찾아 해석."""
    for host in ("TPS-F1B02_1F01_FA_SW1", "SKBA_F1B02_1F01_FA_SW1",
                 "anything_F1B02_1F01_X"):
        r = tps_location.parse(host)
        assert r is not None, host
        assert r["building_name"] == "Assembly"
        assert r["floor"] == 1 and r["tps"] == "01"


def test_parse_non_tps_returns_none():
    assert tps_location.parse("RANDOM-HOST-01") is None
    assert tps_location.parse("") is None
    assert tps_location.parse(None) is None


def test_api_state_includes_tps_location(client):
    client.post("/api/switches/manual",
                json={"ip": "10.9.9.9", "name": "FA_SW1", "vendor": "cisco",
                      "hostname": "TPS-F1B02_1F01_FA_SW1"})
    r = client.get("/api/state").get_json()
    sw = next(x for x in r["switches"] if x["ip"] == "10.9.9.9")
    assert "tps_location" in sw
    assert "Assembly" in sw["tps_location"]
