"""M6: ExtremeXOS 고급 지원 — 포트 표기 정규화 고도화 테스트.

검증 목표:
- ExtremeXOS 포트는 native 표기(slot:port 또는 standalone)를 보존한다.
- Cisco "Gi" 접두사가 붙지 않는다 (정규화 결함 수정).
- standalone 포트와 가변 폭 Type 컬럼을 견고하게 파싱한다.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.parsers import utils, extreme_exos
from core import fixtures


# ── normalize_port 단위 테스트 ─────────────────────────────────────────────

# 1. slot:port 정규화 — Gi 접두사 없음
def test_normalize_slot_port_no_gi_prefix():
    assert utils.normalize_port("1:1", vendor="extreme_exos") == "1:1"
    assert utils.normalize_port("1:48", vendor="extreme_exos") == "1:48"
    assert utils.normalize_port("2:24", vendor="extreme_exos") == "2:24"


# 2. standalone 포트 — 숫자 그대로
def test_normalize_standalone_port():
    assert utils.normalize_port("5", vendor="extreme_exos") == "5"
    assert utils.normalize_port("48", vendor="extreme_exos") == "48"


# 3. 공백 정규화
def test_normalize_whitespace_slot_port():
    assert utils.normalize_port(" 1:2 ", vendor="extreme_exos") == "1:2"
    assert utils.normalize_port("1 : 2", vendor="extreme_exos") == "1:2"


# 4. None/빈 문자열
def test_normalize_none_empty():
    assert utils.normalize_port(None, vendor="extreme_exos") is None
    assert utils.normalize_port("", vendor="extreme_exos") is None


# 5. 크로스벤더 오염 차단 — vendor 미지정 시 ":" 있어도 Gi 안 붙음
def test_cross_vendor_colon_not_polluted():
    result = utils.normalize_port("1:2", vendor=None)
    assert not result.startswith("Gi")


# ── 파서 통합 테스트 ───────────────────────────────────────────────────────

# 6. slot:port fixture → 5개 포트, 모두 slot:port 표기
def test_parse_ports_slot_port_format():
    outputs = fixtures.get_extreme_exos_outputs()
    result = extreme_exos.parse(outputs, 3)
    assert len(result["ports"]) == 5
    for p in result["ports"]:
        assert ":" in p["name"]


# standalone 단독 스위치 포트 (Type 컬럼이 단일 토큰 "1000BaseT")
STANDALONE_PORTS = """Port       Type        Status   Speed    Duplex
1          1000BaseT   Up       1Gb      Full
2          1000BaseT   Down     1Gb      Full
3          1000BaseT   Up       1Gb      Full
"""


# 7. standalone 포트 파싱 — 가변 폭 Type 컬럼에도 견고
def test_parse_ports_standalone_format():
    outputs = {"status": STANDALONE_PORTS, "description": "", "mac": "", "arp": ""}
    result = extreme_exos.parse(outputs, 3)
    names = {p["name"] for p in result["ports"]}
    assert names == {"1", "2", "3"}
    # 상태 매핑 검증
    by_name = {p["name"]: p["status"] for p in result["ports"]}
    assert by_name["1"] == "up"
    assert by_name["2"] == "down"


# 8. 파싱 결과 어떤 포트도 Gi 접두사 미포함
def test_parse_ports_no_gi_in_output():
    outputs = fixtures.get_extreme_exos_outputs()
    result = extreme_exos.parse(outputs, 3)
    for p in result["ports"]:
        assert not p["name"].startswith("Gi")


# "Up-Link" 같은 토큰이 status로 오매칭되지 않음 (Codex R1 W1 회귀)
TRICKY_PORTS = """Port  Type       Status  Speed
1     Up-Link    Down    1Gb
2     SFP        Up      1Gb
"""


# 9. status는 정확한 토큰만 — 부분문자열 오인 금지
def test_parse_ports_status_token_not_substring():
    outputs = {"status": TRICKY_PORTS, "description": "", "mac": "", "arp": ""}
    result = extreme_exos.parse(outputs, 3)
    by_name = {p["name"]: p["status"] for p in result["ports"]}
    assert by_name["1"] == "down"  # "Up-Link"을 up으로 오인하면 안 됨
    assert by_name["2"] == "up"


# 들여쓰기된 포트 행 (Codex R1 W2 회귀)
INDENTED_PORTS = """Port  Type   Status  Speed
   1:1   SFP    Up      1Gb
   1:2   SFP    Down    1Gb
"""


# 10. leading whitespace가 있어도 파싱됨
def test_parse_ports_leading_whitespace():
    outputs = {"status": INDENTED_PORTS, "description": "", "mac": "", "arp": ""}
    result = extreme_exos.parse(outputs, 3)
    names = {p["name"] for p in result["ports"]}
    assert names == {"1:1", "1:2"}
