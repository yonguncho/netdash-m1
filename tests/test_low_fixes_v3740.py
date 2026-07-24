# -*- coding: utf-8 -*-
"""2026-07-11 감사 low 버그(L*)의 회귀 테스트."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import credentials, connectivity, notifier, report_builder


# ── credentials: username '|' DPAPI 오염 방지 ──
def test_username_pipe_blocks_persist():
    # win32crypt 없어도(비Windows/미설치) '|' 검사가 먼저 걸려 None
    assert credentials.encrypt_credential("user|evil", "pw") is None


def test_normal_username_persist_path():
    # '|' 없는 정상 username은 (Windows+DPAPI면) blob, 아니면 None — 크래시 없음
    r = credentials.encrypt_credential("admin", "pw")
    assert r is None or isinstance(r, str)


# ── connectivity: 벤더 별칭 collector와 동기화 ──
def test_connectivity_vendor_aliases():
    for alias in ("exos", "extremexos", "extreme_xos", "extreme-xos", "extremenetworks"):
        assert connectivity._NETMIKO_TYPE.get(alias) == "extreme_exos", alias
    assert connectivity._NETMIKO_TYPE.get("cisco_nexus") == "cisco_nxos"


# ── notifier/report: 방화벽 이벤트 한글 라벨 ──
def test_firewall_event_labels_present():
    assert notifier._KIND_KO.get("firewall_unreachable") == "방화벽 연결 실패"
    assert notifier._KIND_KO.get("firewall_recovered") == "방화벽 복구"
    assert report_builder._EVENT_KO.get("firewall_unreachable") == "방화벽 연결 실패"


# ── config_loader: 토큰 파일 ACL 헬퍼 존재 ──
def test_token_acl_helper_exists():
    from core import config_loader
    assert hasattr(config_loader, "_restrict_token_permissions")


# ── app.py 정적 검증 ──
def test_app_low_fixes_static():
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    # 비ASCII 토큰: bytes 비교
    assert 'token.encode("utf-8", "replace")' in src
    # 감사 라벨: 실제 라우트로 교정
    assert '"/api/switches/import-inventory"' in src
    # facility subnet SSRF 검증
    assert "허용되지 않은 대역입니다" in src
    # 단건 collect rate_limit
    assert '@rate_limit("collect_switch"' in src
    # device_type 화이트리스트 단건 PUT
    assert "invalid device_type" in src
    # XFF 신뢰 조건화
    assert "is_private" in src


# ── UI 정적 검증 ──
def test_ui_low_fixes_static():
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    # renderSwitchTable 가드
    assert "if (!tbody) return;" in js
    # VLAN/토폴로지 로드 실패 안내
    assert "VLAN 현황을 불러오지 못했습니다" in js
    # v4.4: 토폴로지 편집기 로드 실패 문구('구성도를 불러오지 못했습니다')
    assert "구성도를 불러오지 못했습니다" in js
    html = (Path(__file__).parent.parent / "web" / "templates" / "index.html").read_text(encoding="utf-8")
    # colspan(설비 7 — 비고 컬럼 추가, 방화벽 7)
    assert 'colspan="7"' in html
