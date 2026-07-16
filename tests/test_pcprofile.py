"""PC 프로필 테스트 — 수집 PC(MAC)별 출발지 IP·계정 등록/사용.

다중 PC 운영 시 A가 저장한 IP/계정이 B PC 수집에 잘못 쓰이던 문제의 수정.
검증 목표:
- 로컬 식별(MAC·IP·hostname) 획득 형식.
- 프로필 upsert/조회 라운드트립 (계정 blob은 같은 PC라 복호화 성공).
- source_ip 우선순위: 내 프로필 > 전역 설정 > None.
- 다른 PC(다른 MAC)의 프로필은 내 조회에 걸리지 않음.
- 자동수집: 스위치 blob 복호화 불가 시 내 프로필 계정으로 폴백.
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, pcprofile


@pytest.fixture
def temp_db(tmp_path):
    p = tmp_path / "test.db"
    db.init_schema(p)
    return p


def test_get_local_identity_format():
    ident = pcprofile.get_local_identity()
    assert ident["hostname"]
    # MAC "AA:BB:CC:DD:EE:FF" 또는 폴백 "HOST:<name>"
    assert (re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", ident["mac"])
            or ident["mac"].startswith("HOST:"))


def test_save_and_get_profile_roundtrip(temp_db):
    pcprofile.save_profile(temp_db, "admin", "secret123", source_ip="10.1.2.3")
    prof = pcprofile.get_profile(temp_db)
    assert prof is not None
    assert prof["source_ip"] == "10.1.2.3"
    # 같은 PC → DPAPI 복호화 성공
    cred = pcprofile.get_credential(temp_db)
    assert cred == ("admin", "secret123")


def test_save_profile_keeps_cred_when_only_ip_updated(temp_db):
    """출발지 IP만 갱신해도 기존 계정 blob은 유지된다."""
    pcprofile.save_profile(temp_db, "admin", "secret123", source_ip="10.1.2.3")
    pcprofile.save_profile(temp_db, source_ip="10.9.9.9")  # 계정 없이 IP만
    assert pcprofile.get_profile(temp_db)["source_ip"] == "10.9.9.9"
    assert pcprofile.get_credential(temp_db) == ("admin", "secret123")


def test_source_ip_priority(temp_db):
    # 아무것도 없음 → None
    assert pcprofile.get_source_ip(temp_db) is None
    # 전역 설정만 → 전역
    db.set_setting(temp_db, "source_ip", "10.0.0.1")
    assert pcprofile.get_source_ip(temp_db) == "10.0.0.1"
    # 내 프로필 등록 → 프로필 우선
    pcprofile.save_profile(temp_db, source_ip="10.2.2.2")
    assert pcprofile.get_source_ip(temp_db) == "10.2.2.2"


def test_other_pc_profile_not_mine(temp_db):
    """다른 PC(다른 MAC)의 프로필은 내 조회/계정에 사용되지 않는다."""
    db.upsert_pc_profile(temp_db, "11:22:33:44:55:66", "OTHER-PC",
                         "10.7.7.7", "not-my-dpapi-blob")
    assert pcprofile.get_profile(temp_db) is None       # 내 MAC 항목 없음
    assert pcprofile.get_credential(temp_db) is None
    # 전역 설정 폴백 동작 유지
    db.set_setting(temp_db, "source_ip", "10.0.0.1")
    assert pcprofile.get_source_ip(temp_db) == "10.0.0.1"


def test_list_pc_profiles_hides_blob(temp_db):
    pcprofile.save_profile(temp_db, "admin", "secret123", source_ip="10.1.2.3")
    rows = db.list_pc_profiles(temp_db)
    assert len(rows) == 1
    assert rows[0]["has_cred"] == 1
    assert "cred_blob" not in rows[0]  # 표시용 목록에 blob 미포함


def test_auto_collect_falls_back_to_profile_cred(temp_db, monkeypatch):
    """스위치 blob이 없거나 이 PC에서 복호화 불가 → 프로필 계정으로 수집."""
    from core import collector
    sid = db.import_switches_bulk(
        temp_db, [{"name": "SW1", "ip": "10.0.0.10", "vendor": "cisco_ios"}])[0]
    # 다른 PC가 저장한(복호화 불가) blob 모사
    db.update_cred_blob(temp_db, sid, "blob-from-another-pc")
    pcprofile.save_profile(temp_db, "myuser", "mypass123", source_ip=None)

    calls = []
    monkeypatch.setattr(collector, "collect_switch",
                        lambda dbp, swid, u, p: calls.append((swid, u, p)))
    monkeypatch.setattr(collector, "_ip_allowed", lambda ip, ranges: True)
    res = collector.collect_all_registered(temp_db)
    assert res["switches"] == 1
    assert calls == [(sid, "myuser", "mypass123")]
