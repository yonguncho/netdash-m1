# -*- coding: utf-8 -*-
"""구형 장비 SSH 레거시 알고리즘 호환 테스트."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_legacy_algorithms_added_to_preferred():
    try:
        from paramiko.transport import Transport
    except Exception:
        pytest.skip("paramiko not available")
    from core import ssh_compat
    ssh_compat.enable_legacy_algorithms()
    # group14-sha1은 대부분의 paramiko 버전에 구현되어 있음 → 선호목록에 추가되어야
    if "diffie-hellman-group14-sha1" in getattr(Transport, "_kex_info", {}):
        assert "diffie-hellman-group14-sha1" in Transport._preferred_kex
    # ssh-rsa 호스트키 재허용(구형 장비 'no acceptable host key' 해결)
    if "ssh-rsa" in getattr(Transport, "_key_info", {}):
        assert "ssh-rsa" in Transport._preferred_keys
    # aes-cbc 계열 암호 폴백
    if "aes128-cbc" in getattr(Transport, "_cipher_info", {}):
        assert "aes128-cbc" in Transport._preferred_ciphers


def test_enable_is_idempotent():
    from core import ssh_compat
    from paramiko.transport import Transport
    ssh_compat.enable_legacy_algorithms()
    before = tuple(Transport._preferred_kex)
    ssh_compat.enable_legacy_algorithms()
    ssh_compat.enable_legacy_algorithms()
    assert tuple(Transport._preferred_kex) == before  # 중복 추가 없음


def test_augment_skips_unavailable():
    from core import ssh_compat
    # available에 없는 알고리즘은 추가되지 않음
    out = ssh_compat._augment(("a",), ("b", "c"), {"b"})
    assert out == ("a", "b")  # c는 available에 없어 제외


def test_friendly_error_incompatible_peer():
    from core import connectivity
    msg = connectivity._friendly_ssh_error(
        "A paramiko SSHException occurred during connection creation: incompatible ssh peer")
    assert "구형 장비" in msg and "incompatible ssh peer" in msg
