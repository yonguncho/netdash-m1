# -*- coding: utf-8 -*-
"""구형 네트워크 장비 SSH 호환.

최신 paramiko(2.9+/3.x)는 약한 KEX/호스트키/암호/MAC 알고리즘을 기본 협상 목록에서
제외했다. 구형 스위치(대표 증상: 'incompatible ssh peer', 'no acceptable kex/host key')는
이들 레거시 알고리즘만 지원하는 경우가 많아 협상이 실패한다.

paramiko가 '구현은 되어 있으나 기본 선호 목록에서 뺀' 레거시 알고리즘을 선호 목록의
'뒤쪽'에 다시 추가한다. 강한 알고리즘이 여전히 우선 협상되므로 보안 저하는 최소화하면서
구형 장비 접속만 가능해진다. (Transport 클래스 속성 패치 → 이후 모든 연결에 적용)
"""
import logging

logger = logging.getLogger(__name__)

# paramiko가 지원(_kex_info 등)하지만 기본 선호에서 빠질 수 있는 레거시 알고리즘
_LEGACY_KEX = (
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
)
_LEGACY_KEYS = ("ssh-rsa", "ssh-dss")
_LEGACY_CIPHERS = ("aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc", "blowfish-cbc")
_LEGACY_MACS = ("hmac-sha1", "hmac-sha1-96", "hmac-md5")

_applied = False


def _augment(current, extras, available):
    """available(구현된 알고리즘 레지스트리)에 있고 아직 목록에 없는 extras를 뒤에 추가."""
    try:
        add = tuple(a for a in extras if a in available and a not in current)
        return tuple(current) + add
    except Exception:
        return current


def enable_legacy_algorithms():
    """paramiko Transport의 선호 알고리즘 목록에 레거시를 폴백으로 추가(1회)."""
    global _applied
    if _applied:
        return
    _applied = True
    try:
        from paramiko.transport import Transport
    except Exception:
        return
    for attr, extras, reg in (
        ("_preferred_kex", _LEGACY_KEX, "_kex_info"),
        ("_preferred_keys", _LEGACY_KEYS, "_key_info"),
        ("_preferred_ciphers", _LEGACY_CIPHERS, "_cipher_info"),
        ("_preferred_macs", _LEGACY_MACS, "_mac_info"),
    ):
        try:
            available = getattr(Transport, reg, {})
            setattr(Transport, attr, _augment(getattr(Transport, attr), extras, available))
        except Exception:
            pass
    logger.info("ssh legacy algorithms enabled (구형 장비 호환)")


# 모듈 import 시 즉시 적용
enable_legacy_algorithms()
