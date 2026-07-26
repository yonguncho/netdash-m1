# -*- coding: utf-8 -*-
"""수집용 세션 자격증명 — 메모리 전용(디스크 저장 없음).

목적: 화면에 계정/비밀번호 입력칸을 상시 노출하지 않으면서, 수집할 때마다
재입력하는 불편도 없애기 위해 '한 번 입력 → 일정 시간(TTL) 동안 재사용'을 제공한다.

보안 설계:
  - 프로세스 메모리에만 보관. 파일·DB에 절대 쓰지 않는다(재시작하면 사라짐).
  - 요청자(브라우저가 접속한 원격 주소)별로 분리 보관 — 다른 PC가 남의 계정을 쓰지 못한다.
  - 조회 API는 활성 여부·남은 시간·마스킹된 계정만 반환하고 비밀번호는 절대 내보내지 않는다.
  - 사용자가 '잠금'을 누르거나 TTL이 지나면 즉시 폐기한다.
"""
import threading
import time

_DEFAULT_TTL = 1800        # 초(30분)
_MAX_TTL = 8 * 3600        # 상한 8시간(그 이상은 상시 저장과 다를 바 없어 금지)

_store = {}                # {owner: {"u":..., "p":..., "exp": epoch}}
_lock = threading.Lock()


def _now():
    return time.time()


def set_credential(owner, username, password, ttl=None):
    """세션 자격증명 등록. 반환: 만료까지 남은 초."""
    if not owner or not username or not password:
        return 0
    try:
        ttl = int(ttl) if ttl else _DEFAULT_TTL
    except (TypeError, ValueError):
        ttl = _DEFAULT_TTL
    ttl = max(60, min(ttl, _MAX_TTL))
    with _lock:
        _store[str(owner)] = {"u": username, "p": password, "exp": _now() + ttl}
    return ttl


def get_credential(owner):
    """(username, password) 또는 None. 만료분은 이 시점에 폐기."""
    key = str(owner or "")
    with _lock:
        ent = _store.get(key)
        if not ent:
            return None
        if ent["exp"] <= _now():
            _store.pop(key, None)
            return None
        return (ent["u"], ent["p"])


def status(owner):
    """UI 표시용 상태 — 비밀번호는 포함하지 않는다.
    {active, remaining, username_masked}
    """
    key = str(owner or "")
    with _lock:
        ent = _store.get(key)
        if not ent or ent["exp"] <= _now():
            _store.pop(key, None)
            return {"active": False, "remaining": 0, "username": ""}
        u = ent["u"] or ""
        masked = (u[:2] + "*" * max(0, len(u) - 2)) if len(u) > 2 else "*" * len(u)
        return {"active": True, "remaining": int(ent["exp"] - _now()), "username": masked}


def clear(owner=None):
    """잠금 — owner 지정 시 그 사용자만, 없으면 전체 폐기."""
    with _lock:
        if owner is None:
            _store.clear()
        else:
            _store.pop(str(owner), None)
    return True


def purge_expired():
    """만료 항목 정리(주기 호출용)."""
    now = _now()
    with _lock:
        for k in [k for k, v in _store.items() if v["exp"] <= now]:
            _store.pop(k, None)
