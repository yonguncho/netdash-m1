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

# 장비 종류별로 분리 보관한다. 스위치·서버·방화벽은 계정 체계가 대개 다르고,
# 하나로 공유하면 스위치 계정이 전 서버에 SSH로 시도돼 수집이 실패할 뿐 아니라
# 반복 인증 실패로 계정이 잠길 수 있다.
KINDS = ("switch", "server", "firewall")
DEFAULT_KIND = "switch"

_store = {}                # {(owner, kind): {"u":..., "p":..., "exp": epoch}}
_lock = threading.Lock()


def _now():
    return time.time()


def _norm_kind(kind):
    k = str(kind or DEFAULT_KIND).lower()
    return k if k in KINDS else DEFAULT_KIND


def _key(owner, kind):
    return (str(owner or ""), _norm_kind(kind))


def set_credential(owner, username, password, ttl=None, kind=DEFAULT_KIND):
    """세션 자격증명 등록(장비 종류별). 반환: 만료까지 남은 초."""
    if not owner or not username or not password:
        return 0
    try:
        ttl = int(ttl) if ttl else _DEFAULT_TTL
    except (TypeError, ValueError):
        ttl = _DEFAULT_TTL
    ttl = max(60, min(ttl, _MAX_TTL))
    with _lock:
        _store[_key(owner, kind)] = {"u": username, "p": password, "exp": _now() + ttl}
    return ttl


def get_credential(owner, kind=DEFAULT_KIND):
    """(username, password) 또는 None. 만료분은 이 시점에 폐기.

    다른 종류의 계정으로 폴백하지 않는다 — 엉뚱한 장비에 계정을 던지지 않기 위함.
    """
    key = _key(owner, kind)
    with _lock:
        ent = _store.get(key)
        if not ent:
            return None
        if ent["exp"] <= _now():
            _store.pop(key, None)
            return None
        return (ent["u"], ent["p"])


def _mask(u):
    u = u or ""
    return (u[:2] + "*" * max(0, len(u) - 2)) if len(u) > 2 else "*" * len(u)


def status(owner, kind=None):
    """UI 표시용 상태 — 비밀번호는 포함하지 않는다.

    kind 지정: {active, remaining, username}
    kind 생략: 위 필드(전체 기준 요약) + kinds={종류: {...}}
    """
    if kind is not None:
        key = _key(owner, kind)
        with _lock:
            ent = _store.get(key)
            if not ent or ent["exp"] <= _now():
                _store.pop(key, None)
                return {"active": False, "remaining": 0, "username": "", "kind": _norm_kind(kind)}
            return {"active": True, "remaining": int(ent["exp"] - _now()),
                    "username": _mask(ent["u"]), "kind": _norm_kind(kind)}
    out = {}
    for k in KINDS:
        out[k] = status(owner, k)
    active = [v for v in out.values() if v["active"]]
    return {"active": bool(active),
            "remaining": max([v["remaining"] for v in active], default=0),
            "username": active[0]["username"] if len(active) == 1 else "",
            "kinds": out}


def clear(owner=None, kind=None):
    """잠금 — owner/kind 조합만 폐기. owner 생략 시 전체."""
    with _lock:
        if owner is None:
            _store.clear()
        elif kind is None:
            for k in [k for k in _store if k[0] == str(owner)]:
                _store.pop(k, None)
        else:
            _store.pop(_key(owner, kind), None)
    return True


def purge_expired():
    """만료 항목 정리(주기 호출용) → 지운 개수.

    조회 시점 만료(lazy)만으로는 부족했다 — 아무도 그 키를 다시 찾지 않으면
    영영 안 지워져서, 평문 비밀번호가 프로세스 수명 내내 메모리에 남았다
    (TTL 30분이 무의미). scheduler가 매 주기 호출한다.
    """
    now = _now()
    with _lock:
        dead = [k for k, v in _store.items() if v["exp"] <= now]
        for k in dead:
            _store.pop(k, None)
    return len(dead)


def active_kinds(owner):
    """지금 계정이 살아 있는 장비 종류 목록 — 수집 전 안내용."""
    return [k for k in KINDS if get_credential(owner, k)]
