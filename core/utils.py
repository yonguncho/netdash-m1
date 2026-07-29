import logging
import json
import re

logger = logging.getLogger(__name__)

# 로그에서 값을 통째로 가릴 키 이름.
# 'key'처럼 흔한 이름은 넣지 않는다 — config_missing_key 같은 진단 로그의
# 값까지 가려서, 무엇이 빠졌는지 알 수 없게 된다(과잉 마스킹).
_SENSITIVE_KEYS = frozenset((
    "password", "passwd", "pw", "token", "secret", "authorization",
    "credential", "cred", "cred_blob", "api_key", "api_token",
    "community", "snmp_community", "enable_secret", "secretkey",
))


def _mask_sensitive_data(obj):
    """CRITICAL FIX (CWE-532): Mask sensitive fields in all logged objects.

    Prevents credentials, tokens, and API keys from being exposed in log files.
    Applies to dicts, lists, tuples, and string patterns.
    """
    if isinstance(obj, dict):
        # 예전에는 민감 키일 때 **값을 재귀**시켜서, 평문 비밀번호가 그대로 통과했다
        # ({'password': 'hunter2'} → 그대로 — 문자열 분기의 정규식은 'key=value'
        # 형태만 잡는다). 민감 키는 값을 통째로 가리고, 나머지 키는 중첩까지 훑는다
        # (중첩 dict를 아예 안 보던 것도 같은 버그였다).
        return {
            k: ("***" if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS
                else _mask_sensitive_data(v))
            for k, v in obj.items()
        }
    elif isinstance(obj, (list, tuple)):
        return type(obj)(_mask_sensitive_data(item) for item in obj)
    elif isinstance(obj, str):
        # Mask password=xxx, token=xxx, secret=xxx patterns
        masked = re.sub(r'(password|token|secret|key|auth)\s*[:=]\s*"?[^"\s]+"?', r'\1=***', obj, flags=re.I)
        return masked
    return obj


def log_event(level: str, event: str, **kwargs):
    """Log events as JSON with automatic sensitive data redaction.

    Prevents credentials, tokens, and secrets from being exposed in log output.
    All sensitive fields are automatically masked with '***'.

    Args:
        level: Log level ('info', 'error', 'warning', 'debug')
        event: Event name/identifier
        **kwargs: Additional event metadata (sensitive fields auto-masked)

    Example:
        log_event('info', 'api_state', switches_count=5)
        → {"event": "api_state", "switches_count": 5}

        log_event('error', 'auth_failed', password='secret123')
        → {"event": "auth_failed", "password": "***"}
    """
    filtered_kwargs = _mask_sensitive_data(kwargs)
    data = {"event": event, **filtered_kwargs}
    getattr(logger, level)(json.dumps(data))


def is_network_path(path) -> bool:
    """경로가 네트워크 위치(UNC 또는 원격 매핑 드라이브)인지 판정.

    공유폴더의 파일에 owner-only ACL(icacls)을 걸면 처음 실행한 계정만
    접근 가능해져 다른 PC에서 db_error가 나므로, 하드닝 적용 전 이 함수로
    네트워크 경로를 걸러낸다. 판정 불가 시 False(로컬로 간주 — 기존 동작 유지).
    """
    import os
    s = str(path)
    if s.startswith("\\\\") or s.startswith("//"):
        return True  # UNC (\\server\share\...)
    if os.name == "nt" and len(s) >= 2 and s[1] == ":":
        try:
            import ctypes
            DRIVE_REMOTE = 4
            return ctypes.windll.kernel32.GetDriveTypeW(s[:2] + "\\") == DRIVE_REMOTE
        except Exception:
            return False
    return False
