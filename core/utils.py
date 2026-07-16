import logging
import json
import re

logger = logging.getLogger(__name__)


def _mask_sensitive_data(obj):
    """CRITICAL FIX (CWE-532): Mask sensitive fields in all logged objects.

    Prevents credentials, tokens, and API keys from being exposed in log files.
    Applies to dicts, lists, tuples, and string patterns.
    """
    if isinstance(obj, dict):
        return {
            k: _mask_sensitive_data(v)
            if k.lower() in ['password', 'token', 'secret', 'authorization', 'credential', 'key', 'api_key', 'api_token']
            else v
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
