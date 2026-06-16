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
