import logging
import json

logger = logging.getLogger(__name__)


def log_event(level: str, event: str, **kwargs):
    """JSON 형식으로 이벤트 로깅

    Args:
        level: 로그 레벨 ('info', 'error', 'warning', 'debug')
        event: 이벤트 이름
        **kwargs: 추가 메타데이터

    Example:
        log_event('info', 'api_state', switches_count=5)
        → {"event": "api_state", "switches_count": 5}
    """
    data = {"event": event, **kwargs}
    getattr(logger, level)(json.dumps(data))
