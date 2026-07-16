import logging
import os
import sys
import ipaddress
import secrets
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

import yaml

from . import utils

logger = logging.getLogger(__name__)

REQUIRED_KEYS = ["db_path", "flap_threshold", "upload_max_mb"]

# 데이터 디렉터리 캐시(쓰기 가능 검사를 매 호출마다 반복하지 않기 위함)
_data_dir_cache: Path | None = None


def _is_dir_writable(d: Path) -> bool:
    """디렉터리에 실제 파일을 만들어 보고 쓰기 가능 여부를 판정(best-effort)."""
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / (".netdash_write_probe_%d" % os.getpid())
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def get_data_dir() -> Path:
    """DB·토큰·로그가 저장될 쓰기 가능한 데이터 디렉터리를 결정.

    - 개발/테스트(비 frozen): 기존 동작 유지 — cwd 기준 상대경로.
    - exe(frozen): cwd가 아닌 **exe가 있는 폴더** 기준. exe를 어디서 실행하든
      (관리자 권한 실행 시 cwd=System32, 바로가기 실행 등) DB 위치가 고정된다.
      exe 폴더가 쓰기 불가(Program Files·읽기전용·네트워크 공유)면
      %LOCALAPPDATA%\\NetDash 로 폴백 — 'unable to open database file' 방지.
    """
    global _data_dir_cache
    if _data_dir_cache is not None:
        return _data_dir_cache

    if not getattr(sys, "frozen", False):
        return Path.cwd()  # dev/test: 캐시하지 않음(테스트가 cwd를 바꿈)

    exe_dir = Path(sys.executable).resolve().parent
    if _is_dir_writable(exe_dir):
        _data_dir_cache = exe_dir
        return exe_dir

    fallback = Path(os.getenv("LOCALAPPDATA")
                    or (Path.home() / "AppData" / "Local")) / "NetDash"
    try:
        fallback.mkdir(parents=True, exist_ok=True)
    except OSError:
        # 최후: exe 폴더 그대로 반환(원래 에러가 그대로 나되 위치는 명확)
        _data_dir_cache = exe_dir
        utils.log_event("error", "data_dir_unwritable", exe_dir=str(exe_dir))
        return exe_dir
    utils.log_event("warning", "data_dir_fallback",
                    exe_dir=str(exe_dir), data_dir=str(fallback),
                    reason="exe folder not writable")
    _data_dir_cache = fallback
    return fallback


@dataclass
class Config:
    # Core fields
    switches: list[dict[str, Any]] = field(default_factory=list)
    flap_threshold: int = 3
    upload_max_mb: int = 16
    db_path: str = "netdash.db"
    api_token: str | None = None

    # App configuration
    app: dict[str, Any] = field(default_factory=lambda: {})

    # Collector configuration
    collector: dict[str, Any] = field(default_factory=lambda: {})

    # Correlator configuration
    correlator: dict[str, Any] = field(default_factory=lambda: {})

    # Database configuration
    database: dict[str, Any] = field(default_factory=lambda: {})

    # Raw outputs configuration
    raw_outputs: dict[str, Any] = field(default_factory=lambda: {})

    # Logging configuration
    logging_config: dict[str, Any] = field(default_factory=lambda: {})

    def get_db_path(self) -> Path:
        """Get database path from config.

        상대경로면 데이터 디렉터리(get_data_dir) 기준으로 고정한다.
        exe(frozen)에서는 실행 위치(cwd)와 무관하게 항상 exe 폴더(또는
        LOCALAPPDATA 폴백)에 DB가 생겨 'unable to open database file'을 막는다.
        개발/테스트에서는 get_data_dir()==cwd 라 기존 동작과 동일하다.
        """
        p = Path(self.db_path)
        if p.is_absolute():
            return p
        resolved = get_data_dir() / p
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)  # db_path에 하위폴더 포함 대비
        except OSError:
            pass
        return resolved

    def get_raw_outputs_path(self) -> Path:
        """Get raw outputs path from config."""
        return Path(self.raw_outputs.get("path", "raw_outputs"))

    def get_max_concurrent(self) -> int:
        """Get max concurrent workers from config."""
        return self.collector.get("max_concurrent", 3)

    def get_commands(self, vendor: str) -> dict:
        """Get SSH commands for a vendor."""
        return self.collector.get("commands", {}).get(vendor, {})

    def get_uplink_threshold(self) -> int:
        """Get uplink threshold from config."""
        return self.correlator.get("uplink_mac_threshold", 4)


def _resolve_config_path(path: str = "config.yaml") -> str:
    """Resolve config path from env var, project root, or cwd.

    Env var paths are converted to absolute to prevent cwd-dependent behavior.
    """
    # 1. Environment variable override (convert to absolute path)
    if env_path := os.getenv("NETDASH_CONFIG"):
        env_path_resolved = str(Path(env_path).resolve())  # Normalize to absolute
        return env_path_resolved
    # 1.5. exe(frozen): exe 옆의 config.yaml이 번들 기본값보다 우선.
    # 사용자가 host/port 등을 파일로 오버라이드 가능(예: 다른 PC에서 브라우저
    # 접속을 허용하려고 host: 0.0.0.0 + api_token 설정). 파일이 없으면 기존처럼
    # 번들 config 사용 — 기존 사용자 동작 불변.
    if getattr(sys, "frozen", False):
        exe_cfg = Path(sys.executable).resolve().parent / path
        if exe_cfg.exists():
            return str(exe_cfg)
    # 2. Project root (parent of core/)
    project_root = Path(__file__).parent.parent
    project_config = project_root / path
    if project_config.exists():
        return str(project_config)
    # 3. Current working directory
    if Path(path).exists():
        return path
    # Return default (will log warning if not found)
    return path


def _validate_config_values(data: dict, demo_mode: bool = False) -> None:
    """Validate config field types and ranges. api_token is optional."""
    # Type validation for api_token if present
    if "api_token" in data and data["api_token"] is not None and not isinstance(data["api_token"], str):
        raise ValueError("api_token must be a string or None")
    if "flap_threshold" in data:
        if not isinstance(data["flap_threshold"], int) or data["flap_threshold"] < 0:
            raise ValueError("flap_threshold must be a non-negative integer")
    if "upload_max_mb" in data:
        if not isinstance(data["upload_max_mb"], int) or data["upload_max_mb"] <= 0 or data["upload_max_mb"] > 1000:
            raise ValueError("upload_max_mb must be a positive integer <= 1000")
    if "db_path" in data:
        if not isinstance(data["db_path"], str):
            raise ValueError("db_path must be a string")
        # Normalize to app data directory
        db_p = Path(data["db_path"])
        if db_p.is_absolute():
            utils.log_event("warning", "config_warn", msg="db_path is absolute; ensure it's in a writable location")
    if "switches" in data and not isinstance(data["switches"], list):
        raise ValueError("switches must be a list")
    # Validate each switch
    for i, sw in enumerate(data.get("switches") or []):
        if not isinstance(sw, dict):
            raise ValueError(f"switches[{i}] must be a dict")
        # name is required
        if "name" not in sw or not isinstance(sw["name"], str) or not sw["name"].strip():
            raise ValueError(f"switches[{i}].name is required and must be a non-empty string")
        # ip is required
        if "ip" not in sw:
            raise ValueError(f"switches[{i}].ip is required")
        try:
            ipaddress.IPv4Address(sw["ip"])
        except ValueError:
            raise ValueError(f"switches[{i}].ip '{sw['ip']}' is not a valid IPv4 address")
        # status validation if present
        if "status" in sw:
            valid_statuses = ("pending", "collecting", "done", "failed", "unsupported")
            if sw["status"] not in valid_statuses:
                raise ValueError(f"switches[{i}].status '{sw['status']}' must be one of {valid_statuses}")
        # vendor validation if present
        if "vendor" in sw:
            if not isinstance(sw["vendor"], str):
                raise ValueError(f"switches[{i}].vendor must be a string")


_LOCAL_TOKEN_FILE = "netdash_token.txt"


def _ensure_local_token() -> str:
    """로컬(loopback) 전용 production 기동을 위한 강한 API 토큰을 로드하거나 생성.

    기존 netdash_token.txt가 있으면 재사용(재시작 간 안정), 없으면 강한 토큰을
    생성해 파일로 영속화한다. 파일 쓰기 실패 시 메모리 전용 토큰(세션 한정)을 반환.
    secrets.token_urlsafe(32)는 길이/엔트로피 검증을 통과한다.
    """
    # DB와 동일한 데이터 디렉터리에 고정(cwd 의존 제거 — 관리자 실행 등에서도 재사용 안정)
    token_path = get_data_dir() / _LOCAL_TOKEN_FILE
    try:
        if token_path.exists():
            existing = token_path.read_text(encoding="utf-8").strip()
            if len(existing) >= 32:
                return existing
    except OSError:
        pass

    # 강도 검증(길이>=32 + 4종 중 3종 이상)을 보장하는 토큰을 생성.
    # token_urlsafe(32)는 거의 항상 충족하나, 결정론을 위해 재시도한다.
    token = secrets.token_urlsafe(32)
    for _ in range(20):
        has_u = any(c.isupper() for c in token)
        has_l = any(c.islower() for c in token)
        has_d = any(c.isdigit() for c in token)
        has_s = any(c in "-_" for c in token)
        if len(token) >= 32 and sum([has_u, has_l, has_d, has_s]) >= 3:
            break
        token = secrets.token_urlsafe(32)

    try:
        token_path.write_text(token, encoding="utf-8")
        _restrict_token_permissions(str(token_path))  # DB와 동일하게 owner-only
        utils.log_event("info", "api_token_persisted", path=str(token_path))
    except OSError:
        utils.log_event("warning", "api_token_persist_failed", path=str(token_path))
    return token


def _restrict_token_permissions(path: str) -> None:
    """토큰 파일을 소유자 전용으로 제한(외부 바인딩 시 유일한 인증 수단).

    DB 파일(db._restrict_db_permissions)과 동일 정책. 실패해도 무해(best-effort).
    네트워크 경로는 스킵(다른 PC 접근 차단 방지 — db와 동일 사유).
    """
    import os
    if utils.is_network_path(path):
        utils.log_event("info", "token_acl_skip_network_path", path=str(path))
        return
    try:
        if os.name == "nt":
            import subprocess
            CREATE_NO_WINDOW = 0x08000000
            subprocess.run(
                ["icacls", path, "/inheritance:r", "/grant:r",
                 "%s:F" % os.getenv("USERNAME", "SYSTEM")],
                check=False, capture_output=True, timeout=10,
                creationflags=CREATE_NO_WINDOW)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass


def load_config(path: str = "config.yaml", demo_mode: bool = False) -> Config:
    resolved_path = _resolve_config_path(path)
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        if demo_mode:
            utils.log_event("warning", "config_not_found", path=resolved_path, action="using_defaults", mode="demo")
            return _get_default_config(demo_mode=True)
        else:
            utils.log_event("error", "config_not_found", path=resolved_path, error="Required in production mode")
            raise RuntimeError(f"Config file '{resolved_path}' not found. Required for production mode.")
    except yaml.YAMLError as e:
        if demo_mode:
            utils.log_event("warning", "config_parse_error", path=resolved_path, error=str(e), action="using_defaults", mode="demo")
            return _get_default_config(demo_mode=True)
        else:
            utils.log_event("error", "config_parse_error", path=resolved_path, error=str(e))
            raise RuntimeError(f"Failed to parse config file '{resolved_path}': {e}")

    # Validate values
    try:
        _validate_config_values(data, demo_mode=demo_mode)
    except ValueError as e:
        utils.log_event("error", "config_validation_error", error=str(e))
        raise

    for key in REQUIRED_KEYS:
        if key not in data:
            utils.log_event("warning", "config_missing_key", key=key, action="using_default")

    # CWE-306 fix: Load api_token from environment variable (higher priority) or config file
    api_token_source = "environment" if os.getenv("API_TOKEN") else "config_file"
    api_token = os.getenv("API_TOKEN", data.get("api_token"))
    utils.log_event("info", "api_token_loaded", source=api_token_source)

    # Production mode: api_token is required and must be strong (CWE-306: enforce authentication + CWE-521: weak credentials)
    if not demo_mode:
        if not api_token:
            # HOTFIX: A closed-network local tool bound to loopback should run out of
            # the box. If no token is configured AND the bind host is loopback-only,
            # auto-generate and persist a strong token. Any externally reachable bind
            # (0.0.0.0 등) STILL requires an explicit token (CWE-306).
            app_cfg = data.get("app", {})
            if not isinstance(app_cfg, dict):
                app_cfg = {}
            bind_host = os.getenv("HOST") or app_cfg.get("host", "127.0.0.1")
            if bind_host in ("127.0.0.1", "localhost", "::1"):
                api_token = _ensure_local_token()
                utils.log_event("warning", "api_token_autogenerated",
                                reason="loopback bind without configured token")
            else:
                raise ValueError("api_token is required in production mode (set API_TOKEN environment variable or api_token in config)")
        # HARDENING (CWE-521 Weak Password): Validate token strength
        if len(api_token) < 32:
            raise ValueError(f"api_token must be at least 32 characters long (current: {len(api_token)}); use secrets.token_urlsafe(32) or similar")
        # Basic check: token should contain mix of character types (not just alphanumeric)
        has_uppercase = any(c.isupper() for c in api_token)
        has_lowercase = any(c.islower() for c in api_token)
        has_digit = any(c.isdigit() for c in api_token)
        has_special = any(c in "-_" for c in api_token) or any(33 <= ord(c) <= 126 and not c.isalnum() for c in api_token)
        entropy_checks = sum([has_uppercase, has_lowercase, has_digit, has_special])
        if entropy_checks < 3:
            raise ValueError("api_token must have sufficient entropy (mix of uppercase, lowercase, digits, and special characters)")

    utils.log_event("info", "config_loaded", path=resolved_path, mode="demo" if demo_mode else "production")
    # Ensure app config has correct demo_mode (override from file if needed)
    app_config = data.get("app", {})
    if not isinstance(app_config, dict):
        app_config = {}
    app_config = {**{"debug": False, "host": "127.0.0.1", "port": 8082}, **app_config}
    app_config["demo_mode"] = demo_mode  # Override with computed demo_mode

    return Config(
        switches=data.get("switches") or [],
        flap_threshold=data.get("flap_threshold", 3),
        upload_max_mb=data.get("upload_max_mb", 16),
        db_path=data.get("db_path", "netdash.db"),
        api_token=api_token,
        app=app_config,
        collector=_merge_collector_config(data.get("collector", {})),
        correlator=data.get("correlator", {"uplink_mac_threshold": 4}),
        database=data.get("database", {"path": "netdash.db"}),
        raw_outputs=data.get("raw_outputs", {"path": "raw_outputs"}),
        logging_config=data.get("logging", {"level": "INFO", "format": "json"}),
    )


def _get_default_config(demo_mode: bool = False) -> Config:
    """Return default Config for demo mode."""
    return Config(
        switches=[],
        flap_threshold=3,
        upload_max_mb=16,
        db_path="netdash.db",
        api_token=None,
        app={"debug": False, "host": "127.0.0.1", "port": 8082, "demo_mode": demo_mode},
        collector=_get_default_collector_config(),
        correlator={"uplink_mac_threshold": 4},
        database={"path": "netdash.db"},
        raw_outputs={"path": "raw_outputs"},
        logging_config={"level": "INFO", "format": "json"},
    )


def _get_default_collector_config() -> dict:
    """Return default collector configuration."""
    return {
        "max_concurrent": 3,
        "ssh_timeout": 30,
        "read_timeout": 60,
        # HARDENING (CWE-918 SSRF): RFC1918 기본 허용 범위. 공인 IP 접근 차단.
        "allowed_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "commands": {
            "cisco_ios": {"status": "show interfaces", "description": "show interfaces description",
                         "mac": "show mac address-table dynamic", "arp": "show arp"},
            "arista_eos": {"status": "show interfaces", "description": "show interfaces description",
                          "mac": "show mac address-table dynamic", "arp": "show ip arp"},
            "extreme_exos": {"status": "show ports no-refresh", "description": "show ports description",
                            "mac": "show fdb", "arp": "show iparp",
                            "logging": "show log messages memory-buffer",
                            "sysinfo": "show switch"}
        }
    }


def _merge_collector_config(from_yaml: dict) -> dict:
    """YAML collector 섹션과 기본값을 딥 병합.

    YAML에 collector 섹션이 있어도 누락된 키는 기본값으로 채워짐.
    이를 통해 allowed_ip_ranges 등 보안 기본값이 항상 보장됨.
    """
    default = _get_default_collector_config()
    merged = {**default, **from_yaml}
    # commands는 벤더별로 병합 (YAML에 일부 벤더만 있어도 나머지 유지)
    if "commands" in from_yaml and isinstance(from_yaml["commands"], dict):
        merged["commands"] = {**default["commands"], **from_yaml["commands"]}
    return merged
