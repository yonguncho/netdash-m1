import logging
import hmac
import os
import re
import io
import argparse
import tempfile
import ipaddress
import sqlite3
import time
import threading
from functools import wraps
from flask import Flask, jsonify, request, render_template, Response
from pathlib import Path

from config import get_config, reset_config
from core import db, collector, correlator, credentials, report_builder, netinfo, connectivity
from core import facility as facility_mod
from core import firewall as firewall_mod
from core.demo import run_demo
from core import flapping as flapping_mod
from core.utils import log_event
from core.collector import _sanitize_error_msg
from core.excel_loader import load_workbook as load_excel_workbook
from core.excel_loader import parse_switch_inventory

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
)
logger = logging.getLogger(__name__)


def validate_credential(value, max_length=256):
    """CRITICAL FIX (CWE-20): Validate credential string length and printable ASCII only.

    Prevents DoS (oversized input), injection attacks (control chars).
    Allows printable ASCII characters except space (to prevent accidental whitespace in passwords).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("credentials must be string")
    if len(value) == 0:
        raise ValueError("credentials cannot be empty")
    if len(value) > max_length:
        raise ValueError(f"credentials max length {max_length}")
    # CWE-20: Accept printable ASCII only (ord 33-126); exclude space (ord 32) to prevent whitespace-only credentials
    if not all(33 <= ord(c) <= 126 for c in value):
        raise ValueError("credentials must contain only printable ASCII characters (no spaces, no control chars)")
    return value


def validate_ipv4(ip_str, allowed_ip_ranges=None):
    """HARDENING (CWE-918 SSRF): Validate IPv4 address and reject reserved/dangerous ranges.

    Args:
        ip_str: IP address string
        allowed_ip_ranges: Optional list of allowed CIDR ranges (e.g., ["10.0.0.0/8", "172.16.0.0/12"])

    Raises:
        ValueError: If IP is invalid or in a reserved/dangerous range
    """
    if not isinstance(ip_str, str) or not ip_str.strip():
        raise ValueError("IP address is required and must be a string")

    try:
        ip_obj = ipaddress.IPv4Address(ip_str.strip())
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid IPv4 address: {ip_str}")

    # Reject reserved/dangerous ranges (loopback, multicast, link-local, etc.)
    if ip_obj.is_loopback:
        raise ValueError(f"Loopback address not allowed: {ip_str}")
    if ip_obj.is_multicast:
        raise ValueError(f"Multicast address not allowed: {ip_str}")
    if ip_obj.is_link_local:
        raise ValueError(f"Link-local address not allowed: {ip_str}")
    if ip_obj.is_reserved:
        raise ValueError(f"Reserved address not allowed: {ip_str}")

    # Check allowed_ip_ranges if provided (whitelist mode)
    if allowed_ip_ranges:
        allowed = False
        for cidr_str in allowed_ip_ranges:
            try:
                network = ipaddress.IPv4Network(cidr_str, strict=False)
                if ip_obj in network:
                    allowed = True
                    break
            except ipaddress.AddressValueError:
                log_event("warning", "invalid_cidr_range", cidr=cidr_str)
        if not allowed:
            raise ValueError(f"IP address not in allowed ranges: {ip_str}")

    return str(ip_obj)


# Rate limiting: IP/token-based request tracking (simple dict-based, no external dependency)
_rate_limit_tracker = {}
_rate_limit_lock = __import__("threading").Lock()

def rate_limit(endpoint, max_requests=5, window_seconds=60):
    """HARDENING (CWE-400): Simple rate limiter decorator.

    Limits requests per IP/token combination.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get identifier: IP + token (or IP alone)
            ip = request.remote_addr or "unknown"
            token = request.headers.get("X-API-Token", "")
            identifier = f"{ip}:{token}" if token else ip

            with _rate_limit_lock:
                now = time.time()
                key = f"{endpoint}:{identifier}"

                # Clean old entries (older than window)
                if key in _rate_limit_tracker:
                    timestamps = [t for t in _rate_limit_tracker[key] if now - t < window_seconds]
                    if len(timestamps) >= max_requests:
                        log_event("warning", "rate_limit_exceeded", endpoint=endpoint, identifier=identifier)
                        return jsonify({"error": "Rate limit exceeded"}), 429
                    _rate_limit_tracker[key] = timestamps + [now]
                else:
                    _rate_limit_tracker[key] = [now]

            return f(*args, **kwargs)
        return wrapper
    return decorator


def create_app(demo_mode=None):
    """Factory function to create and configure Flask app."""
    app = Flask(__name__,
                template_folder=str(Path(__file__).parent / "web" / "templates"),
                static_folder=str(Path(__file__).parent / "web" / "static"))

    # M4: Set 16MB max upload size (CWE-399 fix: prevent DoS via oversized uploads)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

    # Reset config singleton to allow fresh load in tests
    reset_config()
    config = get_config(demo_mode=demo_mode)

    db_path = config.get_db_path()
    db.init_schema(db_path)
    db.validate_schema(db_path)

    collector.init_collector()
    # M14: 하루 N회 자동 수집 스케줄러 시작(설정으로 on/off)
    try:
        from core import scheduler
        scheduler.start_scheduler(db_path)
    except Exception as e:
        log_event("warning", "scheduler_start_failed", error=str(e))

    # Load demo data in demo mode
    if config.app.get("demo_mode"):
        run_demo(config)

    # API Token validation for production mode (CWE-306 fix: enforce authentication on all API routes)
    @app.before_request
    def validate_api_token():
        # Skip token validation only for "/" (home) route and health checks
        if request.path == "/" or request.path == "/health":
            return
        # In demo mode, skip validation only if explicitly enabled in config
        if config.app.get("demo_mode"):
            return
        # Loopback-only bind + request originating from localhost is exempt:
        # a closed-network single-host tool is reachable only by the same machine's
        # user, so the local UI works without a token. The token defends remote
        # access only when bound to an externally reachable address (0.0.0.0 등).
        bind_host = config.app.get("host", "127.0.0.1")
        if bind_host in ("127.0.0.1", "localhost", "::1") and request.remote_addr in ("127.0.0.1", "::1"):
            return
        # Enforce API authentication in production mode (all /api/* routes)
        if request.path.startswith("/api/"):
            token = request.headers.get("X-API-Token")
            expected_token = config.api_token
            # CWE-306 fix: Reject if token is missing or invalid; never accept empty token
            if not token:
                log_event("warning", "api_missing_token", path=request.path)
                return jsonify({"error": "unauthorized"}), 401
            if not expected_token:
                # Production mode requires api_token to be set in config
                log_event("error", "api_token_not_configured", path=request.path)
                return jsonify({"error": "server configuration error"}), 500
            if not hmac.compare_digest(token, expected_token):
                log_event("warning", "api_invalid_token", path=request.path)
                return jsonify({"error": "unauthorized"}), 401

    # Security headers for all responses
    @app.after_request
    def set_security_headers(response):
        # script-src는 'self'만(인라인 스크립트/onclick 차단 → 이벤트 위임 사용).
        # style-src는 인라인 style 속성 허용(레이아웃 정상화). 스타일은 스크립트 실행이
        # 아니므로 XSS 위험이 낮다.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    @app.route("/", methods=["GET"])
    def index():
        demo_mode = config.app.get("demo_mode", False)
        return render_template("index.html", demo_mode=demo_mode)

    @app.route("/api/state", methods=["GET"])
    def get_state():
        log_event("info", "api_state")
        try:
            switches = db.get_switches(db_path)
            snapshots = db.get_snapshots(db_path)

            # hostname → TPS 물리 위치 라벨 + 랙 그룹핑 키 주입(포맷 일치 시)
            from core import tps_location, serverroom
            for sw in switches:
                info = tps_location.parse(sw.get("hostname"))
                if info:
                    sw["tps_location"] = info["label"]
                    sw["tps_group"] = "%d공장 · %s(%s) · %d층" % (
                        info["phase"], info["building_name"], info["building_code"], info["floor"])
                    sw["tps_num"] = "TPS" + info["tps"]
                # location "A09U27" → 서버실 랙/유닛 (서버실 현황 탭용)
                room = serverroom.parse_rack(sw.get("location"))
                if room:
                    sw["room_rack"] = room["rack"]
                    sw["room_unit"] = room["unit"]
                    sw["room_label"] = room["label"]

            return jsonify({
                "switches": switches,
                "snapshots": snapshots,
                "demo": config.app.get("demo_mode", False)
            })
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "api_state_error", error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches", methods=["GET"])
    def get_switches():
        log_event("info", "api_switches")
        try:
            switches = db.get_switches(db_path)
            return jsonify({"switches": switches})
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "api_switches_error", error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/manual", methods=["POST"])
    @rate_limit("add_switch_manual", max_requests=10, window_seconds=60)
    def add_switch_manual():
        """수동으로 스위치 1대 등록 (SSRF 검증 포함)."""
        try:
            data = request.get_json() or {}
            name = data.get("name", "").strip()
            ip = data.get("ip", "").strip()
            hostname = data.get("hostname", "").strip()
            vendor = data.get("vendor", "unknown").strip()
            location = data.get("location", "").strip()

            if not ip:
                return jsonify({"error": "ip is required"}), 400

            # HARDENING (CWE-918 SSRF): Validate IPv4 format and reject reserved ranges
            try:
                validated_ip = validate_ipv4(ip, allowed_ip_ranges=config.collector.get("allowed_ip_ranges"))
            except ValueError as e:
                log_event("warning", "add_switch_invalid_ip", ip=ip, reason=str(e))
                return jsonify({"error": str(e)}), 400

            if not name:
                name = hostname or validated_ip

            rows = [{"name": name, "ip": validated_ip, "hostname": hostname,
                     "vendor": vendor, "location": location, "note": data.get("note", "")}]
            ids = db.import_switches_bulk(db_path, rows)
            return jsonify({"ok": True, "switch_id": ids[0]}), 201
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "add_switch_manual_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/import", methods=["POST"])
    @rate_limit("import_switches_excel", max_requests=5, window_seconds=60)
    def import_switches_excel():
        """엑셀 파일(xlsx)로 스위치 목록 일괄 등록 (압축폭탄 검증 포함).
        컬럼 순서: name, ip, hostname, vendor, location (헤더 행 필수)
        """
        try:
            import openpyxl
            import zipfile
        except ImportError:
            return jsonify({"error": "required libraries not installed"}), 500

        if "file" not in request.files:
            return jsonify({"error": "file field required"}), 400

        file = request.files["file"]
        if not file.filename.endswith((".xlsx", ".xls")):
            return jsonify({"error": "xlsx file required"}), 400

        try:
            file_content = file.read()

            # HARDENING (CWE-409 Zip Bomb DoS): Validate ZIP compression ratio before processing
            max_compressed_size_mb = 16
            max_uncompressed_size_mb = 50
            max_compression_ratio = 100
            max_single_entry_size_mb = 10

            # Check overall file size
            if len(file_content) / (1024 * 1024) > max_compressed_size_mb:
                log_event("warning", "import_excel_file_too_large", size_mb=len(file_content) / (1024 * 1024))
                return jsonify({"error": f"Compressed file size exceeds {max_compressed_size_mb}MB"}), 413

            # Validate ZIP structure before openpyxl processes it
            try:
                with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
                    total_uncompressed = 0
                    for info in zf.infolist():
                        # Check individual entry size
                        if info.file_size / (1024 * 1024) > max_single_entry_size_mb:
                            log_event("warning", "import_excel_entry_too_large", entry=info.filename, size_mb=info.file_size / (1024 * 1024))
                            return jsonify({"error": f"Single ZIP entry exceeds {max_single_entry_size_mb}MB"}), 413

                        total_uncompressed += info.file_size

                        # Check compression ratio bomb
                        if info.compress_size > 0:
                            ratio = info.file_size / info.compress_size
                            if ratio > max_compression_ratio:
                                log_event("warning", "import_excel_compression_bomb", ratio=ratio, entry=info.filename)
                                return jsonify({"error": f"Compression ratio too high (potential zip bomb)"}), 413

                    if total_uncompressed / (1024 * 1024) > max_uncompressed_size_mb:
                        log_event("warning", "import_excel_uncompressed_too_large", size_mb=total_uncompressed / (1024 * 1024))
                        return jsonify({"error": f"Total uncompressed size exceeds {max_uncompressed_size_mb}MB"}), 413
            except zipfile.BadZipFile:
                log_event("warning", "import_excel_invalid_zip")
                return jsonify({"error": "Invalid ZIP/Excel file"}), 400

            wb = openpyxl.load_workbook(io.BytesIO(file_content), read_only=True)
            ws = wb.active
            rows_iter = ws.iter_rows(values_only=True)
            header = [str(c).lower().strip() if c else "" for c in next(rows_iter)]

            parsed_rows = []
            allowed_ip_ranges = config.collector.get("allowed_ip_ranges")
            for row in rows_iter:
                row_dict = dict(zip(header, row))
                ip = str(row_dict.get("ip", "") or "").strip()
                if not ip:
                    continue

                # HARDENING (CWE-918 SSRF): Validate each IP in bulk import
                try:
                    validated_ip = validate_ipv4(ip, allowed_ip_ranges=allowed_ip_ranges)
                except ValueError as e:
                    log_event("warning", "import_excel_invalid_ip", ip=ip, reason=str(e))
                    continue  # Skip invalid IP instead of failing the entire import

                parsed_rows.append({
                    "name": str(row_dict.get("name", "") or "").strip() or validated_ip,
                    "ip": validated_ip,
                    "hostname": str(row_dict.get("hostname", "") or "").strip(),
                    "vendor": str(row_dict.get("vendor", "unknown") or "unknown").strip(),
                    "location": str(row_dict.get("location", "") or "").strip(),
                })

            if not parsed_rows:
                return jsonify({"error": "no valid rows found"}), 400

            ids = db.import_switches_bulk(db_path, parsed_rows)
            return jsonify({"ok": True, "imported": len(ids), "switch_ids": ids}), 201
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "import_excel_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/import-inventory", methods=["POST"])
    @rate_limit("import_inventory", max_requests=5, window_seconds=60)
    def import_switch_inventory():
        """IP/SUBNET/HOSTNAME 인벤토리 엑셀 → 스위치 일괄 등록(벤더 unknown, 이후 수정)."""
        log_event("info", "import_inventory_requested")
        if "file" not in request.files:
            return jsonify({"error": "file field required"}), 400
        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"error": "file required"}), 400
        if not file.filename.endswith(".xlsx"):
            return jsonify({"error": ".xlsx file required"}), 400
        try:
            content = file.read()
            if len(content) / (1024 * 1024) > 16:
                return jsonify({"error": "file too large (16MB)"}), 413
            # CWE-409: 압축폭탄(zip bomb) 방어 — /api/upload와 동일 검증
            import zipfile as _zip
            try:
                with _zip.ZipFile(io.BytesIO(content), "r") as zf:
                    total = 0
                    for info in zf.infolist():
                        if info.file_size / (1024 * 1024) > 10:
                            return jsonify({"error": "ZIP entry too large"}), 413
                        total += info.file_size
                        if info.compress_size > 0 and info.file_size / info.compress_size > 100:
                            return jsonify({"error": "compression ratio too high (zip bomb)"}), 413
                    if total / (1024 * 1024) > 50:
                        return jsonify({"error": "uncompressed size too large"}), 413
            except _zip.BadZipFile:
                return jsonify({"error": "invalid xlsx file"}), 400
            rows = parse_switch_inventory(io.BytesIO(content))
            allowed = config.collector.get("allowed_ip_ranges")
            valid, skipped = [], 0
            for r in rows:
                try:
                    r["ip"] = validate_ipv4(r["ip"], allowed)
                    valid.append(r)
                except ValueError:
                    skipped += 1
            imported = db.import_switches_bulk(db_path, valid) if valid else []
            log_event("info", "inventory_imported", imported=len(imported), skipped=skipped, total=len(rows))
            return jsonify({"ok": True, "imported": len(imported), "skipped": skipped, "total": len(rows)})
        except Exception as e:
            log_event("error", "import_inventory_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/upload", methods=["POST"])
    @rate_limit("upload_excel", max_requests=5, window_seconds=60)
    def upload_excel():
        """M4: 멀티블록 엑셀 로더 엔드포인트 (압축폭탄 검증 포함).

        스위치/호스트 혼합 엑셀 파일을 자동으로 분리해서 DB에 임포트.
        - 16MB 업로드 제한 강제 (MAX_CONTENT_LENGTH)
        - .xlsx 확장자만 허용
        - 멀티블록 분리 + IP 필터링 + 멱등성(upsert)
        - ZIP 압축폭탄 검증
        """
        log_event("info", "upload_excel_requested")

        if "file" not in request.files:
            log_event("warning", "upload_no_file_field")
            return jsonify({"error": "file field required"}), 400

        file = request.files["file"]
        if not file or not file.filename:
            log_event("warning", "upload_empty_file")
            return jsonify({"error": "file required"}), 400

        # M4: CWE-434 fix - Allow only .xlsx extension (CWE-94 prevention)
        if not file.filename.endswith(".xlsx"):
            log_event("warning", "upload_invalid_extension", filename=file.filename)
            return jsonify({"error": ".xlsx file required"}), 400

        tmp_path = None
        try:
            # HARDENING (CWE-409 Zip Bomb DoS): Validate before tempfile creation
            file_content = file.read()
            import zipfile

            max_compressed_size_mb = 16
            max_uncompressed_size_mb = 50
            max_compression_ratio = 100
            max_single_entry_size_mb = 10

            if len(file_content) / (1024 * 1024) > max_compressed_size_mb:
                log_event("warning", "upload_file_too_large", size_mb=len(file_content) / (1024 * 1024))
                return jsonify({"error": f"Compressed file size exceeds {max_compressed_size_mb}MB"}), 413

            try:
                with zipfile.ZipFile(io.BytesIO(file_content), 'r') as zf:
                    total_uncompressed = 0
                    for info in zf.infolist():
                        if info.file_size / (1024 * 1024) > max_single_entry_size_mb:
                            log_event("warning", "upload_entry_too_large", entry=info.filename)
                            return jsonify({"error": f"Single ZIP entry exceeds {max_single_entry_size_mb}MB"}), 413

                        total_uncompressed += info.file_size

                        if info.compress_size > 0:
                            ratio = info.file_size / info.compress_size
                            if ratio > max_compression_ratio:
                                log_event("warning", "upload_compression_bomb_detected", ratio=ratio)
                                return jsonify({"error": "Compression ratio too high (potential zip bomb)"}), 413

                    if total_uncompressed / (1024 * 1024) > max_uncompressed_size_mb:
                        log_event("warning", "upload_uncompressed_too_large")
                        return jsonify({"error": f"Total uncompressed size exceeds {max_uncompressed_size_mb}MB"}), 413
            except zipfile.BadZipFile:
                log_event("warning", "upload_invalid_zip")
                return jsonify({"error": "Invalid ZIP/Excel file"}), 400

            # M4: Store file in temporary location, delete after processing (CWE-377 fix)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
                tmp.write(file_content)
                tmp_path = tmp.name

            # M4: Parse multiblock excel
            result = load_excel_workbook(tmp_path, read_only=True, data_only=True)

            switches = result.get("switches", [])
            hosts = result.get("hosts", [])
            allowed_ranges = config.collector.get("allowed_ip_ranges")

            # HARDENING (CWE-918 SSRF): Validate IPs in excel_loader output before DB import
            valid_switches = []
            for sw in switches:
                ip = sw.get("ip", "")
                try:
                    sw["ip"] = validate_ipv4(ip, allowed_ranges)
                    valid_switches.append(sw)
                except ValueError as e:
                    log_event("warning", "upload_switch_invalid_ip", ip=ip, reason=str(e))
                    result["diagnostics"].setdefault("warnings", []).append(
                        f"Switch IP rejected (SSRF): {ip} — {e}"
                    )

            valid_hosts = []
            for h in hosts:
                ip = h.get("ip", "")
                try:
                    h["ip"] = validate_ipv4(ip, allowed_ranges)
                    valid_hosts.append(h)
                except ValueError as e:
                    log_event("warning", "upload_host_invalid_ip", ip=ip, reason=str(e))
                    result["diagnostics"].setdefault("warnings", []).append(
                        f"Host IP rejected (SSRF): {ip} — {e}"
                    )

            # Import switches (upsert by IP)
            imported_switch_ids = []
            if valid_switches:
                imported_switch_ids = db.import_switches_bulk(db_path, valid_switches)
                log_event("info", "upload_switches_imported", count=len(imported_switch_ids))

            # Import hosts (upsert by IP)
            # M7: Excel hosts are the operator's LEDGER (expected inventory), not
            # measured data. Route them through save_ledger_hosts so they populate
            # ledger/mac columns WITHOUT clobbering measured location columns
            # (switch_id/port/located) that a prior collection may have set.
            imported_host_ids = []
            if valid_hosts:
                imported_host_ids = db.save_ledger_hosts(db_path, valid_hosts)
                log_event("info", "upload_hosts_imported", count=len(imported_host_ids))

            # WARNING 2 fix: 유효 row 0건인 경우 400 반환
            if not valid_switches and not valid_hosts:
                log_event("warning", "upload_no_valid_rows")
                return jsonify({
                    "error": "no valid rows found after IP validation",
                    "diagnostics": result["diagnostics"],
                }), 400

            # WARNING 3 fix: diagnostics imported count를 실제 DB import count로 덮어씀
            diagnostics = result["diagnostics"]
            diagnostics["imported_switches"] = len(imported_switch_ids)
            diagnostics["imported_hosts"] = len(imported_host_ids)

            return jsonify({
                "ok": True,
                "diagnostics": diagnostics,
                "imported_switch_ids": imported_switch_ids,
                "imported_host_ids": imported_host_ids,
            }), 201

        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent path/credential exposure
            sanitized = _sanitize_error_msg(str(e))
            log_event("error", "upload_excel_error", error_type=type(e).__name__, error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

        finally:
            # M4: Clean up temporary file immediately after processing (CWE-377 fix)
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                    log_event("debug", "temp_file_deleted", path=tmp_path)
                except Exception as e:
                    # HARDENING: Retry with delay for Windows file lock issue
                    import time
                    time.sleep(0.1)
                    try:
                        os.unlink(tmp_path)
                    except Exception as retry_e:
                        log_event("warning", "temp_file_delete_failed", path=tmp_path, error=str(retry_e))

    @app.route("/api/search", methods=["GET"])
    def search_ip():
        """IP/이름 종합 검색: 등록 스위치·방화벽 + 수집 ARP + 장부 호스트."""
        ip = request.args.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "ip parameter required"}), 400
        try:
            results = db.search_everywhere(db_path, ip)
            return jsonify({"results": results, "count": len(results)})
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "search_ip_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/facility", methods=["GET"])
    def facility_list():
        """설비 현황 + 수집 진행 상태 조회."""
        try:
            return jsonify({"hosts": db.get_facility_hosts(db_path),
                            "status": facility_mod.get_status()})
        except Exception as e:
            log_event("error", "facility_list_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/facility/rematch", methods=["POST"])
    @rate_limit("facility_rematch", max_requests=30, window_seconds=60)
    def facility_rematch():
        """설비 현황 새로고침: ping 없이 최신 MAC 스냅샷 기준으로 재대조."""
        try:
            n = facility_mod.rematch(db_path)
            return jsonify({"ok": True, "updated": n})
        except Exception as e:
            log_event("error", "facility_rematch_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/facility/detect-subnets", methods=["POST"])
    @rate_limit("facility_detect", max_requests=20, window_seconds=60)
    def facility_detect_subnets():
        """11번 스위치의 directly-connected 대역 자동 도출."""
        try:
            data = request.get_json() or {}
            switch_id = data.get("switch_id")
            if not switch_id:
                return jsonify({"error": "switch_id required"}), 400
            username = data.get("username", "")
            password = data.get("password", "")
            if not (username and password):
                blob = db.get_switch_credential(db_path, switch_id)
                if blob:
                    dec = credentials.decrypt_credential(blob)
                    if dec and "|" in dec:
                        username, password = dec.split("|", 1)
            if not (username and password):
                return jsonify({"error": "스위치 계정이 필요합니다(입력 또는 저장)"}), 400
            src = db.get_setting(db_path, "source_ip") or None
            subnets = facility_mod.detect_subnets(db_path, switch_id, username, password, src)
            return jsonify({"ok": True, "subnets": subnets})
        except Exception as e:
            log_event("error", "facility_detect_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error", "detail": collector._sanitize_error_msg(str(e))}), 500

    @app.route("/api/facility/collect", methods=["POST"])
    @rate_limit("facility_collect", max_requests=10, window_seconds=60)
    def facility_collect():
        """대역 ping sweep + ARP + MAC 대조 (11번 스위치가 직접 ping). 백그라운드."""
        try:
            data = request.get_json() or {}
            switch_id = data.get("switch_id")
            subnet = (data.get("subnet") or "").strip()
            username = data.get("username", "")
            password = data.get("password", "")
            if not switch_id or not subnet:
                return jsonify({"error": "switch_id and subnet required"}), 400
            # 대역 검증: 유효 CIDR + 크기 제한(/22 이하, ping 폭증 방지)
            try:
                net = ipaddress.IPv4Network(subnet, strict=False)
            except (ipaddress.AddressValueError, ValueError):
                return jsonify({"error": "invalid subnet (CIDR)"}), 400
            if net.num_addresses > 1024:
                return jsonify({"error": "대역이 너무 큽니다(/22 이하 권장)"}), 400
            sw = db.get_switch(db_path, switch_id)
            if not sw:
                return jsonify({"error": "switch not found"}), 404
            # 게이트웨이 스위치 IP는 등록 시 검증됨. 계정: 입력 또는 저장된 자격증명.
            if not (username and password):
                blob = db.get_switch_credential(db_path, switch_id)
                if blob:
                    dec = credentials.decrypt_credential(blob)
                    if dec and "|" in dec:
                        username, password = dec.split("|", 1)
            if not (username and password):
                return jsonify({"error": "스위치 계정이 필요합니다(입력 또는 저장)"}), 400
            src = db.get_setting(db_path, "source_ip") or None
            started = facility_mod.start_collect_band(db_path, switch_id, subnet, username, password, src)
            if not started:
                return jsonify({"error": "이미 수집 중입니다"}), 409
            return jsonify({"ok": True, "subnet": subnet})
        except Exception as e:
            log_event("error", "facility_collect_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/vlans", methods=["GET"])
    def get_vlans():
        """전체 VLAN 현황 조회."""
        try:
            vlans = db.get_vlan_summary(db_path)
            return jsonify({"vlans": vlans})
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "get_vlans_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/reconcile", methods=["GET"])
    def get_reconcile():
        """M7: 장부(엑셀) vs 실측(수집) 대조 결과 조회 (6판정 + summary)."""
        try:
            result = correlator.reconcile(db_path)
            return jsonify(result)
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "reconcile_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/report", methods=["GET"])
    def get_report():
        """M9: 현재 DB 상태를 4시트 엑셀 보고서로 내려받기."""
        try:
            data = report_builder.build_report(db_path)
            return Response(
                data,
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": "attachment; filename=netdash_report.xlsx"},
            )
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "report_error", error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/test", methods=["POST"])
    @rate_limit("test_switch", max_requests=20, window_seconds=60)
    def test_switch_connection():
        """M11: 스위치 연결 테스트 (IP+계정 입력값 기반, 저장 전 선검증)."""
        try:
            data = request.get_json() or {}
            ip = (data.get("ip") or "").strip()
            if not ip:
                return jsonify({"error": "ip required"}), 400
            try:
                ip = validate_ipv4(ip, config.collector.get("allowed_ip_ranges"))
            except ValueError as e:
                return jsonify({"ok": False, "stage": "reachable", "detail": f"IP rejected: {e}"}), 400
            src = db.get_setting(db_path, "source_ip") or None
            result = connectivity.test_switch(
                ip, data.get("vendor", ""), data.get("username", ""),
                data.get("password", ""), int(data.get("port", 22)),
                source_ip=src)
            if isinstance(result, dict):
                result["source_ip"] = src or ""  # 화면에 출발지 표시(자동이면 빈값)
            return jsonify(result)
        except Exception as e:
            log_event("error", "test_switch_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/firewalls/test", methods=["POST"])
    @rate_limit("test_firewall", max_requests=20, window_seconds=60)
    def test_firewall_connection():
        """M11: 방화벽 연결 테스트 (입력값 기반, 저장 전 선검증)."""
        try:
            data = request.get_json() or {}
            host = (data.get("host") or "").strip()
            vendor = (data.get("vendor") or "").lower()
            if not host:
                return jsonify({"error": "host required"}), 400
            if vendor not in firewall_mod.SUPPORTED_VENDORS:
                return jsonify({"error": "vendor must be fortigate or paloalto"}), 400
            try:
                host = validate_ipv4(host, config.collector.get("allowed_ip_ranges"))
            except ValueError as e:
                return jsonify({"ok": False, "stage": "reachable", "detail": f"host rejected: {e}"}), 400
            port = data.get("port")
            if port not in (None, "") and not (str(port).isdigit() and 1 <= int(port) <= 65535):
                return jsonify({"error": "port must be 1-65535"}), 400
            src = db.get_setting(db_path, "source_ip") or None
            result = connectivity.test_firewall(
                vendor, host, int(port) if port else None,
                token=data.get("token", ""), username=data.get("username", ""),
                password=data.get("password", ""), verify_ssl=bool(data.get("verify_ssl", False)),
                source_ip=src)
            if isinstance(result, dict):
                result["source_ip"] = src or ""  # 화면에 출발지 표시(자동이면 빈값)
            return jsonify(result)
        except Exception as e:
            log_event("error", "test_firewall_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>", methods=["PUT"])
    @rate_limit("update_switch", max_requests=20, window_seconds=60)
    def update_switch_endpoint(switch_id):
        """스위치 등록 정보 수정."""
        try:
            data = request.get_json() or {}
            ip = (data.get("ip") or "").strip()
            if ip:  # IP 변경 시 SSRF 검증
                try:
                    ip = validate_ipv4(ip, config.collector.get("allowed_ip_ranges"))
                except ValueError as e:
                    return jsonify({"error": str(e)}), 400
            try:
                ok = db.update_switch(
                    db_path, switch_id,
                    name=(data.get("name") or "").strip() or None,
                    ip=ip or None,
                    hostname=(data.get("hostname") or "").strip() or None,
                    vendor=(data.get("vendor") or "").strip() or None,
                    location=(data.get("location") or "").strip() or None,
                    note=(data.get("note") if "note" in data else None),
                )
            except sqlite3.IntegrityError:
                return jsonify({"error": "이미 사용 중인 이름 또는 IP입니다"}), 409
            if not ok:
                return jsonify({"error": "not found"}), 404
            log_event("info", "switch_updated", switch_id=switch_id)
            return jsonify({"ok": True})
        except Exception as e:
            log_event("error", "update_switch_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>", methods=["DELETE"])
    @rate_limit("delete_switch", max_requests=20, window_seconds=60)
    def delete_switch_endpoint(switch_id):
        """스위치 삭제 (잘못 등록 시 제거)."""
        try:
            ok = db.delete_switch(db_path, switch_id)
            if not ok:
                return jsonify({"error": "not found"}), 404
            log_event("info", "switch_deleted", switch_id=switch_id)
            return jsonify({"ok": True})
        except Exception as e:
            log_event("error", "delete_switch_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/bulk-delete", methods=["POST"])
    @rate_limit("bulk_delete_switch", max_requests=20, window_seconds=60)
    def bulk_delete_switches_endpoint():
        """스위치 여러 대 일괄/선택 삭제. body: {ids:[...]}"""
        try:
            data = request.get_json() or {}
            ids = data.get("ids", [])
            if not isinstance(ids, list) or not ids:
                return jsonify({"error": "ids required"}), 400
            if len(ids) > 1000:
                return jsonify({"error": "too many ids"}), 400
            deleted = db.delete_switches_bulk(db_path, ids)
            log_event("info", "switches_bulk_deleted", count=deleted)
            return jsonify({"ok": True, "deleted": deleted})
        except Exception as e:
            log_event("error", "bulk_delete_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/firewalls/<int:fid>", methods=["PUT"])
    @rate_limit("update_firewall", max_requests=20, window_seconds=60)
    def update_firewall_endpoint(fid):
        """방화벽 등록 정보 수정."""
        try:
            data = request.get_json() or {}
            host = (data.get("host") or "").strip()
            if host:
                try:
                    host = validate_ipv4(host, config.collector.get("allowed_ip_ranges"))
                except ValueError as e:
                    return jsonify({"error": f"host rejected: {e}"}), 400
            vendor = (data.get("vendor") or "").strip().lower()
            if vendor and vendor not in firewall_mod.SUPPORTED_VENDORS:
                return jsonify({"error": "vendor must be fortigate or paloalto"}), 400
            port = data.get("port")
            if port not in (None, "") and not (str(port).isdigit() and 1 <= int(port) <= 65535):
                return jsonify({"error": "port must be 1-65535"}), 400
            try:
                ok = db.update_firewall(
                    db_path, fid,
                    name=(data.get("name") or "").strip() or None,
                    vendor=vendor or None,
                    host=host or None,
                    port=int(port) if port not in (None, "") else None,
                )
            except sqlite3.IntegrityError:
                return jsonify({"error": "이미 사용 중인 호스트입니다"}), 409
            if not ok:
                return jsonify({"error": "not found"}), 404
            log_event("info", "firewall_updated", firewall_id=fid)
            return jsonify({"ok": True})
        except Exception as e:
            log_event("error", "update_firewall_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/firewalls/<int:fid>", methods=["DELETE"])
    @rate_limit("delete_firewall", max_requests=20, window_seconds=60)
    def delete_firewall_endpoint(fid):
        """방화벽 삭제 (잘못 등록 시 제거)."""
        try:
            ok = db.delete_firewall(db_path, fid)
            if not ok:
                return jsonify({"error": "not found"}), 404
            log_event("info", "firewall_deleted", firewall_id=fid)
            return jsonify({"ok": True})
        except Exception as e:
            log_event("error", "delete_firewall_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/netinfo", methods=["GET"])
    def get_netinfo():
        """M11: PC 로컬 네트워크 정보(이더넷 IP) 조회. 장비 접근에 쓰는 IP 안내용."""
        try:
            info = netinfo.get_network_info()
            info["source_ip"] = db.get_setting(db_path, "source_ip", "") or ""
            return jsonify(info)
        except Exception as e:
            log_event("error", "netinfo_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/settings/auto_collect", methods=["GET"])
    def get_auto_collect():
        """M14: 자동 수집 설정 조회."""
        try:
            return jsonify({
                "enabled": db.get_setting(db_path, "auto_collect_enabled", "0") == "1",
                "times": db.get_setting(db_path, "auto_collect_times", "06:00,18:00") or "06:00,18:00",
            })
        except Exception as e:
            log_event("error", "get_auto_collect_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/settings/auto_collect", methods=["POST"])
    @rate_limit("set_auto_collect", max_requests=20, window_seconds=60)
    def set_auto_collect():
        """M14: 자동 수집 on/off + 시각(HH:MM,HH:MM) 설정."""
        try:
            data = request.get_json() or {}
            enabled = "1" if data.get("enabled") else "0"
            raw = (data.get("times") or "").strip()
            # HH:MM 형식만 허용(쉼표 구분, 최대 6개)
            valid = []
            for t in raw.split(","):
                t = t.strip()
                if re.match(r"^([01]\d|2[0-3]):[0-5]\d$", t):
                    valid.append(t)
            if not valid:
                valid = ["06:00", "18:00"]
            db.set_setting(db_path, "auto_collect_enabled", enabled)
            db.set_setting(db_path, "auto_collect_times", ",".join(valid[:6]))
            log_event("info", "auto_collect_set", enabled=enabled, times=",".join(valid[:6]))
            return jsonify({"ok": True, "enabled": enabled == "1", "times": ",".join(valid[:6])})
        except Exception as e:
            log_event("error", "set_auto_collect_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/settings/source_ip", methods=["POST"])
    @rate_limit("set_source_ip", max_requests=20, window_seconds=60)
    def set_source_ip():
        """M12: 장비 접근에 사용할 출발지 IP 설정(빈값=자동/OS 기본). PC 이더넷 IP만 허용."""
        try:
            data = request.get_json() or {}
            ip = (data.get("ip") or "").strip()
            if ip and ip not in netinfo.get_local_ipv4_addresses():
                return jsonify({"error": "선택한 IP가 이 PC의 이더넷 IP 목록에 없습니다"}), 400
            db.set_setting(db_path, "source_ip", ip)
            log_event("info", "source_ip_set", source_ip=ip or "(auto)")
            return jsonify({"ok": True, "source_ip": ip})
        except Exception as e:
            log_event("error", "set_source_ip_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    # ── M10: 방화벽 (Palo Alto / Fortinet) ─────────────────────────
    @app.route("/api/firewalls", methods=["GET"])
    def list_firewalls_endpoint():
        """방화벽 장비 목록 조회."""
        try:
            return jsonify({"firewalls": db.list_firewalls(db_path)})
        except Exception as e:
            log_event("error", "firewalls_list_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/firewalls", methods=["POST"])
    @rate_limit("add_firewall", max_requests=10, window_seconds=60)
    def add_firewall_endpoint():
        """방화벽 장비 등록 (벤더: fortigate | paloalto)."""
        try:
            data = request.get_json() or {}
            vendor = (data.get("vendor") or "").lower()
            host = (data.get("host") or "").strip()
            name = (data.get("name") or host).strip()
            if vendor not in firewall_mod.SUPPORTED_VENDORS:
                return jsonify({"error": "vendor must be fortigate or paloalto"}), 400
            if not host:
                return jsonify({"error": "host required"}), 400
            # SSRF: 방화벽 host도 허용 대역 검증
            try:
                host = validate_ipv4(host, config.collector.get("allowed_ip_ranges"))
            except ValueError as e:
                log_event("warning", "firewall_blocked_invalid_ip", host=host, reason=str(e))
                return jsonify({"error": f"host rejected: {e}"}), 400
            # SSRF(CWE-918): port를 정수 1-65535로 강제 검증. SQLite는 타입 강제를
            # 하지 않으므로 '443@evil' 같은 문자열이 저장되어 요청 URL에 주입되는 것을 차단.
            port_raw = data.get("port")
            port = None
            if port_raw is not None and port_raw != "":
                try:
                    port = int(port_raw)
                except (ValueError, TypeError):
                    return jsonify({"error": "port must be an integer 1-65535"}), 400
                if not (1 <= port <= 65535):
                    return jsonify({"error": "port must be an integer 1-65535"}), 400
            fid = db.save_firewall(db_path, name, vendor, host,
                                   port, data.get("auth_type", "token"))
            # M11: 자격증명(토큰/계정)을 DPAPI 암호화하여 저장(입력된 경우만).
            # 저장되면 이후 수집 시 재입력 불필요. 암호화 불가(비Windows) 시 저장 생략.
            cred = {"token": data.get("token", ""), "username": data.get("username", ""),
                    "password": data.get("password", "")}
            if any(cred.values()):
                import json as _json
                blob = credentials.encrypt_text(_json.dumps(cred))
                if blob:
                    db.save_firewall_credential(db_path, fid, blob)
                    log_event("info", "firewall_cred_saved", firewall_id=fid)
            log_event("info", "firewall_added", firewall_id=fid, vendor=vendor)
            return jsonify({"ok": True, "firewall_id": fid, "cred_saved": bool(cred and any(cred.values()))}), 201
        except Exception as e:
            log_event("error", "firewall_add_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/firewalls/<int:fid>", methods=["GET"])
    def get_firewall_detail(fid):
        """방화벽 상세 (인터페이스 + ARP)."""
        try:
            fw = db.get_firewall(db_path, fid)
            if not fw:
                return jsonify({"error": "not found"}), 404
            return jsonify({
                "firewall": fw,
                "interfaces": db.get_firewall_interfaces(db_path, fid),
                "arp": db.get_firewall_arp(db_path, fid),
            })
        except Exception as e:
            log_event("error", "firewall_detail_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/firewalls/<int:fid>/collect", methods=["POST"])
    @rate_limit("collect_firewall", max_requests=10, window_seconds=60)
    def collect_firewall_endpoint(fid):
        """방화벽에서 인터페이스 + ARP 수집 (자격증명은 요청 시점에만 사용)."""
        fw = db.get_firewall(db_path, fid)
        if not fw:
            return jsonify({"error": "not found"}), 404
        # SSRF(CWE-918): collect 시점에도 저장된 host/port를 재검증한다(스위치 collect와
        # 동일 정책). legacy/seed 데이터나 우회 저장이 요청 대상이 되는 것을 차단.
        try:
            validate_ipv4(fw.get("host"), config.collector.get("allowed_ip_ranges"))
        except ValueError as e:
            db.set_firewall_status(db_path, fid, "failed")
            log_event("warning", "firewall_collect_blocked_invalid_ip", firewall_id=fid, reason=str(e))
            return jsonify({"error": f"firewall host rejected: {e}"}), 400
        fw_port = fw.get("port")
        if fw_port is not None and not (isinstance(fw_port, int) and 1 <= fw_port <= 65535):
            db.set_firewall_status(db_path, fid, "failed")
            return jsonify({"error": "stored firewall port is invalid"}), 400
        data = request.get_json() or {}
        token = data.get("token", "")
        username = data.get("username", "")
        password = data.get("password", "")
        provided = bool(token or username or password)  # 요청에 cred 직접 입력 여부
        # M11: 요청에 자격증명이 없으면 저장된(암호화) 자격증명을 복호화해 사용.
        if not (token or username or password):
            blob = db.get_firewall_credential(db_path, fid)
            if blob:
                dec = credentials.decrypt_text(blob)
                if dec:
                    import json as _json
                    try:
                        saved = _json.loads(dec)
                        token = saved.get("token", "")
                        username = saved.get("username", "")
                        password = saved.get("password", "")
                    except (ValueError, TypeError):
                        pass
        db.set_firewall_status(db_path, fid, "collecting")
        try:
            result = firewall_mod.collect_firewall(
                fw["vendor"], fw["host"], fw.get("port"),
                token=token, username=username, password=password,
                verify_ssl=bool(data.get("verify_ssl", False)),
                source_ip=db.get_setting(db_path, "source_ip") or None,
            )
            db.save_firewall_interfaces(db_path, fid, result["interfaces"])
            db.save_firewall_arp(db_path, fid, result["arp"])
            # 수집 모달에서 처음 입력한 자격증명은 저장해 다음 수집부터 재입력 불필요.
            if provided:
                try:
                    import json as _json
                    blob = credentials.encrypt_text(_json.dumps(
                        {"token": token, "username": username, "password": password}))
                    if blob:
                        db.save_firewall_credential(db_path, fid, blob)
                except Exception:
                    pass  # 저장 실패는 수집 성공에 영향 없음
            db.set_firewall_status(db_path, fid, "done")
            log_event("info", "firewall_collected", firewall_id=fid,
                      interfaces=len(result["interfaces"]), arp=len(result["arp"]))
            return jsonify({"ok": True,
                            "interfaces": len(result["interfaces"]),
                            "arp": len(result["arp"])})
        except Exception as e:
            db.set_firewall_status(db_path, fid, "failed")
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "firewall_collect_error", firewall_id=fid, error=sanitized)
            return jsonify({"error": "수집 실패", "detail": sanitized}), 502
        finally:
            token = username = password = None

    @app.route("/api/switches/<int:switch_id>/events", methods=["GET"])
    def get_switch_events(switch_id):
        """스위치의 포트 이벤트(flapping/looping) 조회."""
        try:
            events = db.get_port_events(db_path, switch_id)
            return jsonify({"switch_id": switch_id, "events": events})
        except Exception as e:
            sanitized = collector._sanitize_error_msg(str(e))
            log_event("error", "get_events_error", switch_id=switch_id, error=sanitized)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/bulk-collect", methods=["POST"])
    @rate_limit("bulk_collect", max_requests=10, window_seconds=60)
    def bulk_collect_endpoint():
        """공통 계정으로 선택된 스위치들을 일괄(비동기 동시) 수집.

        body: {ids:[...], username, password, persist?}
        각 스위치를 워커 큐에 넣어 동시 수집한다. 계정은 세션 저장소 경유(평문 큐 비노출).
        """
        try:
            data = request.get_json() or {}
            ids = data.get("ids", [])
            if not isinstance(ids, list) or not ids:
                return jsonify({"error": "ids required"}), 400
            if len(ids) > 500:
                return jsonify({"error": "too many ids"}), 400
            try:
                username = validate_credential(data.get("username"))
                password = validate_credential(data.get("password"))
            except ValueError as ve:
                return jsonify({"error": str(ve)}), 400
            if not config.app.get("demo_mode") and (not username or not password):
                return jsonify({"error": "username and password required"}), 400

            persist = data.get("persist", False)
            queued, skipped = [], []
            allowed = config.collector.get("allowed_ip_ranges")
            for raw in ids:
                try:
                    sid = int(raw)
                except (TypeError, ValueError):
                    continue
                sw = db.get_switch(db_path, sid)
                if not sw:
                    skipped.append({"id": sid, "reason": "not found"})
                    continue
                # SSRF 방어: DB에 저장된 IP도 수집 직전 재검증
                ip = sw.get("ip") if isinstance(sw, dict) else getattr(sw, "ip", None)
                if ip:
                    try:
                        validate_ipv4(ip, allowed)
                    except ValueError as e:
                        skipped.append({"id": sid, "reason": "ip rejected: %s" % e})
                        continue
                result = collector.collect_switch(db_path, sid, username, password)
                if result.get("status") == "queued":
                    queued.append(sid)
                    if persist:
                        cred_blob = credentials.encrypt_credential(username, password)
                        if cred_blob:
                            try:
                                db.update_cred_blob(db_path, sid, cred_blob)
                            except Exception:
                                pass
                else:
                    skipped.append({"id": sid, "reason": result.get("message", "enqueue failed")})
            log_event("info", "bulk_collect", queued=len(queued), skipped=len(skipped))
            return jsonify({"ok": True, "queued": queued, "skipped": skipped,
                            "queued_count": len(queued), "skipped_count": len(skipped)}), 202
        except Exception as e:
            log_event("error", "bulk_collect_error", error=collector._sanitize_error_msg(str(e)))
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>/collect", methods=["POST"])
    def collect_switch_endpoint(switch_id):
        log_event("info", "collect_requested", switch_id=switch_id)

        try:
            data = request.get_json() or {}

            # HIGH FIX (CWE-20): Validate credential string length, type, character set
            try:
                username = validate_credential(data.get("username"))
                password = validate_credential(data.get("password"))
            except ValueError as validation_error:
                log_event("warning", "collect_invalid_credentials", switch_id=switch_id, reason=str(validation_error))
                return jsonify({"error": str(validation_error)}), 400

            # CWE-522 fix: Require credentials in production mode; sanitize log output
            if not config.app.get("demo_mode") and (not username or not password):
                return jsonify({"error": "username and password required"}), 400

            # HARDENING (CWE-918 SSRF): Validate DB switch IP before collection.
            # Prevents legacy/seed data with public IPs from bypassing input validation.
            switch_row = db.get_switch(db_path, switch_id)
            if switch_row:
                switch_ip = switch_row.get("ip") if isinstance(switch_row, dict) else getattr(switch_row, "ip", None)
                if switch_ip:
                    try:
                        validate_ipv4(switch_ip, config.collector.get("allowed_ip_ranges"))
                    except ValueError as e:
                        log_event("warning", "collect_blocked_invalid_ip", switch_id=switch_id, ip=switch_ip, reason=str(e))
                        return jsonify({"error": f"Switch IP rejected: {e}"}), 400

            persist = data.get("persist", False)

            # M5 (CWE-362 race fix): collect_switch owns session storage. It stores
            # the credential ONLY after passing the in-progress check, so a duplicate
            # request can never overwrite or clear an active job's credential. It
            # also disposes the credential itself on any enqueue failure. The async
            # worker loads it at moment-of-use and clears it when collection finishes.
            result = collector.collect_switch(db_path, switch_id, username, password)

            # M5 (W3): Map the async submission outcome to an accurate HTTP status.
            status = result.get("status")
            if status == "queued":
                # M5 R2: Persist the DPAPI blob ONLY after a successful enqueue, so a
                # duplicate request (rejected as in-progress below) can never overwrite
                # an active switch's persisted credential blob.
                if persist:
                    cred_blob = credentials.encrypt_credential(username, password)
                    if cred_blob:
                        try:
                            db.update_cred_blob(db_path, switch_id, cred_blob)
                            log_event("info", "credential_persisted", switch_id=switch_id)
                        except Exception as e:
                            sanitized = _sanitize_error_msg(str(e))
                            log_event("warning", "credential_persist_failed", switch_id=switch_id, error=sanitized)
                return jsonify(result), 202
            if "already being collected" in result.get("message", ""):
                return jsonify(result), 409  # Conflict: collection in progress
            return jsonify(result), 503  # Service Unavailable: queue full / enqueue failed
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "collect_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/switches/<int:switch_id>/detail", methods=["GET"])
    def get_switch_detail(switch_id):
        log_event("info", "detail_requested", switch_id=switch_id)

        try:
            switch = db.get_switch(db_path, switch_id)
            if not switch:
                return jsonify({"error": "Switch not found"}), 404

            from core import tps_location
            _info = tps_location.parse(switch.get("hostname"))
            if _info:
                switch["tps_location"] = _info["label"]

            ports = db.get_ports_by_switch(db_path, switch_id)
            macs = db.get_mac_entries_by_switch(db_path, switch_id)
            arps = db.get_arp_entries_by_switch(db_path, switch_id)
            hosts = db.get_hosts_by_switch(db_path, switch_id)

            # show logging 분석 결과(최근 로그 + 탐지 이벤트)
            logs = None
            raw_logs = db.get_switch_logs(db_path, switch_id)
            if raw_logs:
                import json as _json
                try:
                    events = _json.loads(raw_logs.get("events_json") or "[]")
                except (ValueError, TypeError):
                    events = []
                logs = {
                    "recent": (raw_logs.get("recent_lines") or "").split("\n"),
                    "events": events,
                    "alert": raw_logs.get("log_alert") or "none",
                    "updated": raw_logs.get("updated"),
                }

            return jsonify({
                "switch": switch,
                "ports": ports,
                "macs": macs,
                "arps": arps,
                "hosts": hosts,
                "logs": logs
            })
        except Exception as e:
            # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
            sanitized_error = _sanitize_error_msg(str(e))
            log_event("error", "detail_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
            return jsonify({"error": "Internal server error"}), 500

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        # CWE-532 fix: Sanitize error messages to prevent credential/path exposure in logs
        sanitized_error = _sanitize_error_msg(str(e))
        log_event("error", "internal_error", error_type=type(e).__name__, error=sanitized_error)
        return jsonify({"error": "Internal server error"}), 500

    return app


def _open_browser_when_ready(url, port):
    """서버 기동(포트 LISTEN)을 확인한 뒤 기본 브라우저를 연다.

    headless 웹앱(console=False)이라 더블클릭 시 화면이 안 뜨는 문제를 해결한다.
    별도 스레드에서 포트를 폴링하므로 app.run()을 막지 않는다.
    """
    import socket
    import time
    import webbrowser

    for _ in range(60):  # 최대 ~30초 대기
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.5)
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    import traceback
    try:
        parser = argparse.ArgumentParser(description="NetDash - Network switch current status dashboard")
        parser.add_argument("--demo", action="store_true", help="Run in demo mode with sample data")
        args = parser.parse_args()

        # CLI --demo flag takes precedence over DEMO_MODE environment variable
        demo_mode = args.demo if args.demo else (os.getenv("DEMO_MODE", "").lower() == "true")

        # Create config with determined demo_mode
        reset_config()
        config = get_config(demo_mode=demo_mode)

        app = create_app(demo_mode=demo_mode)

        # CWE-306 fix: In production mode, API token MUST be configured.
        # (config_loader auto-generates a token for loopback binds; this is a safety net.)
        if not demo_mode and not config.api_token:
            api_token_env = os.getenv("API_TOKEN", "")
            if not api_token_env:
                log_event("error", "app_start_failed", reason="API_TOKEN required in production mode")
                raise RuntimeError("API_TOKEN environment variable required in production mode")
            config.api_token = api_token_env

        host = config.app.get("host", "127.0.0.1")
        port = config.app.get("port", 8082)
        # CRITICAL FIX (CWE-489): In production mode, force debug=False to prevent credential/stack-trace exposure.
        # Do NOT allow debug override via environment variables in production (app.run() receives final value here).
        debug = config.app.get("debug", False) and demo_mode

        log_event("info", "app_start", host=host, port=port, debug=debug, demo_mode=demo_mode)

        open_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        url = f"http://{open_host}:{port}"

        # 가시적 콘솔 배너 (console=True): 사용자가 실행 상태/접속 주소/종료법을 명확히 인지.
        mode_label = "데모" if demo_mode else "운영"
        print("=" * 56)
        print("  NetDash 가 시작되었습니다.  (모드: " + mode_label + ")")
        print("  접속 주소:  " + url)
        print("  종료하려면 이 창을 닫거나 Ctrl+C 를 누르세요.")
        print("=" * 56, flush=True)

        # 편의: 서버가 뜨면 브라우저를 자동으로 연다. 콘솔이 떠 있으므로
        # 백그라운드 은닉이 아니라 보조 기능이다(자동으로 안 열려도 위 주소로 접속).
        browser_thread = threading.Thread(
            target=_open_browser_when_ready,
            args=(url, port),
            daemon=True,
        )
        browser_thread.start()

        app.run(host=host, port=port, debug=debug)
    except Exception:
        # console=False(windowed) exe에서는 콘솔에 트레이스백이 보이지 않으므로
        # 작업 디렉터리에 에러 로그를 남겨 진단을 가능하게 한다.
        try:
            with open("netdash_error.log", "w", encoding="utf-8") as _f:
                _f.write(traceback.format_exc())
        except OSError:
            pass
        raise
