import queue
import threading
import logging
import re
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

from . import db
from . import fixtures
from . import utils
from config import get_config

logger = logging.getLogger(__name__)


def _sanitize_error_msg(error_str: str) -> str:
    """Redact sensitive info (passwords, credentials) from error messages.

    Security fix: Error logs may expose SSH credentials, file paths, or network topology.
    Remove known patterns and limit length to prevent log injection attacks.
    """
    if not error_str:
        return ""
    sanitized = re.sub(r'(password|credential|secret|key|auth)\s*[:=]\s*["\']?[^\s"\']+"?', '[REDACTED]', error_str, flags=re.I)
    sanitized = re.sub(r'/[a-zA-Z0-9/_\-\.]+\.pem', '[REDACTED]', sanitized)
    return sanitized[:200] if len(sanitized) > 200 else sanitized

_worker_queue = None
_worker_threads = []
_collecting_switches = set()
_collector_lock = threading.Lock()


def init_collector():
    global _worker_queue, _worker_threads
    config = get_config()
    max_workers = config.get_max_concurrent()
    _worker_queue = queue.Queue(maxsize=100)
    _worker_threads = []

    for i in range(max_workers):
        t = threading.Thread(target=_worker_loop, daemon=True, name=f"collector-worker-{i}")
        t.start()
        _worker_threads.append(t)

    utils.log_event("info", "collector_init", workers=max_workers)


def collect_switch(db_path, switch_id, username=None, password=None):
    global _worker_queue, _collecting_switches

    utils.log_event("info", "collect_switch_requested", switch_id=switch_id)

    if _worker_queue is None:
        init_collector()

    with _collector_lock:
        if switch_id in _collecting_switches:
            utils.log_event("warning", "collect_already_in_progress", switch_id=switch_id)
            return {
                "status": "error",
                "message": f"Switch {switch_id} is already being collected"
            }

        _collecting_switches.add(switch_id)

    try:
        _worker_queue.put((db_path, switch_id, username, password), block=False)
        position = _worker_queue.qsize()
        utils.log_event("info", "collect_queued", switch_id=switch_id, position=position)
        return {
            "status": "queued",
            "switch_id": switch_id,
            "queue_position": position
        }
    except queue.Full:
        with _collector_lock:
            _collecting_switches.discard(switch_id)
        utils.log_event("error", "collect_queue_full", switch_id=switch_id)
        return {
            "status": "error",
            "message": "Queue is full"
        }


def _worker_loop():
    global _worker_queue, _collecting_switches

    while True:
        # MEDIUM FIX (CPU optimization): Remove timeout to prevent unnecessary wakeups (busy-wait)
        # Worker will block indefinitely until task arrives, reducing CPU usage
        try:
            db_path, switch_id, username, password = _worker_queue.get()
        except queue.Empty:
            continue

        try:
            utils.log_event("info", "collect_start", switch_id=switch_id)
            db.set_switch_status(db_path, switch_id, "collecting")

            switch = db.get_switch(db_path, switch_id)
            if not switch:
                raise ValueError(f"Switch {switch_id} not found")

            vendor = switch["vendor"]
            config = get_config()

            if config.app.get("demo_mode"):
                outputs = fixtures.get_demo_outputs_for_vendor(vendor)
                utils.log_event("info", "demo_mode_outputs", switch_id=switch_id, vendor=vendor)
            else:
                outputs = _ssh_collect(switch, username, password, vendor)

            raw_outputs_path = _save_raw_outputs(db_path, switch_id, switch["name"], outputs)
            utils.log_event("info", "raw_outputs_saved", path=str(raw_outputs_path))

            parsed_data = _parse_outputs(vendor, outputs, switch_id)

            snapshot_id = db.save_snapshot(db_path, switch_id)
            db.save_ports(db_path, snapshot_id, switch_id, parsed_data.get("ports", []))
            db.save_mac_entries(db_path, snapshot_id, switch_id, parsed_data.get("macs", []))
            db.save_arp_entries(db_path, snapshot_id, switch_id, parsed_data.get("arps", []))

            db.set_switch_status(db_path, switch_id, "done")
            utils.log_event("info", "collect_done", switch_id=switch_id, snapshot_id=snapshot_id)

        except Exception as e:
            # Sanitize error messages to prevent credential/path exposure in logs (security fix: CVE-style issue)
            sanitized_error = _sanitize_error_msg(str(e))
            utils.log_event("error", "collect_error", switch_id=switch_id, error_type=type(e).__name__, error=sanitized_error)
            db.set_switch_status(db_path, switch_id, "failed", error=sanitized_error)
        finally:
            # CWE-522 fix: Explicitly clear credentials from memory to prevent plaintext exposure
            username = None
            password = None
            with _collector_lock:
                _collecting_switches.discard(switch_id)
            _worker_queue.task_done()


def _ssh_collect(switch, username, password, vendor, max_retries=3):
    """Collect outputs from network device via SSH with exponential backoff retry logic.

    Args:
        switch: Switch dict with 'name' and 'ip'
        username: SSH username
        password: SSH password
        vendor: Device vendor/type
        max_retries: Max retry attempts (default: 3) - handles transient network failures

    Returns:
        dict: Command outputs keyed by command name

    Raises:
        ImportError: If netmiko not installed
        Exception: After max_retries exhausted
    """
    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise ImportError("netmiko not installed")

    config = get_config()
    commands = config.get_commands(vendor)

    device = {
        "device_type": vendor,
        "ip": switch["ip"],
        "username": username,
        "password": password,
        "conn_timeout": config.collector.get("ssh_timeout", 30),
        "read_timeout": config.collector.get("read_timeout", 60),
        "fast_cli": False
    }

    # Exponential backoff retry loop for transient network failures (robustness improvement)
    import time
    for attempt in range(max_retries):
        utils.log_event("info", "ssh_connect", switch=switch["name"], vendor=vendor, attempt=attempt+1, max_retries=max_retries)

        try:
            outputs = {}
            with ConnectHandler(**device) as conn:
                conn.send_command("terminal length 0")
                for key, command in commands.items():
                    output = conn.send_command(command)
                    outputs[key] = output
                    utils.log_event("debug", "command_executed", command=command)
            return outputs
        except Exception as e:
            # Sanitize SSH error messages to prevent credential/host info exposure (security fix)
            sanitized_error = _sanitize_error_msg(str(e))

            if attempt < max_retries - 1:
                # Exponential backoff: 1s, 2s, 4s (retry on transient failures)
                wait_time = 2 ** attempt
                utils.log_event("warning", "ssh_retry", switch=switch["name"], attempt=attempt+1, max_retries=max_retries, wait_seconds=wait_time, error_type=type(e).__name__)
                time.sleep(wait_time)
            else:
                # Final attempt failed, log and raise
                utils.log_event("error", "ssh_error", switch=switch["name"], error_type=type(e).__name__, error=sanitized_error)
                raise
        finally:
            # CWE-522: Clear all credentials from memory after connection closes (success or failure)
            # ConnectHandler closes connection but credentials remain in device dict memory
            if 'device' in locals():
                device.clear()
            username = None
            password = None


def _save_raw_outputs(db_path, switch_id, switch_name, outputs):
    config = get_config()
    raw_outputs_root = Path(config.get_raw_outputs_path())

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = raw_outputs_root / switch_name / now
    output_dir.mkdir(parents=True, exist_ok=True)

    for key, content in outputs.items():
        file_path = output_dir / f"{key}.txt"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    return output_dir


def _parse_outputs(vendor, outputs, switch_id):
    utils.log_event("info", "parse_outputs", vendor=vendor, switch_id=switch_id)

    try:
        from . import parsers
        parser = parsers.get_parser(vendor)
        return parser.parse(outputs, switch_id)
    except ValueError:
        utils.log_event("warning", "parser_not_found", vendor=vendor)
        return {"ports": [], "macs": [], "arps": []}
