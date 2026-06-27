import re
import logging
import ipaddress

# Import log_event from parent utils module to avoid duplication (maintenance fix: DRY principle)
from ..utils import log_event

logger = logging.getLogger(__name__)


MAC_PATTERN = re.compile(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})")
IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")


def normalize_mac(mac_str):
    if not mac_str:
        return None
    mac = re.sub(r"[:\\.-]", "", mac_str.lower())
    if len(mac) != 12:
        return None
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))


def validate_mac(mac_str):
    normalized = normalize_mac(mac_str)
    return normalized is not None


def normalize_port(port_str, vendor=None):
    if not port_str:
        return None

    port_str = port_str.strip()

    # M6: ExtremeXOS uses its own port notation (slot:port or a bare standalone
    # port number) and does NOT use Cisco interface-type prefixes like "Gi".
    # Preserve the native notation; only normalize internal whitespace.
    if vendor == "extreme_exos":
        # slot:port (whitespace tolerant) -> "slot:port"
        m = re.match(r"^(\d+)\s*:\s*(\d+)$", port_str)
        if m:
            return f"{m.group(1)}:{m.group(2)}"
        # standalone port number -> keep as-is
        if re.match(r"^\d+$", port_str):
            return port_str
        return port_str

    if re.match(r"[A-Za-z]+\d+/\d+/\d+", port_str):
        return port_str

    if re.match(r"[A-Za-z]+\d+", port_str):
        return port_str

    return port_str


def validate_ip(ip_str):
    if not ip_str:
        return False
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ValueError, ipaddress.AddressValueError):
        return False


def normalize_vlan(vlan_str):
    if not vlan_str:
        return None
    try:
        vlan_id = int(vlan_str)
        if 1 <= vlan_id <= 4094:
            return vlan_id
    except (ValueError, TypeError):
        pass
    return None


def deduplicate_list(items, key_func):
    seen = set()
    result = []
    for item in items:
        key = key_func(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def parse_interface_status(status_str):
    if not status_str:
        return "unknown"
    status_lower = status_str.lower().strip()
    if "up" in status_lower and "error" not in status_lower:
        return "up"
    elif "down" in status_lower or "notpresent" in status_lower:
        return "down"
    elif "error-disabled" in status_lower or "disabled" in status_lower:
        return "error-disabled"
    return "unknown"
