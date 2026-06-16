import logging
from collections import defaultdict
from . import db
from . import utils
from config import get_config

logger = logging.getLogger(__name__)


def correlate(db_path):
    utils.log_event("info", "correlate_start")

    config = get_config()
    uplink_threshold = config.get_uplink_threshold()

    arps = db.get_arp_entries(db_path)
    macs = db.get_mac_entries(db_path)

    uplink_ports = _identify_uplink_ports(macs, uplink_threshold)
    utils.log_event("info", "uplink_ports_identified", count=len(uplink_ports))

    hosts = _join_arp_mac(arps, macs, uplink_ports)

    db.save_hosts(db_path, hosts)

    utils.log_event("info", "correlate_done", total_ips=len(hosts))

    return {
        "hosts": hosts,
        "stats": {
            "total_ips": len(hosts),
            "located_ips": sum(1 for h in hosts.values() if h.get("located")),
            "accuracy": sum(1 for h in hosts.values() if h.get("located")) / len(hosts) if hosts else 0
        }
    }


def _identify_uplink_ports(macs, threshold):
    port_mac_count = defaultdict(int)

    for mac_entry in macs:
        port_key = (mac_entry.get("switch_id"), mac_entry.get("port"))
        port_mac_count[port_key] += 1

    uplink_ports = set()
    for port_key, count in port_mac_count.items():
        if count >= threshold:
            uplink_ports.add(port_key)
            utils.log_event("debug", "uplink_port_detected", switch_id=port_key[0], port=port_key[1], mac_count=count)

    return uplink_ports


def _join_arp_mac(arps, macs, uplink_ports):
    hosts = {}

    mac_to_port = {}
    for mac_entry in macs:
        mac = mac_entry.get("mac")
        switch_id = mac_entry.get("switch_id")
        port = mac_entry.get("port")

        port_key = (switch_id, port)
        if port_key not in uplink_ports:
            mac_to_port[mac] = (switch_id, port)

    for arp_entry in arps:
        ip = arp_entry.get("ip")
        mac = arp_entry.get("mac")

        if mac in mac_to_port:
            switch_id, port = mac_to_port[mac]
            hosts[ip] = {
                "mac": mac,
                "switch_id": switch_id,
                "port": port,
                "located": True,
                "confidence": 0.95,
                "reason": None
            }
        else:
            hosts[ip] = {
                "mac": mac,
                "switch_id": None,
                "port": None,
                "located": False,
                "confidence": 0.0,
                "reason": "MAC not found in any port"
            }

    return hosts
