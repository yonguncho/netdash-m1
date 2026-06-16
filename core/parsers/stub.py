COMMANDS: dict[str, str] = {
    "status": "",
    "mac": "",
    "arp": "",
}


def parse(outputs: dict[str, str]) -> dict:
    return {
        "ports": [
            {"name": "GigabitEthernet0/1", "link": "connected", "vlan": "10",
             "speed": "1000", "descr": "UPLINK-SW", "flap_count": 0},
            {"name": "GigabitEthernet0/2", "link": "notconnect", "vlan": "20",
             "speed": "auto", "descr": "WORKSTATION", "flap_count": 2},
        ],
        "mac_entries": [
            {"vlan": "10", "mac": "aabb.cc00.0001", "port": "GigabitEthernet0/1"},
            {"vlan": "20", "mac": "aabb.cc00.0002", "port": "GigabitEthernet0/2"},
        ],
        "arp_entries": [
            {"ip": "192.168.100.10", "mac": "aabb.cc00.0001", "interface": "Vlan10"},
            {"ip": "192.168.100.20", "mac": "aabb.cc00.0002", "interface": "Vlan20"},
        ],
    }
