CISCO_IOS_SHOW_INTERFACES = """Interface                      Status         Protocol
Gi1/0/1                        up             up
Gi1/0/2                        up             up
Gi1/0/3                        down           down
Gi1/0/4                        up             up
Gi1/0/5                        up             up
"""

CISCO_IOS_SHOW_INTERFACES_DESC = """Interface                      Status         Protocol Description
Gi1/0/1                        up             up      VLAN10-PC01
Gi1/0/2                        up             up      VLAN20-PC02
Gi1/0/3                        down           down    VLAN30-PC03
Gi1/0/4                        up             up      VLAN40-PC04
Gi1/0/5                        up             up      CORE-Link
"""

CISCO_IOS_SHOW_MAC_ADDRESS_TABLE = """Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 1      0011223344aa      dynamic     Gi1/0/1
 1      0011223344bb      dynamic     Gi1/0/2
 1      0011223344cc      dynamic     Gi1/0/4
 1      0011223344dd      dynamic     Gi1/0/4
 1      0011223344ee      dynamic     Gi1/0/5
 1      0011223344ff      dynamic     Gi1/0/5
"""

CISCO_IOS_SHOW_ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.1.100       5           0011.2233.44aa  DYNAMIC  Vlan1
Internet  10.0.1.101       6           0011.2233.44bb  DYNAMIC  Vlan1
Internet  10.0.1.102       7           0011.2233.44cc  DYNAMIC  Vlan1
Internet  10.0.1.103       8           0011.2233.44dd  DYNAMIC  Vlan1
Internet  10.0.1.104       9           0011.2233.44ee  DYNAMIC  Vlan1
"""

ARISTA_EOS_SHOW_INTERFACES = """Interface       Status       Protocol            Description
Et1              up           up
Et2              up           up
Et3              down         notpresent
Et4              up           up
Et5              up           up
"""

ARISTA_EOS_SHOW_INTERFACES_DESC = """Interface       Status       Description
Et1              up           VLAN10-PC01
Et2              up           VLAN20-PC02
Et3              down         VLAN30-PC03
Et4              up           VLAN40-PC04
Et5              up           CORE-Link
"""

ARISTA_EOS_SHOW_MAC_ADDRESS_TABLE = """Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 1      0011223344aa      dynamic     Et1
 1      0011223344bb      dynamic     Et2
 1      0011223344cc      dynamic     Et4
 1      0011223344dd      dynamic     Et4
 1      0011223344ee      dynamic     Et5
 1      0011223344ff      dynamic     Et5
"""

ARISTA_EOS_SHOW_ARP = """Address         Age (min)  Hardware Addr   Interface
10.0.1.100      5          0011:2233:44aa  Vlan1
10.0.1.101      6          0011:2233:44bb  Vlan1
10.0.1.102      7          0011:2233:44cc  Vlan1
10.0.1.103      8          0011:2233:44dd  Vlan1
10.0.1.104      9          0011:2233:44ee  Vlan1
"""

EXTREME_EXOS_SHOW_PORTS = """Port       Type                     Status             Speed    Duplex
1:1        10GbE SFP+              Up                 10Gb     Full
1:2        10GbE SFP+              Up                 10Gb     Full
1:3        10GbE SFP+              Down               10Gb     Full
1:4        10GbE SFP+              Up                 10Gb     Full
1:5        10GbE SFP+              Up                 10Gb     Full
"""

EXTREME_EXOS_SHOW_PORTS_DESC = """Port       Description
1:1        VLAN10-PC01
1:2        VLAN20-PC02
1:3        VLAN30-PC03
1:4        VLAN40-PC04
1:5        CORE-Link
"""

EXTREME_EXOS_SHOW_MAC_ADDRESS = """Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 1      0011223344aa      dynamic     1:1
 1      0011223344bb      dynamic     1:2
 1      0011223344cc      dynamic     1:4
 1      0011223344dd      dynamic     1:4
 1      0011223344ee      dynamic     1:5
 1      0011223344ff      dynamic     1:5
"""

EXTREME_EXOS_SHOW_ARP = """IP Address              MAC Address       VLAN ID  Interface
10.0.1.100              00:11:22:33:44:aa     1        1:1
10.0.1.101              00:11:22:33:44:bb     1        1:2
10.0.1.102              00:11:22:33:44:cc     1        1:4
10.0.1.103              00:11:22:33:44:dd     1        1:4
10.0.1.104              00:11:22:33:44:ee     1        1:5
"""


def get_demo_switches():
    return [
        {"name": "CORE-SW01", "ip": "10.0.0.10", "vendor": "cisco_ios"},
        {"name": "CORE-SW02", "ip": "10.0.0.11", "vendor": "arista_eos"},
        {"name": "ACC-SW01", "ip": "10.0.0.20", "vendor": "extreme_exos"}
    ]


def get_demo_hosts():
    return [
        {"ip": "10.0.1.100", "mac": "00:11:22:33:44:aa", "hostname": "PC01"},
        {"ip": "10.0.1.101", "mac": "00:11:22:33:44:bb", "hostname": "PC02"},
        {"ip": "10.0.1.102", "mac": "00:11:22:33:44:cc", "hostname": "PC03"},
        {"ip": "10.0.1.103", "mac": "00:11:22:33:44:dd", "hostname": "PC04"},
        {"ip": "10.0.1.104", "mac": "00:11:22:33:44:ee", "hostname": "PC05"},
    ]


def get_cisco_ios_outputs():
    return {
        "status": CISCO_IOS_SHOW_INTERFACES,
        "description": CISCO_IOS_SHOW_INTERFACES_DESC,
        "mac": CISCO_IOS_SHOW_MAC_ADDRESS_TABLE,
        "arp": CISCO_IOS_SHOW_ARP
    }


def get_arista_eos_outputs():
    return {
        "status": ARISTA_EOS_SHOW_INTERFACES,
        "description": ARISTA_EOS_SHOW_INTERFACES_DESC,
        "mac": ARISTA_EOS_SHOW_MAC_ADDRESS_TABLE,
        "arp": ARISTA_EOS_SHOW_ARP
    }


def get_extreme_exos_outputs():
    return {
        "status": EXTREME_EXOS_SHOW_PORTS,
        "description": EXTREME_EXOS_SHOW_PORTS_DESC,
        "mac": EXTREME_EXOS_SHOW_MAC_ADDRESS,
        "arp": EXTREME_EXOS_SHOW_ARP
    }


def get_demo_outputs_for_vendor(vendor):
    if vendor == "cisco_ios":
        return get_cisco_ios_outputs()
    elif vendor == "arista_eos":
        return get_arista_eos_outputs()
    elif vendor == "extreme_exos":
        return get_extreme_exos_outputs()
    else:
        raise ValueError(f"Unknown vendor: {vendor}")
