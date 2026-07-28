"""Parser factory for switch output parsing."""

from . import (cisco_ios, arista_eos, extreme_exos, cisco_nxos, alteon,
               juniper_junos, hp_procurve, aruba_cx)


# vendor(=netmiko device_type) → 파서 모듈.
# ArubaOS-Switch는 ProCurve의 리브랜딩이라 CLI가 같아 같은 파서를 쓴다.
_PARSERS = {
    "cisco_ios": cisco_ios,
    "arista_eos": arista_eos,
    "extreme_exos": extreme_exos,
    "cisco_nxos": cisco_nxos,
    "alteon": alteon,
    "juniper_junos": juniper_junos,
    "hp_procurve": hp_procurve,
    "aruba_osswitch": hp_procurve,
    "aruba_procurve": hp_procurve,
    "aruba_os": aruba_cx,
}


def get_parser(vendor: str):
    """Get parser module by vendor name."""
    if vendor not in _PARSERS:
        raise ValueError(f"Unknown vendor: {vendor}. Supported: {list(_PARSERS.keys())}")

    return _PARSERS[vendor]


def supported_vendors():
    """파서가 있는 벤더 키 목록(수집 가능 여부 판정용)."""
    return sorted(_PARSERS.keys())
