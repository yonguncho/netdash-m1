"""Parser factory for switch output parsing."""

from . import cisco_ios, arista_eos, extreme_exos, cisco_nxos, alteon


def get_parser(vendor: str):
    """Get parser module by vendor name."""
    parsers = {
        "cisco_ios": cisco_ios,
        "arista_eos": arista_eos,
        "extreme_exos": extreme_exos,
        "cisco_nxos": cisco_nxos,
        "alteon": alteon,
    }

    if vendor not in parsers:
        raise ValueError(f"Unknown vendor: {vendor}. Supported: {list(parsers.keys())}")

    return parsers[vendor]
