from types import ModuleType
from core.parsers import stub

PARSERS: dict[str, ModuleType] = {}


def get_parser(vendor: str) -> ModuleType:
    return PARSERS.get(vendor, stub)
