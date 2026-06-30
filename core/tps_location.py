# -*- coding: utf-8 -*-
"""TPS 스위치 hostname → 물리 위치 해석.

포맷: TPS-F{phase}B{building}_{floor}F{tps}_...
  예) TPS-F1B02_1F01_FA_SW1
      F1   → Phase(공장) 1
      B02  → Building 02 (Phase1 → Assembly)
      1F   → Floor 1 (1층)
      01   → TPS 번호 01
→ "1공장 Assembly(B02) 1층 TPS01"
"""
import re

# Phase별 building 코드 → 이름 (사용자 제공)
PHASE1_BUILDINGS = {
    "B01": "Electrode", "B02": "Assembly", "B03": "Formation/Module",
    "B11": "Cell Discharge", "B12": "Electrolyte Storage", "B15": "NMP Tank Storage",
    "B17": "Utility", "B18": "Main Substation", "B19": "Cooling Tower",
    "B20": "Pump Room", "B21": "Hot Oil", "B51": "Admin", "B52": "Raw Material",
    "B53": "QE", "B54": "Main Guard House", "B55": "Sub Guard House",
    "B57": "Module Packing Storage", "B57-1": "Cell Discharge Container",
}
PHASE2_BUILDINGS = {
    "B1E": "Electrode", "B1A": "Assembly", "B1F": "Formation/Module",
    "B05": "Cooling Tower2", "B06": "Electrolyte Storage 2", "B07": "Hazard Waste 2",
    "B10": "Waste Storage2", "B17": "Utility Building", "B19": "Cooling Tower",
    "B20": "Pump Room", "B31": "Cell Discharge2", "B32": "NMP2",
    "B33": "Canteen1", "B34": "Canteen2", "B51": "Admin",
}

# 핵심 패턴 F{phase}B{building}_{floor}F{tps} 를 hostname 어디서든 검색.
# 접두(TPS-, SKBA_ 등)는 무관. 건물코드는 B + 영숫자(B57-1, B1E 등) 허용.
_PAT = re.compile(r"F(\d+)(B[0-9A-Z]+(?:-\d+)?)_(\d+)F(\d+)", re.IGNORECASE)


def parse(hostname):
    """hostname에서 F{phase}B{building}_{floor}F{tps} 패턴을 찾아 위치 정보 반환.

    접두(TPS-/SKBA_ 등) 무관. 패턴이 없으면 None.
    Returns: {phase, building_code, building_name, floor, tps, label} | None
    """
    if not hostname:
        return None
    m = _PAT.search(str(hostname).strip())
    if not m:
        return None
    phase_s, bcode, floor_s, tps = m.groups()
    bcode = bcode.upper()
    try:
        phase = int(phase_s)
        floor = int(floor_s)
    except ValueError:
        return None
    table = PHASE1_BUILDINGS if phase == 1 else PHASE2_BUILDINGS if phase == 2 else {}
    bname = table.get(bcode, bcode)
    label = "{0}공장 {1}({2}) {3}층 TPS{4}".format(phase, bname, bcode, floor, tps)
    return {
        "phase": phase,
        "building_code": bcode,
        "building_name": bname,
        "floor": floor,
        "tps": tps,
        "label": label,
    }
