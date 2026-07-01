# -*- coding: utf-8 -*-
"""서버실 랙 위치 해석. location 필드에 "A09U27"처럼 기재하면 랙/유닛으로 해석.

포맷: {랙}U{유닛}
  예) A09U27 → A09 랙, U27 유닛
      B12U04 → B12 랙, U4 유닛
랙 = 영문+숫자, 유닛 = U 뒤 숫자. 대소문자·공백 허용.
이 포맷과 일치하는 장비만 "서버실 소속"으로 본다.
"""
import re

# {랙: 영문1자이상+숫자1자이상}U{유닛: 숫자} — 접미 공백/대소문자 허용
_PAT = re.compile(r"^\s*([A-Za-z]+\d+)\s*[Uu]\s*(\d+)\s*$")


def parse_rack(location):
    """location에서 "{랙}U{유닛}" 패턴을 해석.

    일치하지 않으면 None(= 서버실 소속 아님).
    Returns: {rack, unit, label} | None
    """
    if not location:
        return None
    m = _PAT.match(str(location))
    if not m:
        return None
    rack = m.group(1).upper()
    try:
        unit = int(m.group(2))
    except ValueError:
        return None
    return {"rack": rack, "unit": unit, "label": "%s랙 U%d" % (rack, unit)}
