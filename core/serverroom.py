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


# 장비 종류 → 엑셀 셀 채움색(ARGB, 프론트 _RACK_KIND와 동일 팔레트)
_KIND_FILL = {
    "Firewall": "FFEF4444", "BackBone": "FFA855F7", "L3 Switch": "FF8B5CF6",
    "L4 Switch": "FFF59E0B", "L2 Switch": "FF14B8A6", "Server": "FF3B82F6",
    "AP": "FF22C55E",
}
_RACK_U = 42          # 랙 높이(U)
_RACKS_PER_ROW = 2    # 한 줄에 랙 2개(첨부 엑셀 형식)


def _infer_dt(name):
    t = (name or "").upper()
    import re as _re
    if _re.search(r"_FW|-FW|FIREWALL|ASA|PALO|FORTI", t):
        return "Firewall"
    if _re.search(r"L4|SLB|ADC|ALTEON|OASVR", t):
        return "L4 Switch"
    if _re.search(r"BACKBONE|\bBB\b|BB\d|CORE", t):
        return "BackBone"
    if _re.search(r"L3|DSW", t):
        return "L3 Switch"
    if _re.search(r"L2|FASW|ASW|ACC|SW", t):
        return "L2 Switch"
    return ""


def build_rack_xlsx(devices):
    """서버실 랙 배치를 첨부 엑셀 형식으로 생성.

    devices: [{name, ip, rack, unit, device_type}] — parse_rack 통과분만.
    Returns: xlsx bytes.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
    from openpyxl.utils import get_column_letter
    import io

    # 랙 → {unit: dev}
    racks = {}
    for d in devices:
        rk, u = d.get("rack"), d.get("unit")
        if not rk or not u:
            continue
        racks.setdefault(rk, {})[u] = d
    rack_names = sorted(racks.keys())

    # 열(letter: A/B...)별 그룹핑 — 랙뷰와 동일하게 같은 열의 랙을 한 줄에 나란히.
    import re as _re
    by_letter = {}
    for rk in rack_names:
        m = _re.match(r"[A-Za-z]+", rk)
        letter = m.group(0).upper() if m else "#"
        by_letter.setdefault(letter, []).append(rk)
    letters = sorted(by_letter)
    max_racks_row = max((len(by_letter[l]) for l in letters), default=1)

    wb = Workbook()
    ws = wb.active
    ws.title = "ServerRoom"

    thin = Side(style="thin", color="FFBFBFBF")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    hdr_fill = PatternFill("solid", fgColor="FF1F2937")
    hdr_font = Font(bold=True, color="FFFFFFFF", size=12)
    u_font = Font(color="FF64748B", size=9)
    dev_font = Font(bold=True, color="FFFFFFFF", size=10)
    center = Alignment(horizontal="center", vertical="center")
    left = Alignment(horizontal="left", vertical="center")

    # 각 랙 블록: 2컬럼(U라벨, 장비명) + 1컬럼 간격
    BLOCK_COLS = 3
    row0 = 1
    for letter in letters:
        chunk = sorted(by_letter[letter])   # 이 열의 모든 랙(A03,A04,A06...)을 나란히
        # 이 줄에서 사용할 최대 U (기본 42, 초과 시 확장)
        max_u = _RACK_U
        for rk in chunk:
            for u in racks[rk]:
                if u > max_u:
                    max_u = u
        # 헤더(랙명) — U라벨+장비명 두 칸 병합
        for ci, rk in enumerate(chunk):
            c0 = 1 + ci * BLOCK_COLS  # U라벨 컬럼
            c1 = c0 + 1               # 장비명 컬럼
            ws.merge_cells(start_row=row0, start_column=c0, end_row=row0, end_column=c1)
            cell = ws.cell(row=row0, column=c0, value=rk)
            cell.fill = hdr_fill
            cell.font = hdr_font
            cell.alignment = center
            cell.border = border
            ws.cell(row=row0, column=c1).border = border
        # U 행 (U{max_u} → U1)
        for idx, u in enumerate(range(max_u, 0, -1)):
            r = row0 + 1 + idx
            for ci, rk in enumerate(chunk):
                c0 = 1 + ci * BLOCK_COLS
                c1 = c0 + 1
                uc = ws.cell(row=r, column=c0, value="U%d" % u)
                uc.font = u_font
                uc.alignment = center
                uc.border = border
                dc = ws.cell(row=r, column=c1)
                dc.border = border
                dc.alignment = left
                dev = racks[rk].get(u)
                if dev:
                    dc.value = dev.get("name") or ""
                    dc.font = dev_font
                    dt = dev.get("device_type") or _infer_dt(dev.get("name"))
                    fill = _KIND_FILL.get(dt)
                    if fill:
                        dc.fill = PatternFill("solid", fgColor=fill)
        row0 = row0 + 1 + max_u + 2  # 다음 랙-줄 블록(간격 2행)

    # 컬럼 너비 — 한 줄 최대 랙 수 기준
    ncols = max_racks_row * BLOCK_COLS
    for c in range(1, ncols + 1):
        col = get_column_letter(c)
        if (c - 1) % BLOCK_COLS == 0:
            ws.column_dimensions[col].width = 6      # U라벨
        elif (c - 1) % BLOCK_COLS == 1:
            ws.column_dimensions[col].width = 26     # 장비명
        else:
            ws.column_dimensions[col].width = 2      # 간격

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
