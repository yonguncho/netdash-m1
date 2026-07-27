# -*- coding: utf-8 -*-
"""현황 페이지 공통 내보내기 — CSV / TXT(탭 구분).

각 화면(서버실·방화벽·스위치·서버·설비)의 표를 화면과 같은 컬럼 구성으로 저장한다.
CSV는 UTF-8 BOM을 붙여 Excel에서 한글이 깨지지 않게 한다.
"""
import csv
import io
import json

from . import db, serverroom, server_collector, tps_location, topology


def _s(v):
    """셀 값 문자열화(None/빈값은 빈 문자열, 개행·탭 제거)."""
    if v is None:
        return ""
    return str(v).replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def to_csv(columns, rows):
    """[{col: val}] → CSV 바이트(UTF-8 BOM — Excel 한글 정상)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(columns)
    for r in rows:
        w.writerow([_s(r.get(c)) for c in columns])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def to_txt(columns, rows):
    """[{col: val}] → 탭 구분 TXT 바이트(UTF-8 BOM)."""
    lines = ["\t".join(columns)]
    for r in rows:
        lines.append("\t".join(_s(r.get(c)) for c in columns))
    return ("﻿" + "\r\n".join(lines)).encode("utf-8")


def _switch_location(sw):
    """표시 위치: TPS 라벨 > 서버실 랙 라벨 > location 원문."""
    info = tps_location.parse(sw.get("hostname"))
    if info:
        return info["label"]
    room = serverroom.parse_rack(sw.get("location"))
    if room:
        return room["label"]
    return sw.get("location") or ""


def _location_raw(sw):
    """DB에 저장된 location 원문 — 화면 표에 보이는 값과 같다.

    라벨('A09랙 U27')만 내보내면 엑셀에서 화면 값('A09U27')으로 검색·VLOOKUP이
    안 맞는다. 라벨과 원문을 함께 낸다.
    """
    return sw.get("location") or ""


# ── 데이터셋별 컬럼·행 구성(화면 표와 동일한 순서) ─────────────
# '이름'은 등록 시 사용자가 붙인 식별자다. 호스트네임은 수집에 성공해야 채워지므로
# 미수집 스위치는 이름이 없으면 IP로만 식별된다 — 반드시 첫 컬럼으로 내보낸다.
SWITCH_COLS = ["이름", "구분", "IP", "호스트네임", "벤더", "모델", "버전", "시리얼",
               "위치", "위치(원문)", "상태", "경보", "마지막 수집", "비고"]


def switches_rows(db_path):
    cfgs = db.get_latest_configs(db_path)
    rows = []
    for sw in db.get_switches(db_path):
        if (sw.get("device_type") or "") == "Server":
            continue                      # 서버는 서버 현황에서 내보낸다(화면과 동일)
        kind = sw.get("device_type") if sw.get("device_type") in (
            "BackBone", "L2 Switch", "L3 Switch", "L4 Switch") else None
        if not kind:
            kind = topology.classify_switch_kind(cfgs.get(sw["id"]), sw.get("vendor")) or "SWITCH"
        rows.append({
            "이름": sw.get("name"),
            "구분": kind, "IP": sw.get("ip"), "호스트네임": sw.get("hostname"),
            "벤더": sw.get("vendor"), "모델": sw.get("model"), "버전": sw.get("os_version"),
            "시리얼": sw.get("serial"), "위치": _switch_location(sw),
            "위치(원문)": _location_raw(sw),
            "상태": sw.get("status"),
            "경보": "" if (sw.get("alert") or "none") == "none" else sw.get("alert"),
            "마지막 수집": sw.get("last_collected"), "비고": sw.get("note"),
        })
    return rows


SERVER_COLS = ["이름", "IP", "hostname", "MAC", "OS",
               "CPU", "코어", "메모리(GB)", "메모리 구성", "메모리 슬롯",
               "디스크 전체(GB)", "디스크 사용(GB)", "디스크 구성", "디스크 개수",
               "구분", "열린 포트",
               "연결 스위치", "포트", "위치", "상태", "마지막 수집"]


def _hw_list(raw):
    """JSON 문자열로 저장된 장착 구성 → 리스트(깨져 있으면 빈 리스트)."""
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except (ValueError, TypeError):
        return []


def servers_rows(db_path):
    rows = []
    for s in db.list_servers(db_path):
        mem_mb = s.get("mem_total_mb")
        mods = _hw_list(s.get("mem_modules"))
        disks = _hw_list(s.get("disk_devices"))
        rows.append({
            "이름": s.get("name"), "IP": s.get("ip"), "hostname": s.get("hostname"),
            "MAC": s.get("mac"), "OS": s.get("os_info") or s.get("os_type"),
            "CPU": s.get("cpu_model"), "코어": s.get("cpu_cores"),
            "메모리(GB)": round(mem_mb / 1024.0, 1) if mem_mb else "",
            "메모리 구성": server_collector.summarize_modules(
                mods, s.get("mem_slots_total") or 0),
            "메모리 슬롯": ("%d/%d" % (len(mods), s.get("mem_slots_total"))
                        if s.get("mem_slots_total") else ""),
            "디스크 전체(GB)": s.get("disk_total_gb"),
            "디스크 사용(GB)": s.get("disk_used_gb"),
            "디스크 구성": " / ".join(
                "%s %sGB%s" % (d.get("model") or d.get("name") or "디스크",
                               d.get("size_gb"), (" " + d["kind"]) if d.get("kind") else "")
                for d in disks),
            "디스크 개수": len(disks) or "",
            "구분": "VM" if s.get("is_vm") else "물리",
            "열린 포트": s.get("open_ports"), "연결 스위치": s.get("switch_name"),
            "포트": s.get("switch_port"), "위치": s.get("location"),
            "상태": s.get("status"), "마지막 수집": s.get("last_collected"),
        })
    return rows


FIREWALL_COLS = ["이름", "벤더", "호스트", "포트", "위치", "상태", "연결 상태",
                 "마지막 수집"]


def firewalls_rows(db_path):
    rows = []
    # 도달성은 DB 컬럼이 아니라 감시 스레드의 메모리 상태다. 예전엔 여기서
    # f.get("reachable")를 읽었는데 그 키가 존재할 수 없어 **항상 '확인 중'**이었다
    # (화면은 연결됨/끊김을 정확히 아는데 엑셀만 고정값). 감시 상태를 직접 읽는다.
    try:
        from . import reachability
        fw_state = reachability.get_fw_state()
    except Exception:
        fw_state = {}
    for f in db.list_firewalls(db_path):
        reach = fw_state.get(f.get("id"))
        rows.append({
            "이름": f.get("name"), "벤더": f.get("vendor"), "호스트": f.get("host"),
            "포트": f.get("port"), "위치": f.get("location"),
            "상태": f.get("status"),
            "연결 상태": ("연결됨" if reach is True else
                      "끊김" if reach is False else "확인 중"),
            "마지막 수집": f.get("last_collected"),
        })
    return rows


ROOM_COLS = ["랙", "유닛", "종류", "이름", "IP", "벤더/OS", "상태", "위치"]


def serverroom_rows(db_path):
    """서버실(위치가 A09U27 형식) 장비 — 스위치·방화벽·물리 서버."""
    rows = []
    for sw in db.get_switches(db_path):
        room = serverroom.parse_rack(sw.get("location"))
        if not room:
            continue
        rows.append({"랙": room["rack"], "유닛": room["unit"], "종류": "스위치",
                     "이름": sw.get("name"), "IP": sw.get("ip"),
                     "벤더/OS": sw.get("vendor"), "상태": sw.get("status"),
                     "위치": sw.get("location")})
    for f in db.list_firewalls(db_path):
        room = serverroom.parse_rack(f.get("location"))
        if not room:
            continue
        rows.append({"랙": room["rack"], "유닛": room["unit"], "종류": "방화벽",
                     "이름": f.get("name"), "IP": f.get("host"),
                     "벤더/OS": f.get("vendor"), "상태": f.get("status"),
                     "위치": f.get("location")})
    for s in db.list_servers(db_path):
        if s.get("is_vm"):
            continue                       # VM은 물리 위치 없음(화면과 동일)
        room = serverroom.parse_rack(s.get("location"))
        if not room:
            continue
        rows.append({"랙": room["rack"], "유닛": room["unit"], "종류": "서버",
                     "이름": s.get("name"), "IP": s.get("ip"),
                     "벤더/OS": s.get("os_info") or s.get("os_type"),
                     "상태": s.get("status"), "위치": s.get("location")})
    rows.sort(key=lambda r: (str(r["랙"]), -int(r["유닛"] or 0)))
    return rows


FACILITY_COLS = ["대역", "IP", "MAC", "연결 스위치", "포트", "포트 설명", "상태", "비고"]


def facility_rows(db_path):
    """설비 현황 — 화면과 동일(연결 미확인 사유·과거 연결은 '비고')."""
    hosts = db.get_facility_hosts(db_path)
    unknown = [h for h in hosts if not h.get("switch_name")]
    mac_last = db.get_mac_last_seen(db_path, [h.get("mac") for h in unknown]) if unknown else {}
    import re as _re
    rows = []
    for h in hosts:
        direct = h.get("direct", 1) and h.get("switch_name")
        online = bool(h.get("online"))
        remarks = []
        if not online:
            remarks.append("오프라인(마지막 수집 무응답)")
        if not direct:
            if h.get("via"):
                remarks.append("업링크 경유 관측: %s" % h["via"])
            remarks.append("연결 액세스 스위치 미수집이거나 최신 MAC 테이블에 없음")
            _hx = _re.sub(r"[^0-9a-f]", "", (h.get("mac") or "").lower())
            hist = mac_last.get(_hx) if len(_hx) == 12 else None
            if hist and hist.get("switch_name"):
                remarks.append("과거 연결: %s %s (%s)" % (
                    hist.get("switch_name"), hist.get("port") or "",
                    (hist.get("ts") or "")[:16]))
        elif not online:
            remarks.append("연결이 끊기기 전 마지막으로 관측된 위치")
        rows.append({
            "대역": h.get("subnet"), "IP": h.get("ip"), "MAC": h.get("mac"),
            "연결 스위치": h.get("switch_name") or "직접 연결 미확인",
            "포트": h.get("port") if direct else "",
            "포트 설명": h.get("port_desc") if direct else "",
            "상태": "온라인" if online else "연결 실패",
            "비고": " · ".join(remarks),
        })
    return rows


# 화면 키 → (컬럼, 행 생성 함수, 파일명)
DATASETS = {
    "switches": (SWITCH_COLS, switches_rows, "switches"),
    "servers": (SERVER_COLS, servers_rows, "servers"),
    "firewalls": (FIREWALL_COLS, firewalls_rows, "firewalls"),
    "serverroom": (ROOM_COLS, serverroom_rows, "serverroom"),
    "facility": (FACILITY_COLS, facility_rows, "facility"),
}


def export(db_path, kind, fmt="csv"):
    """지정 화면 데이터를 CSV/TXT 바이트로. 반환: (bytes, mimetype, filename)."""
    if kind not in DATASETS:
        raise ValueError("unknown dataset: %s" % kind)
    cols, fn, base = DATASETS[kind]
    rows = fn(db_path)
    if (fmt or "csv").lower() == "txt":
        return to_txt(cols, rows), "text/plain; charset=utf-8", base + ".txt"
    return to_csv(cols, rows), "text/csv; charset=utf-8", base + ".csv"
