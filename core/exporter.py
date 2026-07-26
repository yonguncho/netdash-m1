# -*- coding: utf-8 -*-
"""현황 페이지 공통 내보내기 — CSV / TXT(탭 구분).

각 화면(서버실·방화벽·스위치·서버·설비)의 표를 화면과 같은 컬럼 구성으로 저장한다.
CSV는 UTF-8 BOM을 붙여 Excel에서 한글이 깨지지 않게 한다.
"""
import csv
import io

from . import db, serverroom, tps_location, topology


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


# ── 데이터셋별 컬럼·행 구성(화면 표와 동일한 순서) ─────────────
SWITCH_COLS = ["구분", "IP", "호스트네임", "벤더", "모델", "버전", "시리얼",
               "위치", "상태", "경보", "마지막 수집", "비고"]


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
            "구분": kind, "IP": sw.get("ip"), "호스트네임": sw.get("hostname"),
            "벤더": sw.get("vendor"), "모델": sw.get("model"), "버전": sw.get("os_version"),
            "시리얼": sw.get("serial"), "위치": _switch_location(sw),
            "상태": sw.get("status"),
            "경보": "" if (sw.get("alert") or "none") == "none" else sw.get("alert"),
            "마지막 수집": sw.get("last_collected"), "비고": sw.get("note"),
        })
    return rows


SERVER_COLS = ["이름", "IP", "hostname", "MAC", "OS", "구분", "열린 포트",
               "연결 스위치", "포트", "위치", "상태", "마지막 수집"]


def servers_rows(db_path):
    rows = []
    for s in db.list_servers(db_path):
        rows.append({
            "이름": s.get("name"), "IP": s.get("ip"), "hostname": s.get("hostname"),
            "MAC": s.get("mac"), "OS": s.get("os_info") or s.get("os_type"),
            "구분": "VM" if s.get("is_vm") else "물리",
            "열린 포트": s.get("open_ports"), "연결 스위치": s.get("switch_name"),
            "포트": s.get("switch_port"), "위치": s.get("location"),
            "상태": s.get("status"), "마지막 수집": s.get("last_collected"),
        })
    return rows


FIREWALL_COLS = ["이름", "벤더", "호스트", "포트", "위치", "상태", "마지막 수집"]


def firewalls_rows(db_path):
    rows = []
    for f in db.list_firewalls(db_path):
        rows.append({
            "이름": f.get("name"), "벤더": f.get("vendor"), "호스트": f.get("host"),
            "포트": f.get("port"), "위치": f.get("location"),
            "상태": f.get("status"), "마지막 수집": f.get("last_collected"),
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
