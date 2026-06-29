"""M9: 엑셀 현황 보고서 빌더.

build_report(db_path) -> bytes
4개 시트:
  - 스위치 현황
  - 포트 현황
  - 이벤트 로그
  - 호스트 대장 (M7 장부 대조 판정 포함)

프로덕션본(C:\\AI_WORKPLACE\\NetDash) report_builder를 개발본 스키마에 맞게 적응 이식.
"""
import io
import logging

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

from . import db as _db
from . import correlator

logger = logging.getLogger(__name__)


# ── 헤더 스타일 ──────────────────────────────────────────────────────
_HEADER_FONT = Font(bold=True, color="FFFFFF")
_HEADER_FILL = PatternFill(fill_type="solid", fgColor="1F497D")
_HEADER_ALIGN = Alignment(horizontal="center", vertical="center")


def _style_header_row(ws):
    """첫 행을 헤더 스타일로 변환."""
    for cell in ws[1]:
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = _HEADER_ALIGN


def _auto_col_width(ws):
    """각 컬럼 너비를 내용 기준으로 자동 조정 (최대 60)."""
    for col_cells in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col_cells[0].column)
        for cell in col_cells:
            try:
                cell_len = len(str(cell.value)) if cell.value is not None else 0
                if cell_len > max_len:
                    max_len = cell_len
            except Exception:
                pass
        ws.column_dimensions[col_letter].width = min(max_len + 4, 60)


# ── 시트 빌더 ────────────────────────────────────────────────────────
def _build_switch_sheet(wb, db_path):
    """스위치 현황: id, name, ip, vendor, status, port_count, mac_count, last_collected"""
    ws = wb.create_sheet("스위치 현황")
    ws.append(["id", "name", "ip", "vendor", "status",
               "port_count", "mac_count", "last_collected"])
    _style_header_row(ws)

    for sw in _db.get_switches(db_path):
        snap_id = _db.latest_snapshot_id(db_path, sw["id"])
        port_count = len(_db.get_ports(db_path, snap_id)) if snap_id else 0
        mac_count = _db.get_mac_count(db_path, snap_id) if snap_id else 0
        ws.append([
            sw.get("id"),
            sw.get("name"),
            sw.get("ip"),
            sw.get("vendor"),
            sw.get("status"),
            port_count,
            mac_count,
            sw.get("last_collected") or "",
        ])

    _auto_col_width(ws)
    return ws


def _build_port_sheet(wb, db_path):
    """포트 현황: switch_name, port_name, status, vlan, speed, description"""
    ws = wb.create_sheet("포트 현황")
    ws.append(["switch_name", "port_name", "status", "vlan", "speed", "description"])
    _style_header_row(ws)

    switches = _db.get_switches(db_path)
    sw_map = {sw["id"]: sw["name"] for sw in switches}

    for sw in switches:
        snap_id = _db.latest_snapshot_id(db_path, sw["id"])
        if not snap_id:
            continue
        for port in _db.get_ports(db_path, snap_id):
            ws.append([
                sw_map.get(port.get("switch_id"), sw.get("name")) or "",
                port.get("name") or "",
                port.get("status") or "",
                port.get("vlan") if port.get("vlan") is not None else "",
                port.get("speed") or "",
                port.get("description") or "",
            ])

    _auto_col_width(ws)
    return ws


def _build_event_sheet(wb, db_path):
    """이벤트 로그: switch_name, port_name, event_type, count, first_seen, last_seen"""
    ws = wb.create_sheet("이벤트 로그")
    ws.append(["switch_name", "port_name", "event_type", "count", "first_seen", "last_seen"])
    _style_header_row(ws)

    for sw in _db.get_switches(db_path):
        for ev in _db.get_port_events(db_path, sw["id"]):
            ws.append([
                sw.get("name") or "",
                ev.get("port_name") or "",
                ev.get("event_type") or "",
                ev.get("count") if ev.get("count") is not None else 0,
                ev.get("first_seen") or "",
                ev.get("last_seen") or "",
            ])

    _auto_col_width(ws)
    return ws


def _build_host_sheet(wb, db_path):
    """호스트 대장 + 대조: ip, hostname, mac, ledger_switch, ledger_port,
    actual_switch, actual_port, verdict (M7 reconcile 판정 포함)
    """
    ws = wb.create_sheet("호스트 대장")
    ws.append(["ip", "hostname", "mac", "ledger_switch", "ledger_port",
               "actual_switch", "actual_port", "verdict"])
    _style_header_row(ws)

    rec_by_ip = {h["ip"]: h for h in correlator.reconcile(db_path)["hosts"]}

    for host in _db.list_hosts(db_path):
        ip = host.get("ip") or ""
        r = rec_by_ip.get(ip, {})
        ws.append([
            ip,
            host.get("hostname") or "",
            host.get("mac") or "",
            r.get("ledger_switch") or host.get("ledger_switch") or "",
            r.get("ledger_port") or host.get("ledger_port") or "",
            r.get("actual_switch") or "",
            r.get("actual_port") or host.get("port") or "",
            r.get("verdict") or "",
        ])

    _auto_col_width(ws)
    return ws


# ── 공개 API ─────────────────────────────────────────────────────────
def build_report(db_path: str) -> bytes:
    """현재 DB 상태를 4시트 엑셀로 빌드해 bytes 반환.

    시트: 스위치 현황 / 포트 현황 / 이벤트 로그 / 호스트 대장(대조 판정 포함).
    빈 DB여도 헤더만 있는 정상 워크북을 반환한다.
    """
    logger.info("build_report: start db_path=%s", db_path)

    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # 기본 빈 시트 제거

    _build_switch_sheet(wb, db_path)
    _build_port_sheet(wb, db_path)
    _build_event_sheet(wb, db_path)
    _build_host_sheet(wb, db_path)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    result = buf.read()

    logger.info("build_report: done size=%d", len(result))
    return result
