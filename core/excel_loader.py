"""
M4: 멀티블록 엑셀 로더

단일 엑셀 파일에서 여러 개의 데이터 블록(스위치, 호스트, 제목 등)을 자동으로 분리하고
각 블록을 해당 테이블에 DB 반영하는 모듈.

알려진 필드:
  - 스위치: name, ip, hostname, vendor, location
  - 호스트: ip, mac

멀티블록 분리:
  - 헤더 후보: 알려진 필드 ≥ MIN_MATCHED_COLS(기본값 2) 매칭
  - 새 헤더 발견 시 이전 블록 확정
  - IP 정규식 매칭 0개 블록은 폐기 (제목, 요약, 섹션 헤더)

멱등성:
  - IP 기준 UPSERT (동일 IP 재업로드 시 중복 삽입 금지)
"""

import re
import logging
from typing import Tuple, List, Dict, Any, Optional
from openpyxl import load_workbook as openpyxl_load

logger = logging.getLogger(__name__)

MIN_MATCHED_COLS = 2

# 알려진 필드와 별칭 매핑 (모두 정규화된 형태: 공백 제거 + 소문자)
ALIASES = {
    'name': {'name', 'switchname', 'devicename'},
    'ip': {'ip', 'ipv4', 'ipaddress', 'address'},
    'hostname': {'hostname', 'dnsname', 'fqdn', '사용서버명', '서버명'},
    'vendor': {'vendor', 'manufacturer', 'os', 'platform'},
    'location': {'location', 'site', 'datacenter', 'dc', '랙위치'},
    'mac': {'mac', 'macaddress', 'hwaddr'},
    # M7: 장부(ledger) 위치 — 호스트 블록에서 기대 연결 위치를 적재
    'ledger_switch': {'연결스위치', 'connectedswitch', 'ledgerswitch', 'uplinkswitch'},
    'ledger_port': {'연결포트', 'connectedport', 'ledgerport', 'uplinkport'},
    # 장비 인벤토리 업로드용 서브넷
    'subnet': {'subnet', 'ipsubnet', 'cidr', 'network', 'netmask', '서브넷', '대역', '네트워크'},
}

IP_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)


def _norm(s: Optional[Any]) -> str:
    """정규화: 앞뒤 공백 제거 + 내부 공백 모두 제거 + 소문자"""
    if not isinstance(s, str):
        return ""
    return s.strip().lower().replace(" ", "")


def _is_valid_ip(ip_str: Optional[Any]) -> bool:
    """IP 주소 검증 (IPv4)"""
    if not isinstance(ip_str, str):
        return False
    return bool(IP_REGEX.match(ip_str.strip()))


def parse_switch_inventory(source) -> List[Dict[str, Any]]:
    """IP/SUBNET/HOSTNAME 인벤토리 엑셀 → 스위치 등록 행 목록.

    벤더 무관: IP가 있는 모든 행을 스위치로 본다(벤더는 'unknown', 이후 수정).
    헤더에서 ip/hostname/name/subnet/location 컬럼을 자동 매핑.
    Returns: [{name, ip, hostname, subnet, location, vendor='unknown'}]
    """
    wb = openpyxl_load(source, read_only=True, data_only=True)
    wanted = ('ip', 'hostname', 'name', 'subnet', 'location')
    field_alias = {f: ALIASES[f] for f in wanted if f in ALIASES}
    out = []
    seen = set()
    for ws in wb.worksheets:
        colmap = None
        for row in ws.iter_rows(values_only=True):
            if colmap is None:
                m = {}
                for ci, cell in enumerate(row):
                    n = _norm(cell)
                    for f, al in field_alias.items():
                        if n in al:
                            m[f] = ci
                if 'ip' in m:  # ip 컬럼이 있는 행을 헤더로 인식
                    colmap = m
                continue

            def _get(field):
                ci = colmap.get(field)
                if ci is None or ci >= len(row):
                    return ""
                v = row[ci]
                return str(v).strip() if v is not None else ""

            ip = _get('ip')
            if not _is_valid_ip(ip) or ip in seen:
                continue
            seen.add(ip)
            host = _get('hostname')
            name = _get('name') or host or ip
            out.append({
                "name": name, "ip": ip, "hostname": host,
                "subnet": _get('subnet'), "location": _get('location'),
                "vendor": "unknown",
            })
    return out


def _looks_like_header(row: List[Any]) -> bool:
    """
    헤더 후보인가?
    알려진 필드의 별칭과 MIN_MATCHED_COLS 개 이상 매칭하면 헤더로 간주.
    """
    if not row:
        return False

    normalized_row = [_norm(cell) for cell in row]
    matched_fields = set()

    for norm_cell in normalized_row:
        if not norm_cell:  # 빈 셀 스킵
            continue
        for known_field, aliases in ALIASES.items():
            if norm_cell in aliases:
                matched_fields.add(known_field)
                break

    return len(matched_fields) >= MIN_MATCHED_COLS


def _extract_blocks(rows: List[List[Any]]) -> List[List[List[Any]]]:
    """
    행 리스트를 멀티블록으로 분리.
    새 헤더 발견 시 이전 블록 확정.

    반환:
      blocks: 각 블록은 [헤더_행, 데이터_행1, 데이터_행2, ...]
    """
    blocks = []
    current_block = []
    current_header = None

    for row in rows:
        if _looks_like_header(row):
            if current_header is not None:
                # 새 헤더 발견 → 이전 블록 확정
                if current_block:
                    blocks.append(current_block)
                current_block = [row]
            else:
                # 첫 헤더 발견
                current_block = [row]
            current_header = row
        else:
            # 첫 헤더 이후 데이터만 추가
            if current_header is not None:
                current_block.append(row)

    # 마지막 블록 확정
    if current_block:
        blocks.append(current_block)

    return blocks


def _get_header_map(header_row: List[Any]) -> Dict[str, int]:
    """
    헤더 행을 정규화하고 별칭 매핑해서 {canonical_field: column_index} 딕셔너리 반환.

    예:
      header_row = ['Switch Name', 'IPv4 Address', 'Vendor']
      반환: {'name': 0, 'ip': 1, 'vendor': 2}
    """
    header_map = {}
    for idx, cell in enumerate(header_row):
        norm_cell = _norm(cell)
        for canonical, aliases in ALIASES.items():
            if norm_cell in aliases:
                header_map[canonical] = idx
                break
    return header_map


def _block_to_records(block: List[List[Any]]) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """
    블록(헤더+데이터)을 레코드로 변환.

    입력:
      block: [헤더_행, 데이터_행1, ...]

    출력:
      (block_type, records)
      block_type: 'switch', 'host', 또는 None (폐기)
      records: [{field: value}, ...]

    로직:
      1. 헤더 파싱
      2. 데이터 행만 필터링
      3. IP 정규식 매칭된 행만 추출
      4. IP 매칭 = 0 → 폐기 (None)
      5. 'vendor' 있음 → 'switch'
      6. 'vendor' 없음 → 'host'
    """
    if not block or len(block) < 1:
        return None, []

    header_row = block[0]
    data_rows = block[1:]

    header_map = _get_header_map(header_row)

    if not header_map:
        return None, []

    # 데이터를 딕셔너리로 변환
    records = []
    for row in data_rows:
        record = {}
        for canonical, idx in header_map.items():
            value = row[idx] if idx < len(row) else None
            record[canonical] = _norm(value) if isinstance(value, str) else value

        # IP 검증: 유효한 IP만 포함
        if 'ip' in record and _is_valid_ip(record['ip']):
            records.append(record)

    # IP 매칭 = 0 → 폐기
    if not records:
        return None, []

    block_type = 'switch' if 'vendor' in header_map else 'host'

    return block_type, records


def load_workbook(
    file_path: str,
    read_only: bool = True,
    data_only: bool = True,
) -> Dict[str, Any]:
    """
    엑셀 파일을 로드하고 멀티블록으로 분리해서 DB 임포트 가능한 포맷으로 변환.

    입력:
      file_path: 엑셀 파일 경로 (.xlsx)
      read_only: openpyxl read_only 모드
      data_only: openpyxl data_only 모드

    출력:
      {
        "switches": [{name, ip, hostname, vendor, location}, ...],
        "hosts": [{ip, mac}, ...],
        "diagnostics": {
          "total_blocks": int,
          "discarded_blocks": int,
          "switch_blocks": int,
          "host_blocks": int,
          "imported_switches": int,
          "imported_hosts": int,
          "warnings": [str]
        }
      }

    예외:
      - FileNotFoundError: 파일 없음
      - openpyxl.utils.exceptions: 엑셀 형식 오류
    """
    try:
        wb = openpyxl_load(file_path, read_only=read_only, data_only=data_only)
    except Exception as e:
        logger.error(f"Failed to load workbook {file_path}: {e}")
        raise

    try:
        ws = wb.active
        if not ws:
            logger.warning(f"No active sheet in {file_path}")
            return {
                "switches": [],
                "hosts": [],
                "diagnostics": {
                    "total_blocks": 0,
                    "discarded_blocks": 0,
                    "switch_blocks": 0,
                    "host_blocks": 0,
                    "imported_switches": 0,
                    "imported_hosts": 0,
                    "warnings": ["No active sheet found"],
                }
            }

        # 행 추출 (None 값 포함, 나중에 필터링)
        rows = []
        for row in ws.iter_rows(values_only=True):
            rows.append(list(row) if row else [])
    finally:
        wb.close()

    if not rows:
        return {
            "switches": [],
            "hosts": [],
            "diagnostics": {
                "total_blocks": 0,
                "discarded_blocks": 0,
                "switch_blocks": 0,
                "host_blocks": 0,
                "imported_switches": 0,
                "imported_hosts": 0,
                "warnings": ["No rows found"],
            }
        }

    # 멀티블록 분리
    blocks = _extract_blocks(rows)

    switches = []
    hosts = []
    warnings = []
    switch_block_count = 0
    host_block_count = 0
    discarded_block_count = 0

    for block_idx, block in enumerate(blocks):
        block_type, records = _block_to_records(block)

        if block_type is None:
            discarded_block_count += 1
            warnings.append(f"Block #{block_idx + 1} discarded (no IP matches)")
            continue

        if block_type == 'switch':
            switch_block_count += 1
            switches.extend(records)
        elif block_type == 'host':
            host_block_count += 1
            hosts.extend(records)

    return {
        "switches": switches,
        "hosts": hosts,
        "diagnostics": {
            "total_blocks": len(blocks),
            "discarded_blocks": discarded_block_count,
            "switch_blocks": switch_block_count,
            "host_blocks": host_block_count,
            "imported_switches": len(switches),
            "imported_hosts": len(hosts),
            "warnings": warnings,
        }
    }
