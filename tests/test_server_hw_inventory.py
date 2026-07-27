# -*- coding: utf-8 -*-
"""서버 장착 구성 — 메모리 모듈 목록 · 물리 디스크 목록 수집/표시.

'총량'뿐 아니라 '무엇이 몇 개 꽂혀 있는지'를 보여주는 기능의 회귀 테스트.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, exporter, server_collector as sc

ROOT = Path(__file__).parent.parent
APPJS = (ROOT / "web" / "static" / "app.js").read_text(encoding="utf-8")
HTML = (ROOT / "web" / "templates" / "index.html").read_text(encoding="utf-8")


# ── 리눅스: dmidecode -t 17 ───────────────────────────────────────
DMIDECODE = """# dmidecode 3.2
Handle 0x1100, DMI type 17, 40 bytes
Memory Device
\tArray Handle: 0x1000
\tTotal Width: 72 bits
\tSize: 16384 MB
\tForm Factor: DIMM
\tLocator: DIMM_A1
\tBank Locator: NODE 1
\tType: DDR4
\tSpeed: 2400 MT/s
\tManufacturer: Samsung
\tSerial Number: 12345678
\tPart Number: M393A2G40EB1-CRC

Handle 0x1101, DMI type 17, 40 bytes
Memory Device
\tSize: No Module Installed
\tLocator: DIMM_A2
\tType: Unknown
\tManufacturer: NO DIMM

Handle 0x1102, DMI type 17, 40 bytes
Memory Device
\tSize: 16384 MB
\tLocator: DIMM_B1
\tType: DDR4
\tSpeed: 2400 MT/s
\tManufacturer: Samsung
\tPart Number: M393A2G40EB1-CRC

Handle 0x1103, DMI type 17, 40 bytes
Memory Device
\tSize: No Module Installed
\tLocator: DIMM_B2
\tType: Unknown
"""


def test_parse_dmidecode_counts_modules_and_slots():
    mods, slots = sc.parse_dmidecode_memory(DMIDECODE)
    assert slots == 4, "빈 슬롯도 슬롯 수에는 포함돼야 한다"
    assert len(mods) == 2, "빈 슬롯이 모듈로 잡혔다"
    m = mods[0]
    assert m["size_mb"] == 16384
    assert m["locator"] == "DIMM_A1" and m["type"] == "DDR4"
    assert m["maker"] == "Samsung" and m["part"] == "M393A2G40EB1-CRC"
    assert m["speed"] == "2400 MT/s"


def test_parse_dmidecode_gb_unit_and_noise():
    mods, slots = sc.parse_dmidecode_memory(
        "Memory Device\n\tSize: 32 GB\n\tLocator: A1\n\tManufacturer: Not Specified\n")
    assert slots == 1 and mods[0]["size_mb"] == 32768
    assert mods[0]["maker"] == "", "'Not Specified'가 제조사로 저장됐다"


def test_parse_dmidecode_permission_denied_is_empty():
    """dmidecode는 root가 필요하다 — 권한이 없으면 빈 결과여야 한다(예외 금지)."""
    assert sc.parse_dmidecode_memory("") == ([], 0)
    assert sc.parse_dmidecode_memory("dmidecode: Permission denied") == ([], 0)


# ── 리눅스: lsblk ────────────────────────────────────────────────
LSBLK = (
    'NAME="sda" MODEL="SAMSUNG MZ7LH960HAJR-00005" SIZE="894.3G" ROTA="0" TYPE="disk"\n'
    'NAME="sdb" MODEL="ST2000NM0055-1V4104" SIZE="1.8T" ROTA="1" TYPE="disk"\n'
    'NAME="nvme0n1" MODEL="INTEL SSDPE2KX010T8" SIZE="931.5G" ROTA="0" TYPE="disk"\n'
    'NAME="sr0" MODEL="" SIZE="1024M" ROTA="1" TYPE="rom"\n'
)


def test_parse_lsblk_disks():
    disks = sc.parse_lsblk_disks(LSBLK)
    assert len(disks) == 3, "rom(광학드라이브)이 디스크로 잡혔다"
    assert disks[0]["model"] == "SAMSUNG MZ7LH960HAJR-00005", "모델명 공백에서 파싱이 깨졌다"
    assert disks[0]["kind"] == "SSD"
    assert disks[1]["kind"] == "HDD" and disks[1]["size_gb"] == 1843.2
    assert disks[2]["kind"] == "NVMe"


def test_parse_lsblk_empty():
    assert sc.parse_lsblk_disks("") == []
    assert sc.parse_lsblk_disks("lsblk: command not found") == []


# ── 솔라리스: iostat -En ─────────────────────────────────────────
def test_parse_iostat_disks():
    out = """c0t0d0           Soft Errors: 0 Hard Errors: 0 Transport Errors: 0
Vendor: SEAGATE  Product: ST973402SSUN72G Revision: 0400 Serial No: 0812R2
Size: 73.40GB <73400057856 bytes>
Media Error: 0 Device Not Ready: 0 No Device: 0 Recoverable: 0
c0t1d0           Soft Errors: 0 Hard Errors: 0 Transport Errors: 0
Vendor: HITACHI  Product: H101414SCSUN146G Revision: SA25 Serial No: 0901
Size: 146.80GB <146800115712 bytes>
"""
    disks = sc.parse_iostat_disks(out)
    assert len(disks) == 2
    assert disks[0]["name"] == "c0t0d0" and "SEAGATE" in disks[0]["model"]
    assert disks[0]["size_gb"] == 73.4
    assert disks[1]["size_gb"] == 146.8


# ── 요약 문자열 ──────────────────────────────────────────────────
def test_summarize_modules():
    mods = [{"size_mb": 16384, "type": "DDR4"}] * 4
    assert sc.summarize_modules(mods, 8) == "16GB×4 (DDR4) · 4/8 슬롯"
    # 슬롯이 꽉 찼으면 슬롯 표기를 생략
    assert sc.summarize_modules(mods, 4) == "16GB×4 (DDR4)"
    mixed = [{"size_mb": 32768, "type": "DDR4"}, {"size_mb": 16384, "type": "DDR4"}]
    assert sc.summarize_modules(mixed, 2) == "32GB×1 + 16GB×1 (DDR4)"
    assert sc.summarize_modules([], 4) == ""


def test_summarize_disks():
    assert sc.summarize_disks([{"kind": "SSD"}, {"kind": "SSD"}, {"kind": "HDD"}]) == \
        "HDD 1 · SSD 2"
    assert sc.summarize_disks([{"kind": ""}]) == "디스크 1"
    assert sc.summarize_disks([]) == ""


# ── 조립: 명령 출력 → 저장 필드 ───────────────────────────────────
def test_specs_from_unix_includes_inventory():
    spec = sc._specs_from_unix({
        sc._CMD_LSCPU: "CPU(s):              8\nModel name:          Intel Xeon\n",
        "cat /proc/meminfo": "MemTotal:       32946200 kB\n",
        sc._CMD_DIMM: DMIDECODE,
        sc._CMD_LSBLK: LSBLK,
    })
    mods = json.loads(spec["mem_modules"])
    assert len(mods) == 2 and spec["mem_slots_total"] == 4
    disks = json.loads(spec["disk_devices"])
    assert len(disks) == 3


def test_specs_from_unix_without_root_keeps_totals():
    """dmidecode 권한이 없어도 총량·디스크 목록은 그대로 나온다."""
    spec = sc._specs_from_unix({
        "cat /proc/meminfo": "MemTotal:       32946200 kB\n",
        sc._CMD_DIMM: "",
        sc._CMD_LSBLK: LSBLK,
    })
    assert spec["mem_total_mb"] == 32174
    assert "mem_modules" not in spec and "mem_slots_total" not in spec
    assert len(json.loads(spec["disk_devices"])) == 3


def test_solaris_disk_fallback_used_when_lsblk_absent():
    spec = sc._specs_from_unix({
        sc._CMD_LSBLK: "",
        sc._CMD_IOSTAT: ("c1t0d0  Soft Errors: 0 Hard Errors: 0 Transport Errors: 0\n"
                         "Vendor: SEAGATE  Product: ST300MM0006 Revision: 0001 Serial No: X\n"
                         "Size: 300.00GB <300000000000 bytes>\n"),
    })
    disks = json.loads(spec["disk_devices"])
    assert len(disks) == 1 and disks[0]["name"] == "c1t0d0"


# ── 윈도우 ───────────────────────────────────────────────────────
WMIC_DIMM = (
    "\r\nCapacity=17179869184\r\nDeviceLocator=ChannelA-DIMM0\r\nManufacturer=Samsung\r\n"
    "PartNumber=M471A2K43CB1-CTD\r\nSMBIOSMemoryType=26\r\nSpeed=2667\r\n"
    "\r\nCapacity=17179869184\r\nDeviceLocator=ChannelB-DIMM0\r\nManufacturer=Samsung\r\n"
    "PartNumber=M471A2K43CB1-CTD\r\nSMBIOSMemoryType=26\r\nSpeed=2667\r\n"
)


def test_parse_win_memorychip():
    mods = sc.parse_win_memorychip(WMIC_DIMM)
    assert len(mods) == 2
    assert mods[0]["size_mb"] == 16384 and mods[0]["type"] == "DDR4"
    assert mods[0]["locator"] == "ChannelA-DIMM0"
    assert mods[0]["speed"] == "2667 MT/s"


def test_parse_win_diskdrive():
    out = ("\r\nInterfaceType=SCSI\r\nModel=Samsung SSD 970 EVO 1TB\r\nSize=1000202273280\r\n"
           "\r\nInterfaceType=IDE\r\nModel=ST2000DM008-2FR102\r\nSize=2000398934016\r\n")
    disks = sc.parse_win_diskdrive(out)
    assert len(disks) == 2
    assert disks[0]["model"] == "Samsung SSD 970 EVO 1TB"
    assert disks[0]["size_gb"] == 931.5
    # InterfaceType은 버스 종류다 — NVMe SSD도 'SCSI'로 나오므로 종류로 쓰면 안 된다
    assert disks[0]["bus"] == "SCSI"
    assert disks[0]["kind"] == "", "버스 종류가 SSD/HDD 자리에 들어갔다"


def test_jedec_manufacturer_code_becomes_name():
    """wmic은 제조사를 JEDEC 16진 코드로 준다(80CE=Samsung). 코드가 그대로 보이면 안 된다."""
    mods = sc.parse_win_memorychip(
        "Capacity=17179869184\r\nDeviceLocator=DIMM A\r\nManufacturer=80CE000080CE\r\n"
        "PartNumber=M471A2K43CB1-CRC\r\nSMBIOSMemoryType=26\r\nSpeed=2400\r\n")
    assert mods[0]["maker"] == "Samsung", mods[0]["maker"]


def test_unknown_jedec_code_is_blank_not_garbage():
    mods = sc.parse_win_memorychip(
        "Capacity=17179869184\r\nDeviceLocator=DIMM A\r\nManufacturer=FFFFFFFFFFFF\r\n"
        "SMBIOSMemoryType=26\r\n")
    assert mods[0]["maker"] == "", "모르는 16진 코드가 그대로 노출됐다"


def test_real_manufacturer_name_is_kept():
    """dmidecode처럼 제대로 된 이름이 오면 그대로 둔다."""
    mods, _ = sc.parse_dmidecode_memory(
        "Memory Device\n\tSize: 16384 MB\n\tLocator: A1\n\tManufacturer: SK Hynix\n")
    assert mods[0]["maker"] == "SK Hynix"


def test_parse_win_ps_hw():
    out = ("DIMM|17179869184|ChannelA-DIMM0|Samsung|M471A2K43CB1-CTD|2667|26\r\n"
           "SLOTS|4\r\n"
           "DISK|Samsung SSD 970 EVO 1TB|1000202273280|SSD\r\n"
           "DISK|ST2000DM008|2000398934016|HDD\r\n")
    mods, slots, disks = sc.parse_win_ps_hw(out)
    assert len(mods) == 1 and mods[0]["type"] == "DDR4"
    assert slots == 4
    assert len(disks) == 2 and disks[1]["kind"] == "HDD"


def test_specs_from_windows_includes_inventory():
    spec = sc._specs_from_windows({
        sc._CMD_WIN_MEM: "TotalPhysicalMemory=34359738368\r\n",
        sc._CMD_WIN_DIMM: WMIC_DIMM,
        sc._CMD_WIN_SLOTS: "MemoryDevices=4\r\n",
        sc._CMD_WIN_PDISK: "InterfaceType=SCSI\r\nModel=Samsung SSD\r\nSize=1000202273280\r\n",
    })
    assert len(json.loads(spec["mem_modules"])) == 2
    assert spec["mem_slots_total"] == 4
    assert len(json.loads(spec["disk_devices"])) == 1


def test_windows_ps_supplies_ssd_hdd_when_wmic_cannot():
    """wmic diskdrive는 SSD/HDD를 구분 못 한다 — PowerShell MediaType이 채운다."""
    spec = sc._specs_from_windows({
        sc._CMD_WIN_PDISK: ("InterfaceType=SCSI\r\nModel=Samsung SSD\r\n"
                            "Size=1000202273280\r\n"),
        sc._CMD_WIN_PS_HW: "DISK|Samsung SSD 970 EVO|1000202273280|SSD\r\n",
    })
    disks = json.loads(spec["disk_devices"])
    assert disks[0]["kind"] == "SSD"
    assert disks[0]["bus"] == "SCSI", "wmic이 알던 버스 종류가 유실됐다"


def test_merge_disks_keeps_wmic_when_no_powershell():
    wmic = [{"name": "", "model": "X", "size_gb": 100.0, "kind": "", "bus": "IDE"}]
    assert sc._merge_disks(wmic, []) == wmic


def test_powershell_result_merged_even_when_wmic_complete():
    """wmic이 모든 필드를 채워도 SSD/HDD는 PowerShell에만 있다 — 조건부로 두면 영영 빈다."""
    spec = sc._specs_from_windows({
        sc._CMD_WIN_CPU: "Name=Xeon\r\nNumberOfLogicalProcessors=8\r\n",
        sc._CMD_WIN_MEM: "TotalPhysicalMemory=34359738368\r\n",
        sc._CMD_WIN_DISK: "DeviceID=C:\r\nFreeSpace=1\r\nSize=1000202273280\r\n",
        sc._CMD_WIN_DIMM: WMIC_DIMM,
        sc._CMD_WIN_SLOTS: "MemoryDevices=2\r\n",
        sc._CMD_WIN_PDISK: "InterfaceType=SCSI\r\nModel=T\r\nSize=1000202273280\r\n",
        sc._CMD_WIN_PS_HW: "DISK|TOSHIBA KSG60|1000202273280|SSD\r\n",
    })
    disks = json.loads(spec["disk_devices"])
    assert disks[0]["kind"] == "SSD", "wmic이 완전하다는 이유로 PowerShell 결과가 버려졌다"
    assert disks[0]["bus"] == "SCSI"


# ── PowerShell 명령 전달 방식(실측으로 잡은 버그) ─────────────────
def test_powershell_commands_use_encoded_command():
    """따옴표로 감싸 넘기면 cmd.exe/SSH를 지나며 `$` 변수가 통째로 사라진다.

    이때 PowerShell은 명령을 실행하지 않고 문자열을 그대로 되돌려주는데
    종료코드가 0이라 성공처럼 보인다(실측으로 확인). base64로 넘겨야 안전하다.
    """
    for cmd in (sc._CMD_WIN_PS, sc._CMD_WIN_PS_HW):
        assert "-EncodedCommand " in cmd, cmd[:80]
        assert '-Command "' not in cmd, "따옴표 방식이 남아 있다: %s" % cmd[:80]
        assert "$_" not in cmd and "$c=" not in cmd, "명령에 원문 $ 변수가 노출됐다"


def test_ps_command_roundtrip():
    """_ps_command로 만든 base64를 되돌리면 원본 스크립트가 나온다."""
    import base64
    script = "$d=Get-WmiObject Win32_LogicalDisk;Write-Output ('X=' + $d.Size)"
    cmd = sc._ps_command(script)
    b64 = cmd.split("-EncodedCommand ", 1)[1]
    assert base64.b64decode(b64).decode("utf-16-le") == script


def test_hw_powershell_runs_in_first_pass():
    """장착구성 PS는 1차 명령에 포함돼야 한다(2차로 두면 SSH 인증이 2회로 늘어난다)."""
    assert sc._CMD_WIN_PS_HW in sc._WIN_CMDS
    assert sc._CMD_WIN_PS not in sc._WIN_CMDS      # 요약 PS는 폴백 전용
    assert sc._WIN_CMDS_PS == [sc._CMD_WIN_PS]


# ── 저장·보존 ────────────────────────────────────────────────────
def test_inventory_persisted_and_preserved(temp_db):
    sid = db.save_server(temp_db, "HW-1", "10.80.0.1")
    mods = json.dumps([{"size_mb": 16384, "locator": "A1", "type": "DDR4"}])
    disks = json.dumps([{"name": "sda", "model": "X", "size_gb": 894.3, "kind": "SSD"}])
    db.update_server(temp_db, sid, mem_modules=mods, mem_slots_total=4, disk_devices=disks)
    row = db.get_server(temp_db, sid)
    assert json.loads(row["mem_modules"])[0]["size_mb"] == 16384
    assert row["mem_slots_total"] == 4
    assert json.loads(row["disk_devices"])[0]["kind"] == "SSD"
    # 사양을 못 얻은 재수집이 기존 구성을 지우면 안 된다
    db.update_server(temp_db, sid, status="failed")
    assert db.get_server(temp_db, sid)["mem_slots_total"] == 4
    assert db.list_servers(temp_db)[0]["disk_devices"]


def test_legacy_db_gets_inventory_columns(tmp_path):
    import sqlite3
    p = tmp_path / "legacy2.db"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE servers (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "name TEXT NOT NULL, ip TEXT NOT NULL UNIQUE, os_type TEXT, "
                 "hostname TEXT, mac TEXT, is_vm INTEGER DEFAULT 0, location TEXT, "
                 "open_ports TEXT, os_info TEXT, switch_name TEXT, switch_port TEXT, "
                 "status TEXT, last_error TEXT, last_collected TIMESTAMP, cred_blob TEXT)")
    conn.commit()
    conn.close()
    db.init_schema(p)
    sid = db.save_server(p, "OLD", "10.80.1.1")
    assert db.update_server(p, sid, mem_slots_total=8, disk_devices="[]")
    assert db.get_server(p, sid)["mem_slots_total"] == 8


# ── 내보내기 ─────────────────────────────────────────────────────
def test_export_has_inventory_columns(temp_db):
    sid = db.save_server(temp_db, "HW-2", "10.80.0.2")
    db.update_server(
        temp_db, sid, mem_total_mb=32768, mem_slots_total=4,
        mem_modules=json.dumps([{"size_mb": 16384, "type": "DDR4"}] * 2),
        disk_devices=json.dumps([{"name": "sda", "model": "SAMSUNG MZ7",
                                  "size_gb": 894.3, "kind": "SSD"}]))
    for col in ("메모리 구성", "메모리 슬롯", "디스크 구성", "디스크 개수"):
        assert col in exporter.SERVER_COLS, col
    row = exporter.servers_rows(temp_db)[0]
    assert row["메모리 구성"] == "16GB×2 (DDR4) · 2/4 슬롯"
    assert row["메모리 슬롯"] == "2/4"
    assert "SAMSUNG MZ7" in row["디스크 구성"] and row["디스크 개수"] == 1
    data, _, _ = exporter.export(temp_db, "servers", "csv")
    assert "16GB×2" in data.decode("utf-8-sig")


def test_export_handles_corrupt_inventory_json(temp_db):
    """구성 JSON이 깨져 있어도 내보내기가 죽지 않는다."""
    sid = db.save_server(temp_db, "HW-3", "10.80.0.3")
    db.update_server(temp_db, sid, mem_modules="{not json", disk_devices="null")
    row = exporter.servers_rows(temp_db)[0]
    assert row["메모리 구성"] == "" and row["디스크 개수"] == ""


# ── 화면 ─────────────────────────────────────────────────────────
def test_cells_link_to_inventory_detail():
    assert "function memCell(" in APPJS and "function diskCell(" in APPJS
    assert "function showHwDetail(" in APPJS
    assert "data-action='hw-detail'" in APPJS
    assert 'case "hw-detail":' in APPJS
    assert "memCell(s)" in APPJS and "diskCell(s)" in APPJS


def test_inventory_modal_exists():
    assert 'id="modal-hw-detail"' in HTML
    assert 'id="hw-detail-body"' in HTML and 'id="hw-detail-title"' in HTML


def test_frontend_and_export_summary_match():
    """화면 셀과 CSV의 구성 요약 표기가 어긋나면 같은 서버가 달라 보인다.

    프론트는 요약 전용 압축 라벨(_sizeLabelCompact, 공백 없음)을 써야 한다.
    """
    assert "function _sizeLabelCompact(" in APPJS
    block = APPJS[APPJS.index("function summarizeModules("):APPJS.index("function summarizeDisks(")]
    assert "_sizeLabelCompact(k)" in block, "요약에 상세표용 라벨(공백 포함)을 쓰고 있다"
    # 백엔드 기준값 — 프론트 검증은 scripts/verify_hw_cells.js가 같은 문자열로 확인한다
    assert sc.summarize_modules([{"size_mb": 16384, "type": "DDR4"}] * 2, 4) == \
        "16GB×2 (DDR4) · 2/4 슬롯"


def test_frontend_parses_inventory_defensively():
    """깨진 JSON이 표 전체 렌더를 막지 않아야 한다."""
    assert "function _hwList(" in APPJS
    block = APPJS[APPJS.index("function _hwList("):APPJS.index("function _sizeLabel(")]
    assert "try {" in block and "catch" in block
