# -*- coding: utf-8 -*-
"""서버 하드웨어 사양(CPU·메모리·디스크) 수집 — 파서·저장·화면·내보내기."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, exporter, server_collector as sc

HTML = Path(__file__).parent.parent / "web" / "templates" / "index.html"
APPJS = Path(__file__).parent.parent / "web" / "static" / "app.js"


# ── 파서 ──────────────────────────────────────────────────────────
def test_parse_lscpu():
    out = """Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
CPU(s):              16
Thread(s) per core:  2
Model name:          Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
"""
    model, cores = sc._parse_lscpu(out)
    assert model == "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"
    assert cores == 16


def test_parse_cpuinfo_fallback():
    out = "model name\t: AMD EPYC 7302 16-Core Processor\n32\n"
    model, cores = sc._parse_cpuinfo(out)
    assert model == "AMD EPYC 7302 16-Core Processor"
    assert cores == 32


def test_parse_meminfo():
    assert sc._parse_meminfo_mb("MemTotal:       16303456 kB\nMemFree: 100 kB\n") == 15921
    assert sc._parse_meminfo_mb("") == 0


def test_parse_df_skips_pseudo_and_remote():
    """의사 FS·NFS·CIFS·중복 장치는 합산에서 빠진다."""
    out = """Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1         41153856  12582912  26789012      32% /
tmpfs              8151728         0   8151728       0% /dev/shm
devtmpfs           8140000         0   8140000       0% /dev
/dev/sdb1        104857600  52428800  52428800      50% /data
nas01:/vol/app   524288000 104857600 419430400      20% /mnt/nas
/dev/sda1         41153856  12582912  26789012      32% /var/lib/docker
"""
    total, used = sc.parse_df_kb(out)
    assert total == 41153856 + 104857600      # 로컬 2개만
    assert used == 12582912 + 52428800
    assert sc._kb_to_gb(total) == 139.2


def test_parse_df_zfs_pool_not_multiplied():
    """ZFS 데이터셋은 각각 풀 전체를 보고한다 — 그대로 더하면 배수로 부풀려진다."""
    out = """Filesystem     1024-blocks      Used Available Capacity Mounted on
rpool/ROOT/solaris  287047680  62914560 224133120      22% /
rpool/export        287047680      1024 224133120       1% /export
rpool/export/home   287047680    524288 224133120       1% /export/home
rpool/VARSHARE      287047680      2048 224133120       1% /var/share
"""
    total, used = sc.parse_df_kb(out)
    assert total == 287047680, "풀 1개인데 여러 번 더해졌다"
    # 사용 = 풀 크기 - 공유 여유 공간
    assert used == 287047680 - 224133120


def test_parse_df_apfs_container_not_multiplied():
    """APFS 볼륨은 같은 컨테이너 용량을 각각 보고한다(/dev/disk1sN)."""
    out = """Filesystem   1024-blocks      Used Available Capacity Mounted on
/dev/disk1s5s1  976490576  22000000 800000000      3% /
/dev/disk1s4    976490576   4000000 800000000      1% /System/Volumes/VM
/dev/disk1s2    976490576  10000000 800000000      2% /System/Volumes/Data
"""
    total, used = sc.parse_df_kb(out)
    assert total == 976490576
    assert used == 976490576 - 800000000


def test_parse_df_esxi_counts_every_datastore():
    """ESXi는 Filesystem 칸이 타입명(VMFS-6)이라 장치명으로 묶으면 대부분 누락된다."""
    out = """Filesystem    1024-blocks      Used  Available Use% Mounted on
VMFS-6         2147483648 1073741824 1073741824  50% /vmfs/volumes/ds01
VMFS-6         4294967296 1073741824 3221225472  25% /vmfs/volumes/ds02
VMFS-6         1073741824  536870912  536870912  50% /vmfs/volumes/ds03
"""
    total, used = sc.parse_df_kb(out)
    assert total == 2147483648 + 4294967296 + 1073741824
    assert used == 1073741824 + 1073741824 + 536870912


def test_parse_df_plain_ext4_uses_reported_used():
    """단독 행은 df가 보고한 Used를 그대로 쓴다(ext4 예약 블록 포함)."""
    out = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
           "/dev/sda1 100000000 60000000 35000000 64% /\n")
    assert sc.parse_df_kb(out) == (100000000, 60000000)


def test_parse_df_bdf_and_xpg4_share_parser():
    """HP-UX bdf / Solaris xpg4 df 도 같은 컬럼 순서라 같은 파서로 처리된다."""
    bdf = ("Filesystem          kbytes    used   avail %used Mounted on\n"
           "/dev/vg00/lvol3    1048576  524288  524288   50% /\n")
    assert sc.parse_df_kb(bdf) == (1048576, 524288)


def test_specs_from_unix_uses_df_fallback_when_posix_df_missing():
    """Solaris/HP-UX는 `df -Pk`가 거부된다 — 대체 명령 출력으로 채워져야 한다."""
    o = {sc._CMD_DF: "df: illegal option -- P\n",
         sc._CMD_DF_XPG4: ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                           "/dev/dsk/c0t0d0s0 20971520 10485760 10485760 50% /\n")}
    spec = sc._specs_from_unix(o)
    assert spec["disk_total_gb"] == 20.0 and spec["disk_used_gb"] == 10.0


def test_unicode_digit_does_not_kill_ssh_detail(monkeypatch):
    """'²'.isdigit()는 True지만 int()는 예외 — 사양 파싱이 죽어도 나머지는 살아야 한다."""
    def fake_exec(ip, u, p, cmds, timeout=15, port=22):
        return {"hostname": "db01", "uname -a": "Linux db01 5.15",
                "ip -o link": "2: eth0: <BROADCAST> link/ether aa:bb:cc:dd:ee:ff",
                "ss -tln": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
                sc._CMD_CPUINFO: "model name\t: Intel Xeon\n²\n"}

    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_unix("10.0.0.4", "u", "p")
    assert d["hostname"] == "db01", "사양 파싱 실패가 hostname까지 날렸다"
    assert d["mac"] == "AA:BB:CC:DD:EE:FF" and d["os_info"].startswith("Linux")
    assert d["cpu_model"] == "Intel Xeon"
    assert "cpu_cores" not in d          # 깨진 값은 저장하지 않는다


def test_absurd_spec_values_are_dropped():
    """깨진 출력의 거대 정수가 sqlite 바인딩을 터뜨리지 않게 버린다."""
    spec = sc._specs_from_unix({
        sc._CMD_LSCPU: "CPU(s):              99999999999999999999\nModel name:  X\n",
        "cat /proc/meminfo": "MemTotal:       99999999999999999999 kB\n",
    })
    assert "cpu_cores" not in spec and "mem_total_mb" not in spec
    assert spec["cpu_model"] == "X"


def test_korean_locale_lscpu_falls_back_to_cpuinfo():
    """한글 로케일 lscpu는 키가 '모델명:'이라 못 읽는다 — /proc/cpuinfo가 복구한다."""
    spec = sc._specs_from_unix({
        sc._CMD_LSCPU: "아키텍처:            x86_64\nCPU:                 16\n모델명:  Intel Xeon Gold 6248\n",
        sc._CMD_CPUINFO: "model name\t: Intel(R) Xeon(R) Gold 6248\n16\n",
    })
    assert spec["cpu_cores"] == 16 and "6248" in spec["cpu_model"]


def test_lscpu_command_forces_c_locale():
    assert sc._CMD_LSCPU.startswith("LC_ALL=C"), "로케일 고정이 없으면 한글 서버에서 파싱 실패"


def test_windows_disk_without_freespace_omits_usage():
    """Size는 읽혔는데 FreeSpace가 비면 사용률 100%(빨강)로 오표시된다 → 사용량 생략."""
    spec = sc._specs_from_windows({
        sc._CMD_WIN_DISK: "DeviceID=C:\r\nFreeSpace=\r\nSize=107374182400\r\n"})
    assert spec["disk_total_gb"] == 100.0
    assert "disk_used_gb" not in spec


def test_parse_prtconf_aix():
    out = """System Model: IBM,8286-42A
Processor Type: PowerPC_POWER8
Number Of Processors: 4
Memory Size: 16384 MB
"""
    model, cores, mem = sc._parse_prtconf(out)
    assert (model, cores, mem) == ("PowerPC_POWER8", 4, 16384)


def test_parse_prtconf_solaris_megabytes():
    _, _, mem = sc._parse_prtconf("System Configuration: Oracle\nMemory size: 32768 Megabytes\n")
    assert mem == 32768


def test_parse_psrinfo_x86_and_sparc():
    x86 = """The physical processor has 4 cores and 8 virtual processors (0-7)
  x86 (GenuineIntel 306E4 family 6 model 62 step 4 clock 2500 MHz)
      Intel(r) Xeon(r) CPU E5-2670 v2 @ 2.50GHz
"""
    model, virt = sc._parse_psrinfo(x86)
    assert model == "Intel(r) Xeon(r) CPU E5-2670 v2 @ 2.50GHz" and virt == 8

    sparc = """The physical processor has 8 cores and 64 virtual processors (0-63)
    SPARC-T5 (chipid 0, clock 3600 MHz)
"""
    model, virt = sc._parse_psrinfo(sparc)
    assert model == "SPARC-T5" and virt == 64


def test_parse_machinfo_hpux():
    out = """CPU info:
   4 Intel(R) Itanium 2 9100 series processors (1.6 GHz, 18 MB)
Memory: 16344 MB (15.96 GB)
"""
    model, cores, mem = sc._parse_machinfo(out)
    assert cores == 4 and mem == 16344
    assert "Itanium" in model


def test_parse_sysctl_bsd():
    out = "hw.model: Intel(R) Xeon(R) CPU\nhw.ncpu: 8\nhw.physmem: 17179869184\n"
    model, cores, mem = sc._parse_sysctl(out)
    assert cores == 8 and mem == 16384 and model == "Intel(R) Xeon(R) CPU"


def test_parse_esxcli_hardware():
    out = "   CPU Packages: 2\n   CPU Cores: 16\n   CPU Threads: 32\n   Physical Memory: 68702699520 Bytes\n"
    cores, mem = sc._parse_esxcli_hw(out)
    assert cores == 32 and mem == 65520


# ── 명령 출력 → 사양 필드 조립 ─────────────────────────────────────
def test_specs_from_unix_linux():
    o = {
        "lscpu": "CPU(s):              8\nModel name:          Intel Xeon Silver 4210\n",
        "cat /proc/meminfo": "MemTotal:       32946200 kB\n",
        "df -Pk": ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                   "/dev/sda2 209715200 104857600 104857600 50% /\n"),
    }
    spec = sc._specs_from_unix(o)
    assert spec["cpu_model"] == "Intel Xeon Silver 4210"
    assert spec["cpu_cores"] == 8
    assert spec["mem_total_mb"] == 32174
    assert spec["disk_total_gb"] == 200.0 and spec["disk_used_gb"] == 100.0


def test_specs_from_unix_empty_when_nothing_collected():
    """명령이 전부 실패해도 예외 없이 빈 dict — 기존 값이 지워지지 않는다."""
    assert sc._specs_from_unix({c: "" for c in sc._UNIX_CMDS}) == {}


def test_specs_from_windows_wmic():
    o = {
        sc._CMD_WIN_CPU: "\r\nName=Intel(R) Xeon(R) Gold 6248\r\nNumberOfLogicalProcessors=20\r\n"
                         "\r\nName=Intel(R) Xeon(R) Gold 6248\r\nNumberOfLogicalProcessors=20\r\n",
        sc._CMD_WIN_MEM: "\r\nTotalPhysicalMemory=68719476736\r\n",
        sc._CMD_WIN_DISK: ("\r\nDeviceID=C:\r\nFreeSpace=53687091200\r\nSize=107374182400\r\n"
                           "\r\nDeviceID=D:\r\nFreeSpace=107374182400\r\nSize=214748364800\r\n"),
    }
    spec = sc._specs_from_windows(o)
    assert spec["cpu_model"] == "Intel(R) Xeon(R) Gold 6248"
    assert spec["cpu_cores"] == 40                  # 소켓 2개 합산
    assert spec["mem_total_mb"] == 65536
    assert spec["disk_total_gb"] == 300.0 and spec["disk_used_gb"] == 150.0


def test_specs_from_windows_powershell_fallback():
    """wmic이 없는 최신 윈도우 — PowerShell 출력으로 폴백."""
    o = {
        sc._CMD_WIN_CPU: "'wmic' is not recognized as an internal or external command,",
        sc._CMD_WIN_PS: "CPU=AMD EPYC 7443P\r\nCORES=48\r\nMEM=137438953472\r\n"
                        "DTOTAL=1099511627776\r\nDFREE=549755813888\r\n",
    }
    spec = sc._specs_from_windows(o)
    assert spec["cpu_model"] == "AMD EPYC 7443P" and spec["cpu_cores"] == 48
    assert spec["mem_total_mb"] == 131072
    assert spec["disk_total_gb"] == 1024.0 and spec["disk_used_gb"] == 512.0


def test_windows_powershell_runs_only_when_wmic_insufficient(monkeypatch):
    """PowerShell 콜드 스타트 비용 — wmic으로 다 채워지면 2차 실행을 하지 않는다."""
    calls = []
    # 장착 구성(DIMM·물리 디스크)까지 wmic으로 전부 얻은 상태
    full_wmic = {
        "hostname": "WIN-01", "ver": "Microsoft Windows [Version 10.0.17763.1]",
        sc._CMD_WIN_CPU: "Name=Intel Xeon Gold 6248\r\nNumberOfLogicalProcessors=40\r\n",
        sc._CMD_WIN_MEM: "TotalPhysicalMemory=68719476736\r\n",
        sc._CMD_WIN_DISK: "DeviceID=C:\r\nFreeSpace=53687091200\r\nSize=107374182400\r\n",
        sc._CMD_WIN_DIMM: ("Capacity=34359738368\r\nDeviceLocator=DIMM1\r\n"
                           "Manufacturer=Samsung\r\nPartNumber=M393\r\n"
                           "SMBIOSMemoryType=26\r\nSpeed=2666\r\n"),
        sc._CMD_WIN_SLOTS: "MemoryDevices=4\r\n",
        sc._CMD_WIN_PDISK: ("InterfaceType=SCSI\r\nModel=Samsung SSD\r\n"
                            "Size=107374182400\r\n"),
    }

    def fake_exec(ip, u, p, cmds, timeout=15, port=22):
        calls.append(list(cmds))
        return full_wmic if cmds is sc._WIN_CMDS else {}

    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_windows("10.0.0.7", "u", "p")
    assert d["cpu_cores"] == 40 and d["hostname"] == "WIN-01"
    assert len(calls) == 1, "wmic으로 충분한데 PowerShell을 또 실행했다"
    assert sc._CMD_WIN_PS not in calls[0]


def test_windows_falls_back_to_powershell_without_wmic(monkeypatch):
    """wmic이 없으면 PowerShell 2차 실행으로 사양을 채운다."""
    def fake_exec(ip, u, p, cmds, timeout=15, port=22):
        if cmds is sc._WIN_CMDS:
            return {"hostname": "WIN-25",
                    sc._CMD_WIN_CPU: "'wmic' is not recognized as an internal or external command,"}
        return {sc._CMD_WIN_PS: "CPU=AMD EPYC 7443P\r\nCORES=48\r\nMEM=137438953472\r\n"
                                "DTOTAL=1099511627776\r\nDFREE=549755813888\r\n"}

    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_windows("10.0.0.8", "u", "p")
    assert d["hostname"] == "WIN-25"
    assert d["cpu_model"] == "AMD EPYC 7443P" and d["cpu_cores"] == 48
    assert d["disk_total_gb"] == 1024.0


def test_windows_powershell_failure_keeps_partial(monkeypatch):
    """2차 SSH가 예외를 던져도 1차에서 얻은 정보는 살아남는다."""
    def fake_exec(ip, u, p, cmds, timeout=15, port=22):
        if cmds is sc._WIN_CMDS:
            return {"hostname": "WIN-09", "ver": "Microsoft Windows [Version 6.3.9600]"}
        raise OSError("connection reset")

    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_windows("10.0.0.11", "u", "p")
    assert d["hostname"] == "WIN-09" and "6.3.9600" in d["os_info"]


def test_windows_fallback_triggers_for_thirdparty_ssh(monkeypatch):
    """서드파티 SSH 서버(Bitvise 등)는 배너·uname으로 OS를 못 잡아 unknown이 된다.

    이때 hostname·netstat는 cmd.exe에도 있어 UNIX 상세가 '비어 있지 않으므로',
    '비었는가'로 폴백을 판정하면 윈도우 사양이 영영 수집되지 않는다.
    """
    from core import db as _db

    unix_out = {"hostname": "WINSRV", "netstat -an": "  TCP  0.0.0.0:3389  LISTENING"}
    win_out = {"hostname": "WINSRV", "ver": "Microsoft Windows [Version 10.0.20348.1]",
               sc._CMD_WIN_CPU: "Name=Intel Xeon Gold 5218\r\nNumberOfLogicalProcessors=32\r\n",
               sc._CMD_WIN_MEM: "TotalPhysicalMemory=137438953472\r\n",
               sc._CMD_WIN_DISK: "DeviceID=C:\r\nFreeSpace=53687091200\r\nSize=107374182400\r\n"}

    monkeypatch.setattr(sc, "_ssh_detail_unix",
                        lambda ip, u, p, port=22: dict(sc._specs_from_unix(unix_out),
                                                       hostname="WINSRV"))
    monkeypatch.setattr(sc, "_ssh_detail_windows",
                        lambda ip, u, p, port=22: dict(sc._specs_from_windows(win_out),
                                                       hostname="WINSRV",
                                                       os_info="Microsoft Windows [Version 10.0.20348.1]"))
    monkeypatch.setattr(sc, "detect_os", lambda *a, **k: "unknown")
    monkeypatch.setattr(sc, "scan_ports", lambda ip, ports=None, timeout=1.0: [22, 3389])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(sc, "netbios_name", lambda ip, timeout=2: "")

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "t.db"
        _db.init_schema(p)
        sid = _db.save_server(p, "WINSRV", "10.44.0.1", os_type="auto")
        res = sc.collect_server(p, sid, "u", "pw")
        assert res["status"] == "done"
        row = _db.get_server(p, sid)
        assert row["os_type"] == "windows", "서드파티 SSH 윈도우가 unknown으로 남았다"
        assert row["cpu_cores"] == 32 and row["mem_total_mb"] == 131072
        assert row["cpu_model"] == "Intel Xeon Gold 5218"


def test_collect_survives_db_save_failure(monkeypatch):
    """저장 실패가 예외로 새면 서버가 'collecting'에 고착되고 일괄 루프가 끊긴다."""
    from core import db as _db
    import tempfile

    monkeypatch.setattr(sc, "scan_ports", lambda ip, ports=None, timeout=1.0: [22])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(sc, "netbios_name", lambda ip, timeout=2: "")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "t.db"
        _db.init_schema(p)
        sid = _db.save_server(p, "X", "10.45.0.1")
        real = _db.update_server
        calls = {"n": 0}

        def flaky(db_path, server_id, **f):
            calls["n"] += 1
            if f.get("collected"):
                raise OverflowError("Python int too large to convert to SQLite INTEGER")
            return real(db_path, server_id, **f)

        monkeypatch.setattr(sc.db, "update_server", flaky)
        res = sc.collect_server(p, sid, None, None)
        assert res["status"] == "failed"
        monkeypatch.setattr(sc.db, "update_server", real)
        assert _db.get_server(p, sid)["status"] != "collecting", "상태가 고착됐다"


def test_ssh_detail_unix_includes_specs(monkeypatch):
    """SSH 상세 수집 결과에 사양 필드가 함께 담긴다."""
    def fake_exec(ip, u, p, cmds, timeout=15, port=22):
        return {"hostname": "web01", "uname -a": "Linux web01 5.15.0",
                "lscpu": "CPU(s):              4\nModel name:          Intel Xeon E5\n",
                "cat /proc/meminfo": "MemTotal:        8123456 kB\n"}
    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_unix("10.0.0.5", "u", "p")
    assert d["hostname"] == "web01"
    assert d["cpu_cores"] == 4 and d["mem_total_mb"] == 7933
    assert d["cpu_model"] == "Intel Xeon E5"


# ── 저장·조회 ─────────────────────────────────────────────────────
def test_server_specs_persisted(temp_db):
    sid = db.save_server(temp_db, "SRV-01", "10.9.0.1", os_type="linux")
    db.update_server(temp_db, sid, collected=True, cpu_model="Intel Xeon Silver 4210",
                     cpu_cores=8, mem_total_mb=32173,
                     disk_total_gb=200.0, disk_used_gb=100.0)
    s = db.get_server(temp_db, sid)
    assert s["cpu_model"] == "Intel Xeon Silver 4210"
    assert s["cpu_cores"] == 8 and s["mem_total_mb"] == 32173
    assert s["disk_total_gb"] == 200.0 and s["disk_used_gb"] == 100.0
    assert db.list_servers(temp_db)[0]["cpu_cores"] == 8


def test_specs_not_wiped_when_recollect_fails(temp_db):
    """재수집에서 사양을 못 얻어도(None 미전달) 기존 값이 유지된다."""
    sid = db.save_server(temp_db, "SRV-02", "10.9.0.2")
    db.update_server(temp_db, sid, cpu_cores=16, mem_total_mb=65536)
    db.update_server(temp_db, sid, status="done")      # 사양 필드 없이 갱신
    s = db.get_server(temp_db, sid)
    assert s["cpu_cores"] == 16 and s["mem_total_mb"] == 65536


def test_legacy_db_migrates_spec_columns(tmp_path):
    """사양 컬럼이 없는 옛 DB도 init_schema 재실행으로 채워진다."""
    import sqlite3
    p = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE servers (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "name TEXT NOT NULL, ip TEXT NOT NULL UNIQUE, os_type TEXT, "
                 "hostname TEXT, mac TEXT, is_vm INTEGER DEFAULT 0, location TEXT, "
                 "open_ports TEXT, os_info TEXT, switch_name TEXT, switch_port TEXT, "
                 "status TEXT, last_error TEXT, last_collected TIMESTAMP, cred_blob TEXT)")
    conn.commit()
    conn.close()
    db.init_schema(p)
    sid = db.save_server(p, "OLD-01", "10.9.0.3")
    assert db.update_server(p, sid, cpu_cores=4, disk_total_gb=50.0)
    assert db.get_server(p, sid)["cpu_cores"] == 4


# ── 화면·내보내기 ──────────────────────────────────────────────────
def test_export_includes_spec_columns(temp_db):
    sid = db.save_server(temp_db, "SRV-03", "10.9.0.4")
    db.update_server(temp_db, sid, cpu_model="Intel Xeon Gold 6248", cpu_cores=40,
                     mem_total_mb=65536, disk_total_gb=300.0, disk_used_gb=150.0)
    for col in ("CPU", "코어", "메모리(GB)", "디스크 전체(GB)", "디스크 사용(GB)"):
        assert col in exporter.SERVER_COLS
    row = exporter.servers_rows(temp_db)[0]
    assert row["CPU"] == "Intel Xeon Gold 6248" and row["코어"] == 40
    assert row["메모리(GB)"] == 64.0
    data, _, _ = exporter.export(temp_db, "servers", "csv")
    assert "Intel Xeon Gold 6248" in data.decode("utf-8-sig")


def test_server_table_has_spec_headers():
    html = HTML.read_text(encoding="utf-8")
    head = html[html.index('id="srv-check-all"'):html.index('id="server-table-body"')]
    for th in ("<th>이름</th>", ">CPU</th>", ">메모리</th>", ">디스크</th>"):
        assert th in head, th
    # 헤더 수와 빈 목록 colspan이 어긋나면 표가 깨진다
    assert head.count("</th>") == 16
    assert 'colspan="16"' in html


def test_server_row_renders_spec_cells():
    js = APPJS.read_text(encoding="utf-8")
    for fn in ("fmtCpu(s)", "fmtMem(s.mem_total_mb)", "fmtDisk(s)"):
        assert fn in js, fn
    assert "colspan='16'" in js
