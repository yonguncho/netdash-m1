# -*- coding: utf-8 -*-
"""Windows/Linux가 아닌 OS(AIX·Solaris·HP-UX·ESXi·BSD·macOS·미상)도 수집."""
import io
import sys
from pathlib import Path

from openpyxl import Workbook

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc, excel_loader


def _xlsx(rows):
    wb = Workbook()
    ws = wb.active
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ── OS 계열 판정 ────────────────────────────────────────────────
def test_os_family_from_uname():
    f = sc.os_family_from_uname
    assert f("Linux srv 5.15.0") == "linux"
    assert f("AIX 3 7") == "aix"
    assert f("SunOS server1 5.11 11.4") == "solaris"
    assert f("HP-UX hpsrv B.11.31") == "hpux"
    assert f("VMkernel esxi01 7.0.3") == "esxi"
    assert f("Darwin mac 22.6.0") == "macos"
    assert f("FreeBSD bsd1 13.2") == "bsd"
    assert f("") == "unknown"
    assert f("SomeWeirdOS 1.0") == "unknown"   # 미상이어도 예외 없이 unknown


# ── MAC 파싱: OS별 표기 ─────────────────────────────────────────
def test_mac_parsing_per_os():
    m = sc._first_mac_from_text
    assert m("2: ens192: <UP> mtu 1500\\    link/ether 00:50:56:aa:bb:cc brd ff:ff:ff:ff:ff:ff") \
        == "00:50:56:AA:BB:CC"                                    # Linux iproute2
    assert m("en0 1500 link#2  0.9.6b.8f.ab.cd  1234 0 5678 0 0") == "00:09:6B:8F:AB:CD"   # AIX
    assert m("net0: flags=1000843 mtu 1500\n        ether 0:50:56:aa:bb:cc") \
        == "00:50:56:AA:BB:CC"                                    # Solaris(앞 0 생략)
    assert m("em0: flags=8843 mtu 1500\n        ether 00:1c:14:11:22:33") == "00:1C:14:11:22:33"
    assert m("lan0  0x00306EF4A1B2  1  UP") == "00:30:6E:F4:A1:B2"                          # HP-UX
    assert m("vmnic0 0000:02 ixgbe Up 10000 00:50:56:01:02:03 1500") == "00:50:56:01:02:03"  # ESXi


def test_mac_parsing_no_false_positive():
    m = sc._first_mac_from_text
    assert m("inet 10.92.10.5 netmask 255.255.255.0") == ""
    assert m("uptime 12:34:56 up 3 days") == ""
    assert m("inet6 fe80::250:56ff:feaa:bbcc/64") == ""


def test_norm_mac_zero_pads_short_octets():
    assert sc._norm_mac("0:9:6b:8f:ab:cd") == "00:09:6B:8F:AB:CD"
    assert sc._norm_mac("0.9.6b.8f.ab.cd") == "00:09:6B:8F:AB:CD"
    assert sc._norm_mac("00-1C-14-11-22-33") == "00:1C:14:11:22:33"


# ── 리스닝 포트: 플랫폼별 netstat/ss ────────────────────────────
def test_listening_ports_per_os():
    p = sc._listening_ports_from_text
    assert 22 in p("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*")            # ss(Linux)
    assert 443 in p("LISTEN 0 128 [::]:443 [::]:*")
    assert 22 in p("  *.22   *.*  0 0 128 0 LISTEN")               # Solaris netstat -an
    assert p("ESTABLISHED 0 0 10.0.0.1:22 10.0.0.2:5000") == set()  # LISTEN 아님


# ── 범용 UNIX 상세 수집: 되는 명령만 취합 ───────────────────────
def test_ssh_detail_unix_partial_commands(monkeypatch):
    """AIX처럼 ip/ss가 없는 OS에서도 hostname·OS·MAC·포트를 수집한다."""
    def fake_exec(ip, u, p, cmds, timeout=15, port=22, batch=False):
        return {
            "hostname": "aixsrv01",
            "uname -n": "aixsrv01",
            "uname -a": "AIX aixsrv01 3 7 00F8B1234C00",
            "uname -sr": "AIX 3",
            "ip -o link": "",                  # 없는 명령 → 빈 출력
            "ifconfig -a": "",
            "netstat -in": "en0 1500 link#2 0.9.6b.8f.ab.cd 1 0 2 0 0",
            "lanscan": "",
            "ss -tln": "",
            "netstat -an": "  *.22   *.*  0 0 128 0 LISTEN\n  *.1521 *.* 0 0 128 0 LISTEN",
            "esxcli system version get": "",
            "esxcli network nic list": "",
        }
    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_unix("10.0.0.9", "u", "p")
    assert d["hostname"] == "aixsrv01"
    assert d["os_info"].startswith("AIX")
    assert d["mac"] == "00:09:6B:8F:AB:CD"
    assert d["open_ports"] == "22,1521"


def test_ssh_detail_unix_esxi(monkeypatch):
    def fake_exec(ip, u, p, cmds, timeout=15, port=22, batch=False):
        return {
            "hostname": "esxi01",
            "uname -a": "VMkernel esxi01 7.0.3",
            "esxcli system version get": "   Product: VMware ESXi\n   Version: 7.0.3\n   Build: 20328353",
            "esxcli network nic list": "Name   PCI      Driver Link Speed MAC Address       MTU\n"
                                       "vmnic0 0000:02  ixgbe  Up   10000 00:50:56:01:02:03 1500",
            "ss -tln": "", "netstat -an": "", "ip -o link": "", "ifconfig -a": "",
            "netstat -in": "", "lanscan": "", "uname -n": "esxi01", "uname -sr": "VMkernel 7.0.3",
        }
    monkeypatch.setattr(sc, "_ssh_exec", fake_exec)
    d = sc._ssh_detail_unix("10.0.0.10", "u", "p")
    assert "ESXi" in d["os_info"] and "7.0.3" in d["os_info"]
    assert d["mac"] == "00:50:56:01:02:03"


# ── collect_server: 미상 OS도 UNIX 경로로 수집 ──────────────────
def test_collect_server_unknown_os_uses_unix_path(temp_db, monkeypatch):
    sid = db.save_server(temp_db, "S-AIX", "10.0.0.50", os_type="auto")
    monkeypatch.setattr(sc, "scan_ports", lambda ip, **k: [22, 1521])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(sc, "netbios_name", lambda ip, **k: "")
    monkeypatch.setattr(db, "find_mac_location", lambda dbp, ip: {})
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, **k: "aix")   # 비-linux/windows
    called = {}
    def fake_unix(ip, u, p, port=22):
        called["unix"] = True
        return {"hostname": "aixsrv", "os_info": "AIX 3 7", "mac": "00:09:6B:8F:AB:CD"}
    monkeypatch.setattr(sc, "_ssh_detail_unix", fake_unix)
    monkeypatch.setattr(sc, "_ssh_detail_windows",
                        lambda ip, u, p, port=22: {"os_info": "SHOULD NOT BE USED"})
    res = sc.collect_server(temp_db, sid, "admin", "pw")
    assert called.get("unix") is True          # 윈도우 경로로 가지 않음
    sv = db.get_server(temp_db, sid)
    assert sv["os_type"] == "aix" and sv["hostname"] == "aixsrv"
    assert sv["os_info"] == "AIX 3 7"
    assert res["status"] == "done"


def test_collect_server_unknown_falls_back_to_windows(temp_db, monkeypatch):
    """UNIX 명령이 전부 실패하고 OS 미상이면 윈도우 경로도 한 번 시도한다."""
    sid = db.save_server(temp_db, "S-UNK", "10.0.0.51", os_type="auto")
    monkeypatch.setattr(sc, "scan_ports", lambda ip, **k: [22])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(sc, "netbios_name", lambda ip, **k: "")
    monkeypatch.setattr(db, "find_mac_location", lambda dbp, ip: {})
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, **k: "unknown")
    monkeypatch.setattr(sc, "_ssh_detail_unix", lambda ip, u, p, port=22: {})   # 전부 실패
    monkeypatch.setattr(sc, "_ssh_detail_windows",
                        lambda ip, u, p, port=22: {"hostname": "WINSRV", "os_info": "Windows 10.0.17763"})
    sc.collect_server(temp_db, sid, "admin", "pw")
    sv = db.get_server(temp_db, sid)
    assert sv["os_type"] == "windows" and sv["hostname"] == "WINSRV"


# ── 엑셀/등록 API가 비-linux/windows OS를 보존 ──────────────────
def test_excel_os_type_other_families():
    rows = excel_loader.parse_server_inventory(
        _xlsx([["호스트명", "대표 IP", "OS Version"],
               ["AIXSRV", "10.9.0.1", "AIX 7.2"],
               ["SOL01", "10.9.0.2", "Solaris 11.4"],
               ["ESX01", "10.9.0.3", "VMware ESXi 7.0"],
               ["HPUX01", "10.9.0.4", "HP-UX 11.31"]]))
    by = {r["name"]: r["os_type"] for r in rows}
    assert by["AIXSRV"] == "aix" and by["SOL01"] == "solaris"
    assert by["ESX01"] == "esxi" and by["HPUX01"] == "hpux"


def test_server_api_accepts_other_os(client):
    r = client.post("/api/servers", json={"name": "AIX-1", "ip": "10.9.1.1", "os_type": "aix"})
    assert r.status_code == 201
    from config import get_config
    dbp = get_config(demo_mode=True).get_db_path()
    sv = [s for s in db.list_servers(dbp) if s["ip"] == "10.9.1.1"][0]
    assert sv["os_type"] == "aix"          # linux/windows로 강제되지 않음
    # 허용 목록 밖 임의 값은 auto로 방어
    r2 = client.post("/api/servers", json={"name": "X", "ip": "10.9.1.2", "os_type": "<script>"})
    assert r2.status_code == 201
    sv2 = [s for s in db.list_servers(dbp) if s["ip"] == "10.9.1.2"][0]
    assert sv2["os_type"] == "auto"
