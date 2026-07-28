# -*- coding: utf-8 -*-
"""UNIX 서버 사양 수집이 SSH 세션 한도에 막히던 문제 (v6.5.2).

사용자 보고: "물리 서버(RHEL 8.6)인데 CPU·메모리·디스크 사양을 못 가져온다.
Windows 서버만 정상이고 나머지 OS는 전부 못 가져왔다."

원인: paramiko의 exec_command()는 명령마다 새 SSH 세션 채널을 연다. OpenSSH의
`MaxSessions` 기본값은 **10**이라 11번째부터 서버가 채널 개설을 거부하고, 그 예외를
삼켜 빈 문자열이 됐다. UNIX 상세는 명령이 26개이고 사양 명령이 전부 13번째
이후여서 **hostname·OS·MAC·포트만 채워지고 사양은 통째로 비었다.**
Windows는 명령이 9개라 한도에 걸리지 않아 정상이었다.
"""
import re
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import server_collector as sc  # noqa: E402

RHEL = {
    "hostname": "rhel-app01\n",
    "uname -a": ("Linux rhel-app01 4.18.0-372.9.1.el8.x86_64 #1 SMP x86_64 "
                 "x86_64 x86_64 GNU/Linux\n"),
    "ip -o link": ("2: eno1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state UP "
                   "\\    link/ether 3c:ec:ef:11:22:33 brd ff:ff:ff:ff:ff:ff\n"),
    "ss -tln": ("State   Recv-Q  Send-Q  Local Address:Port\n"
                "LISTEN  0       128           0.0.0.0:22       0.0.0.0:*\n"),
    sc._CMD_LSCPU: ("Architecture:        x86_64\n"
                    "CPU(s):              8\n"
                    "Core(s) per socket:  4\n"
                    "Model name:          Intel(R) Xeon(R) Silver 4110 CPU @ 2.10GHz\n"),
    "cat /proc/meminfo": "MemTotal:       32778132 kB\n",
    sc._CMD_DF: ("Filesystem            1024-blocks     Used Available Capacity Mounted on\n"
                 "/dev/mapper/rhel-root    52403200 18874368  33528832      37% /\n"
                 "/dev/sda1                 1038336   287744    750592      28% /boot\n"),
    sc._CMD_LSBLK: 'NAME="sda" MODEL="PERC H730P Mini" SIZE="558.9G" ROTA="1" TYPE="disk"\n',
    sc._CMD_DIMM: "",
}


class _Stdout:
    def __init__(self, t):
        self.t = t

    def read(self):
        return self.t.encode()


def _install_fake_ssh(monkeypatch, max_sessions, fixtures):
    """MaxSessions 상한이 있는 SSH 서버를 흉내낸다."""
    calls = {"sessions": 0}

    class FakeClient:
        def set_missing_host_key_policy(self, p):
            pass

        def connect(self, *a, **k):
            pass

        def close(self):
            pass

        def exec_command(self, cmd, timeout=None):
            calls["sessions"] += 1
            if calls["sessions"] > max_sessions:
                raise Exception("ChannelException(1, 'Administratively prohibited')")
            if sc._BATCH_MARK % 0 in cmd:
                buf = []
                for line in cmd.split("\n"):
                    m = re.match(r"echo '(__NETDASH_CMD_\d+__)'$", line.strip())
                    if m:
                        buf.append(m.group(1) + "\n")
                        continue
                    m2 = re.match(r"\{ (.*) ; \} 2>/dev/null$", line.strip())
                    if m2:
                        buf.append(fixtures.get(m2.group(1), ""))
                return None, _Stdout("".join(buf)), None
            return None, _Stdout(fixtures.get(cmd, "")), None

    fake = types.ModuleType("paramiko")
    fake.SSHClient = FakeClient
    fake.AutoAddPolicy = lambda: None
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    return calls


# ── 핵심 회귀 ────────────────────────────────────────────────────
def test_specs_collected_on_default_maxsessions(monkeypatch):
    """OpenSSH 기본값(MaxSessions=10)에서도 사양이 수집돼야 한다."""
    _install_fake_ssh(monkeypatch, 10, RHEL)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    assert "Xeon" in (d.get("cpu_model") or ""), "CPU 모델 미수집"
    assert d.get("cpu_cores") == 8
    assert d.get("mem_total_mb") == 32009
    # 픽스처의 두 파일시스템 합계: root 50GB + boot 1GB
    assert d.get("disk_total_gb") == 51.0
    assert d.get("disk_used_gb") == 18.3
    assert "PERC" in (d.get("disk_devices") or ""), "물리 디스크 구성 미수집"


def test_specs_collected_even_with_single_session(monkeypatch):
    """세션을 1개만 허용하는 장비에서도 동작(배치 실행이면 1개로 충분)."""
    _install_fake_ssh(monkeypatch, 1, RHEL)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    assert d.get("cpu_cores") == 8 and d.get("mem_total_mb") == 32009


def test_unix_detail_uses_one_session(monkeypatch):
    """왕복 26회 → 1회. 세션 수를 직접 센다."""
    calls = _install_fake_ssh(monkeypatch, 10, RHEL)
    sc._ssh_detail_unix("10.1.1.5", "u", "p")
    assert calls["sessions"] == 1, "세션 %d개 사용(배치가 아니다)" % calls["sessions"]


def test_basic_info_survives_when_specs_fail(monkeypatch):
    """사양 명령이 전부 실패해도 hostname·MAC은 살아야 한다."""
    lean = {k: RHEL[k] for k in ("hostname", "uname -a", "ip -o link")}
    _install_fake_ssh(monkeypatch, 10, lean)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    assert d.get("hostname") == "rhel-app01"
    assert d.get("mac") == "3C:EC:EF:11:22:33"
    assert "cpu_cores" not in d, "값이 없으면 키를 넣지 않아야 기존값이 보존된다"


def test_falls_back_to_per_command_when_batch_unusable(monkeypatch):
    """배치를 못 쓰는 셸이면 개별 실행으로 폴백해야 한다."""
    _install_fake_ssh(monkeypatch, 30, RHEL)
    monkeypatch.setattr(sc, "_ssh_exec_batched",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no shell")))
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    assert d.get("cpu_cores") == 8


# ── 배치 실행 자체의 계약 ────────────────────────────────────────
def test_batch_script_separates_commands_by_newline():
    """'; '로 이으면 명령에 포함된 세미콜론과 구분되지 않는다."""
    import inspect
    src = inspect.getsource(sc._ssh_exec_batched)
    assert '"\\n".join(parts)' in src


def test_batch_reconstructs_each_command_output(monkeypatch):
    """마커로 자른 결과가 명령별로 정확히 매핑되는가(세미콜론 포함 명령 포함)."""
    fx = {"hostname": "h1\n", sc._CMD_CPUINFO: "model name : Xeon\n8\n",
          sc._CMD_LSCPU: "CPU(s): 8\n"}
    _install_fake_ssh(monkeypatch, 10, fx)
    out = sc._ssh_exec("10.1.1.5", "u", "p",
                       ["hostname", sc._CMD_CPUINFO, sc._CMD_LSCPU], batch=True)
    assert out["hostname"] == "h1\n"
    assert "Xeon" in out[sc._CMD_CPUINFO], "세미콜론 포함 명령의 출력이 밀렸다"
    assert "CPU(s): 8" in out[sc._CMD_LSCPU]


def test_batch_raises_when_all_empty(monkeypatch):
    """마커가 전혀 안 나오면(배치 미지원) 예외 → 상위에서 폴백."""
    _install_fake_ssh(monkeypatch, 10, {})
    with pytest.raises(Exception):
        sc._ssh_exec_batched(sys.modules["paramiko"].SSHClient(), ["hostname"], 15)


def test_windows_path_not_batched():
    """cmd.exe는 POSIX 배치 문법을 못 쓴다 — 윈도우 경로는 배치를 쓰면 안 된다."""
    import inspect
    src = inspect.getsource(sc._ssh_detail_windows)
    assert "batch=True" not in src


# ── dmidecode 권한 폴백 ─────────────────────────────────────────
def test_dimm_sudo_fallback(monkeypatch):
    """dmidecode는 root 필요 — NOPASSWD sudo가 있으면 메모리 모듈도 수집한다."""
    fx = dict(RHEL)
    fx[sc._CMD_DIMM] = "dmidecode: /dev/mem: Permission denied\n"
    fx[sc._CMD_DIMM_SUDO] = (
        "Memory Device\n\tSize: 16384 MB\n\tLocator: DIMM_A1\n\tType: DDR4\n"
        "\tSpeed: 2400 MT/s\n\tManufacturer: Samsung\n\tPart Number: M393A2G40EB1-CRC\n"
        "Memory Device\n\tSize: No Module Installed\n\tLocator: DIMM_A2\n")
    _install_fake_ssh(monkeypatch, 10, fx)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    assert "DIMM_A1" in (d.get("mem_modules") or ""), "sudo 폴백이 동작하지 않는다"
    assert d.get("mem_slots_total") == 2


def test_sudo_uses_non_interactive_flag():
    """sudo가 비밀번호를 물으면 세션이 멈춘다 — -n 필수."""
    assert " sudo -n " in sc._CMD_DIMM_SUDO
