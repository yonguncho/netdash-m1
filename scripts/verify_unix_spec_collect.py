# -*- coding: utf-8 -*-
"""UNIX 서버 사양 수집 실동작 검증.

`MaxSessions` 제한이 있는 SSH 서버(OpenSSH 기본 10)를 흉내내는 가짜 서버로
CPU/메모리/디스크 사양이 실제로 수집되는지 확인한다.

사용자 보고: "물리 서버(RHEL 8.6)인데 CPU·메모리·디스크 사양을 못 가져온다.
Windows 서버만 정상." → 명령이 26개인데 사양 명령이 전부 13번째 이후라
11번째부터 서버가 채널 개설을 거부해 조용히 빈값이 됐다.
"""
import re
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import server_collector as sc  # noqa: E402

R = []


def rep(label, ok, detail=""):
    R.append(ok)
    print("  [%s] %s%s" % ("OK" if ok else "FAIL", label,
                           (" — " + str(detail)) if detail else ""))


# ── 실제 장비 출력 픽스처 ────────────────────────────────────────
RHEL = {
    "hostname": "rhel-app01\n",
    "uname -n": "rhel-app01\n",
    "uname -a": ("Linux rhel-app01 4.18.0-372.9.1.el8.x86_64 #1 SMP Tue Mar 22 "
                 "EDT 2022 x86_64 x86_64 x86_64 GNU/Linux\n"),
    "ip -o link": ("1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN "
                   "\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                   "2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP "
                   "\\    link/ether 3c:ec:ef:11:22:33 brd ff:ff:ff:ff:ff:ff\n"),
    "ss -tln": ("State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port\n"
                "LISTEN  0       128            0.0.0.0:22           0.0.0.0:*\n"
                "LISTEN  0       128            0.0.0.0:443          0.0.0.0:*\n"),
    sc._CMD_LSCPU: ("Architecture:        x86_64\n"
                    "CPU op-mode(s):      32-bit, 64-bit\n"
                    "CPU(s):              8\n"
                    "Thread(s) per core:  2\n"
                    "Core(s) per socket:  4\n"
                    "Socket(s):           1\n"
                    "Vendor ID:           GenuineIntel\n"
                    "Model name:          Intel(R) Xeon(R) Silver 4110 CPU @ 2.10GHz\n"),
    "cat /proc/meminfo": "MemTotal:       32778132 kB\nMemFree:         1234567 kB\n",
    sc._CMD_DF: ("Filesystem              1024-blocks     Used Available Capacity Mounted on\n"
                 "devtmpfs                   16371564        0  16371564       0% /dev\n"
                 "tmpfs                      16389064        0  16389064       0% /dev/shm\n"
                 "/dev/mapper/rhel-root      52403200 18874368  33528832      37% /\n"
                 "/dev/sda1                   1038336   287744    750592      28% /boot\n"
                 "/dev/mapper/rhel-home     104806400  5242880  99563520       5% /home\n"),
    sc._CMD_LSBLK: ('NAME="sda" MODEL="PERC H730P Mini" SIZE="558.9G" ROTA="1" TYPE="disk"\n'
                    'NAME="sdb" MODEL="PERC H730P Mini" SIZE="1.1T" ROTA="0" TYPE="disk"\n'),
    # dmidecode는 root 권한이 필요 → 일반 계정에서는 빈 출력(정상 상황)
    sc._CMD_DIMM: "",
}


class _Stdout:
    def __init__(self, t):
        self.t = t

    def read(self):
        return self.t.encode()


def make_client(max_sessions, fixtures):
    class FakeClient:
        def __init__(self):
            self.sessions = 0

        def set_missing_host_key_policy(self, p):
            pass

        def connect(self, *a, **k):
            pass

        def close(self):
            pass

        def exec_command(self, cmd, timeout=None):
            self.sessions += 1
            if self.sessions > max_sessions:
                raise Exception("ChannelException(1, 'Administratively prohibited')")
            if sc._BATCH_MARK % 0 in cmd:
                return None, _Stdout(self._run_script(cmd)), None
            return None, _Stdout(fixtures.get(cmd, "")), None

        @staticmethod
        def _run_script(script):
            """POSIX 셸처럼 줄 단위로 실행."""
            buf = []
            for line in script.split("\n"):
                m = re.match(r"echo '(__NETDASH_CMD_\d+__)'$", line.strip())
                if m:
                    buf.append(m.group(1) + "\n")
                    continue
                m2 = re.match(r"\{ (.*) ; \} 2>/dev/null$", line.strip())
                if m2:
                    buf.append(fixtures.get(m2.group(1), ""))
            return "".join(buf)

    return FakeClient


def install(max_sessions, fixtures):
    fake = types.ModuleType("paramiko")
    fake.SSHClient = make_client(max_sessions, fixtures)
    fake.AutoAddPolicy = lambda: None
    sys.modules["paramiko"] = fake


def main():
    print("[1] MaxSessions=10 (OpenSSH 기본값) — RHEL 8.6 물리 서버")
    install(10, RHEL)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    rep("hostname", d.get("hostname") == "rhel-app01", d.get("hostname"))
    rep("MAC", d.get("mac") == "3C:EC:EF:11:22:33", d.get("mac"))
    rep("열린 포트", d.get("open_ports") == "22,443", d.get("open_ports"))
    rep("CPU 모델", "Xeon" in (d.get("cpu_model") or ""), d.get("cpu_model"))
    rep("CPU 코어", d.get("cpu_cores") == 8, d.get("cpu_cores"))
    rep("메모리(MB)", d.get("mem_total_mb") == 32009, d.get("mem_total_mb"))
    rep("디스크 전체(GB)", d.get("disk_total_gb") == 150.9, d.get("disk_total_gb"))
    rep("디스크 사용(GB)", d.get("disk_used_gb") == 23.3, d.get("disk_used_gb"))
    rep("물리 디스크 구성", "PERC" in (d.get("disk_devices") or ""),
        (d.get("disk_devices") or "")[:50])

    print("[2] 세션 제한이 더 심한 서버(MaxSessions=1)")
    install(1, RHEL)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    rep("한 세션만 허용돼도 사양 수집", d.get("cpu_cores") == 8 and d.get("mem_total_mb") == 32009,
        "cores=%s mem=%s" % (d.get("cpu_cores"), d.get("mem_total_mb")))

    print("[3] 배치를 못 쓰는 셸(마커 미출력) → 개별 실행 폴백")
    install(30, RHEL)                      # 세션 여유 + 배치 스크립트 무응답
    orig = sc._ssh_exec_batched
    sc._ssh_exec_batched = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no shell"))
    try:
        d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    finally:
        sc._ssh_exec_batched = orig
    rep("폴백으로도 수집됨", d.get("cpu_cores") == 8, d.get("cpu_cores"))

    print("[4] 사양 명령이 전부 실패해도 기본 정보는 살아야 한다")
    lean = {k: v for k, v in RHEL.items() if k in ("hostname", "uname -a", "ip -o link")}
    install(10, lean)
    d = sc._ssh_detail_unix("10.1.1.5", "u", "p")
    rep("hostname 유지", d.get("hostname") == "rhel-app01")
    rep("사양은 비어 있음(기존값 보존)", "cpu_cores" not in d)

    print()
    ok = all(R)
    print(("ALL PASS — UNIX 사양 수집 정상" if ok else "FAIL %d건" % R.count(False)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
