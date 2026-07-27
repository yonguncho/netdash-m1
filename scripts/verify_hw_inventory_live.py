# -*- coding: utf-8 -*-
"""장착 구성 파서를 '이 PC의 실제 하드웨어 출력'으로 검증한다.

픽스처만으로는 못 잡는 것(제조사가 JEDEC 코드로 오는 것, SSD/HDD가 버스 종류로
바뀌어 오는 것 등)을 실측으로 확인하기 위한 스크립트. Windows에서만 의미가 있다.

실행: python scripts/verify_hw_inventory_live.py
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import server_collector as sc      # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print(("  [OK]   " if cond else "  [FAIL] ") + name + (" — " + str(detail) if detail else ""))
    if not cond:
        FAILS.append(name)


def run(cmd, timeout=120):
    """실제 서버에서 SSH로 실행되는 것과 같은 문자열을 cmd.exe에 그대로 넘긴다."""
    try:
        r = subprocess.run(["cmd", "/c", cmd], capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace")
    except Exception as e:
        print("    (명령 실패: %s)" % str(e)[:80])
        return ""


def main():
    print("\n[1] wmic 단독 (1차 수집 경로)")
    o = {}
    for c in (sc._CMD_WIN_CPU, sc._CMD_WIN_MEM, sc._CMD_WIN_DISK,
              sc._CMD_WIN_DIMM, sc._CMD_WIN_SLOTS, sc._CMD_WIN_PDISK):
        o[c] = run(c)
    spec = sc._specs_from_windows(dict(o))
    mods = json.loads(spec.get("mem_modules") or "[]")
    disks = json.loads(spec.get("disk_devices") or "[]")
    check("CPU 모델 수집", bool(spec.get("cpu_model")), spec.get("cpu_model"))
    check("메모리 총량 수집", bool(spec.get("mem_total_mb")), spec.get("mem_total_mb"))
    check("메모리 모듈 1개 이상", len(mods) >= 1, len(mods))
    check("메모리 슬롯 수 수집", bool(spec.get("mem_slots_total")), spec.get("mem_slots_total"))
    check("물리 디스크 1개 이상", len(disks) >= 1, len(disks))
    for m in mods:
        check("모듈 용량이 있다", m["size_mb"] > 0, m)
        check("제조사가 JEDEC 16진 코드로 새지 않음",
              not (m["maker"] and all(ch in "0123456789ABCDEFabcdef" for ch in m["maker"])),
              m["maker"])
    for d in disks:
        check("디스크 kind에 버스 종류(SCSI/IDE)가 들어가지 않음",
              d.get("kind", "").upper() not in ("SCSI", "IDE", "USB", "RAID"), d)
    print("  요약(메모리):", sc.summarize_modules(mods, spec.get("mem_slots_total") or 0))
    print("  요약(디스크):", sc.summarize_disks(disks))

    print("\n[2] PowerShell 폴백 경로 (wmic 없는 최신 윈도우 대비)")
    ps_out = run(sc._CMD_WIN_PS_HW)
    print("  원문 앞부분:", (ps_out or "").strip().splitlines()[:3])
    pm, slots, pd = sc.parse_win_ps_hw(ps_out)
    check("PowerShell이 명령을 실행함(문자열을 되돌려주지 않음)",
          "Get-WmiObject" not in (ps_out or ""), (ps_out or "")[:80])
    check("PowerShell 메모리 모듈 파싱", len(pm) >= 1, len(pm))
    check("PowerShell 슬롯 수 파싱", slots >= 1, slots)
    check("PowerShell 디스크 파싱", len(pd) >= 1, len(pd))
    check("PowerShell이 SSD/HDD(MediaType)를 알려줌",
          any(d.get("kind") for d in pd), [d.get("kind") for d in pd])

    print("\n[3] wmic + PowerShell 병합 (실제 2단계 수집과 동일)")
    o2 = dict(o)
    o2[sc._CMD_WIN_PS] = run(sc._CMD_WIN_PS)
    o2[sc._CMD_WIN_PS_HW] = ps_out
    spec2 = sc._specs_from_windows(o2)
    disks2 = json.loads(spec2.get("disk_devices") or "[]")
    mods2 = json.loads(spec2.get("mem_modules") or "[]")
    for d in disks2:
        print("   DISK:", d)
    check("병합 후 디스크 종류(SSD/HDD)가 채워짐",
          all(d.get("kind") for d in disks2), disks2)
    check("병합 후에도 버스 종류가 보존됨", any(d.get("bus") for d in disks2), disks2)
    check("병합 후 모듈 유실 없음", len(mods2) == len(mods), (len(mods2), len(mods)))
    print("  요약(디스크):", sc.summarize_disks(disks2))

    print("\n" + "=" * 60)
    if FAILS:
        print("FAILED %d건: %s" % (len(FAILS), ", ".join(FAILS)))
        return 1
    print("ALL PASS — 실제 하드웨어 출력으로 장착 구성 파싱 검증 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
