# -*- coding: utf-8 -*-
"""서버 사양 수집이 왜 안 되는지 한 대씩 짚어주는 진단 도구.

NetDash는 사양을 네 경로로 시도한다: SSH → WinRM → WMI(DCOM) → SNMP.
화면에는 마지막 사유 한 줄만 남아서, 어느 경로가 어디서 막혔는지 알기 어렵다.
이 스크립트는 **각 경로를 순서대로 직접 두들겨** 결과를 그대로 보여준다.

사용:
    python scripts/diag_server_spec.py 10.0.0.5
    python scripts/diag_server_spec.py 10.0.0.5 --user administrator
      (비밀번호는 화면에 안 보이게 입력받는다 — 명령행에 쓰지 않는다)

읽기만 한다. DB를 고치지 않고 장비에 아무것도 남기지 않는다.
"""
import argparse
import getpass
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import server_collector as sc  # noqa: E402
from core import snmp_collect, wmi_collect  # noqa: E402

OK, NG, INFO = "  [OK]  ", "  [--]  ", "  [i ]  "


def _t(fn, *a, **k):
    """(결과, 예외, 걸린시간)"""
    t0 = time.time()
    try:
        return fn(*a, **k), None, time.time() - t0
    except Exception as e:
        return None, e, time.time() - t0


def main():
    ap = argparse.ArgumentParser(description="서버 사양 수집 경로 진단")
    ap.add_argument("ip")
    ap.add_argument("--user", default="")
    ap.add_argument("--community", default="public", help="SNMP 커뮤니티")
    a = ap.parse_args()
    return run_diagnosis(a.ip, a.user, a.community)


def run_diagnosis(ip, user="", community="public"):
    """진단 본체 — exe(--diag-server)와 스크립트 양쪽에서 부른다."""
    class _Args(object):
        pass

    args = _Args()
    args.ip, args.user, args.community = ip, user, community

    pw = ""
    if args.user:
        pw = getpass.getpass("비밀번호(입력해도 화면에 안 보입니다): ")

    print("\n대상: %s" % args.ip)
    print("=" * 66)

    # 0) 포트 스캔 — 이후 모든 경로의 전제
    print("\n[0] 열린 포트")
    ports, err, dt = _t(sc.scan_ports, args.ip)
    if err:
        print(NG + "스캔 실패: %s" % err)
        return 1
    print(INFO + "%s  (%.1f초)" % (ports or "없음", dt))
    if not ports:
        print(NG + "열린 포트가 없습니다 → 도달 불가. 방화벽/전원/IP를 먼저 확인하세요.")
        return 1

    # 1) SSH
    print("\n[1] SSH")
    sshp, _, _ = _t(sc.find_ssh_port, args.ip, ports)
    if not sshp:
        print(NG + "SSH 응답 없음(배너 미확인) — 이 경로는 건너뜁니다")
    elif not args.user:
        print(INFO + "SSH 포트 %s 열림 — 계정을 안 줘서 시도 안 함(--user 로 지정)" % sshp)
    else:
        d, err, dt = _t(sc._ssh_detail_unix, args.ip, args.user, pw, port=sshp)
        if err:
            print(NG + "포트 %s 접속 실패 (%.1f초): %s" % (sshp, dt, str(err)[:140]))
            if sc._is_auth_error(err):
                print(INFO + "→ 계정 거부입니다. 그 서버의 계정인지 확인하세요"
                             "(공통 계정이 서버마다 다를 수 있습니다).")
        else:
            got = {k: d.get(k) for k in
                   ("cpu_model", "cpu_cores", "mem_total_mb", "disk_total_gb")}
            if any(got.values()):
                print(OK + "사양 수집됨: %s" % got)
                print("\n→ SSH로 되는 서버입니다. 수집이 안 됐다면 계정 저장 여부를 확인하세요.")
                return 0
            print(NG + "접속은 됐는데 사양 명령이 무응답 (%.1f초)" % dt)
            if d.get("_spec_hint"):
                print(INFO + str(d["_spec_hint"])[:160])

    # 2) WinRM / 3) DCOM
    print("\n[2-3] WinRM(5985/5986) · WMI DCOM(135)")
    trs = wmi_collect.transports_for(ports)
    if not trs:
        print(NG + "5985/5986/135 중 열린 것이 없습니다 — 이 경로는 불가")
        if 3389 in (ports or []):
            print(INFO + "RDP(3389)는 열려 있습니다. 대상 서버에서 관리자 PowerShell로")
            print(INFO + "  Enable-PSRemoting -Force")
            print(INFO + "를 실행하면 5985가 열려 사양을 읽을 수 있습니다.")
    elif not wmi_collect.available():
        print(NG + "이 PC가 Windows가 아니라 WMI 경로를 쓸 수 없습니다")
    elif not args.user:
        print(INFO + "%s — 계정을 안 줘서 시도 안 함" % [t for t, _ in trs])
    else:
        for tr, port in trs:
            r, err, dt = _t(wmi_collect.collect, args.ip, args.user, pw,
                            transport=tr, port=port)
            if err:
                print(NG + "%-5s:%-5s 실패 (%.1f초): %s" % (tr, port, dt, str(err)[:130]))
            else:
                print(OK + "%-5s:%-5s 사양 수집됨: cores=%s mem=%sMB disk=%sGB"
                      % (tr, port, r.get("cpu_cores"), r.get("mem_total_mb"),
                         r.get("disk_total_gb")))
                return 0

    # 4) SNMP
    print("\n[4] SNMP(161/UDP)  커뮤니티=%s" % args.community)
    r, err, dt = _t(snmp_collect.collect, args.ip, args.community, timeout=2.0)
    if err:
        print(NG + "실패 (%.1f초): %s" % (dt, str(err)[:150]))
    else:
        spec = {k: r.get(k) for k in ("cpu_cores", "mem_total_mb", "disk_total_gb")}
        if any(spec.values()):
            print(OK + "사양 수집됨: %s" % spec)
            return 0
        print(NG + "응답은 오는데 사양 정보가 없습니다(HOST-RESOURCES-MIB 미개방)")
        print(INFO + "→ 대상의 /etc/snmp/snmpd.conf view에 .1.3.6.1.2.1.25 추가")

    print("\n" + "=" * 66)
    print("네 경로 모두 실패했습니다. 위 사유를 그대로 알려주시면 원인을 좁힐 수 있습니다.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
