# -*- coding: utf-8 -*-
"""서버 사양 수집이 왜 안 되는지 한 대씩 짚어주는 진단 도구.

NetDash는 사양을 네 경로로 시도한다: SSH → WinRM → WMI(DCOM) → SNMP.
화면에는 마지막 사유 한 줄만 남아서, 어느 경로가 어디서 막혔는지 알기 어렵다.
이 스크립트는 **각 경로를 순서대로 직접 두들겨** 결과를 그대로 보여준다.

사용:
    python scripts/diag_server_spec.py 10.0.0.5
    python scripts/diag_server_spec.py 10.0.0.5 --user administrator
      (비밀번호는 화면에 안 보이게 입력받는다 - 명령행에 쓰지 않는다)

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

# 한국어 콘솔은 cp949라 em-dash 같은 문자가 '?'로 깨진다. 여기서 출력하는 문장에는
# 다른 모듈(core/*)의 오류 메시지가 그대로 실려 오므로, 이 스크립트만 깨끗이 써서는
# 부족하다 — 출력 직전에 한 번 걸러 준다. 사용자가 이 출력을 그대로 복사해 붙인다.
_CP949_MAP = {"—": "-", "–": "-", "‘": "'", "’": "'",
              "“": '"', "”": '"', "…": "..."}


def _clean(s):
    """콘솔 인코딩에서 깨지지 않게 정리."""
    s = str(s)
    for a, b in _CP949_MAP.items():
        s = s.replace(a, b)
    enc = (getattr(sys.stdout, "encoding", None) or "utf-8")
    try:
        s.encode(enc)
    except (UnicodeEncodeError, LookupError):
        s = s.encode(enc, "replace").decode(enc, "replace")
    return s


def _p(s):
    print(_clean(s))


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


def run_diagnosis(ip, user="", community="public", password=None, emit=None):
    """진단 본체 - CLI(--diag-server)와 웹 화면 양쪽에서 부른다.

    password를 주면 물어보지 않는다(웹에서 호출할 때). emit을 주면 출력 대신
    그 함수로 한 줄씩 넘긴다 - 화면에 그대로 실어 보내기 위해서다.
    반환: 종료코드(0=사양 확보). 수집한 줄은 lines에 쌓인다.
    """
    lines = []

    def out(s):
        s = _clean(s)
        lines.append(s)
        (emit or _p)(s)

    class _Args(object):
        pass

    args = _Args()
    args.ip, args.user, args.community = ip, user, community
    args.lines = lines

    pw = password if password is not None else ""
    if args.user and password is None:
        pw = getpass.getpass("비밀번호(입력해도 화면에 안 보입니다): ")

    out("\n대상: %s" % args.ip)
    out("=" * 66)

    # 0) 포트 스캔 - 이후 모든 경로의 전제
    out("\n[0] 열린 포트")
    ports, err, dt = _t(sc.scan_ports, args.ip)
    if err:
        out(NG + "스캔 실패: %s" % err)
        return 1
    out(INFO + "%s  (%.1f초)" % (ports or "없음", dt))
    if not ports:
        out(NG + "열린 포트가 없습니다 → 도달 불가. 방화벽/전원/IP를 먼저 확인하세요.")
        return 1

    # 1) SSH
    out("\n[1] SSH")
    sshp, _, _ = _t(sc.find_ssh_port, args.ip, ports)
    if not sshp:
        out(NG + "SSH 응답 없음(배너 미확인) - 이 경로는 건너뜁니다")
    elif not args.user:
        out(INFO + "SSH 포트 %s 열림 - 계정을 안 줘서 시도 안 함(--user 로 지정)" % sshp)
    else:
        d, err, dt = _t(sc._ssh_detail_unix, args.ip, args.user, pw, port=sshp)
        if err:
            out(NG + "포트 %s 접속 실패 (%.1f초): %s" % (sshp, dt, str(err)[:140]))
            if sc._is_auth_error(err):
                out(INFO + "→ 계정 거부입니다. 그 서버의 계정인지 확인하세요"
                             "(공통 계정이 서버마다 다를 수 있습니다).")
        else:
            got = {k: d.get(k) for k in
                   ("cpu_model", "cpu_cores", "mem_total_mb", "disk_total_gb")}
            if any(got.values()):
                out(OK + "사양 수집됨: %s" % got)
                out("\n→ SSH로 되는 서버입니다. 수집이 안 됐다면 계정 저장 여부를 확인하세요.")
                return 0
            out(NG + "접속은 됐는데 사양 명령이 무응답 (%.1f초)" % dt)
            if d.get("_spec_hint"):
                out(INFO + str(d["_spec_hint"])[:160])

    # 2) WinRM / 3) DCOM
    out("\n[2-3] WinRM(5985/5986) · WMI DCOM(135)")
    trs = wmi_collect.transports_for(ports)
    if not trs:
        out(NG + "5985/5986/135 중 열린 것이 없습니다 - 이 경로는 불가")
        if 3389 in (ports or []):
            out(INFO + "RDP(3389)는 열려 있습니다. 대상 서버에서 관리자 PowerShell로")
            out(INFO + "  Enable-PSRemoting -Force")
            out(INFO + "를 실행하면 5985가 열려 사양을 읽을 수 있습니다.")
    elif not wmi_collect.available():
        out(NG + "이 PC가 Windows가 아니라 WMI 경로를 쓸 수 없습니다")
    elif not args.user:
        out(INFO + "%s - 계정을 안 줘서 시도 안 함" % [t for t, _ in trs])
    else:
        for tr, port in trs:
            r, err, dt = _t(wmi_collect.collect, args.ip, args.user, pw,
                            transport=tr, port=port)
            if err:
                out(NG + "%-5s:%-5s 실패 (%.1f초): %s" % (tr, port, dt, str(err)[:130]))
            else:
                out(OK + "%-5s:%-5s 사양 수집됨: cores=%s mem=%sMB disk=%sGB"
                      % (tr, port, r.get("cpu_cores"), r.get("mem_total_mb"),
                         r.get("disk_total_gb")))
                return 0

    # 4) SNMP
    out("\n[4] SNMP(161/UDP)  커뮤니티=%s" % args.community)
    r, err, dt = _t(snmp_collect.collect, args.ip, args.community, timeout=2.0)
    if err:
        out(NG + "실패 (%.1f초): %s" % (dt, str(err)[:150]))
    else:
        spec = {k: r.get(k) for k in ("cpu_cores", "mem_total_mb", "disk_total_gb")}
        if any(spec.values()):
            out(OK + "사양 수집됨: %s" % spec)
            return 0
        out(NG + "응답은 오는데 사양 정보가 없습니다(HOST-RESOURCES-MIB 미개방)")
        out(INFO + "→ 대상의 /etc/snmp/snmpd.conf view에 .1.3.6.1.2.1.25 추가")

    out("\n" + "=" * 66)
    out("네 경로 모두 실패했습니다. 위 사유를 그대로 알려주시면 원인을 좁힐 수 있습니다.")
    return 1


def diagnose_lines(ip, user="", password="", community="public"):
    """웹 화면용 - (종료코드, 출력줄 목록)을 돌려준다.

    CLI를 못 쓰는 환경(서비스로 상주, 콘솔 접근 불가)에서도 같은 진단을
    화면에서 볼 수 있어야 한다. 그래야 이 도구가 쓸모가 있다.
    """
    lines = []
    rc = run_diagnosis(ip, user=user, community=community,
                       password=password or "", emit=lines.append)
    return rc, lines


if __name__ == "__main__":
    sys.exit(main())
