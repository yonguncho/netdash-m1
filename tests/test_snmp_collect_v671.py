# -*- coding: utf-8 -*-
"""SSH가 닫힌 리눅스·UNIX 서버의 사양 수집 — SNMP 경로 (v6.7.1).

사용자 보고: "사양이 수집 안 되는데, SSH 포트 미개방이거나
authentication (keyboard-interactive) failed 인 경우가 대부분이다."

Windows는 WMI(135)로 덮었지만 리눅스·UNIX는 방법이 없었다. 운영 서버는 감시용
snmpd가 이미 떠 있는 경우가 많아 HOST-RESOURCES-MIB 읽기 전용 조회로 해결한다.

이 테스트는 **실제 UDP 소켓에 뜬 가짜 SNMP 에이전트**를 상대로 돈다.
BER 인코딩/디코딩을 직접 구현했기 때문에, 픽스처로 흉내 내면 프로토콜이 틀려도
통과해 버린다(실장비에서만 실패). 그래서 진짜 소켓으로 검증한다.
"""
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, server_collector as sc, snmp_collect as sn  # noqa: E402

ROOT = Path(__file__).parent.parent

# net-snmp를 얹은 RHEL 8.6 서버의 전형적인 응답
MIB = {
    "1.3.6.1.2.1.1.1.0": b"Linux rhel86 4.18.0-372.9.1.el8.x86_64 #1 SMP x86_64",
    "1.3.6.1.2.1.1.5.0": b"rhel86.corp.local",
    # 논리 CPU 4개
    "1.3.6.1.2.1.25.3.3.1.2.196608": 1,
    "1.3.6.1.2.1.25.3.3.1.2.196609": 0,
    "1.3.6.1.2.1.25.3.3.1.2.196610": 2,
    "1.3.6.1.2.1.25.3.3.1.2.196611": 0,
    # 장치 테이블 — 3=processor
    "1.3.6.1.2.1.25.3.2.1.2.196608": "1.3.6.1.2.1.25.3.1.3",
    "1.3.6.1.2.1.25.3.2.1.2.768": "1.3.6.1.2.1.25.3.1.5",
    "1.3.6.1.2.1.25.3.2.1.3.196608": b"GenuineIntel: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz",
    "1.3.6.1.2.1.25.3.2.1.3.768": b"network interface ens192",
    # 저장소 테이블: 1=물리메모리(RAM), 2=/(디스크), 3=tmpfs(제외), 4=가상메모리
    "1.3.6.1.2.1.25.2.3.1.2.1": "1.3.6.1.2.1.25.2.1.2",
    "1.3.6.1.2.1.25.2.3.1.2.2": "1.3.6.1.2.1.25.2.1.4",
    "1.3.6.1.2.1.25.2.3.1.2.3": "1.3.6.1.2.1.25.2.1.4",
    "1.3.6.1.2.1.25.2.3.1.2.4": "1.3.6.1.2.1.25.2.1.3",
    "1.3.6.1.2.1.25.2.3.1.3.1": b"Physical memory",
    "1.3.6.1.2.1.25.2.3.1.3.2": b"/",
    "1.3.6.1.2.1.25.2.3.1.3.3": b"/dev/shm (tmpfs)",
    "1.3.6.1.2.1.25.2.3.1.3.4": b"Virtual memory",
    "1.3.6.1.2.1.25.2.3.1.4.1": 1024,
    "1.3.6.1.2.1.25.2.3.1.4.2": 4096,
    "1.3.6.1.2.1.25.2.3.1.4.3": 4096,
    "1.3.6.1.2.1.25.2.3.1.4.4": 1024,
    "1.3.6.1.2.1.25.2.3.1.5.1": 16_301_384,     # 16301384 KiB ≈ 15919 MB
    "1.3.6.1.2.1.25.2.3.1.5.2": 26_214_400,     # 4KiB * 26214400 = 100 GiB
    "1.3.6.1.2.1.25.2.3.1.5.3": 2_000_000,
    "1.3.6.1.2.1.25.2.3.1.5.4": 33_554_432,
    "1.3.6.1.2.1.25.2.3.1.6.1": 9_000_000,
    "1.3.6.1.2.1.25.2.3.1.6.2": 6_553_600,      # 25 GiB 사용
    "1.3.6.1.2.1.25.2.3.1.6.3": 0,
    "1.3.6.1.2.1.25.2.3.1.6.4": 100,
    # 인터페이스 MAC (첫 항목은 루프백이라 000000)
    "1.3.6.1.2.1.2.2.1.6.1": b"\x00\x00\x00\x00\x00\x00",
    "1.3.6.1.2.1.2.2.1.6.2": b"\x00\x50\x56\xab\x12\x34",
}


def _oid_key(o):
    return tuple(int(x) for x in o.split("."))


class FakeAgent(object):
    """진짜 UDP 소켓에 뜨는 최소 SNMPv2c 에이전트(GET/GETBULK)."""

    def __init__(self, mib=None, community=b"public", silent=False):
        self.mib = mib if mib is not None else MIB
        self.community = community
        self.silent = silent
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self):
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if self.silent:
                continue
            try:
                reply = self._handle(data)
            except Exception:
                continue
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    return

    def _handle(self, data):
        # 요청도 응답과 같은 구조라 같은 파서로 읽는다
        i = 1
        _, i = sn._read_len(data, 1)
        ln, i = sn._read_len(data, i + 1)          # version
        i += ln
        ln, j = sn._read_len(data, i + 1)          # community
        comm = data[j:j + ln]
        if comm != self.community:
            return None                            # 커뮤니티 불일치 → 무응답
        i = j + ln
        pdu_tag = data[i]
        vbs = sn._parse_varbinds(data)
        oids = [o for o, _v in vbs]
        keys = sorted(self.mib.keys(), key=_oid_key)
        out = []
        if pdu_tag == 0xA0:                        # GET
            for o in oids:
                out.append((o, self.mib.get(o)))
        else:                                      # GETBULK
            for o in oids:
                cnt = 0
                for k in keys:
                    if _oid_key(k) > _oid_key(o):
                        out.append((k, self.mib[k]))
                        cnt += 1
                        if cnt >= 20:
                            break
        return self._encode(out)

    @staticmethod
    def _encode(pairs):
        body = b""
        for oid, val in pairs:
            if val is None:
                v = sn._tlv(0x81, b"")             # noSuchInstance
            elif isinstance(val, bool):
                v = sn._enc_int(int(val))
            elif isinstance(val, int):
                v = sn._enc_int(val)
            elif isinstance(val, bytes):
                v = sn._tlv(0x04, val)
            else:
                v = sn._enc_oid(val)
            body += sn._tlv(0x30, sn._enc_oid(oid) + v)
        pdu = sn._tlv(0xA2, sn._enc_int(1) + sn._enc_int(0) + sn._enc_int(0)
                      + sn._tlv(0x30, body))
        return sn._tlv(0x30, sn._enc_int(1) + sn._tlv(0x04, b"public") + pdu)

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def agent(monkeypatch):
    a = FakeAgent()
    monkeypatch.setattr(sn, "SNMP_PORT", a.port)
    yield a
    a.close()


# ── BER 인코딩 ──────────────────────────────────────────────────
def test_oid_encoding_handles_large_arcs():
    """25.3.3.1.2.196608 처럼 127을 넘는 arc가 흔하다."""
    enc = sn._enc_oid("1.3.6.1.2.1.25.3.3.1.2.196608")
    assert sn._dec_oid(enc[2:]) == "1.3.6.1.2.1.25.3.3.1.2.196608"


def test_length_encoding_multibyte():
    assert sn._enc_len(5) == b"\x05"
    assert sn._enc_len(200) == b"\x81\xc8"
    assert sn._enc_len(400) == b"\x82\x01\x90"


def test_integer_encoding_roundtrip():
    for v in (0, 1, 127, 128, 255, 65535, 16301384, -1, -200):
        enc = sn._enc_int(v)
        assert sn._dec_int(enc[2:]) == v, v


# ── 실제 소켓 대화 ──────────────────────────────────────────────
def test_collect_reads_specs_over_real_socket(agent):
    got = sn.collect("127.0.0.1", "public", timeout=2.0)
    assert got["hostname"] == "rhel86"
    assert "Linux rhel86" in got["os_info"]
    assert got["cpu_cores"] == 4, "hrProcessorLoad 엔트리 수 = 논리 CPU 수"
    assert got["cpu_model"].startswith("Intel(R) Xeon(R) Gold 6248")
    assert got["mem_total_mb"] == 15919, got["mem_total_mb"]
    assert got["disk_total_gb"] == 100.0, got["disk_total_gb"]
    assert got["disk_used_gb"] == 25.0, got["disk_used_gb"]
    assert got["mac"] == "00:50:56:AB:12:34"


def test_tmpfs_excluded_from_disk_total(agent):
    """tmpfs를 더하면 디스크 용량이 실제보다 커진다."""
    assert sn.collect("127.0.0.1", "public", timeout=2.0)["disk_total_gb"] == 100.0


def test_virtual_memory_not_counted_as_ram(agent):
    """가상 메모리(스왑)를 물리 메모리로 세면 안 된다."""
    assert sn.collect("127.0.0.1", "public", timeout=2.0)["mem_total_mb"] == 15919


def test_wrong_community_fails_fast(agent):
    """커뮤니티가 틀리면 에이전트는 무응답 — 오래 매달리지 않아야 한다."""
    with pytest.raises(Exception):
        sn.collect("127.0.0.1", "wrong-community", timeout=0.4)


def test_no_agent_raises_timeout(monkeypatch):
    a = FakeAgent(silent=True)
    monkeypatch.setattr(sn, "SNMP_PORT", a.port)
    try:
        with pytest.raises(Exception):
            sn.collect("127.0.0.1", "public", timeout=0.4)
    finally:
        a.close()


# ── 수집 경로 통합 ──────────────────────────────────────────────
def _stub(monkeypatch, ports):
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: list(ports))
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: None)


def test_snmp_fills_specs_when_ssh_closed(temp_db, monkeypatch, agent):
    """SSH가 닫힌 리눅스 서버(443만 열림)에서도 사양이 채워져야 한다."""
    _stub(monkeypatch, [443])
    sid = db.save_server(temp_db, "RHEL", "127.0.0.1")
    sc.collect_server(temp_db, sid, "svc", "pw")
    row = db.get_server(temp_db, sid)
    assert row["cpu_cores"] == 4 and row["mem_total_mb"] == 15919
    assert row["disk_total_gb"] == 100.0
    assert row["os_type"] == "linux"


def test_snmp_works_without_credentials(temp_db, monkeypatch, agent):
    """계정이 없어도 SNMP는 동작한다 — 계정 없는 서버가 실제로 많다."""
    _stub(monkeypatch, [443])
    sid = db.save_server(temp_db, "SRV", "127.0.0.1")
    sc.collect_server(temp_db, sid, None, None)
    assert db.get_server(temp_db, sid)["cpu_cores"] == 4


def test_solved_ssh_reason_is_cleared(temp_db, monkeypatch, agent):
    """SNMP로 사양을 얻었으면 'SSH 못 찾음' 사유를 계속 보여주면 안 된다."""
    _stub(monkeypatch, [443])
    sid = db.save_server(temp_db, "SRV", "127.0.0.1")
    sc.collect_server(temp_db, sid, "svc", "pw")
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "SSH" not in err and "계정 없음" not in err, err


def test_snmp_skipped_when_ssh_already_got_specs(temp_db, monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: [22])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sc, "find_ssh_port", lambda ip, p, probe=True: 22)
    monkeypatch.setattr(sc, "detect_os", lambda ip, u, p, port=22: "linux")
    monkeypatch.setattr(sc, "_ssh_detail_unix", lambda ip, u, pw, port=22: {
        "hostname": "h", "os_info": "Linux", "cpu_model": "Xeon", "cpu_cores": 8,
        "mem_total_mb": 16000, "disk_total_gb": 50.0})
    monkeypatch.setattr(sn, "collect",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    sid = db.save_server(temp_db, "SRV", "10.9.9.1")
    sc.collect_server(temp_db, sid, "svc", "pw")
    assert called["n"] == 0, "SSH로 이미 사양을 얻었는데 SNMP를 또 호출했다"


def test_snmp_can_be_disabled(temp_db, monkeypatch):
    called = {"n": 0}
    _stub(monkeypatch, [443])
    db.set_setting(temp_db, "snmp_enabled", "0")
    monkeypatch.setattr(sn, "collect",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    sid = db.save_server(temp_db, "SRV", "10.9.9.2")
    sc.collect_server(temp_db, sid, "svc", "pw")
    assert called["n"] == 0


def test_no_reply_leaves_actionable_message(temp_db, monkeypatch):
    _stub(monkeypatch, [443])
    a = FakeAgent(silent=True)
    monkeypatch.setattr(sn, "SNMP_PORT", a.port)
    try:
        sid = db.save_server(temp_db, "SRV", "127.0.0.1")
        sc.collect_server(temp_db, sid, None, None)
        err = db.get_server(temp_db, sid).get("last_error") or ""
        # 응답이 아예 없으면 원인이 둘(방화벽 차단·커뮤니티 불일치)이라 둘 다 알린다.
        assert "SNMP" in err and "커뮤니티" in err and "차단" in err, err
    finally:
        a.close()


# ── 설정 ────────────────────────────────────────────────────────
def test_community_defaults_to_public(temp_db):
    assert sc.snmp_community(temp_db) == "public"
    assert sc.snmp_enabled(temp_db) is True


def test_community_is_stored_encrypted(temp_db):
    from core import credentials
    blob = credentials.encrypt_text("s3cret-comm")
    if not blob:
        pytest.skip("이 환경에서 암호화 불가")
    db.set_setting(temp_db, "snmp_community_blob", blob)
    assert "s3cret-comm" not in blob, "커뮤니티가 평문으로 저장됐다"
    assert sc.snmp_community(temp_db) == "s3cret-comm"


def test_settings_api_does_not_leak_community():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index('"snmp_has_community"')
    assert '"snmp_community"' not in src[i - 400:i], "커뮤니티 값을 화면에 내려주면 안 된다"


def test_empty_community_keeps_stored_value():
    """다른 설정을 저장할 때마다 커뮤니티가 지워지면 안 된다."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    i = src.index('comm = data.get("snmp_community")')
    assert 'if isinstance(comm, str) and comm.strip():' in src[i:i + 200]
    assert 'set_setting(db_path, "snmp_community_blob", "")' not in src


def test_read_only_no_set_pdu():
    """SET(0xA3)을 보내는 코드가 있으면 안 된다 — 읽기 전용 조회다."""
    src = (ROOT / "core" / "snmp_collect.py").read_text(encoding="utf-8")
    assert "0xA3" not in src


def test_snmp_not_tried_when_unreachable(temp_db, monkeypatch):
    """열린 포트가 하나도 없는 서버에 SNMP를 시도하면 안 된다.

    진짜 사유('도달 불가')를 'SNMP 무응답'으로 덮어쓰고, 서버마다 몇 초씩
    헛되이 기다린다.
    """
    called = {"n": 0}
    monkeypatch.setattr(sc, "scan_ports", lambda ip, *a, **k: [])
    monkeypatch.setattr(sc, "reverse_dns", lambda ip: None)
    monkeypatch.setattr(sc, "netbios_name", lambda ip: None)
    monkeypatch.setattr(sn, "collect",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    sid = db.save_server(temp_db, "DEAD", "10.9.9.9")
    sc.collect_server(temp_db, sid, None, None)
    row = db.get_server(temp_db, sid)
    assert called["n"] == 0
    assert row["status"] == "failed"
    assert "도달 불가" in (row.get("last_error") or ""), row.get("last_error")


# ── 무응답의 원인 구분 ──────────────────────────────────────────
def test_closed_port_distinguished_from_blocked():
    """161을 아무도 안 들으면 ICMP가 돌아온다 — 커뮤니티 문제와 조치가 다르다.

    Windows는 이때 recvfrom에서 ConnectionResetError(10054)를 낸다.
    이걸 타임아웃과 뭉뚱그리면 '커뮤니티 확인'만 안내하게 되는데,
    snmpd가 아예 없는 서버에서는 커뮤니티를 백날 바꿔도 안 된다.
    """
    s = sn._Session("127.0.0.1", "public", timeout=1.0)
    with pytest.raises(sn.SnmpClosed) as e:
        s.get([sn._SYS_DESCR])          # 아무도 안 듣는 포트
    assert "snmpd" in str(e.value)


def test_closed_port_does_not_retry(monkeypatch):
    """재시도해도 결과가 같다 — 서버마다 몇 초씩 낭비하면 안 된다."""
    sent = {"n": 0}
    real = socket.socket

    class _S:
        def __init__(self, *a, **k):
            self._s = real(*a, **k)

        def settimeout(self, t):
            pass

        def sendto(self, *a):
            sent["n"] += 1

        def recvfrom(self, n):
            raise ConnectionResetError(10054, "reset")

        def close(self):
            self._s.close()

    monkeypatch.setattr(socket, "socket", _S)
    with pytest.raises(sn.SnmpClosed):
        sn._Session("10.0.0.1", "public", timeout=1.0, retries=2).get([sn._SYS_DESCR])
    assert sent["n"] == 1, "닫힌 포트에 재시도했다"


def test_silent_agent_reports_both_causes(monkeypatch):
    a = FakeAgent(silent=True)
    monkeypatch.setattr(sn, "SNMP_PORT", a.port)
    try:
        with pytest.raises(sn.SnmpSilent) as e:
            sn.collect("127.0.0.1", "public", timeout=0.4)
        assert "커뮤니티" in str(e.value) and "차단" in str(e.value)
    finally:
        a.close()


def test_collector_messages_differ_by_cause(temp_db, monkeypatch):
    _stub(monkeypatch, [443])

    def closed(*a, **k):
        raise sn.SnmpClosed("161/UDP에서 응답할 프로세스가 없습니다 — snmpd 없음")

    monkeypatch.setattr(sn, "collect", closed)
    sid = db.save_server(temp_db, "NOSNMPD", "10.9.9.20")
    sc.collect_server(temp_db, sid, None, None)
    err = db.get_server(temp_db, sid).get("last_error") or ""
    assert "snmpd가 떠 있지 않" in err, err
    assert "커뮤니티" not in err, "조치와 무관한 안내를 섞으면 안 된다: %s" % err
