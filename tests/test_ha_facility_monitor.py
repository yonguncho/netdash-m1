# -*- coding: utf-8 -*-
"""HA 동일 IP 도달성 dedupe + 설비 known 호스트 자주 모니터링 + 이메일 직접 전달."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db, reachability, facility, notifier


# ── 1) 도달성 감시: 동일 IP(FW_M/FW_B) 1회만 확인, 대기측이 활성측 결과 공유 ──
def test_reachability_dedupes_shared_ip(temp_db, monkeypatch):
    fid_m = db.save_firewall(temp_db, "FW_M", "fortigate", "10.0.0.9", 443)
    fid_b = db.save_firewall(temp_db, "FW_B", "fortigate", "10.0.0.9", 443)
    calls = []

    def _fake(ip, port=22, timeout=3):
        calls.append((ip, port))
        return True     # 활성측(VIP 보유)이 응답

    monkeypatch.setattr(reachability, "_check_tcp", _fake)
    reachability._state.clear()
    reachability._fw_state.clear()
    reachability._sweep(temp_db)
    # 동일 (IP, 포트)는 한 번만 확인 → 대기측(FW_B) 오탐 없음
    assert calls.count(("10.0.0.9", 443)) == 1
    st = reachability.get_fw_state()
    assert st.get(fid_m) is True and st.get(fid_b) is True


def test_reachability_switch_and_fw_by_port(temp_db, monkeypatch):
    """스위치(22)와 방화벽(443)은 포트가 달라 각각 확인된다."""
    db.save_switch(temp_db, "SW1", "10.0.0.20", "cisco_ios")
    db.save_firewall(temp_db, "FW1", "fortigate", "10.0.0.21", 443)
    seen = []
    monkeypatch.setattr(reachability, "_check_tcp",
                        lambda ip, port=22, timeout=3: (seen.append((ip, port)), True)[1])
    reachability._state.clear()
    reachability._fw_state.clear()
    reachability._sweep(temp_db)
    assert ("10.0.0.20", 22) in seen
    assert ("10.0.0.21", 443) in seen


# ── 2) 설비 자주 모니터링: MAC 실종 연속 2회 → offline, MAC 재등장 → online ──
def test_monitor_known_hosts_offline_then_recover(temp_db, monkeypatch):
    facility._miss_counts.clear()
    db.save_facility_hosts(temp_db, [
        {"subnet": "10.7.0.0/24", "ip": "10.7.0.5", "mac": "AA:BB:CC:00:00:05",
         "switch_name": "SW", "port": "Gi1/0/5", "direct": 1, "online": 1}])
    # (a) MAC 테이블에 살아있음 → 변화 없음
    monkeypatch.setattr(db, "get_mac_to_switchport",
                        lambda dbp: {"aa:bb:cc:00:00:05": [(1, "SW", "Gi1/0/5")]})
    assert facility.monitor_known_hosts(temp_db) == (0, 0)
    # (b) MAC 실종 — 다른 장비 MAC만 존재(빈 dict면 판단 보류되므로 더미 넣음)
    monkeypatch.setattr(db, "get_mac_to_switchport",
                        lambda dbp: {"ff:ff:ff:ff:ff:ff": [(9, "OTHER", "Gi9")]})
    # 디바운스 기준은 '감시 주기 횟수'가 아니라 '서로 다른 MAC 스냅샷'이다.
    # (같은 스냅샷을 다시 본 것은 새 근거가 아니라서 조용한 설비가 오탐됐다)
    # 스위치 재수집으로 스냅샷 세대가 바뀌는 상황을 흉내낸다.
    _gen = [0]
    monkeypatch.setattr(facility, "_mac_generation", lambda dbp: (("sw", _gen[0]),))
    assert facility.monitor_known_hosts(temp_db) == (0, 0)   # 1번째 세대에서 실종 1회
    assert facility.monitor_known_hosts(temp_db) == (0, 0)   # 같은 세대 재확인 — 세지 않음
    assert facility.monitor_known_hosts(temp_db) == (0, 0)   # 몇 번을 더 봐도 그대로
    _gen[0] = 1
    assert facility.monitor_known_hosts(temp_db) == (0, 1)   # 새 세대에서도 실종 → 오프라인
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.7.0.5"]["online"] == 0
    offs = [e for e in db.list_device_events(temp_db, limit=20)
            if e["kind"] == "device_offline" and e["ip"] == "10.7.0.5"]
    assert offs and "MAC 실종" in offs[0]["message"]
    # (c) MAC 재등장 → 복구
    monkeypatch.setattr(db, "get_mac_to_switchport",
                        lambda dbp: {"aa:bb:cc:00:00:05": [(1, "SW", "Gi1/0/5")]})
    assert facility.monitor_known_hosts(temp_db) == (1, 0)
    hosts = {h["ip"]: h for h in db.get_facility_hosts(temp_db)}
    assert hosts["10.7.0.5"]["online"] == 1


def test_monitor_skips_while_scan_running(temp_db, monkeypatch):
    """대역 스캔 진행 중이면 monitor는 건너뛴다(스캔이 곧 정확히 갱신)."""
    facility._set(running=True)
    try:
        monkeypatch.setattr(db, "get_mac_to_switchport", lambda dbp: {"x": []})
        assert facility.monitor_known_hosts(temp_db) == (0, 0)
    finally:
        facility._set(running=False)


# ── 3) 이메일: SMTP 서버 미지정 시 수신 도메인으로 직접 전달 ──
def test_email_direct_delivery_when_no_host(temp_db, monkeypatch):
    db.set_setting(temp_db, "email_to", "admin@corp.local")
    db.set_setting(temp_db, "smtp_host", "")       # 릴레이 없음 → 직접 전달
    db.set_setting(temp_db, "smtp_from", "netdash@localhost")

    sent = {}

    class _FakeSMTP:
        def __init__(self, host, port, timeout=15):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def has_extn(self, name):
            return False

        def sendmail(self, frm, to, msg):
            sent["frm"] = frm
            sent["to"] = to

    monkeypatch.setattr(notifier.smtplib, "SMTP", _FakeSMTP)
    ok = notifier.send_email(temp_db, "제목", "본문")
    assert ok is True
    # 후보 메일 서버는 수신 도메인에서 유도(corp.local / mail.corp.local ...)
    assert sent["host"] in ("corp.local", "mail.corp.local", "smtp.corp.local", "mx.corp.local")
    assert sent["frm"] == "netdash@localhost"
    assert sent["to"] == ["admin@corp.local"]


def test_mx_hosts_fallback_order():
    hosts = notifier._mx_hosts("corp.local")
    assert hosts[0] == "corp.local"
    assert "mail.corp.local" in hosts and "smtp.corp.local" in hosts
