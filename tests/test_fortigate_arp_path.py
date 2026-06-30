"""FortiGate ARP monitor 경로 폴백 테스트 (버전별 경로 차이 대응)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.firewall import fortigate


class _FakeResp:
    def __init__(self, status, data=None):
        self.status_code = status
        self._d = data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"HTTP {self.status_code}")

    def json(self):
        return self._d


def test_arp_path_priority():
    # network/arp(7.x)를 router/arp보다 먼저 시도
    assert fortigate._ARP_PATHS[0] == "/api/v2/monitor/network/arp"
    assert "/api/v2/monitor/router/arp" in fortigate._ARP_PATHS


def test_arp_falls_back_to_network_path(monkeypatch):
    """router/arp가 404여도 network/arp로 수집 성공."""
    calls = []

    class FakeSession:
        def get(self, url, timeout=None):
            calls.append(url)
            if url.endswith("/network/arp"):
                return _FakeResp(200, {"results": [
                    {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "port1"}]})
            return _FakeResp(404)

    monkeypatch.setattr(fortigate, "_make_session",
                        lambda *a, **k: (FakeSession(), "https://h:443"))
    entries = fortigate.get_arp_table("h", token="t")
    assert len(entries) == 1
    assert entries[0]["ip"] == "10.0.0.1"
    assert any("network/arp" in c for c in calls)


def test_arp_all_paths_404_returns_empty(monkeypatch):
    """모든 ARP 경로가 404면 예외 없이 빈 리스트(수집 전체 실패 방지)."""
    class FakeSession:
        def get(self, url, timeout=None):
            return _FakeResp(404)

    monkeypatch.setattr(fortigate, "_make_session",
                        lambda *a, **k: (FakeSession(), "https://h:443"))
    assert fortigate.get_arp_table("h", token="t") == []
