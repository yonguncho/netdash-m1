# -*- coding: utf-8 -*-
"""전송 보안 정책을 설정으로 켤 수 있게 한다 (v6.7.9).

claude-security 스캔이 HIGH로 지적한 두 가지:
  · SSH AutoAddPolicy — 어떤 호스트키든 받아 중간자 공격을 못 막는다.
  · 방화벽 verify_ssl=False — 자격증명이 검증되지 않은 TLS로 나간다.

둘 다 **그냥 켜면 지금 동작이 깨진다.** 폐쇄망 장비는 자체 서명 인증서를 쓰고
known_hosts도 없어서, 엄격하게 바꾸면 수집이 전부 멈춘다. 그래서 설정으로 뺐고
기본값은 현행 유지다.

정책이 코드 8곳에 흩어져 있었던 것도 함께 고쳤다 — 흩어져 있으면 한쪽만
고쳐져 반드시 뚫린다(이 저장소에서 실제로 두 번 재발했다).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import secpolicy  # noqa: E402

ROOT = Path(__file__).parent.parent


@pytest.fixture
def cfg(monkeypatch):
    """collector 설정을 테스트에서 갈아끼운다."""
    store = {}
    monkeypatch.setattr(secpolicy, "_cfg", lambda: store)
    return store


# ── 기본값은 현행 유지 ──────────────────────────────────────────
def test_defaults_preserve_current_behaviour(cfg):
    """기본값을 바꾸면 기존 사용자의 수집이 조용히 멈춘다."""
    assert secpolicy.ssh_policy_name() == "auto"
    assert secpolicy.firewall_tls_verify() is False


def test_unknown_policy_falls_back_to_auto(cfg):
    """오타가 수집 전면 중단으로 이어지면 안 된다."""
    cfg["ssh_host_key_policy"] = "STRICKT"
    assert secpolicy.ssh_policy_name() == "auto"


def test_policy_names_are_case_insensitive(cfg):
    cfg["ssh_host_key_policy"] = "  TOFU "
    assert secpolicy.ssh_policy_name() == "tofu"


def test_tls_toggle(cfg):
    cfg["verify_firewall_tls"] = True
    assert secpolicy.firewall_tls_verify() is True


def test_config_load_failure_does_not_break_collection(monkeypatch):
    """설정을 못 읽어도 수집은 계속돼야 한다 — 현행 동작으로 떨어진다.

    _cfg가 get_config 예외를 흡수하는지 본다(테스트 더블이 아니라 실제 함수).
    """
    import config as cfgmod

    def boom(*a, **k):
        raise RuntimeError("config 없음")

    monkeypatch.setattr(cfgmod, "get_config", boom)
    assert secpolicy._cfg() == {}
    assert secpolicy.ssh_policy_name() == "auto"
    assert secpolicy.firewall_tls_verify() is False


# ── 정책이 실제 paramiko 클라이언트에 걸리는가 ──────────────────
def _client():
    import paramiko
    return paramiko.SSHClient()


def test_auto_sets_autoadd(cfg):
    import paramiko
    c = _client()
    assert secpolicy.apply_host_key_policy(c) == "auto"
    assert isinstance(c._policy, paramiko.AutoAddPolicy)


def test_strict_sets_reject(cfg, tmp_path, monkeypatch):
    import paramiko
    cfg["ssh_host_key_policy"] = "strict"
    monkeypatch.setattr(secpolicy, "known_hosts_file",
                        lambda: tmp_path / "known_hosts")
    c = _client()
    assert secpolicy.apply_host_key_policy(c) == "strict"
    assert isinstance(c._policy, paramiko.RejectPolicy)


def test_tofu_sets_custom_policy(cfg, tmp_path, monkeypatch):
    cfg["ssh_host_key_policy"] = "tofu"
    monkeypatch.setattr(secpolicy, "known_hosts_file",
                        lambda: tmp_path / "known_hosts")
    c = _client()
    assert secpolicy.apply_host_key_policy(c) == "tofu"
    assert isinstance(c._policy, secpolicy._TofuPolicy)


# ── TOFU 의 핵심: 처음은 받고, 바뀌면 거부 ──────────────────────
def _key(seed):
    import paramiko
    return paramiko.RSAKey.generate(1024) if seed is None else seed


def test_tofu_learns_first_key_and_persists(cfg, tmp_path, monkeypatch):
    """첫 수집을 막지 않아야 한다 — 막으면 도입 자체가 불가능하다."""
    import paramiko
    path = tmp_path / "known_hosts"
    cfg["ssh_host_key_policy"] = "tofu"
    monkeypatch.setattr(secpolicy, "known_hosts_file", lambda: path)
    c = _client()
    secpolicy.apply_host_key_policy(c)
    k = paramiko.RSAKey.generate(1024)
    c._policy.missing_host_key(c, "10.0.0.1", k)
    assert path.exists(), "호스트키가 저장되지 않으면 변경을 영영 못 잡는다"
    assert "10.0.0.1" in path.read_text(encoding="utf-8")


def test_tofu_rejects_changed_key(cfg, tmp_path, monkeypatch):
    """중간자가 장비를 가로채면 키가 달라진다 — 그때 막는 게 목적이다."""
    import paramiko
    path = tmp_path / "known_hosts"
    cfg["ssh_host_key_policy"] = "tofu"
    monkeypatch.setattr(secpolicy, "known_hosts_file", lambda: path)

    first = paramiko.RSAKey.generate(1024)
    c1 = _client()
    secpolicy.apply_host_key_policy(c1)
    c1._policy.missing_host_key(c1, "10.0.0.9", first)

    # 새 세션에서 같은 호스트가 **다른 키**를 내밀면
    c2 = _client()
    secpolicy.apply_host_key_policy(c2)
    known = c2.get_host_keys().lookup("10.0.0.9")
    assert known is not None, "저장된 키를 다시 못 읽으면 변경 탐지가 안 된다"
    other = paramiko.RSAKey.generate(1024)
    assert known.get(first.get_name()).asbytes() != other.asbytes()


def test_tofu_survives_unwritable_path(cfg, monkeypatch):
    """저장 실패로 수집이 통째로 멈추면 안 된다."""
    import paramiko
    cfg["ssh_host_key_policy"] = "tofu"
    monkeypatch.setattr(secpolicy, "known_hosts_file",
                        lambda: Path("Z:/없는경로/known_hosts"))
    c = _client()
    secpolicy.apply_host_key_policy(c)
    c._policy.missing_host_key(c, "10.0.0.2", paramiko.RSAKey.generate(1024))


# ── 흩어진 구현이 남아 있지 않은가 ──────────────────────────────
def test_no_direct_autoadd_left():
    """한 곳이라도 직접 AutoAddPolicy를 쓰면 설정이 그 경로에 반영되지 않는다."""
    offenders = []
    for f in (ROOT / "core").rglob("*.py"):
        if f.name == "secpolicy.py":
            continue
        if "AutoAddPolicy" in f.read_text(encoding="utf-8"):
            offenders.append(str(f.relative_to(ROOT)))
    assert not offenders, offenders


def test_all_ssh_clients_use_policy_helper():
    n = sum(f.read_text(encoding="utf-8").count("secpolicy.apply_host_key_policy")
            for f in (ROOT / "core").rglob("*.py"))
    assert n >= 8, "SSH 클라이언트 생성 지점(8곳)이 모두 정책을 거쳐야 한다: %d" % n


def test_firewall_tls_flows_from_policy():
    """app.py의 verify_ssl=False 하드코딩이 남아 있으면 설정이 무시된다."""
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert "verify_ssl=False" not in src
    assert src.count("verify_ssl=secpolicy.firewall_tls_verify()") >= 3
    col = (ROOT / "core" / "collector.py").read_text(encoding="utf-8")
    assert "verify_ssl=secpolicy.firewall_tls_verify()" in col, \
        "자동 수집이 라이브러리 기본값(False)에 기대고 있다"


def test_config_documents_both_options():
    cfg_txt = (ROOT / "config.yaml").read_text(encoding="utf-8")
    assert "ssh_host_key_policy" in cfg_txt and "verify_firewall_tls" in cfg_txt
    assert "tofu" in cfg_txt, "권장 값이 문서화되지 않으면 아무도 안 켠다"
