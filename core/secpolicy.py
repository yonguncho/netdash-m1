# -*- coding: utf-8 -*-
"""전송 계층 보안 정책 — SSH 호스트키 검증, 방화벽 TLS 검증.

두 정책 모두 **켜면 지금 동작이 깨질 수 있어** 기본값은 현행 유지다.
폐쇄망 현장에서는 장비가 자체 서명 인증서를 쓰고 known_hosts도 없기 때문에,
무턱대고 엄격하게 바꾸면 수집이 전부 멈춘다. 그래서 config로 단계를 고른다.

이 모듈이 존재하는 이유가 하나 더 있다. 같은 정책이 코드 여러 곳에 흩어져
있으면 한쪽만 고쳐져 반드시 뚫린다(NetDash에서 실제로 두 번 재발했다).
정책은 여기 한 곳에만 두고, 각 호출부는 이 함수를 부른다.

  ssh_host_key_policy:
    auto   — 어떤 호스트키든 받는다(현행 기본). 기억하지 않으므로 바뀌어도 모른다.
    tofu   — 처음 본 장비는 받아 적고, **이후 키가 바뀌면 거부**한다.
             (Trust On First Use) 첫 수집을 막지 않으면서 중간자 교체를 잡는다.
    strict — known_hosts에 미리 등록된 장비만 접속한다.

  verify_firewall_tls:
    false  — 인증서를 검증하지 않는다(현행 기본). 자체 서명 장비가 대부분이라서.
    true   — 검증한다. 사설 CA를 신뢰 목록에 넣어 두지 않으면 수집이 실패한다.
"""
import os
import threading

from . import utils

_lock = threading.Lock()
_known_hosts_path = None


def _cfg():
    """설정 dict(collector 섹션). 로드 실패해도 수집을 멈추지 않는다."""
    try:
        from config import get_config
        return get_config().collector or {}
    except Exception:
        return {}


def ssh_policy_name():
    v = str(_cfg().get("ssh_host_key_policy", "auto") or "auto").strip().lower()
    return v if v in ("auto", "tofu", "strict") else "auto"


def firewall_tls_verify():
    """방화벽 HTTPS 인증서를 검증할지. 기본 False(현행 유지)."""
    return bool(_cfg().get("verify_firewall_tls", False))


def known_hosts_file():
    """호스트키를 기억할 파일 경로(DB 옆)."""
    global _known_hosts_path
    if _known_hosts_path:
        return _known_hosts_path
    try:
        from .config_loader import get_data_dir
        p = get_data_dir() / "known_hosts"
    except Exception:
        p = None
    with _lock:
        _known_hosts_path = p
    return p


def apply_host_key_policy(client):
    """paramiko SSHClient에 설정된 호스트키 정책을 건다.

    호출부가 8곳이라 각자 AutoAddPolicy를 쓰면 정책 변경이 반영되지 않는다 →
    전부 이 함수를 통하게 한다.
    """
    import paramiko
    mode = ssh_policy_name()
    if mode == "auto":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return mode

    path = known_hosts_file()
    if path:
        try:
            if os.path.exists(str(path)):
                # 기존 키를 읽어 두면, 키가 **바뀐** 경우 paramiko가 접속 전에
                # BadHostKeyException으로 막는다(중간자 교체 탐지의 핵심).
                client.load_host_keys(str(path))
        except Exception as e:
            utils.log_event("warning", "known_hosts_load_failed",
                            path=str(path), error=str(e)[:120])
    if mode == "strict":
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(_TofuPolicy(path))
    return mode


class _TofuPolicy(object):
    """처음 본 장비의 키는 받아 적고, 다음부터는 바뀌면 거부(TOFU).

    paramiko.MissingHostKeyPolicy를 상속하지 않고 duck typing으로 둔다 —
    import 시점에 paramiko를 강제하지 않기 위해서다(테스트·비 SSH 환경).
    """

    def __init__(self, path):
        self.path = path

    def missing_host_key(self, client, hostname, key):
        try:
            client.get_host_keys().add(hostname, key.get_name(), key)
            if self.path:
                client.save_host_keys(str(self.path))
            utils.log_event("info", "ssh_host_key_learned",
                            host=hostname, keytype=key.get_name())
        except Exception as e:
            # 저장에 실패해도 이번 접속은 막지 않는다 — 수집이 통째로 멈추는 것보다
            # 낫다. 다만 다음에도 '처음 본 키'로 취급되어 변경 탐지는 못 한다.
            utils.log_event("warning", "ssh_host_key_save_failed",
                            host=hostname, error=str(e)[:120])
