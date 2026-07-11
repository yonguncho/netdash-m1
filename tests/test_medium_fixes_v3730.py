# -*- coding: utf-8 -*-
"""2026-07-11 감사 medium 버그(M1~M11)의 회귀 테스트."""
import sys
import inspect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import collector, db, reachability, notifier
from core.parsers import extreme_exos


# ── M2: reachability interval NameError ──
def test_m2_interval_bound_before_try():
    """interval이 try 밖에서 먼저 바인딩되어 첫 예외에도 NameError 없음."""
    src = inspect.getsource(reachability._loop)
    # interval 초기화가 try 앞에 있어야
    body = src.split("while not _stop:", 1)[1]
    pre_try = body.split("try:", 1)[0]
    assert "interval = 60" in pre_try, "interval이 try 안에서만 초기화됨"


# ── M1: notifier 고정 60초 flush(debounce 아님) ──
def test_m1_notifier_fixed_flush():
    src = inspect.getsource(notifier._loop)
    assert "last_flush" in src, "고정 주기 flush 기준(last_flush) 없음"
    assert "monotonic" in src


# ── M3: -Main 호스트네임 Alteon 오분류 ──
def test_m3_normal_main_hostname_not_alteon():
    assert collector._prompt_looks_alteon("SW-Main#") is False
    assert collector._prompt_looks_alteon("Core-Main#") is False


def test_m3_real_alteon_still_detected():
    assert collector._prompt_looks_alteon("SKBA - Standard ADC - Main#") is True
    assert collector._prompt_looks_alteon(">> Something - Main#") is True
    assert collector._prompt_looks_alteon("Application Switch") is True


# ── M8: delete_switch 파생 데이터 정리 ──
def test_m8_delete_switch_purges_children(temp_db):
    sid = db.save_switch(temp_db, "SW1", "10.0.0.1", "cisco_ios")
    # config_backup + enable_secret 설정 생성
    db.save_config_backup(temp_db, sid, "hostname SW1\npassword secret123")
    db.set_setting(temp_db, "enable_secret_%d" % sid, "encrypted_blob")
    assert db.get_setting(temp_db, "enable_secret_%d" % sid) == "encrypted_blob"
    # 삭제
    assert db.delete_switch(temp_db, sid) is True
    # 파생 데이터가 남지 않아야 (config_backups·enable_secret 설정)
    assert db.get_setting(temp_db, "enable_secret_%d" % sid, "GONE") == "GONE"
    with db.get_db(temp_db) as conn:
        n = conn.execute("SELECT COUNT(*) FROM config_backups WHERE switch_id=?", (sid,)).fetchone()[0]
        assert n == 0, "config_backups 잔존(삭제 장비 config 다운로드 가능)"


def test_m8_purge_helper_lists_key_tables():
    assert "config_backups" in db._SWITCH_CHILD_TABLES
    assert "switch_logs" in db._SWITCH_CHILD_TABLES
    assert "neighbors" in db._SWITCH_CHILD_TABLES


# ── M10: excel_loader 표시용 컬럼 표기 보존 ──
def test_m10_display_cols_preserve_case_spaces():
    from core import excel_loader
    # _DISPLAY_COLS에 표시용 컬럼 포함
    assert "name" in excel_loader._DISPLAY_COLS
    assert "location" in excel_loader._DISPLAY_COLS
    assert "hostname" in excel_loader._DISPLAY_COLS
    # ip는 매칭용이라 제외(=_norm 적용 대상)
    assert "ip" not in excel_loader._DISPLAY_COLS


# ── M11: extreme out_errors 정상 카운터 제외 ──
def test_m11_out_errors_excludes_collisions():
    # tx: Coll=100, Late=0, Deferred=50, Errors=0, Lost=0, Parity=0 → 실오류 0
    errs = extreme_exos._parse_port_errors("", "1:1  A  100  0  50  0  0  0")
    assert errs["1:1"]["out_errors"] == 0


def test_m11_out_errors_counts_real_errors():
    # tx: Coll=0, Late=3, Deferred=0, Errors=7, Lost=2, Parity=1 → 3+7+2+1=13
    errs = extreme_exos._parse_port_errors("", "1:2  A  0  3  0  7  2  1")
    assert errs["1:2"]["out_errors"] == 13


def test_m11_rx_in_errors_excludes_lost():
    # rx: Crc=5, Over=0, Under=0, Frag=1, Jabber=0, Align=0, Lost=99(제외)
    errs = extreme_exos._parse_port_errors("1:3  A  5  0  0  1  0  0  99", "")
    assert errs["1:3"]["crc"] == 5
    assert errs["1:3"]["in_errors"] == 6  # 5+0+0+1+0+0 (Lost 제외)


# ── M9: 방화벽 동시 수집 가드(app 전역) ──
def test_m9_firewall_collect_guard_exists():
    src = (Path(__file__).parent.parent / "app.py").read_text(encoding="utf-8")
    assert "_collecting_firewalls" in src
    assert "이미 수집 중입니다" in src


# ── M5/M6/M7: UI (정적 검증) ──
def test_ui_medium_fixes_present():
    js = (Path(__file__).parent.parent / "web" / "static" / "app.js").read_text(encoding="utf-8")
    # M5: 그리드 스코프 카드 조회
    assert 'grid.querySelector(\'[id="swcard-' in js
    # M6: 백드롭 닫기 시 터미널 세션 정리
    assert "modal-terminal" in js and "closeTerminal()" in js
    # M7: 위치 필터 변경 시 선택 해제
    assert "_tblSel = {}" in js
