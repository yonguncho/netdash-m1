"""성능 인덱스 + 런타임 파일 로그(서버 오류 진단) 회귀 테스트."""
import logging


def test_perf_indexes_created(tmp_path):
    """init_db가 hot 쿼리용 인덱스를 만들고, 스냅샷 MAX 쿼리가 인덱스를 탄다."""
    from core import db
    p = str(tmp_path / "t.db")
    db.init_db(p)
    with db.get_db(p) as c:
        names = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_snapshots_switch_id" in names
        assert "idx_mac_mac" in names
        assert "idx_mac_switch_port" in names
        # 거의 모든 hot 경로가 쓰는 서브쿼리가 풀스캔이 아니라 인덱스를 타야 함
        plan = " ".join(str(r[-1]) for r in c.execute(
            "EXPLAIN QUERY PLAN SELECT MAX(id) FROM snapshots GROUP BY switch_id"))
        assert "idx_snapshots_switch_id" in plan


def test_attach_file_logger(tmp_path):
    """_attach_file_logger가 DB 옆 netdash.log에 로그를 남긴다(중복 부착 방지)."""
    import app as _app
    root = logging.getLogger()
    before = list(root.handlers)
    _app._file_log_attached = False
    logpath = tmp_path / "sub" / "netdash.log"
    try:
        _app._attach_file_logger(logpath)
        logging.getLogger("core.x").warning("diag-marker")
        for h in root.handlers:
            try:
                h.flush()
            except Exception:
                pass
        assert logpath.exists()
        assert "diag-marker" in logpath.read_text(encoding="utf-8")
    finally:
        for h in list(root.handlers):
            if h not in before:
                root.removeHandler(h)
        _app._file_log_attached = False
