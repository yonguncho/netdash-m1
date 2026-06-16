# NetDash M2 — 온디맨드 수집·벤더 파싱·상관분석

온디맨드 네트워크 스위치 수집, 벤더별 show 명령 파싱, ARP+MAC 조인으로 호스트 위치를 자동 확정하는 폐쇄망 네이티브 솔루션입니다.

## Installation

### 시스템 요구사항
- Python 3.9+
- Windows (또는 Linux/macOS)

### 의존성 설치

```bash
pip install -r requirements.txt
```

### 데이터베이스 초기화

```bash
python -c "from core import db; from config import get_config; cfg = get_config(); db.init_schema(cfg.get_db_path())"
```

## Usage

### 1. 데모 모드 실행 (fixture 데이터)

```bash
python app.py
```

설정을 열어서 `demo_mode: true`로 확인하고, http://127.0.0.1:8082 에서 웹 UI 접근.

### 2. 실장비 수집 (SSH 접속)

```bash
# config.yaml에서 demo_mode를 false로 변경
# 스위치 정보를 미리 DB에 등록 필요

# API 호출로 수집 시작
curl -X POST http://127.0.0.1:8082/api/switches/1/collect \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"***"}'
```

### 3. 테스트 실행

```bash
pytest tests/ -v
pytest tests/ --cov=core
```

## Features

- **온디맨드 수집**: POST /api/switches/<id>/collect로 특정 스위치 1대 수집 (비동기, MAX_CONCURRENT=3)
- **벤더 파서 3종**: Cisco IOS, Arista EOS, Extreme EXOS (플러그인 구조, 새 벤더 추가 용이)
- **상관분석**: ARP+MAC 조인으로 호스트 위치(switch_id, port) 자동 확정
- **원본 보존**: 모든 show 출력을 raw_outputs/<switch>/<timestamp>/*.txt에 저장 (파서 실패 시 재분석 가능)
- **폐쇄망 네이티브**: 외부 API/CDN 호출 0, localhost:8082 전용, read-only show 명령만
- **실시간 대시보드**: Vanilla JS 3초 폴링으로 스위치 상태 갱신

## API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/state | 모든 스위치 상태 조회 |
| POST | /api/switches/<id>/collect | 특정 스위치 수집 시작 |
| GET | /api/switches/<id>/detail | 스위치 상세 (포트, MAC, ARP, 호스트 위치) |

## 설정 (config.yaml)

```yaml
app:
  demo_mode: true       # true: fixture, false: 실장비 SSH
  host: "127.0.0.1"     # localhost only
  port: 8082

collector:
  max_concurrent: 3     # 동시 워커 수
  ssh_timeout: 30       # 초
  read_timeout: 60      # 초

correlator:
  uplink_mac_threshold: 4  # ≥4개 MAC이 있는 포트 = 업링크

database:
  path: "netdash.db"
```

## 아키텍처

```
API (Flask) → Collector (큐 + 워커) → Parser (3종) → Correlator → DB
                                           ↓
                                      raw_outputs (선저장)
```

- **큐**: queue.Queue(maxsize=100)
- **워커**: 3개 스레드, threading.Lock으로 동시성 보호
- **파서**: 정규식 기반, 벤더별 독립 파일
- **상관분석**: 업링크 필터 + ARP-MAC 조인

## 테스트

```bash
# 전체 테스트
pytest tests/ -x

# 커버리지
pytest tests/ --cov=core --cov-report=html
```

- 파서 정확도: ≥95% (fixture 기준)
- 상관분석 정확도: ≥85% (호스트 위치)
- 테스트 커버리지: ≥80%

## 로깅

JSON 구조화 로깅:

```python
logger.info(json.dumps({"event": "collect_start", "switch_id": 123}))
```

- 레벨: INFO (기본)
- 포맷: JSON ({"time":"...", "level":"...", "name":"...", "msg":"..."})
- Paramiko 로그: 자동 필터링 (credentials 보호)

## 보안

- ✅ read-only show만 (설정 변경 금지)
- ✅ localhost:8082 전용 (LAN 노출 X)
- ✅ 평문 계정 메모리 전용 (M2, M6까지 DPAPI 선택)
- ✅ 외부 호출 0 (API/CDN/폰트 불사용)
- ✅ 파서 정규식 injection 검증 (OWASP A03 방지)

## M3 계획

- 스냅샷 diff 로직 (끊김 탐지)
- show logging 파싱 강화 (Flapping 탐지)
- 상태 변화 이벤트 저장

## 라이선스

MIT License — see LICENSE

## 문제 해결

**Q: 수집이 안 됩니다**
- A: config.yaml 확인, demo_mode=true일 때는 fixture 사용. SSH는 실장비 IP/계정 확인.

**Q: 파서가 실패했습니다**
- A: raw_outputs/<switch>/<timestamp>/ 에서 원본 확인, 정규식 재검토.

**Q: 호스트 위치가 확정 안 됩니다**
- A: ARP/MAC 테이블 데이터 확인, uplink_mac_threshold 조정 검토.

## 문의

GitHub Issues 또는 PR 제출
