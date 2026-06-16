# NetDash M1 — 네트워크 현황판 코어 골격

폐쇄망(VDI/Windows) 환경에서 스위치 상태를 한 화면에 표시하는 로컬 웹 대시보드.  
M1 마일스톤: 실제 스위치 없이 **데모 모드**로 전체 UI 흐름 검증 가능.

## Features

- Flask 기반 로컬 웹 서버 (`127.0.0.1:8082`, 포트 충돌 시 자동 회피)
- SQLite 7개 테이블 자동 초기화 (`netdash.db`)
- 기본 REST API: `/api/state`, `/api/switches`, `GET /`
- `--demo` 플래그: fixtures 데이터로 가상 스위치 3대 표시 (SSH 연결 없음)
- Vanilla JS 3초 폴링 UI (외부 CDN/폰트 의존 0개)
- `threading.Lock` 동시성 보호

## Installation

Python 3.10+ 필요.

```powershell
cd C:\AI_WORKPLACE\today_product
pip install -r requirements.txt
```

## Usage

### 일반 모드

```powershell
python app.py
# → http://127.0.0.1:8082 에서 UI 확인
```

### 데모 모드 (스위치 없이 실행)

```powershell
python app.py --demo
# → http://127.0.0.1:8082 — [DEMO MODE] 배지 + 스위치 3대 표시
```

### DB 테이블 확인

```powershell
sqlite3 netdash.db ".tables"
# → arp_entries  events  hosts  mac_entries  ports  snapshots  switches
```

### API 응답 확인

```powershell
curl http://127.0.0.1:8082/api/state
curl http://127.0.0.1:8082/api/switches
```

### 단위 테스트

```powershell
python -m pytest tests/ -v
```

## License

MIT License — see LICENSE
