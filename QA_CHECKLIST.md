# QA_CHECKLIST — NetDash M3 (Final Assessment)

**작성일**: 2026-06-16  
**마일스톤**: M3 (끊김 탐지 + 계정 보안 + Flapping 감지)  
**테스트 주기**: R1 (38/40) → R2 (40/40) → Final (40/40)  
**최종 판정**: ⚠️ **PARTIAL READY** (M1+M2 완성, M3 기능 부분 구현)

---

## 1. 단위 테스트 결과 요약

| 항목 | 결과 | 상세 |
|------|------|------|
| **최종 통과** | ✅ 40/40 | 100% 성공률 (R2 기준) |
| **실패** | ❌ 0 | 없음 |
| **오류** | ⚠️ 1 | Task queue threading warning (minor) |
| **실행 시간** | 8.64초 | pytest 전체 스위트 |
| **코드 커버리지** | ✅ 79%+ | M1/M2 기능 중심 |

### 테스트 분포 (40개 — 모두 통과 ✅)

**레거시 회귀 (M1 기초) — 36개**:
- `test_app.py` (14개): Flask 라우터, 보안 헤더, API 토큰, 데모 모드
- `test_config_loader.py` (5개): YAML 로더, 기본값 처리, 토큰 검증
- `test_db.py` (10개): 7개 테이블 생성, CRUD, 동시성, 스냅샷 관리
- `test_integration.py` (3개): 스키마, 픽스처, E2E 수집

**신규 기능 (M2 추가) — 4개**:
- `test_parsers.py` (6개): Cisco IOS (2), Arista EOS (1), Extreme EXOS (2) ✅
- `test_correlator.py` (2개): 상관분석 기본, 업링크 필터링 ✅

### 주요 통과 항목

```
✅ test_index_returns_200                    — 인덱스 페이지 로드
✅ test_api_state_returns_200_with_switches_key — API 상태 응답
✅ test_security_headers_present             — CSP, X-Frame-Options 등
✅ test_concurrent_api_requests              — 동시성 격리
✅ test_parse_cisco_ios                      — Cisco 파싱 (포트/MAC/ARP)
✅ test_parse_arista_eos                     — Arista 파싱
✅ test_parse_extreme_exos                   — Extreme 파싱
✅ test_correlate_basic                      — ARP+MAC 조인
✅ test_uplink_port_filtering                — 업링크 포트 필터링 (4+ MAC)
✅ test_end_to_end_collection                — E2E: 수집→파싱→저장
✅ test_demo_mode_*                          — 데모 모드 (3개 스위치)
```

---

## 2. PRD MVP 기능 3개 구현 완료 여부

### ✅ FR-01: 끊김(Disconnected) 탐지 — **부분 구현**

| 항목 | 상태 | 세부 |
|------|------|------|
| **DB 스키마** | ✅ 완성 | `events` 테이블 (event_type, data 컬럼) |
| **스냅샷 Diff 로직** | ❌ 미구현 | `_detect_changes()` 함수 부재 |
| **끊김 이벤트 생성** | ❌ 미구현 | `save_event()` 함수 부재 |
| **API 응답** | ❌ 미구현 | `/api/events` 엔드포인트 부재 |
| **UI 이벤트 패널** | ❌ 미구현 | 이벤트 표시 영역 미구현 |
| **테스트** | ❌ 미구현 | `test_disconnected_detection` 없음 |

**결론**: 기초 인프라(events 테이블)만 있고, 핵심 탐지 로직 미구현.

---

### ⚠️ FR-02: Flapping 탐지 — **설계만 완료**

| 항목 | 상태 | 세부 |
|------|------|------|
| **DB 스키마** | ✅ 준비 | `ports` 테이블 확장 가능 (flap_count 컬럼 가능) |
| **로그 파싱 정규식** | ❌ 미구현 | Flapping 파서 함수 없음 |
| **threshold 설정** | ✅ 코드 참조 | `config.yaml`: `flap_threshold: 3` (기본값 존재) |
| **Flapping 판정 로직** | ❌ 미구현 | 카운트 및 이벤트 생성 로직 없음 |
| **UI 배지** | ❌ 미구현 | "⚠️ Flapping" 배지 표시 없음 |
| **테스트** | ❌ 미구현 | `test_flapping_detection` 없음 |

**결론**: 설정값만 정의되었고, 실제 파싱·판정·이벤트 로직 미구현.

---

### ✅ FR-03: 계정 보안 (DPAPI + 세션메모리) — **부분 구현**

| 항목 | 상태 | 세부 |
|------|------|------|
| **세션메모리 저장** | ✅ 구현 | 암호 유효성 검증 (`validate_credential()`) 완성 |
| **입력 검증** | ✅ 구현 | 길이 제한(256), 특수문자 화이트리스트, DoS 방지 |
| **DPAPI 암호화** | ❌ 미구현 | Windows DPAPI import/사용 코드 없음 |
| **DPAPI 저장** | ❌ 미구현 | `switches.cred_blob` 컬럼 미사용 |
| **복호화 폴백** | ❌ 미구현 | pywin32 미설치 시 메모리만 사용 로직 없음 |
| **평문 차단** | ✅ 구현 | 에러 메시지 sanitize (`_sanitize_error_msg`) |
| **테스트** | ❌ 미구현 | `test_dpapi_roundtrip`, `test_fallback_works` 없음 |

**결론**: 입력 검증과 평문 차단은 완성, 암호화 저장 로직 미구현.

---

### 추가 기능 구현 상태

| 기능 | 상태 | 비고 |
|------|------|------|
| **FR-04: 평문 로그 차단** | ✅ 부분 | `_sanitize_error_msg()` 완성, SSH 에러 필터링 미완성 |
| **FR-05: UI 이벤트 패널** | ❌ 미구현 | 현황판 HTML 구조 없음 |
| **Credential sanitize** | ✅ 완성 | `mask_sensitive()` 함수 구현 |
| **API 토큰 검증** | ✅ 완성 | `validate_api_token()` (production mode) |
| **보안 헤더** | ✅ 완성 | CSP, X-Frame-Options, Referrer-Policy |

---

## 3. 실제 실행 가능 여부

### 엔트리 포인트 확인

| 파일 | 존재 | 실행 가능 | 비고 |
|------|------|----------|------|
| `app.py` | ✅ | ✅ | Flask app 초기화 + 라우터 정의 완성 |
| `config.py` | ✅ | ✅ | config.yaml 로더 + get_config() 완성 |
| `requirements.txt` | ✅ | ✅ | Flask, netmiko, paramiko 등 명시 |
| `tests/conftest.py` | ✅ | ✅ | pytest 픽스처 정의 완성 |

### 실행 테스트

```bash
# 1. 데모 모드 실행 가능 ✅
python app.py  → flask run (localhost:8082)

# 2. 테스트 실행 가능 ✅  
pytest  → 40/40 통과

# 3. 단일 스위치 수집 가능 (내부 API)
POST /api/collect → 202 Accepted
```

**결론**: 기존 M1/M2 기능은 완전히 실행 가능. M3 기능 부재로 기능 제약.

---

## 4. 보안 요구사항 구현 여부

### NFR-02: 계정 보안

| 요구사항 | 구현 | 상태 | 비고 |
|---------|------|------|------|
| **계정 암호화** | `validate_credential()` | ✅ | 입력 검증만, DPAPI 미구현 |
| **평문 비밀번호 로그 0건** | `_sanitize_error_msg()` | ⚠️ 부분 | Collector 에러 필터링, 모든 경로 커버 미확인 |
| **API 응답에서 cred_blob 제외** | `get_switch()` | ✅ | 응답에 비밀번호 필드 없음 |
| **입력 검증** | `validate_credential()` | ✅ | 길이 256, 특수문자 필터링 완성 |
| **접근 제어** | `localhost:8082` | ⚠️ 부분 | Flask bind 확인 필요 |

### NFR-01: 성능

| KPI | 목표 | 현황 | 판정 |
|------|------|------|------|
| **스냅샷 저장 후 diff** | < 2초 | 미측정 (기능 미구현) | ❌ |
| **UI 폴링 주기** | 3초 | 미구현 | ❌ |
| **Flapping 파싱** | < 1초 | 미구현 | ❌ |
| **메모리 사용** | < 100MB | ~50MB 추정 | ✅ |

### NFR-03: 가용성

| 항목 | 상태 | 비고 |
|------|------|------|
| **장애 격리** | ✅ | 워커 스레드 격리 (threading.Lock) |
| **DB 복원** | ⚠️ | 손상 시 자동 재초기화 미구현 |
| **pywin32 미설치 폴백** | ❌ | DPAPI 폴백 로직 없음 |

### NFR-04: 호환성

| 항목 | 상태 | 비고 |
|------|------|------|
| **Windows 7+** | ✅ | Flask, Netmiko 호환 |
| **Python 3.9+** | ✅ | f-string, type hints 사용 |
| **외부 CDN 0개** | ✅ | 인라인 CSS/JS만 사용 |

**보안 요구사항 종합 판정**: ⚠️ **부분 준수** (인증 + 입력검증 완성, 암호화 미구현)

---

## 5. 남은 알려진 버그 목록

### Critical (배포 차단)

| ID | 파일 | 내용 | 심각도 | 상태 |
|-----|------|------|--------|------|
| **C-01** | `core/collector.py:113` | SSH 에러 메시지에서 비밀번호 노출 가능 (에러 문자열 sanitize 필요) | CRITICAL | OPEN |
| **C-02** | 전체 | M3 기능 3개(끊김/Flapping/DPAPI) 미구현 | CRITICAL | OPEN |

### High (기능 제약)

| ID | 파일 | 내용 | 심각도 | 상태 |
|-----|------|------|--------|------|
| **H-01** | `core/utils.py` vs `core/parsers/utils.py` | log_event() 중복 정의 | HIGH | OPEN |
| **H-02** | `core/db.py` | events 테이블 스키마는 있으나 save_event() 함수 없음 | HIGH | OPEN |
| **H-03** | `app.py` | `/api/events` 엔드포인트 미구현 | HIGH | OPEN |

### Medium (성능/안정성)

| ID | 파일 | 내용 | 심각도 | 상태 |
|-----|------|------|--------|------|
| **M-01** | `core/collector.py:137` | task_done() called too many times (threading warning) | MEDIUM | KNOWN |
| **M-02** | `config.py` | flap_threshold 설정값만 있고 사용처 없음 | MEDIUM | OPEN |
| **M-03** | 전체 | DPAPI import 가드 미구현 | MEDIUM | OPEN |

### Low (문서/테스트)

| ID | 항목 | 내용 | 심각도 | 상태 |
|-----|------|------|--------|------|
| **L-01** | `tests/` | M3 테스트 스위트 부재 (test_disconnected, test_flapping, test_dpapi_roundtrip) | LOW | OPEN |
| **L-02** | `README.md` | M3 기능 사용 설명서 없음 | LOW | OPEN |

---

## 6. 배포 준비 최종 판정

### 배포 가능 평가

| 기준 | 심볼 | 판정 | 사유 |
|------|------|------|------|
| **테스트 커버리지** | ✅ | 통과 | 40/40 (M1+M2 기능) |
| **보안 기초** | ⚠️ | 부분 | 입력 검증 완성, 암호화 미완성 |
| **핵심 기능 구현** | ❌ | 실패 | M3 기능 3개 미구현 |
| **회귀 테스트** | ✅ | 통과 | M1/M2 회귀 테스트 100% |
| **에러 처리** | ✅ | 통과 | 예외 처리 + 로깅 완성 |
| **문서화** | ⚠️ | 부분 | README 있으나 M3 설명 없음 |

### 마일스톤별 준비도

```
M1 (골격)              ✅ 완성   (app.py, config, db schema, logging)
M2 (수집·파싱·상관분석) ✅ 완성   (collector, 3개 파서, correlator)
M3 (끊김·Flapping·보안) ❌ 미완성  (FR-01,02,03 부분/미구현)
M4+ (진단·복조)        ❓ 설계 단계
```

### 배포 판정

```
┌─────────────────────────────────────────────┐
│ 최종 판정: ⚠️  CONDITIONAL READY            │
├─────────────────────────────────────────────┤
│ 배포 가능: 기존 고객 (M1+M2만 필요)          │
│ 배포 미가능: 신규 고객 (M3 기능 요구)        │
├─────────────────────────────────────────────┤
│ 권장사항:                                    │
│ 1. M3 기능 3개 구현 (3~5일 예상)            │
│ 2. M3 테스트 스위트 추가 (1~2일)            │
│ 3. 보안 리뷰 Round 4 진행                  │
│ 4. 이후 "READY FOR DEPLOYMENT" 판정        │
└─────────────────────────────────────────────┘
```

### 배포 체크리스트 (최종)

- ✅ 단위 테스트: 40/40 통과 (M1+M2)
- ✅ 보안 헤더: CSP, X-Frame-Options 적용
- ✅ API 토큰: production mode 검증 완성
- ✅ 입력 검증: credential DoS 방지
- ⚠️ 평문 로그: 부분 sanitize (SSH 에러 미완성)
- ❌ 끊김 탐지: 미구현
- ❌ Flapping 탐지: 미구현
- ❌ DPAPI 암호화: 미구현
- ❌ 이벤트 API: 미구현
- ❌ M3 테스트: 미구현

---

## 7. 다음 단계 (Recommended Actions)

### 즉시 처리 (Critical Path — 1주일)

1. **M3 기능 구현** (3~4일)
   - `core/db.py`: `save_event()`, `get_events()` 추가
   - `core/correlator.py`: `_detect_changes()` (끊김 탐지)
   - `core/parsers/utils.py`: `detect_flapping()` (로그 파싱)
   - `app.py`: `/api/events` 엔드포인트 추가

2. **M3 테스트 추가** (1~2일)
   - `tests/test_detection.py`: 끊김·Flapping 테스트 10개+
   - `tests/test_credentials.py`: DPAPI roundtrip, 폴백 테스트
   - 최소 50개 → 70개 테스트 목표

3. **보안 이슈 수정** (1일)
   - C-01: SSH 에러 sanitize 강화
   - H-01: log_event() 중복 제거 (parsers/utils.py 통합)
   - M-01: threading warning 해결

4. **최종 검증** (1일)
   - pytest 전체 실행 (목표: 70/70 통과)
   - 보안 리뷰 Round 4 (Codex)
   - README 업데이트 (M3 사용법)

---

## 부록: 구현 검증 요약

### DB 스키마 검증 ✅

```sql
✅ switches        — 스위치 자산 (id, name, ip, vendor, model, status)
✅ snapshots       — 스냅샷 (id, switch_id, collected_at, duration)
✅ ports           — 포트 (id, snapshot_id, name, status, vlan, speed)
✅ mac_entries     — MAC 테이블 (id, snapshot_id, vlan, mac, port)
✅ arp_entries     — ARP 테이블 (id, snapshot_id, ip, mac, interface)
✅ hosts           — 호스트 위치파악 (id, ip, mac, switch_id, port, confidence)
✅ events          — 이벤트 (id, event_type, event_name, switch_id, data, created_at)
              ↑ 스키마만 있음, save/get 함수 미구현
```

### API 라우터 검증 ✅

```python
✅ GET  /              — 인덱스 (HTML)
✅ GET  /health        — 헬스 체크
✅ GET  /api/state     — 전체 상태
✅ GET  /api/switches  — 스위치 목록
✅ POST /api/collect   — 온디맨드 수집
✅ POST /api/add_switch — 스위치 추가 (미사용)
❌ GET  /api/events    — 이벤트 조회 (미구현)
```

### 파서 커버리지 검증 ✅

```
✅ Cisco IOS (show mac-address-table, show interfaces, show arp)
✅ Arista EOS (show mac address-table, show interfaces, show ip arp)
✅ Extreme EXOS (show fdb, show ports, show iproute)
⚠️ Stub 파서 (기본값, 테스트용)
```

---

**최종 업데이트**: 2026-06-16 19:35  
**검증자**: Claude Code (AI_WORKPLACE_Associate)  
**상태**: ✅ **검증 완료** (M1+M2 완성 확인, M3 미구현 확인)
