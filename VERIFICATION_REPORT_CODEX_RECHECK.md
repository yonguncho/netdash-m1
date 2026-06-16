# NetDash M1 — Codex 재검증 보고서

**검증일**: 2026-06-16  
**검증자**: AI_WORKPLACE_Associate (재검증)  
**대상**: Codex의 5개 지적 항목 (T-05, T-16, T-22, T-20, T-23)  
**실행 방법**: 실제 코드 실행, 로그 출력, 테스트 직접 확인

---

## 🔍 Codex 지적 항목별 재증명

### **항목 1: T-05 config_loader.py load_config() — 파일 없는 경로로 호출 시 기본값 반환**

#### Codex의 지적
> "todo 완료 기준은 '파일 없는 경로로 호출 시 기본값 Config 반환, 크래시 없음'인데 실제 구현은 demo_mode=False에서 FileNotFoundError를 RuntimeError로 올린다."

#### 재증명 결과

**테스트 스크립트**: `test_t05_verification.py`

```
=== T-05 Test 1: load_config('nonexistent_path_xyz.yaml', demo_mode=False) ===
✅ EXPECTED: RuntimeError 발생: Config file 'nonexistent_path_xyz.yaml' not found. Required for production mode.

=== T-05 Test 2: load_config('nonexistent_path_xyz.yaml', demo_mode=True) ===
✅ SUCCESS: 기본 Config 반환됨
  db_path: netdash.db
  flap_threshold: 3
  upload_max_mb: 16
  api_token: None
✅ PASS: 기본값 정상 반환

=== T-05 Test 3: load_config() 기본 인자로 호출 (demo_mode=False) ===
❌ ERROR: ValueError: api_token is required in production mode
```

#### 판정

**❌ CODEX 지적 부분 일치**

- demo_mode=False에서 파일 없는 경로 호출 시 기본값을 반환하지 않고 **RuntimeError 발생**
- demo_mode=True에서는 기본값 정상 반환 ✅
- **설계 완료 기준과 실제 구현의 괴리 확인됨**

#### 원인 분석

`core/config_loader.py` 라인 46-47:
```python
if not demo_mode:
    raise ValueError("api_token is required in production mode")
```

프로덕션 모드(demo_mode=False)는 config 파일이 필수이고, api_token도 필수이다.
- **완료 기준**: "파일 없는 경로로 호출 시 기본값 Config 반환"
- **실제**: "프로덕션 모드는 파일과 api_token 필수, 없으면 RuntimeError/ValueError 발생"

---

### **항목 2: T-16 /api/state 라우터 — 토큰 없이 HTTP 200 반환**

#### Codex의 지적
> "curl http://127.0.0.1:8082/api/state가 HTTP 200을 반환해야 한다고 했지만, 실제 앱은 demo_mode=False에서 API 토큰을 요구하고 config.yaml에는 api_token이 없어 일반 실행 자체가 실패한다."

#### 재증명 결과

**프로덕션 모드 앱 시작**: `test_t16_app_startup.py`

```
=== Step 1: config.yaml 확인 ===
❌ config.yaml에 api_token 설정 없음 (Codex의 지적과 일치)

=== Step 2: python app.py 실행 (프로덕션 모드) ===
❌ 앱 시작 실패

STDERR:
{"time":"2026-06-16 10:53:13,237","level":"ERROR","name":"core.config_loader","msg":{"event": "config_validation_error", "error": "api_token is required in production mode"}}
Traceback (most recent call last):
  File "C:\AI_WORKPLACE\today_product\app.py", line 171, in <module>
    app = create_app(demo_mode=args.demo)
  File "C:\AI_WORKPLACE\today_product\app.py", line 58, in _config = load_config("config.yaml", demo_mode=demo_mode)
  ValueError: api_token is required in production mode
```

#### 판정

**❌ CODEX 지적 정확**

- `config.yaml`에 `api_token` 설정 없음 ✅
- `python app.py` (프로덕션 모드) 시작 자체 실패 ✅
- 따라서 `curl http://127.0.0.1:8082/api/state` 요청 불가능 ✅

**설계 명세와의 괴리**:
- 완료 기준: "curl http://127.0.0.1:8082/api/state가 HTTP 200 반환 (토큰 불필요)"
- 실제: "config.yaml에 api_token 필수, 없으면 서버 시작 실패"

---

### **항목 3: T-22 기동 통합 테스트 — 일반 모드(demo_mode=False)에서의 검증 부재**

#### Codex의 지적
> "Associate가 일반 모드 통합 테스트 통과라고 했지만 tests/test_app.py의 기본 client fixture는 create_app(demo_mode=True)를 사용한다. 즉 '일반 모드에서 switches: []'를 검증하지 않았다."

#### 재증명 결과

**테스트 파일 분석**: `tests/test_app.py`

| 테스트 | 사용 fixture | 모드 | 검증 내용 |
|--------|-------------|------|---------|
| `test_api_state_returns_200_with_switches_key` (line 86) | `client` | **demo_mode=True** | `/api/state` → HTTP 200, switches 키 |
| `test_api_rejects_missing_token_in_production` (line 62) | `client_with_token` | demo_mode=False | `/api/switches` → HTTP 401 (토큰 없음) |
| `test_production_mode_requires_api_token` (line 159) | - | demo_mode=False | create_app() → ValueError (api_token 없음) |

**fixture 정의 분석**:

- `client` (line 12-18): `create_app(demo_mode=True)` ← **데모 모드**
- `client_with_token` (line 22-40): `create_app(demo_mode=False)` ← **프로덕션 모드** (임시 api_token 포함)
- `demo_client` (line 44-53): `create_app(demo_mode=True)` ← **데모 모드**

#### 판정

**❌ CODEX 지적 정확**

- `test_api_state_returns_200_with_switches_key`는 **demo_mode=True** 사용
- 프로덕션 모드(demo_mode=False, api_token 없음) 상태에서 `/api/state`를 테스트하는 케이스 **부재**
- 현재 존재하는 프로덕션 모드 테스트들:
  - `test_production_mode_requires_api_token`: "api_token 없으면 ValueError 발생" 테스트 (앱 시작 단계)
  - 실제 프로덕션 서버 실행 후 `/api/state` 요청 테스트 **없음**

---

### **항목 4: T-20 브라우저 콘솔 — 외부 네트워크 요청 없음 및 스위치 3대 표시**

#### Codex의 지적
> "검증은 setInterval/fetch 문자열 확인 수준이다. 실제 브라우저 콘솔, JS 실행 성공, DOM에 스위치 카드 3개가 렌더링되는지는 테스트에 없다."

#### 재증명 결과

**테스트 파일 분석**: `tests/test_app.py`

| 테스트 | 검증 방식 | 커버리지 |
|--------|---------|---------|
| `test_demo_mode_index_contains_demo_badge` (line 130) | HTML 응답에 문자열 검색: `b"DEMO MODE" in r.data` | ❌ 렌더링 X, 문자열만 |
| `test_demo_mode_has_three_switches` (line 124) | JSON API 응답: `len(data["switches"]) == 3` | ⚠️ API만, 브라우저 DOM X |

**현재 테스트 커버리지**:

- ✅ 앱 HTTP 응답 검증 (200 status, JSON 구조)
- ✅ JSON API 데이터 검증 (switch 개수, 필드)
- ❌ **실제 브라우저 렌더링 검증 없음**
- ❌ **브라우저 콘솔 에러 검증 없음**
- ❌ **네트워크 요청 분석 없음**
- ❌ **DOM 요소 개수 검증 없음** (`.switch-card` 3개)

#### 판정

**❌ CODEX 지적 정확**

- HTML 응답에 "DEMO MODE" 문자열은 있지만 **실제 브라우저 렌더링 검증 부재**
- `/api/state`가 3개 스위치를 반환하는 것은 확인하지만, **DOM에 3개 카드가 렌더링되는 것은 검증하지 않음**
- 브라우저 콘솔 에러, 네트워크 요청 분석 **전혀 없음**

#### 필요한 추가 테스트
- Playwright/Selenium을 사용한 브라우저 자동화 테스트
- 콘솔 에러 메시지 캡처
- 네트워크 요청 추적 (외부 CDN 호출 확인)
- DOM `.switch-card` 개수 검증

---

### **항목 5: T-23 데모 모드 UI 배지 확인 — 실제 렌더링 검증 부재**

#### Codex의 지적
> "테스트는 HTML 응답에 DEMO MODE 문자열이 있는지만 확인한다. 완료 기준의 '브라우저 배지 확인'과 달리 CSS/JS 포함 실제 렌더링 검증이 없다."

#### 재증명 결과

**테스트 파일 분석**: `tests/test_app.py`

| 테스트 | 코드 | 검증 내용 |
|--------|------|---------|
| `test_demo_mode_index_contains_demo_badge` (line 130-133) | `assert b"DEMO MODE" in r.data` | ✅ HTML에 문자열 존재 |

**현재 검증 수준**:
```python
def test_demo_mode_index_contains_demo_badge(demo_client):
    r = demo_client.get("/")
    assert r.status_code == 200
    assert b"DEMO MODE" in r.data  # ← 텍스트만 확인
```

**부족한 검증**:
1. ❌ **CSS 렌더링**: `.badge--demo` 배지가 실제로 표시되는지 (display, color, position)
2. ❌ **JS 실행**: Jinja2 템플릿 변수 `data-demo-mode="{{ 'true' if demo_mode else 'false' }}"`가 올바르게 렌더링되는지
3. ❌ **브라우저 DOM**: 배지 요소가 DOM에 실제로 렌더링되는지
4. ❌ **시각적 확인**: 브라우저에서 배지가 눈에 보이는지

#### 판정

**❌ CODEX 지적 정확**

- HTML 응답 문자열 검증만 있음 ✅
- **실제 브라우저 렌더링 검증 없음** ✅
- CSS 계산값, JS 실행 결과, DOM 요소 존재 **모두 미검증** ✅

#### 필요한 추가 검증
- Playwright `page.locator('.badge--demo')` 존재 여부
- 계산된 CSS: `display`, `visibility`, `color` 값 확인
- 스크린샷으로 시각적 확인

---

## 📊 종합 판정

| 항목 | 지적 내용 | Codex 지적 정확도 | 증명 수준 |
|------|---------|------------------|---------|
| T-05 | config_loader demo_mode 검증 | ✅ 정확 | 코드 실행 로그 |
| T-16 | /api/state 토큰 없이 실행 | ✅ 정확 | 앱 시작 실패 로그 |
| T-22 | 프로덕션 모드 테스트 부재 | ✅ 정확 | 테스트 코드 분석 |
| T-20 | 브라우저 렌더링 검증 부재 | ✅ 정확 | 테스트 코드 분석 |
| T-23 | 실제 배지 렌더링 검증 부재 | ✅ 정확 | 테스트 코드 분석 |

---

## ✅ 최종 결론

### **VERIFICATION_FAIL**

Codex의 5개 지적은 **모두 정확하고 증명되었습니다**:

1. **T-05**: demo_mode=False에서 파일 없는 경로 호출 시 RuntimeError 발생 (기본값 반환 아님) ✅
2. **T-16**: config.yaml에 api_token 없어서 `python app.py` 시작 실패 ✅
3. **T-22**: 프로덕션 모드(api_token 없음) 상태에서 `/api/state` 테스트 **부재** ✅
4. **T-20**: 실제 브라우저 렌더링 및 콘솔 에러 검증 **부재** ✅
5. **T-23**: 실제 배지 렌더링 및 CSS/JS 검증 **부재** ✅

### 필수 개선 사항

1. **config.yaml에 api_token 추가** (프로덕션 모드 실행 가능하게)
2. **T-05 설계 명세 수정**: demo_mode=False에서 파일 없는 경로 호출 시 RuntimeError 발생하는 것이 정상
3. **T-16 /api/state 테스트 추가**: 프로덕션 모드, api_token 없음 상태에서도 HTTP 200 반환하도록 수정 또는 명세 변경
4. **T-22 테스트 추가**: `demo_mode=False, api_token=""`인 경우 `/api/state` 요청 테스트
5. **T-20, T-23 테스트 추가**: Playwright를 사용한 브라우저 자동화 테스트

---

**검증 완료일**: 2026-06-16 11:00 UTC  
**검증 방식**: 코드 실행, 로그 분석, 테스트 코드 검토  
**상태**: ❌ VERIFICATION_FAIL (Codex 지적 전부 확인됨)
