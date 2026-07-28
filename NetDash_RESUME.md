# NetDash 재개 스냅샷

**현재 버전**: v6.7.4 (커밋 2ee0e54, 릴리스 발행 완료)
**상태**: 백로그 비었음 — 다음 지시 대기

## 방금 완료한 것 (v6.7.4)

### 서버 MAC·연결스위치·포트 수집률
- `core/db.py` `find_location_by_mac()` — MAC → 스위치/포트(표기 정규화, 물리 포트 우선).
- `core/server_collector.py` `local_arp_mac()` — 이 PC ARP 캐시(같은 서브넷 공짜 경로).
  한국어 로케일 출력('동적')로 실측 확인 — 타입 컬럼 문자열에 기대지 않는다.
- 수집 마지막에 MAC은 있는데 위치가 비면 재조회(`_apply_location`). 이미 찾았으면 유지.

## v6.7.3에서 한 것

### 관제 설비 재수집 409 해소
- `core/facility.py` — `_worker` 등록 + `_reap_dead_worker()` + `_run()` finally.
  스레드가 죽었는데 running만 남으면 스스로 해제(주인을 모르면 해제 안 함).
  끝난 스레드는 주인 자리에서 비운다.
- `busy_reason()` → 409에 "대역·진행률·경과시간" 동봉. `get_status()`에 elapsed_sec.
- `web/static/wall.js` — 409 시 "중지하고 재수집?" 확인 → stop → 폴링 → 1회 재시도.

## v6.7.2에서 한 것

### 랙뷰 장비 드래그 이동
- `web/static/app.js` — `_rackOccupancy()` / `_rackDropTarget()` + mousedown 핸들러.
  커서 칸 = 장비 윗변. 다른 랙 이동 가능. 겹침·랙 경계 거부. 4px 임계값으로 클릭 구분.
- 드래그 직후 click은 '방금 끈 그 장비'일 때만 삼킨다(무조건 삼키면 리스너가 남아
  나중의 정상 클릭을 잡아먹는다 — jsdom 검증에서 실제로 잡힘).

### SNMP 무응답 원인 구분
- `core/snmp_collect.py` — `SnmpClosed`(ICMP port-unreachable = snmpd 없음, 재시도 안 함)
  / `SnmpSilent`(타임아웃 = 차단 또는 커뮤니티 불일치). 로그도 분리.

## v6.7.1에서 한 것

### 서버 사양 수집 3중 폴백
- `core/server_collector.py` — `_cred_candidates()` / `_is_auth_error()`:
  입력 계정이 **인증 거부될 때만** 서버별 저장 계정으로 재시도(최대 2회).
  SSH 경로와 WMI 경로 양쪽에 적용.
- `core/snmp_collect.py` (신규) — SNMPv2c GET/GETBULK를 외부 라이브러리 없이
  BER 직접 구현. HOST-RESOURCES-MIB로 CPU·메모리·디스크·MAC 수집.
  도달 불가 서버에는 시도 안 함(진짜 사유를 덮어쓰지 않게).
- 설정 API/화면: `snmp_enabled`, `snmp_community_blob`(암호화, 값 미노출).
- 수집 경로: **SSH → WMI(Windows·135) → SNMP(161)**

### 서버실 랙뷰 높이 드래그
- `web/static/app.js` — 윗변(topU) 고정, 시작 유닛이 내려가도록 수정.
  아래 빈 칸 수(`freeBelow`)만큼만 확장. 겹친 장비는 `conflicts`로 화면에 노출.

## 근거
- `python -m pytest tests/ -q` → **1286 passed** (exit 0)
- 신규 테스트가 수정 전 실패함을 `git stash`로 확인: 자격증명 6건 / 랙 드래그 8건
- `node scripts/verify_rack_resize.js` → ALL PASS (jsdom 실제 마우스 이벤트, 높이+이동)
- SNMP는 실제 UDP 소켓에 띄운 가짜 에이전트(`tests/test_snmp_collect_v671.py`
  `FakeAgent`)로 프로토콜까지 검증
- 프로덕션 기동: 배포 `config.yaml` 그대로 exe 실행 → `mode: production`,
  `HTTP 200` 확인

## 미커밋 파일
없음 (`.verify_tz.js`, `build/` 산출물 제외)

## 다음 단계
사용자 지시 대기. 열린 후속 항목:
- FortiGate `get sys ha status` 실제 응답 필드 확인(구조는 `fw_ha_role`에 존재,
  실장비 응답 필요)
- SNMP 실장비 검증 — 폐쇄망 리눅스 서버에서 커뮤니티 설정 후 사양 수집 확인
