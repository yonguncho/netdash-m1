# NetDash 재개 스냅샷

**현재 버전**: v6.8.0 (커밋 c723112, 릴리스 발행 완료)
**상태**: 백로그 비었음 — 다음 지시 대기

## 방금 완료한 것 (v6.8.0) — 사양 진단 도구

사용자 보고 "사양이 여전히 수집 안 된다"가 반복. 같은 증상을 네 번 고쳤으므로
(SSH 세션한도 → keyboard-interactive → 공통계정 덮어쓰기 → DCOM 단독)
다섯 번째 추측 대신 **실제 장비 응답을 받을 수단**을 만들었다.

- `scripts/diag_server_spec.py` — 네 경로(SSH/WinRM/WMI/SNMP)를 순서대로 두들겨
  각 결과·소요시간·조치를 출력. 읽기 전용, 비밀번호 미출력.
- CLI: `netdash.exe --diag-server <IP> --user <계정>`
- **화면**: 서버 진단 결과 아래 "🔎 사양 수집 경로 진단" 버튼
  (`POST /api/servers/<id>/diag-spec`). 사용자가 "서버에서 툴을 못 돌린다"고
  해서 추가 — CLI만으로는 못 쓰는 환경이 있다.
- exe 빌드 후 실행해 **한국어 콘솔 cp949 깨짐**을 발견해 수정(다른 모듈 메시지가
  실려 오므로 출력 직전에 거른다).

**다음: 사용자가 진단 출력을 주면 그 원인을 특정해 수정.**

## v6.7.9

### 전송 보안을 설정으로 (core/secpolicy.py 신규)
claude-security 스캔의 HIGH 2건(SSH AutoAddPolicy, 방화벽 verify_ssl=False)을
**기본값을 바꾸지 않고** 설정으로 뺐다 — 그냥 켜면 자체서명 인증서·known_hosts
부재로 수집이 전부 멈춘다.
- `collector.ssh_host_key_policy`: auto(기본) / **tofu(권장)** / strict
  tofu = 처음 본 키는 받아 적고 이후 변경 시 거부. 첫 수집을 막지 않으면서
  중간자 교체를 잡는다.
- `collector.verify_firewall_tls`: false(기본)
- AutoAddPolicy가 8곳에 흩어져 있던 것을 단일 지점으로. "직접 쓰면 실패"하는
  테스트로 고정 — 이번 주 두 번 당한 '경로가 둘인데 한쪽만' 재발 방지.

## v6.7.7 / v6.7.8

### v6.7.8 — claude-security 스캔 반영
플러그인 스캔(medium, 연구원 31명 → 후보 46 → 검증 통과 10건) 중 재현 확인 5건 반영.
- **자체 감사가 놓친 2건**(둘 다 '경로가 둘인데 한쪽만 봄'):
  serverroom 랙 엑셀 수식 주입(exporter.py만 확인했었음),
  /api/upload XML 엔티티 폭탄(_read_xlsx_safe를 안 거치는 별도 경로).
  → `_xlsx_has_xml_entities()` 공통화 + '구현 1개·호출 2곳 이상' 테스트로 고정.
- 진단·설비 라우트 4곳 validate_credential 적용, `_cred_owner`를 `_client_ip()`로.
- **보류(사용자 판단 필요)**: FortiGate verify_ssl=False, SSH AutoAddPolicy —
  둘 다 켜면 현재 수집이 깨진다(자체서명 인증서·known_hosts 부재).

### v6.7.7 — WinRM 사양 수집
RDP만 열린 Windows 서버. RDP 자체로는 조회 불가하나 그런 서버는 WinRM(5985)이
대개 열려 있다. 기존엔 DCOM(135)만 시도해 동적 포트가 막히면 전멸이었다.
`transports_for()`로 WinRM 우선 → DCOM 폴백. 한국어 stderr(cp949) 디코딩도 수정.
**미검증**: 이 PC에 WinRM이 꺼져 있어 원격 수집 성공까지의 종단 확인 못 함.

## v6.7.5 / v6.7.6 — 자체 보안 감사

claude-security 플러그인(Anthropic 공식) 설치 완료. **스캔은 사용자가 직접 실행해야
한다** — 스킬에 `disable-model-invocation: true`, 워크플로에 "do not improvise a
scan by hand" 명시. `/reload-plugins` → `/claude-security` (NetDash_dev 에서).
플러그인이 `python3`를 호출하는데 이 PC엔 `python`만 있어, 작업 범위 안인
`C:\AI_WORKPLACE\...\Python310\python3.exe` 를 만들어 두었다.

대신 5축 병렬 감사를 직접 돌려 반영:
- **SNMP 응답 위조(HIGH)** — 출처·request-id·커뮤니티 미검증. 실제 UDP 소켓으로
  재현 확인 후 connect() 고정 + rid/커뮤니티 대조로 차단.
- **장비 주소 변경 시 저장 계정 잔류(HIGH)** — IP만 바꿔 계정 탈취 가능 → 지운다.
- **DNS 리바인딩(HIGH)** — Host 허용목록(IP·localhost만, `app.allowed_hosts`).
  실기동으로 IP/localhost/LAN IP/[::1] 200 확인 — 잠기지 않는다.
- MED 8건(잘린 패킷 IndexError, walk 시간 상한, 0.0.0.0, SMTP 주소, 로그 마스킹,
  세션 계정 잔류, 저장 XSS 2건, xlsx 엔티티 폭탄).
- **현행 유지 결정**: config 백업 평문 저장 — 관리자 전용·폐쇄망(사용자 판단).

## v6.7.4에서 한 것

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
