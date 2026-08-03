# NetDash 재개 스냅샷

**현재 버전**: v6.14.0 작업 중 (전체 테스트 진행 중)
**직전 릴리스**: v6.13.0 (커밋 2166f0e)

> **[병행 작업 · 코드 무변경 · 2026-07-31]** CHOICEGUIDELAB 포스트용 데모 스크린샷 7장을
> 고객사 식별자(`SKBA_*`) 없이 재촬영 완료. 원인은 개발용 `netdash.db`에 누적된 스테일
> 테스트 스위치(픽스처는 깨끗). `scripts/_clean_demo_for_screenshots.py`로 DB 정리(리네임 2
> ·삭제 4·토폴로지 주입), `scripts/_capture_screenshots.py`(Playwright)로 캡처+식별자 0건 검증.
> 앱 코드·커밋 무관. DB는 5대 깨끗·위치 비움으로 복원, 백업 `netdash.db.bak_screenshot`.
> 결과물: `shared/handoff/tool_posts/NetDash/`, 회신 `shared/commands/NetDash_cmd.done`+`.response`.

## 작업 중 (v6.17.0) — 제조사(벤더사)와 제품 분리

사용자 지적: 방화벽 현황의 '벤더'가 `fortigate`로 나오는데 FortiGate는 제품이고
벤더사는 Fortinet이다. 벤더사 컬럼을 추가하고, 앞으로 제품 정보로 벤더사를
판단할 수 있게 해달라.

- 같은 문제가 스위치에도 있었다 — `cisco_nxos`는 netmiko 드라이버 키다.
  화면(JS `_VENDOR_LABELS`)에만 매핑이 있어 **엑셀 내보내기는 원본 키를 그대로**
  내보내고 있었다(자산 목록에 제조사가 아닌 값이 들어감).
- `core/manufacturer.py` 신규 — 판별을 파이썬 한 곳에 둔다(화면·API·엑셀이
  각자 다른 표기를 갖지 않게). 순서: ① 드라이버/제품 키 ② 모델명 패턴
  (`N9K-`, `PA-`, `FG-`, `JL256A` …) ③ OS 문자열. **못 찾으면 빈 문자열** —
  모르면서 아무 제조사나 적으면 자산 목록이 조용히 틀린다.
- 방화벽 표: 제조사·제품 컬럼 분리. 스위치 표: 서버 판별 우선(JS 표는 폴백).
- 엑셀: '벤더' 컬럼 값을 제조사로 교정 + '제품' 컬럼 추가(컬럼명은 유지 —
  바꾸면 기존 보고서 검증이 깨진다).
- 벤더 미인식 장비도 수집된 모델명으로 제조사를 알아낸다.

## v6.16.0 — SNMP 환경 정보(온도·팬) 수집

사용자 질문 2건: ① 방화벽·스위치·서버 현황에서 장비 온도도 볼 수 있나
② SNMP 연동 수집 기능은 구현돼 있나.

**답(확인 완료)**:
- 온도는 전혀 수집 안 하고 있었다.
- SNMP는 **절반** 있었다 — `core/snmp_collect.py`에 직접 구현한 v2c 클라이언트
  (GET/GETBULK/walk, SET 없음), 커뮤니티 암호화 저장(`snmp_community_blob`)과
  설정 UI까지. 단 **서버 사양 수집의 4번째 폴백으로만** 쓰이고 스위치·방화벽엔
  연결 안 됨. v3 미지원. 실장비 검증은 여전히 열린 항목.

두 질문이 같은 지점에서 만난다 — 온도의 벤더 중립 표준 경로가 SNMP의
**ENTITY-SENSOR-MIB(RFC 3433)** 이다. CLI로 하면 벤더별 파서 8개가 필요한데
이건 구현이 하나면 된다. SNMP 확장의 첫 실사용처로도 맞다.

- `core/snmp_env.py` 신규 — 센서 테이블 walk + 정규화. **RFC 3433의 scale·
  precision을 반영**(무시하면 밀리섭씨 45000이나 0.1도 단위 455가 그대로 온도가
  된다). 온도/팬/유무만 남기고 전압·전류는 버린다(화면 잡음).
- `db.device_env` 테이블 — (kind, device_id) 단일 테이블. 스위치·방화벽·서버가
  같은 MIB로 같은 모양을 내므로 나누면 저장·조회·삭제가 3벌이 된다.
  `_purge_switch_children`에 삭제 연결(switch_id 컬럼이 아니라 안 걸린다).
- `collector.collect_env_snmp()` — 스위치·방화벽 수집 후 호출. 기존 SNMP 설정
  (사용 여부·커뮤니티)을 그대로 재사용(온도 때문에 또 입력받지 않는다).
  실패는 조용히 넘긴다(이 MIB 미지원 장비가 흔하고, SSH 결과까지 버리면 손해).
- 화면: 스위치·방화벽 표에 온도 컬럼(`tempCell` 하나를 공유), 상세보기에 센서 목록.

**검증 방식**: 실장비가 없으므로 walk 결과를 바꿔 끼우는 가짜 세션으로 테스트.
BER·소켓은 snmp_collect가 이미 담당하므로 여기선 '센서 해석'만 검증한다.

**남은 것**: 서버 온도는 이 경로로 리눅스(net-snmp+lm-sensors)만 가능.
Windows는 `MSAcpi_ThermalZoneTemperature`가 서버 하드웨어에서 대부분 미지원 —
iDRAC/iLO/IPMI가 필요하다. 실장비 SNMP 검증도 여전히 미완.

## v6.15.0 — 등록 장비를 설비 현황에서 제외

사용자 신고: 10.92.140.0/22를 수집하면 그 안의 TPS 스위치 10.92.140.13 자신이
'설비'로 잡히고, BB MAC 테이블에서 그 MAC이 Po124(업링크)에 보이니
'직접 연결 미확인 / BB Po 경유로만 관측'으로 뜬다. 상태는 '연결됨'.

- **판정은 옳고 대상이 틀렸다** — 스위치는 스위치 현황에 따로 있다. 업링크 너머에
  있는 게 맞으므로 설비 기준 판정은 정확했지만, 애초에 설비가 아니다.
- 요청대로 스위치·방화벽·서버로 등록된 IP는 설비 현황에서 제외.
- **저장 경계에서 막았다** — 화면에서 거르면 설비·관제·엑셀 세 곳을 챙겨야 하고
  언젠가 한 곳을 빠뜨린다(이번 세션에서 4번 겪은 패턴).
  `db.registered_device_ips()` + `_drop_registered_devices()`를 쓰기 함수 둘
  (`save_facility_hosts` / `replace_facility_subnet`) 양쪽에 적용.
- 옛 스캔으로 이미 저장된 행은 `purge_registered_devices_from_facility()`가
  `rematch()`에서 정리 — 재수집을 강요하지 않는다.
- 조용히 사라지면 오해하므로 새로고침 응답에 `excluded` 개수를 실어 화면에 표시.

## v6.14.0 — 과거 이력·포트 설명 경로에도 업링크 판정 적용

사용자 4차 신고: 10.92.140.88의 TPS 포트가 **DOWN**인데도 백본
`SKBA_F1_N9508_FA_BB_1 1/24`로 표시된다. 추가로 "TPS 인터페이스 description에
IP가 적혀 있는데 하나도 참고를 못 하나".

- **진단**: 링크 DOWN → MAC이 어느 현재 테이블에도 없음 → `_choose_attachment`는
  아무것도 못 고름. 화면 표시는 **과거 이력 폴백**에서 왔다.
  `db._build_mac_last_map`이 MAC별로 '스냅샷 id 최대' 하나만 고르므로, 백본이
  TPS보다 나중에 수집되기만 하면 백본의 업링크 관측이 이긴다.
  v6.13.0의 업링크 판정은 `_choose_attachment`에만 있었다 —
  **같은 기능 경로가 둘인데 한쪽만 고친 그 패턴의 4번째 재발**.
- 호출처가 셋(설비 현황·관제·엑셀)이라 app.py가 아니라 **맵 빌더 자체**를 고침:
  액세스 관측을 업링크 관측보다 항상 우선, 그 안에서 최신. 업링크뿐이면 버리지
  않고 `via_uplink=True`로 표시.
- `db.find_location_by_mac`도 같은 구멍('물리 포트 우선'이 백본 Eth1/24를 뽑음)
  → 업링크 배제를 먼저 적용.
- **포트 설명 단서를 관제에 연결** — 지금까지 관제에는 아예 없어서 설명에 IP가
  버젓이 적혀 있어도 '위치 미확인'만 나왔다. `find_ports_by_description()` 배치
  신설(10초 폴링에 설비마다 쿼리 금지), 단건 함수는 배치를 호출해 규칙 일원화.
- 설명 매칭 결함 2건: ① `LIKE '%ip%'`가 `10.92.140.9`를 `10.92.140.98`에 매칭
  (경계 검사 추가) ② 같은 IP가 두 포트에 적히면 통째로 버림 → 같은 스위치면
  스위치는 확정으로 보고 `ambiguous_ports`로 넘김.
- 화면: '과거 연결' 배지와 '업링크에서만 관측'을 구분(전자는 접속 지점, 후자는
  지나간 길목). 엑셀 내보내기(세 번째 경로)도 같은 구분 + 설명 단서 적용,
  보강 대상을 `switch_name`이 빈 것 → `direct=0` 전체로 확대.
- **성능 회귀 자초·해소**: `uplinks_for`를 호출마다 계산하게 두니 전체 스위트가
  8%에서 기어갔다(`find_location_by_mac`은 서버마다 호출된다). 60초 TTL 캐시 +
  `invalidate_mac_last_cache`에 무효화를 묶음(호출처마다 챙기면 언젠가 빠뜨린다).
  1515 PASS / 590초 — 기준선 583초와 동일.

**근거**: 신규 14건 중 9건 수정 전 실패 확인(git stash), 전체 1515 PASS.

## 방금 완료한 것 (v6.13.0) — 업링크 판정 기준 교체 + 판정 근거 보기

재신고: v6.11.0을 냈는데도 10.92.140.88이 백본 `Eth1/24 (Po124)` 직결로 표시.

- **원인**: v6.11.0은 "Po의 MAC 수가 많으면 트렁크"로 걸렀다. 업링크라도 그 뒤
  장비가 대부분 꺼져 있으면 학습 MAC이 몇 개뿐이라 통과한다. 개수는 장비 상태에
  따라 흔들리는 신호였다.
- **교체**: `facility.uplink_ports()` 신규 — 이미 수집 중이던 `neighbors`
  (CDP/LLDP) + 등록 스위치 소유 MAC으로 '너머에 등록 스위치가 있는' 포트를 뽑는다.
  등록 스위치로 확인될 때만 인정(IP전화·AP 오인 방지). Po↔물리멤버 양방향 전파.
- `_choose_attachment(..., uplinks)` — 업링크는 후보에서 먼저 제외하고, 최종
  선택 포트가 업링크면 어느 분기를 거쳤든 `direct=False`로 되돌린다. 물리 포트에도
  같은 구멍이 있었다(유일 물리 관측이면 무조건 direct).
- CDP/LLDP 미수집 환경은 기존 개수 판정 그대로 — 회귀 없음.
- **판정 근거 보기**: `explain_attachment()` + `GET /api/facility/explain?ip=`,
  설비 현황 각 행에 '근거' 버튼(진단 팝업 재사용). 관측 위치·포트별 MAC 수·
  포트채널 멤버·CDP 이웃·저장값 대 재계산값 차이를 그대로 표시.

**근거**: pytest 1503 PASS, 신규 16건 중 10건 수정 전 실패 확인(git stash),
exe 기동 후 `/api/facility/explain` 400·200 응답 및 app.js 배포 확인.

## v6.12.0 — 스위치 현황 표에 상세보기 버튼

상세보기가 현황판 카드·랙뷰에만 있어 스위치 현황에서 포트/MAC/ARP를 보려면
현황판으로 되돌아가야 했다. `renderSwitchTable` 작업 열 맨 앞에 추가.
클릭 위임 핸들러(`case "detail-switch"`)는 페이지 공용이라 그대로 재사용,
`payloadAttr(sw)`로 객체 전체 전달(패널 제목이 name·ip·hostname을 씀).

**근거**: pytest 1488 PASS, 신규 5건 중 3건 수정 전 실패 확인, exe 데모 기동 후
`/`·`/static/app.js`·`/wall` 200 + 버튼 문자열 확인.

## v6.11.0 — 업링크 트렁크 오판 + 이력/설명 보강

사용자 보고: 설비 10.92.140.88의 연결 스위치가 백본(Po124)으로 나오는데
실제로는 TPS 스위치(10.92.140.13) 1/0/25에 물려 있고, 그 TPS는 정상 수집됐는데도
설비 정보가 없다. TPS의 1/0/24 description엔 그 IP가 적혀 있기까지 하다.

- `_choose_attachment` — 포트채널에만 MAC 개수 검사가 빠져 있었다. pc_map으로
  물리 멤버가 풀리기만 하면 무조건 direct=True. 백본↔액세스 업링크 트렁크가
  '직접 연결'로 표시된 원인. 물리 포트와 같은 `_EDGE_MAC_MAX` 검사 적용,
  트렁크면 멤버로 풀지 않고 Po 이름 그대로 둔다.
- `app.py facility_list` — 과거 이력(hist_*) 보강이 `switch_name`이 **완전히 빈**
  설비에만 적용됐다. 위 버그로 이름이 잘못 채워져 있어 조회 자체가 안 됐다.
  조건을 `not switch_name or not direct` 로 확대.
- `db.find_port_by_description()` 신규 — 포트 Description에 적힌 장비 IP를 최후
  단서로 사용(MAC은 에이징되지만 설명은 설정의 일부라 남는다). 다중 매치는 오탐
  방지로 미반환. 우선순위: 현재 MAC → 과거 이력 → 포트 설명(덮어쓰지 않고 힌트만).

**근거**: pytest 1483 PASS, 신규 8건 수정 전 실패 확인, rematch() 종단 재현 테스트.

## v6.10.0 — 관제 카테고리별 전체 일괄 재수집

사용자 요청: v6.9.0에서 만든 개별 설비 재수집에 이어, "설비 연결 실패 /
도달 불가 / 수집 실패" 세 카테고리 각각을 전체 한 번에 재수집하는 기능.

- `core/facility.py recollect_offline_facility()` 신규 — 대역(게이트웨이
  스위치)당 세션을 한 번만 열어 재사용, 그 대역의 오프라인 IP들만 ping
  (대역 전체 스윕 아님). `switch_filter`로 관제 화면 칩 필터와 대응.
- 연결·확인·저장 로직을 `_gateway_connect()`/`_probe_ips()`/
  `_apply_host_results()`로 뽑아 `recollect_single_host`와 공유(이번 세션에서
  "경로가 둘인데 한쪽만 고침"을 두 번 겪어 세 번째 재발 방지).
- `POST /api/wall/recollect-switches` — 도달불가/수집실패(스위치) 카테고리.
  공통 계정을 새로 묻지 않고 각 스위치 저장 계정을 그대로 씀(없으면
  skipped_no_cred). 기존 "정보 수집" 백그라운드 큐(`_sw_bulk`) 공유.
- `gateway_credential()` 중앙화 — app.py의 로컬 함수를 facility.py로 이동.
- wall.js/wall.css — 세 카테고리 제목 줄에 "⟳ 전체 재수집 (N)" 버튼.

**근거**: pytest 1473 PASS. 신규 18건 수정 전 실패 확인(git stash). exe 실행
+ HTTP 200(`/`, `/wall`) 확인.

## 이전 릴리스 요약 (v6.7.x ~ v6.9.0)

- v6.9.0 관제 재수집 — 대역 전체 재스캔 → 클릭한 설비 하나만(`recollect_single_host`).
  v6.7.3 409 문제의 근본 원인(대역 전체 스캔 경합) 제거.
- v6.8.2 서버 사양 엑셀 일괄 반영(IP 매칭, 새 서버 생성 안 함).
- v6.8.1 WMI "접근 거부" = 계정 권한이 아니라 UAC 원격 제한(LocalAccountTokenFilterPolicy).
- v6.8.0 사양 수집 경로 진단 도구(`--diag-server`, CLI+화면). 네 번째 재발 대응책.
- v6.7.9 전송 보안 설정화(`core/secpolicy.py`) — ssh_host_key_policy(tofu 권장),
  verify_firewall_tls. 기본값은 현행 유지(켜면 수집이 멈출 수 있어서).
- v6.7.7/8 WinRM 사양 수집 경로 + claude-security 스캔 반영(수식 주입·엔티티 폭탄 등 5건).
- v6.7.5/6 자체 5축 보안 감사(SNMP 응답 위조·계정 잔류·DNS 리바인딩 등) — claude-security
  플러그인은 사용자가 직접 `/claude-security` 로 실행해야 함(모델이 대신 못 돌림).
- v6.7.1~4 서버 사양 수집 SSH→WinRM→WMI→SNMP 4중 폴백, MAC/포트 수집률 개선.

상세 이력은 `git log --oneline`과 각 커밋 메시지에 남아 있다 — 이 파일은 스냅샷만 유지.

## 열린 후속 항목 (미착수, 지시 없으면 손대지 않음)

실장비 확인이 필요한 것:
- FortiGate `get sys ha status` 실제 응답 필드 확인(구조는 있음, 실장비 응답 필요)
- SNMP 실장비 검증 — 폐쇄망 리눅스 서버에서 커뮤니티 설정 후 사양 수집 확인
- v6.7.7 WinRM 종단 검증 — 이 PC에 WinRM이 꺼져 있어 원격 수집 성공까지 미확인
- EXOS `show iparp` 변형(Port 컬럼 없는 버전) 파싱 — 실장비 응답 필요

우선순위 낮은 견고성 항목(v6.4.0 전수 검토에서 나왔고 아직 유효):
- `save_neighbors`/`save_vlan_names` 등 **DELETE+INSERT 루프가 비원자적** —
  예외를 `except`로 삼키고 넘어가서 부분 상태가 그대로 커밋된다
  (`core/db.py:1229` 확인. 설비 경로는 v6.4.0에서 트랜잭션화 완료, 나머지는 남음)
- `reachability._state`/`_fw_state`가 삭제된 장비 id를 영구 보유(누수) —
  `core/reachability.py:22` 확인, 프루닝 없음. 또 `_sweep`이 대상 수만큼 스레드를
  만든다(500대면 매 주기 500개)
- upsert들의 SELECT→INSERT 사이가 트랜잭션 밖 — 인스턴스 락이 정상이면 쓰기
  프로세스가 하나라 평소엔 안전(이중 주 서버일 때만 실현)
- 스캔 시작 직후의 '중지' 클릭이 삼켜짐(워커가 플래그를 초기화하는 경합)
- 승격 시 `init_collector()` 재호출로 구 워커 3개가 옛 큐에 영구 블록

## 알아둘 것 (메모리에 없는 것만)

- 릴리스 저장소 `yonguncho/netdash-m1` 은 **public**.
- 커밋 메시지에 따옴표가 있으면 PowerShell `git commit -m @'...'@` 가 깨진다
  → bash heredoc `git commit -F -` 를 쓴다.
- PowerShell here-string `@"..."@` 은 `$_` 를 치환한다 → 검증 스크립트는 파일로
  쓰고 실행한다.
- 백로그 전체 표: `NetDash_dev/docs/REVIEW_BACKLOG.md`
- **`state/pipeline_status.json` 은 낡았다**(v3.71.0 / 2026-07-11에서 멈춤).
  현재 버전 확인에 쓰지 말 것 — `git log --oneline -3` 또는 `gh release list` 를 쓴다.
  (지우지 않고 둔 이유: 내가 만든 파일이 아니고 다른 파이프라인이 읽을 수 있다)

나머지 반복 교훈(em-dash·escHtml·EncodedCommand·onTick·서브에이전트 오탐·
릴리스 링크 형식·판정 로직 수정 후 새로고침)은 세션 메모리에 있다:
`C:\Users\yongu\.claude\projects\C--AI-WORKPLACE-AI-WORKPLACE-NetDash\memory\`

## 미커밋 파일
없음 (`build/` 산출물, `.verify_tz.js`, 실패한 `CLAUDE-SECURITY-*` 스캔 폴더 제외)

## 경로·재개 절차

```
C:\AI_WORKPLACE\NetDash_dev\NetDash_RESUME.md          ← 이 파일(SSOT, 매 단계 갱신)
C:\AI_WORKPLACE\NetDash_dev\                           ← 개발본 (git repo, 메인 작업)
C:\AI_WORKPLACE\NetDash\                               ← 배포본 (exe only, git 없음)
C:\AI_WORKPLACE\AI_WORKPLACE_NetDash\NetDash_RESUME.md ← 포인터만. 내용 없음
```
SSOT를 git 저장소 안에 두는 이유: 커밋과 함께 갱신 이력이 남고, 코드와 스냅샷이
같은 시점으로 묶인다. 예전엔 저장소 밖 사본이 SSOT였는데 v6.7.0에서 갱신이 끊긴
채 방치돼(6개 릴리스 동안) 재개 시 잘못된 상태를 읽을 뻔했다.

재개 순서: ① 이 파일 읽기 → ② `git -C C:\AI_WORKPLACE\NetDash_dev log --oneline -3` +
`status --short` → ③ "다음 단계"부터 즉시 이어서 작업(재대기 금지)
