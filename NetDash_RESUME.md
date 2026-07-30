# NetDash 재개 스냅샷

**현재 버전**: v6.11.0 (커밋 e02d10d, origin/master 푸시·릴리스 발행 완료)
**상태**: 백로그 비었음 — 다음 지시 대기

## 방금 완료한 것 (v6.11.0) — 업링크 트렁크 오판 + 이력/설명 보강

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

- FortiGate `get sys ha status` 실제 응답 필드 확인(구조는 있음, 실장비 응답 필요)
- SNMP 실장비 검증 — 폐쇄망 리눅스 서버에서 커뮤니티 설정 후 사양 수집 확인
- v6.7.7 WinRM 종단 검증 — 이 PC에 WinRM이 꺼져 있어 원격 수집 성공까지 미확인

## 미커밋 파일
없음 (`build/` 산출물, `.verify_tz.js`, 실패한 `CLAUDE-SECURITY-*` 스캔 폴더 제외)

## 경로·재개 절차

```
C:\AI_WORKPLACE\NetDash_dev\                          ← 개발본 (git repo, 메인 작업)
C:\AI_WORKPLACE\NetDash\                              ← 배포본 (exe only, git 없음)
C:\AI_WORKPLACE\AI_WORKPLACE_NetDash\NetDash_RESUME.md ← 이 파일(SSOT, 매 단계 갱신)
```

재개 순서: ① 이 파일 읽기 → ② `git -C C:\AI_WORKPLACE\NetDash_dev log --oneline -3` +
`status --short` → ③ "다음 단계"부터 즉시 이어서 작업(재대기 금지)
