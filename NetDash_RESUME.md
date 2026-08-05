# NetDash 재개 스냅샷

**현재 버전**: v6.14.0 작업 중 (전체 테스트 진행 중)
**직전 릴리스**: v6.13.0 (커밋 2166f0e)

> **[병행 작업 · 코드 무변경 · 2026-07-31]** CHOICEGUIDELAB 포스트용 데모 스크린샷 7장을
> 고객사 식별자(`SKBA_*`) 없이 재촬영 완료. 원인은 개발용 `netdash.db`에 누적된 스테일
> 테스트 스위치(픽스처는 깨끗). `scripts/_clean_demo_for_screenshots.py`로 DB 정리(리네임 2
> ·삭제 4·토폴로지 주입), `scripts/_capture_screenshots.py`(Playwright)로 캡처+식별자 0건 검증.
> 앱 코드·커밋 무관. DB는 5대 깨끗·위치 비움으로 복원, 백업 `netdash.db.bak_screenshot`.
> 결과물: `shared/handoff/tool_posts/NetDash/`, 회신 `shared/commands/NetDash_cmd.done`+`.response`.

## 릴리스 게이트 확장 (2026-08-05, 사용자 요구 — "네가 먼저 보고 고쳐라")

pytest만으로 릴리스 금지. UI·동작 변경 릴리스는 반드시:
① `python -m pytest tests/ -q` PASS
② `python scripts/selfcheck_e2e.py` PASS — 실제 클릭(탭·상세보기·일괄수집
   모달→실행·서버실 저장/업데이트·관제 탭/기간/팝업) + pageerror/console/
   오류성 alert/undefined·NaN 검사
③ `build/selfcheck/*.png` 직접 열어 UX 자기검토(사유 없는 누락·0/0·빈 카드 금지)
새 화면 흐름을 만들면 selfcheck에 그 클릭 단계를 같이 추가한다.
상세: 메모리 `netdash_release_gate_selfcheck`. 실장비 의존 항목만 사용자 확인 요청.

## 작업 중 (v6.27.0) — 라이선스 만료일 + 객체 수 (합의된 마지막 항목)

- REST 확장: `_fetch_license`(monitor/license/status → parse_license_status:
  forticare 중첩+최상위 구독, 미보유 제외, epoch→ISO) + `_fetch_objects`
  (address/addrgrp/service/service_group/vip/ippool — format=name으로 개수만).
- merge_fw_extra extra 키에 license/objects 합류 → metrics_json 저장.
- wallstats: license_rows(만료→임박(90일)→정상 정렬), license_bad(KPI),
  objects_rows.
- 관제 방화벽 탭: KPI '라이선스 만료·임박', 정책 표에 '객체' 열(툴팁에 내역),
  라이선스 카드(전 방화벽 합본, 만료·임박 우선). 상세(fwStatusHtml)에도
  라이선스 표 + 객체 facts.
- **실화면 검증이 잡은 결함**: objByFw 정의를 사용처(polTable) 뒤에 삽입해
  렌더 전체가 죽음(콘솔 오류로 발견 — pageerror 아님) → 정의 순서 수정.

## v6.26.0 — 시계열: 이력 테이블 + 폴러 + uPlot 번들

- `metrics_history` 테이블 — kind(firewall/switch/facility/ports)별 시각 점.
  30일 보존, 폴러가 하루 1회 정리.
- `core/metrics_poller.py` — 기본 5분(⚙설정 `지표 기록 주기(분)`, 0=끔).
  FortiGate cpu/mem/sessions/temp(SNMP, 예산 8s/6s), 스위치 temp, 설비·포트는
  DB 집계(네트워크 접근 없음). 데모 모드는 SNMP 생략(가짜 IP 타임아웃 방지).
  장비 하나 죽어도 나머지 기록(테스트 고정). 실행 시간 차감 대기(주기 밀림 방지).
- `GET /api/wall/series?hours=1|24|168` (상한 720h).
- **uPlot v1.6.32 (MIT) 번들** — `web/static/vendor/uplot.*` (vendor는 기존
  xterm처럼 spec에 이미 포함). CDN 참조 없음(테스트 고정).
- 관제 위젯: 방화벽 탭 세션·CPU 추이(장비별 다중 선), 스위치 탭 포트 사용·온도
  추이, 설비 탭 온라인 설비 추이(계단 꺾임 = 장애 시각). 1h/24h/7d 전환.
  데이터 없으면 "기록 수집 중" 안내(켠 직후 빈 그래프 오해 방지).
- 시리즈 갱신 60초(5분 격자라 충분).
- **검증 중 잡은 결함 2건**: ① 30초 통계 갱신(renderStats)이 innerHTML을 다시
  그리며 차트를 지움 → renderStats 끝에서 차트 재렌더. ② `PALETTE` 정의가 이전
  블록 교체 때 유실 — 에러가 .catch에 잡혀 pageerror에 안 걸림("JS errors: none"
  인데 차트 빈 화면). console 수집으로 발견. 메모리
  `netdash_block_replace_drops_shared_defs` 기록.
- 실화면: 세션·CPU 하루 파형, 설비 온라인 계단(1240→1180→복구) 렌더 확인.

## v6.25.0 — 방화벽 현황 단순화 + get sys status + EOS/EoES

사용자 지시: 방화벽 현황은 **리스트만**(상단 통계 제거 — 관제 전담, 부하·온도
컬럼 제거), get sys status 기준 **모델·버전** 컬럼. 보유 모델 1000D/1500D/1100E
+ FortiOS 6.0~7.4 수명주기 조사.

- **수명주기 조사 결과(2026-08-04 기준, `core/fortilifecycle.py` 내장)**:
  - FG-1000D: EOO 2023-04-16 / EOS 2028-04-16 (Fortinet 공식 커뮤니티 확인)
  - FG-1500D: **EOS 2025-04-15 — 이미 지원 종료**(2개 출처 수렴, 일부 자료
    2026-12 표기 상충 → confidence에 명시)
  - FG-1100E: 수명주기 미발표(지원 중)
  - FortiOS: 6.0~7.0 **EOS 경과**(7.0은 2025-09-30), **7.2 EOS 2026-09-30 임박**,
    7.4 EoES 2026-05-11 지남/EOS 2027-11-11.
  - 표는 낡는다 — `AS_OF` 기준일을 조회 결과에 항상 포함.
- `get system status` 수집: SSH 배치에 추가 + `parse_sys_status`(모델/버전/시리얼/
  호스트네임). REST `monitor/system/status` 폴백(`_fetch_sysinfo`). 표기 우선순위:
  SSH get sys status > REST > SNMP(사용자 지정 기준이라 SSH가 덮는다).
- 방화벽 현황: fw-dashboard 제거, 제품·온도·부하 컬럼 제거 → 모델·버전 컬럼
  (+수명주기 배지: 지원 종료/EOS 임박/EoES 지남, 툴팁에 날짜·기준일).
- 관제 방화벽 카드에도 모델 + 수명주기 문구.
- **테스트가 잡은 내 실수**: 대시보드 블록 삭제 때 상세보기가 쓰는 `fwBar`까지
  지워짐(호출 시점 에러라 문법 검사 무통과) → 복구.

**남은 것(합의된 다음 단계)**: 시계열(metrics_history+폴러+uPlot 번들) — 사용자
uPlot 승인·폴링 주기 답 대기. 라이선스(REST monitor/license/status)·객체 수.

## v6.24.0 — 사용자 지적 5건: 일괄수집 버그·SNMP CPU/DISK·정돈·팝업

- **일괄 수집 "수집 오류" 버그** — app.js `_fwRunBulk`의 `.then` 핸들러가 **중복**
  돼 있었다(5559-5560행). 두 번째가 파싱된 객체에 다시 `.json()` → TypeError →
  catch. **서버는 202로 수집을 시작했는데 화면만 항상 오류**. 중복 줄 삭제 +
  인접 중복 .then 회귀 테스트.
- **SNMP에서 MEM만 나오던 건**: ① CPU — `fgSysCpuUsage`를 안 주는 펌웨어가 있어
  코어별 `fgProcessorUsage`(.4.4.2.1.2) 평균 폴백 추가(probe에도 노출).
  ② DISK — 용량 0 = 로그 디스크 없는 모델(흔함). `disk_absent` 플래그로 구분,
  상세 미터에 '없음'(정상) 표기.
- **상세의 VPN 0/0·SSL 0명 잡음** — 설정된(>0) 장비에만 표기.
- **관제 Top10 클릭** — 리디렉션 제거, 관제 안 `wsw-modal` 팝업(System
  Information식 라벨:값 표 + 포트 사용 미터). detail API에 manufacturer 주입.
- **방화벽 탭 정돈** — 카드의 터널 목록 제거(모니터링 카드로 일원화), 칩 →
  FortiGate System Information식 라벨:값 표(`fwc__tb`).

## v6.23.0 — 방화벽 탭 v3 (사용자 지적 반영) + SNMP 안내

사용자 지적: ① 어느 방화벽의 어느 터널이 끊겼는지/연결됐는지 모니터링 불가
② 정책·부하 표에 방화벽 2대만 나옴(이유 불명) ③ 도표는 목록과 짝이어야
④ SNMP 버튼 실패 — 커뮤니티를 어디 등록하는지 모름.

- 터널: **연결도 모니터링이다** — 끊김 있을 때만 보여주던 로직 제거. 장비 카드와
  'VPN 터널 모니터링' 카드(도넛+방화벽별 전체 터널 목록, 끊김 우선, 연결/끊김
  배지) 상시 표시.
- 표: 지표 없는 방화벽을 말없이 빼지 않는다 — 부하/정책 표가 **전 장비** 기준,
  없는 줄엔 `whyEmpty()` 사유("미수집 — '수집' 누르세요" / "수집 실패 — <사유>" /
  "지표 없음 — SNMP/SSH 지정 후 재수집"). "왜 2대만?"이 화면에서 답이 된다.
- 도표+목록 짝: VPN(도넛+터널목록) / 수집상태(도넛+표) / 정책(도넛+표) 한 카드씩.
- SNMP 커뮤니티 위치: **상단 ⚙설정 → "📡 SNMP" 섹션** (예전 라벨이 "서버 사양
  수집"이라 못 찾음 — 서버·온도·FortiGate 부하 공용임을 라벨·힌트에 명시).
  probe 실패 메시지에 확인 순서(커뮤니티 → 허용 호스트 → 중간 방화벽) 안내.
- 검증: Playwright 전체 펼침 캡처(wall_firewall_full.png)로 사유 줄까지 확인.

## v6.22.0 — 관제 대시보드 2차 개편

사용자 요청: 빈 공간 채우기 / Top10 리스트(클릭→상세) / 고급스러운 시각화 /
**샘플 먼저 보여줄 것** / 방화벽별 VPN 터널·정책(Firewall+Proxy)·수집상태 리스트 /
get sys perf status로 CPU·MEM·세션 / 설비 실패다발 스위치·대역 통계 / 큰 글씨.

**목업**: `build/wall_mockup.html` (브라우저로 열면 됨) — 그라데이션+글로우 막대,
순위 배지 Top10, 방화벽 장비 카드(미터+터널 목록), 수집상태·정책 표.
스크린샷 `build/wall_verify/mockup_full.png`. **사용자 승인 후 wall.js에 적용.**

**백엔드(디자인 무관, 완료)**:
- `core/firewall/fortiperf.py` — `get system performance status` 파서.
  CPU(전체 줄 idle 역산, CPU0 개별 코어 줄 무시), 메모리(신형 k단위+%/구형
  states 둘 다), 세션(1분 평균), 트래픽, 업타임. 오류 출력은 빈 dict.
- `fortisensor._ssh_run()` — SSH 1접속 다명령(관리 세션 제한 회피).
  `collect_ssh_all()` = 센서 + perf 동시 수집.
- `merge_fw_extra` — perf는 **빈 값만** 채운다(SNMP 우선). level 재계산.
- REST에 proxy-policy 수(`cmdb/firewall/proxy-policy`) 추가.
- `wallstats` 확장: fw_status_list(수집 상태+사유), policy_rows(방화벽별
  Firewall/Proxy/미사용/비활성), vpn_rows(방화벽별 up/down 터널 이름·상대IP,
  지표 없는 방화벽은 목록에서 제외 — 빈 줄 금지), facility.offline_by_switch
  (최근 7일 device_offline을 설비 연결 스위치로 대조), offline_24h.

**목업 승인됨("진행해") → UI 적용 완료**:
- wall.js 대시보드 블록 전면 교체(rankList 금은동 배지·그라데이션 글로우 막대·
  SVG 그라데이션 도넛·방화벽 장비 카드+터널 목록+미터·수집상태/정책 표).
- wall.css 대시보드 블록 교체 + 배경 라디얼 글로우 그라데이션.
- Top10 클릭 → `/#switch=<id>` 새 탭 → app.js `_openHashDetail()`이 폴링 후
  상세 패널 자동 오픈(해시는 지워 새로고침 재열림 방지).
- wallstats: top_ports/by_switch/offline_by_switch에 스위치 id(이름 유일할 때만),
  방화벽 `devices`(카드용 종합 — 지표 있는 장비만, 빈 카드 금지).
- Playwright 실화면 재검증: 3탭 모두 신디자인 렌더 확인(build/wall_verify/*.png).
- GitHub Pages 목업 공유: raw.githack.com 링크 + yonguncho.github.io 재빌드.

## v6.21.0 — 랙 배치 저장/업데이트 + 높이 저장 하드닝 + 대시보드 검증

사용자 3건: ① 랙 높이 저장 "TypeError: failed to fetch" 버그 확인 ② 서버실
배치 저장 + 업데이트 버튼(자동 갱신으로 사라지지 않게) ③ 관제 대시보드 재검증.

- **① 진단**: curl로 신고 시나리오 전 구간 재현 → 201/200/200, 프로세스 생존.
  서버 결함 아님 — 요청이 도달 전에 끊긴 것(순단·재시작·절전). 멱등 PUT을
  `_ruSavePut()`으로 모아 1회 자동 재시도, 최종 실패 시 서버 상태로 화면 복원
  (저장 안 된 배치가 화면에 남으면 저장된 걸로 오해한다). 리사이즈·이동 공용.
- **② `core/racklayout.py`** — 배치 스냅샷. 키는 (kind, **ip**): 재등록하면 id는
  바뀌어도 IP는 대개 유지된다. 💾 배치 저장 = 전체 스냅샷(0건 저장도 유효 —
  옛 보관본 잔류 방지). 🔄 업데이트 = 현황 재로딩 + **위치 빈 장비에만** 보관
  위치 복원(이미 배치된 장비는 안 건드림 — 사용자가 옮겼을 수 있다).
  유령(보관본에만 있는 장비)은 랙뷰 하단에 표시 — 조용히 사라지지 않게.
  API: GET /api/room/layout, POST /save, POST /restore.
- **③ Playwright 실화면 검증**(`scripts/_verify_wall_dashboard.py`, `build/wall_verify/*.png`):
  세 탭 모두 데이터 주입 상태로 정상 렌더 확인. 이 과정에서 **관제 제조사별
  카드가 드라이버 키(cisco_ios)를 그대로 노출**하는 걸 발견 — v6.17.0 원칙대로
  manufacturer.resolve로 묶도록 수정(cisco_ios+cisco_nxos → Cisco 합산).

## v6.20.0 — 관제를 통합 대시보드로 (탭 + 통계 차트)

사용자 정정: v6.19.0에서 방화벽 페이지에 붙인 대시보드가 아니라 **관제 페이지**가
통합 대시보드가 되어야 한다. 스위치/방화벽/설비 탭으로 나누고 각 탭에서 목록만이
아니라 그래프·표로 통계를 봐야 한다.

- `core/wallstats.py` 신규 — 집계는 **SQL 한 번**으로. 장비 수백 대에서 파이썬으로
  목록을 돌면 폴링마다 전체를 훑는다. 구획별 try로 감싸 한 곳이 실패해도 나머지는 산다.
  - 스위치: 상태·제조사·계층 분포, 포트 사용률(전체/상위 8), 경보, 도달성, 온도 상위
  - 방화벽: 상태·도달성, VPN 터널 up/down, 정책 총계·미사용·비활성, 센서 알람·PSU,
    장비별 CPU/MEM/DISK/세션, 온도
  - 설비: 온라인/오프라인, 연결지점 확인/미확인, 대역별 온라인 비율, 스위치별 설비 수
- `GET /api/wall/stats` 신규.
- `wall.html` 탭 4개(요약·장애 / 스위치 / 방화벽 / 설비). **기존 장애 목록은 요약 탭에
  그대로 유지** — 관제의 본래 목적이라 없애면 안 된다.
- `wall.js` — 인라인 SVG 도넛(stroke-dasharray) + CSS 막대. 외부 차트 라이브러리
  금지(폐쇄망 = CDN 불가). 포트 상태는 `up`/`connected` 둘 다 사용 중으로 센다
  (벤더마다 표기가 다르다).
- 통계 폴링은 30초(문제 목록은 10초 유지) — 집계 쿼리를 10초마다 돌리면 관제가
  DB를 계속 붙잡는다.

## v6.19.0 — FortiGate 센서 수집 + 방화벽 모니터링 대시보드

사용자 요청 3건: ① `execute sensor list`로 PSU·온도·암페어 수집
② 방화벽 현황을 모니터링 대시보드로(그래프·도표) ③ 장비 선택 시 VPN 터널·정책
개수·CPU/MEM/PSU/DISK 등 종합 정보.

- `core/firewall/fortisensor.py` — `execute sensor list` 파서(SSH).
  PSU/CPU/FAN/SYSTEM/POWER로 그룹핑, C·V·A·rpm 단위 분류.
  **등급은 장비가 준 alarm 플래그를 따른다** — 전압 임계를 우리가 추측하면
  12V 레일과 3.3V 레일이 같을 리 없어 오탐이 난다. 팬 0rpm만 추가로 경고.
- `fortigate.py` — `_fetch_vpn()`(IPsec 터널·SSL VPN 접속자),
  `_fetch_policy_stats()`(정책 총계·미사용·비활성). 터널은 **phase1 단위로 세고
  phase2 하나라도 up이면 up** — proxyid를 개별로 세면 개수가 부풀고 지사 장애가
  안 보인다. 정책 목록 자체는 저장하지 않는다(수천 개인 장비가 있다).
- **`collector.save_firewall_result()` 신설 — 수집 저장을 한 곳으로.**
  호출부가 셋(자동·수집버튼·일괄)인데 v6.16.0의 온도·지표가 자동 경로에만 붙어
  **'수집' 버튼으로는 안 채워지고 있었다**(내가 만든 구멍). 셋 다 이 함수를 쓴다.
- 대시보드: `#fw-dashboard`(KPI 카드 + 장비별 타일). 외부 차트 라이브러리 없이
  CSS 막대로 그린다(폐쇄망이라 CDN 불가). 검색 필터 **적용 전** 목록으로 그려
  검색 중에 KPI가 흔들리지 않게 한다.
- 상세: `fwStatusHtml()` — 부하 막대, 펌웨어/업타임/세션/HA, HA 멤버별 부하,
  VPN 터널 목록(끊긴 것 위로), 하드웨어 센서 목록(알람 위로).

**미검증**: REST 엔드포인트(`monitor/vpn/ipsec`, `monitor/firewall/policy`)와
sensor list 출력 형식은 문서·통상 형식 기준이며 실장비 확인이 필요하다.

## v6.18.0 — FortiGate SNMP 상태 지표

사용자 질문: FortiGate SNMP 연동이 가능한데 무엇을 모니터링할 수 있나.

- `core/snmp_fortigate.py` 신규 — FORTINET-FORTIGATE-MIB(1.3.6.1.4.1.12356.101)
  CPU·메모리·디스크·세션 수·펌웨어·업타임 + HA 모드/멤버별 부하·동기화.
  온도·팬은 표준 MIB이라 v6.16.0의 snmp_env가 이미 담당(중복 구현 안 함).
- **OID 실장비 미검증** — 그래서 ① 없는 항목은 그 항목만 빠지고 ② `probe()`로
  장비가 실제 무엇을 주는지 원문을 화면에서 볼 수 있게 했다
  (`POST /api/firewalls/<id>/snmp-probe`, 방화벽 행의 'SNMP' 버튼).
  v6.8.0 사양 진단과 같은 패턴 — 실장비 응답을 받아 파싱을 확정한다.
- `device_env.metrics_json` 컬럼 추가(ALTER 마이그레이션). 온도와 지표는 수집
  경로가 달라 `INSERT OR REPLACE`로 덮으면 서로를 지운다 → `ON CONFLICT DO UPDATE`로
  각자 자기 컬럼만 갱신. 회귀 테스트로 양방향 확인.
- 방화벽 표에 '부하'(CPU·MEM·세션) 컬럼.

**테스트가 잡아준 내 오류 2건**:
- `probe()`가 응답이 빈 목록일 때 "(응답 없음)" 줄을 안 만들어, 정작 '무엇이
  없는지' 묻는 진단이 답을 못 했다.
- "커뮤니티 미설정이면 SNMP를 시도조차 안 한다"고 주석·테스트에 적었는데 사실이
  아니다 — `snmp_community()`는 저장값이 없어도 **기본값 'public'을 돌려준다**.
  끄는 스위치는 `snmp_enabled`뿐이다. v6.16.0 주석·테스트까지 함께 정정.

## v6.17.0 — 제조사(벤더사)와 제품 분리

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
