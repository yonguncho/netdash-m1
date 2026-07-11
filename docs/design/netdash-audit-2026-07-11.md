# NetDash v3.71.0 전체 버그·기능 검증 보고서 (2026-07-11)

4개 영역(수집/파서, API/DB, 웹 UI, 부가모듈) 병렬 정밀 리뷰 + 상위 발견 8건 실행 교차검증.
IPAM 비교·SWOT는 별도 문서 `netdash-ipam-swot.md`.

## 교차검증 완료 (8건 전부 재현 확정)

| # | 발견 | 재현 결과 |
|---|---|---|
| CV1 | log_analyzer 연말 경계 flap 억제 | ✅ 재현 → **수정 완료** |
| CV2 | extreme isdigit 유니코드 int 크래시 | ✅ 재현 → **수정 완료** |
| CV3 | Arista MAC 테이블 전량 유실(Moves 컬럼) | ✅ 파싱 0/2건 |
| CV4 | Arista ARP 유실(Vlan100, Ethernet2) | ✅ 파싱 0/2건 |
| CV5 | raw_outputs 경로 탈출(절대경로/`..`) | ✅ `C:\evil`로 탈출 |
| CV6 | UI encodeURIComponent 작은따옴표 미인코딩 | ✅ 속성 파괴 |
| CV7 | escHtml 작은따옴표 미이스케이프 | ✅ 미이스케이프 |
| CV8 | import_switches_bulk vendor="" 덮어쓰기 | ✅ 코드 확정 |

## 심각도별 발견 종합

### 🔴 즉시 수정 대상 (재현 확정, 실사용 영향 큼)

| ID | 위치 | 문제 | 상태 |
|---|---|---|---|
| B1 | log_analyzer.py | **[내 v3.71 회귀]** 연말 경계 실제 flap 완전 억제 | ✅ 수정(롤오버 보정) |
| B2 | extreme_exos.py:66 | **[내 v3.71]** 유니코드 숫자→int ValueError로 수집 빈 데이터 "성공" | ✅ 수정(isascii 가드) |
| B3 | collector.py:1216 `_save_raw_outputs` | **[보안]** 스위치 이름 경로 탈출 → config(비밀 포함)를 드라이브 임의 위치 기록 | 미수정 |
| B4 | collector.py:711/947 | mac 명령 1회 실패 → 이전 스냅샷 전체가 허위 disconnect 이벤트 수천 건 | 미수정 |
| B5 | arista_eos.py:174 | Arista MAC 테이블 Moves/Last Move 컬럼 → 전량 유실 | 미수정 |
| B6 | arista_eos.py:211 | Arista ARP `Vlan100, Ethernet2` 이중 인터페이스 → 유실 | 미수정 |
| B7 | cisco_nxos.py:169 | `port-channel10 is up` 헤더 미매칭 → Po 포트 영구 누락 | 미수정 |
| B8 | neighbors.py:87 | IOS/NX-OS LLDP detail(`Local Intf:`) 미지원 → CDP 비활성 장비 이웃 0건 | 미수정 |
| B9 | app.js escHtml/encodeURIComponent | 작은따옴표 포함 장비 데이터(SSH 오류)가 data-payload 속성 파괴 → 버튼 무반응 + 삭제버튼 위조 | 미수정 |
| B10 | app.js:3661 | 5초 폴링이 스위치 표 재렌더 → 체크박스 선택 소실(선택 삭제/일괄 불가) | 미수정 |
| B11 | db.py import_switches_bulk | 엑셀 재업로드 시 기존 note/location/vendor 리셋(데이터 손실) | 미수정 |

### 🟡 major/medium (동작 결함, 확신도 높음)

| ID | 위치 | 문제 |
|---|---|---|
| M1 | notifier.py:119 | "60초 묶음"이 실제로는 debounce → 알람 폭주 시 이메일 무기한 지연 |
| M2 | reachability.py:118 | 첫 루프 DB 예외 시 `interval` NameError → 감시 스레드 침묵 사망 |
| M3 | collector.py:604 | `-Main` 호스트네임 장비를 Alteon으로 오분류 후 검증 전 DB 선갱신 → 수집 불능 |
| M4 | collector.py:1232 `_parse_outputs` | 파서 내부 ValueError를 "parser_not_found"로 오분류·삼킴 → B4 캐스케이드 |
| M5 | swcard-<id> DOM id 중복 | 현황판/서버실 그리드 id 충돌 → 서버실 카드 클릭 무반응(간헐) |
| M6 | app.js 터미널 백드롭 | 백드롭 닫기 시 closeTerminal 미호출 → SSH WS 세션 방치 |
| M7 | app.js 위치필터 | 위치 필터 변경 시 _bulkSel 미해제 → 숨긴 장비가 수집/삭제 대상 잔류 |
| M8 | db.py delete_switch | config_backups/enable_secret 등 파생 데이터 미정리 → 삭제 장비 config 계속 다운로드 가능 |
| M9 | app.py firewall collect | 방화벽 동시 수집 가드 없음(스위치는 있음) |
| M10 | excel_loader.py:223 | `/api/upload` 경로가 이름/위치에 _norm 적용 → "Seoul DC" → "seouldc" 표기 훼손 |
| M11 | extreme_exos _parse_port_errors | Tx Coll/Deferred(정상 카운터)를 out_errors 합산 → half-duplex 오탐 |

### 🟢 low (경미·잠복·표기)
app.py device_type 화이트리스트 단건 PUT 누락 / XFF 감사로그 위조 / 비ASCII 토큰 500 / username `\|` DPAPI 오염 / 토큰파일 ACL 미적용 / facility subnet SSRF유사 / 단건 collect rate_limit 없음 / renderSwitchTable 가드 역전 / VLAN 로드실패 placeholder 잔류 / 감사라벨 끊긴 라우트 / connectivity 벤더별칭 불일치 / netbind 소켓 미종료 / notifier kind 한글 누락 등 (상세는 각 영역 리포트).

## 기능 실재 검증 결과 (RELEASE_NOTES v3.26~v3.71)

**전 기능 존재 확인, 라우트 끊김/부재 없음.** 18개 기능(알람·도달성·이동감지·자동스캔·config백업/diff·토폴로지·이메일·월보드·포트이력·감사로그·방화벽HA·PaloAltoHA·인터랙티브토폴로지·flap윈도우·멀티벤더·보고서·예열) 모두 코드+API 라우트 연결 확인. 단 2건 부분 결함: ① 감사 라벨이 죽은 라우트 참조(import-inventory 기록 누락), ② wall.js가 토큰 미전송(원격 바인딩 시 401).

## 결론
- **크리티컬한 기능 부재는 없음** — 릴리스 주장 기능은 실재.
- **데이터 정확성 버그가 집중** — Arista/NX-OS 파서 유실(B5~B8), mac실패 오탐(B4)은 "실측 신뢰성"이 핵심 가치인 제품에서 우선순위 최상위.
- **보안 1건**(B3 경로탈출)은 즉시 수정 권장.
- 내가 만든 v3.71 회귀 2건(B1/B2)은 이미 수정.
