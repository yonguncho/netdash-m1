<#
  NetDash 리뷰 게이트 — Codex 단독 리뷰를 Opus 4.8 3렌즈 그레이더 패널로 상향 (2026-07-11).
  기존: NetDash_ResumeCodexReview가 Codex 단독(다운 시 Opus 폴백).
  개선: 공용 게이트(Opus 3렌즈 정확성/보안/명세)를 주 검증자로, Codex는 이종 보조 투표.
  PIPELINE_PATTERNS.md 4절 3번 개선안.

  사용법(마일스톤 릴리스 전):
    powershell -File scripts\review_gate.ps1          # 변경 파일만
    powershell -File scripts\review_gate.ps1 -Full    # 전체
#>
param([switch] $Full)

$ND    = Split-Path $PSScriptRoot -Parent
$gate  = "C:\AI_WORKPLACE\shared\project_review_gate.ps1"
$rubric = Join-Path $ND "docs\design\netdash-review-rubric.md"   # 있으면 사용
if (-not (Test-Path $gate)) { Write-Error "공용 게이트 없음: $gate"; exit 2 }

$rubricArg = if (Test-Path $rubric) { $rubric } else { "" }
& $gate -CodePath $ND -ChangedOnly (-not $Full) -RubricFile $rubricArg -UseCodex $true
exit $LASTEXITCODE
