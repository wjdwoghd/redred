# AI Scanner Dashboard

웹 취약점 진단의 `데이터 생성 → 수집 → 연결 → 분석 → 시각화` 흐름과 두 차례의 AI 판단을 보여주는 독립형 Streamlit 대시보드입니다.

1. `1차 자동 스캔 시작`: 취약점 후보, 초기 위험도, 신뢰도를 조회합니다.
2. 담당자가 검토 메모와 캡처·HTTP 기록·로그·PDF 등의 증적을 등록합니다.
3. `증적 반영 재분석 실행`: 검토와 증적을 스캐너 경계에 제출하고 최종 위험도를 조회합니다.

현재 기본값은 완전한 모의 동작입니다. 대상 서버 공격, 외부 API 호출, 모델 학습, 가짜 PDF 생성을 수행하지 않습니다. 첨부된 PDF 화면은 표시 항목을 설계하는 참고 자료로만 사용하며 데이터로 파싱하지 않습니다.

## 실행

PowerShell에서 다음 명령을 실행합니다.

```powershell
cd C:\redred\ai_scanner_dashboard
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

종료는 실행 터미널에서 `Ctrl+C`입니다.

## 동작 모드

환경변수 `SCANNER_MODE`로 데이터 공급 방식을 바꿉니다. `.env.example`은 키 이름을 보여주는 예시일 뿐 자동 로딩되지 않으며, 실제 비밀값을 저장하면 안 됩니다.

| 모드 | 화면 배지 | 현재 동작 |
|---|---|---|
| `mock` | `시연 모드 · Mock Data` | 번들 JSON으로 두 단계 흐름을 완전히 시연 |
| `filesystem` | `결과 조회 모드 · Local Files` | 기존 `active-scan-*` 폴더를 읽기 전용으로 조회 |
| `cli` | `연동 대기 · CLI` | 명령 규격이 없으므로 실행하지 않고 설정 안내 |
| `rest` | `연동 대기 · REST` | API 규격이 없으므로 요청하지 않고 설정 안내 |
| `tool` | `연동 대기 · AI Scanner` | 실제 툴 이식을 위한 명시적 TODO 경계 |

Filesystem 모드 예시:

```powershell
$env:SCANNER_MODE = "filesystem"
$env:SCANNER_RESULTS_DIR = "D:\REDRED\ai_scanner\results"
python -m streamlit run app.py
```

이 모드는 수정 시각 기준 최신 `active-scan-*` 폴더를 선택하고 `scan_result.json`, `result.json`, `review.json`, 그 밖의 JSON 순으로 결과를 찾습니다. `diagnostic_guide.pdf`, `final_report.pdf`, `secure_coding_guide.pdf`가 실제로 존재할 때만 다운로드 버튼이 활성화됩니다. 원본 결과나 `review.json`을 수정하지 않습니다.

## 이식 호환 구조

```text
Streamlit UI
  └─ ScannerService
      └─ ScannerAdapter
          ├─ MockScannerAdapter
          ├─ FilesystemScannerAdapter
          ├─ CliScannerAdapter
          ├─ RestScannerAdapter
          └─ ToolScannerAdapter
      └─ scanner_result_normalizer
          └─ ScanResult / Finding / Evidence / ReportArtifacts
```

UI는 오직 `ScannerService`와 표준 모델만 사용합니다. 실제 AI Scanner 코드를 받으면 주로 다음 두 파일만 수정합니다.

- `adapters/tool_adapter.py`: 실제 함수·CLI·REST 호출과 검토/증적 전달
- `normalizers/scanner_result_normalizer.py`: 실제 출력 필드명을 표준 모델로 매핑

어댑터가 지켜야 할 메서드 계약은 다음과 같습니다.

```python
health_check()
run_initial_scan(target_url)
submit_review(scan_id, reviews, evidence)
run_reanalysis(scan_id)
get_scan_result(scan_id)
get_report_artifacts(scan_id)
```

표준 모델은 누락 값을 허용하므로 일부 필드가 없거나 새로운 취약점 유형이 들어와도 화면 전체가 중단되지 않습니다. 실제 연결 절차는 [integration_checklist.md](integration_checklist.md)를 확인하세요.

## 증적과 비밀정보 처리

- 업로드 허용: PNG/JPG, TXT/LOG, JSON, PDF
- 업로드 내용은 현재 Streamlit 세션 메모리에만 보관
- 업로드 파일 실행, 취약 서버 전송, 결과 폴더 기록 없음
- API 키는 UI·로그·오류 메시지에 표시하지 않음
- 보고서 로컬 경로는 UI에 표시하지 않음

## 테스트

```powershell
cd C:\redred\ai_scanner_dashboard
python -m unittest discover -s tests -v
```

테스트는 mock 2단계 흐름, filesystem 읽기, 실제 PDF 존재 여부, Windows/POSIX 경로, 누락·알 수 없는 필드, 잘못된 JSON, CLI/REST 미설정 시 무호출을 확인합니다.

## 기존 서버와 분리

모든 코드는 `ai_scanner_dashboard` 내부에 있습니다. 상위의 PHP·HTML·CSS·JavaScript·SQL·DB 설정을 import하거나 수정하지 않으며, 취약 서버를 실행·중지·스캔하지 않습니다.
## Active-scan result integration

Filesystem mode is read-only. The adapter selects the newest `active-scan-*`
directory and builds an in-memory dashboard view from `scan_summary.json`,
`analysis.json`, and `review.json`; none of those files is rewritten.

The dashboard shows pages scanned, forms discovered, inputs tested, finding
type/URI/method/parameter, initial severity, confidence, Rules and HTTP
evidence, Diagnostic AI reason, and reviewer status. Human evidence is counted
only from the dedicated `evidence/` directory. Scanner internals such as
`raw_captures/` and nested finding `input.json` files are not evidence, which
prevents every finding from incorrectly showing the same count.

`diagnostic_guide.pdf` remains downloadable and is previewed in the page with
`st.pdf()` when supported by the installed Streamlit version. Missing
`final_report.pdf` or `secure_coding_guide.pdf` continues to appear as an
unavailable report.
## Filesystem review persistence

In `filesystem` mode, saving a reviewer status or evidence writes to the
currently selected `active-scan-*` directory. Status values are normalized to
the scanner schema (`CONFIRMED`, `FALSE_POSITIVE`, `PENDING`) and notes are
stored as `reviewer_note`. Uploaded files are written below
`evidence/<finding-id>/` and referenced from `review.json`. The adapter uses an
atomic JSON replacement and never starts a scan.

The reanalysis button calls the existing `ai_scanner.finalize_scan()` flow.
Only `CONFIRMED` and `NEW_FINDING` entries are finalized; false positives and
pending entries are excluded.

## 실제 Scanner 실행 모드

Dashboard에서 URL을 입력하고 `1차 자동 스캔 시작`을 눌러 기존
`ai_scanner.main`을 호출하려면 다음처럼 설정합니다.

```powershell
$env:SCANNER_MODE = "active"
$env:SCANNER_ANALYSIS_MODE = "rules"   # auto, ai 또는 rules
$env:SCANNER_SCAN_MODE = "endpoint"    # single, endpoint 또는 crawl
$env:SCANNER_PROJECT_DIR = "D:\REDRED"
$env:SCANNER_RESULTS_DIR = "D:\REDRED\ai_scanner\results"
$env:SCANNER_COOKIE = "PHPSESSID=..."   # 필요할 때만 설정
python -m streamlit run app.py
```

이 모드는 입력한 URL을 `--target`으로 전달하고 `--scan-mode endpoint`를
사용합니다. 실행 전 결과 디렉터리를 스냅샷하고, 성공 후 이번 실행에서
새로 만들어진 `active-scan-*` 디렉터리만 명시적으로 선택합니다. 실행 실패
또는 새 결과가 생성되지 않은 경우 이전 결과를 대신 표시하지 않습니다.
기존 `filesystem` 모드는 계속 읽기 전용으로 최신 결과를 조회합니다.
