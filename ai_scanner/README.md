# REDRED AI 취약점 진단기

로컬 REDRED PHP/MariaDB 실습 서버에서 수집한 HTTP Request/Response를 분석해 SQL Injection, XSS, File Upload 근거를 구조화된 JSON과 Markdown 보고서로 저장합니다. 서버 코드는 수정하지 않으며, `ai_scanner`는 독립 실행됩니다.

## 구조

`main.py` → `pipeline.py` → 요청 파서/파라미터 추출 → 응답 분석/비교 → Rule Indicator → (선택) OpenAI 분석 → Pydantic 검증 → `analysis.json` → `report.md`

`scanner_adapter.py`는 Burp 또는 자체 Scanner의 envelope를 canonical `ScanInput`으로 변환하는 경계입니다. Stored XSS와 업로드 접근 검증은 선택적인 `verification` 교환으로 전달합니다.

`raw_http_parser.py`는 Burp 원문 파일을 같은 canonical 모델로 변환하며, 이후 분석기는 JSON 입력과 raw 입력을 구분하지 않습니다.

## 설치

```powershell
cd D:\REDRED\ai_scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

`.env`에는 API 키를 저장합니다. 키를 코드나 Git에 넣지 마십시오.

```dotenv
AI_MODE=auto
AI_PROVIDER=openai
AI_API_KEY=
AI_MODEL=gpt-5-mini
```

## 실행

```powershell
python main.py --input samples/sql_injection.json --mode rules
python main.py --input samples/sql_injection.json --mode ai
python main.py --input samples/sql_injection.json --mode auto
python main.py --request samples/raw_request.txt --response samples/raw_response.txt --mode rules
```

저장 위치는 `results/<scan_id>/input.json`, `analysis.json`, `report.md`입니다. `rules` 모드는 네트워크/API 키가 필요 없고, `auto` 모드는 AI 실패 시 명시적으로 Rule 기반 fallback을 사용합니다.

## 입력 형식

필수 필드는 `request`와 `response`입니다. `baseline`은 정상 교환, `verification`은 저장형 XSS 또는 업로드 파일 접근 확인 교환입니다.

```json
{
  "schema_version": "1.0",
  "scan_id": "scan-demo-001",
  "capture_type": "captured",
  "request": {
    "method": "GET",
    "url": "http://192.168.94.128/department_resources.php?dept=marketing&keyword=test",
    "path": "/department_resources.php",
    "headers": {"Host": "192.168.94.128"},
    "parameters": {"dept": "marketing", "keyword": "test"},
    "body": ""
  },
  "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "..."},
  "baseline": null,
  "verification": null
}
```

`capture_type`은 실제 Scanner 자료에는 `captured`, 발표용 fixture에는 `synthetic_fixture`를 사용합니다. 샘플의 Response는 실제 서버 캡처가 아니라 파이프라인 시연용 fixture이므로 실제 진단 결론으로 사용하지 않습니다. 바이너리 파일 본문은 보내지 않고 파일명, MIME, 크기, preview/해시 등 메타데이터만 사용합니다.

## Raw HTTP 입력

Burp에서 복사한 원문을 각각 파일로 저장하면 JSON 변환 없이 실행할 수 있습니다.

```powershell
python main.py --request raw_request.txt --response raw_response.txt --mode ai
```

정상 기준 교환과 저장형 XSS/업로드 접근 확인 교환도 지원합니다.

```powershell
python main.py --request raw_request.txt --response raw_response.txt `
  --baseline-request baseline_request.txt --baseline-response baseline_response.txt `
  --verification-request verification_request.txt --verification-response verification_response.txt `
  --mode rules
```

`raw_http_parser.py`는 요청의 method/path/URL/header/query/cookie/form/JSON/multipart를 추출하고, 응답의 상태 코드/header/body/바이트 길이를 추출합니다. multipart 파일은 filename, content-type, 확장자, 크기와 짧은 preview만 canonical 모델에 보존하며 바이너리 전체를 AI 입력으로 보내지 않습니다. `--input` JSON 방식은 기존과 동일하게 동작합니다.

## 출력

`analysis.json`은 `AnalysisResult` Pydantic 모델로 검증됩니다. 각 finding에는 `status`(CONFIRMED/POSSIBLE/NOT_CONFIRMED), `severity`, `confidence`, URI, method, parameter/location, request/response evidence, baseline comparison, CWE, OWASP, 영향과 대응 방안이 포함됩니다. `is_vulnerable`은 CONFIRMED가 있을 때만 true입니다.

보고서는 JSON을 유일한 사실 원천으로 사용하고 한국어로 렌더링합니다. AI 문장 생성이 실패하거나 근거/구조 검증을 통과하지 못하면 deterministic renderer로 자동 fallback합니다. 대응책은 취약점 종류별로 분리됩니다.

## 최종 서버 기준 입력 포인트

| 유형 | 파일/URI | Method | 파라미터·위치 | 현재 코드 특징 |
|---|---|---|---|---|
| SQL Injection | `department_resources.php` `/department_resources.php` | GET | `keyword` query | 검색 SQL의 LIKE 문자열에 직접 연결 |
| SQL Injection | `resource.php` `/resource.php` | GET | `keyword` query | 첨부파일 검색 SQL에 직접 연결 |
| SQL Injection | `notices.php` `/notices.php` | GET | `keyword` query | 공지 검색 SQL에 직접 연결 |
| SQL Injection | `login.php` `/login.php` | POST | `employee_number`, `password` form | 로그인 SQL에 직접 연결 |
| Stored XSS | `notices.php` `/notices.php` | POST → GET | `title`/`content` form | 저장 후 목록 제목이 encoding 없이 출력되는 흐름 |
| File Upload | `upload.php` `/upload.php` | POST | `file` multipart | 확장자/MIME/내용 검증 없이 `uploads/resource/` 저장 |
| File Upload | `department_resources.php` `/department_resources.php` | POST | `resource_file` multipart | 부서별 업로드 디렉터리에 저장, 검증 부족 |

XSS와 File Upload는 요청 하나만으로 실행/접근을 확정하지 않습니다. 실제 저장/접근 Response를 `verification`으로 제공해야 CONFIRMED 판단이 가능합니다.

## DB 스키마 확인

데이터베이스 스키마와 초기 데이터는 저장소 루트의 `database/`에 있습니다. PHP 서버의 실제 쿼리와 스키마가 일치하는지는 배포 전에 `database/company_portal_full.sql`을 기준으로 확인하세요.

## 테스트

```powershell
cd D:\REDRED
python -m pytest ai_scanner/tests -q
python -m ai_scanner.main --input ai_scanner/samples/sql_injection.json --mode rules
```

실제 Scanner가 완성되면 출력 payload를 `normalize_scanner_payload()`에 넘겨 `ScanInput.model_validate()` 후 기존 pipeline을 호출하면 됩니다. 핵심 분석 모듈은 URI나 PHP 파일명을 하드코딩하지 않습니다.

## Active Scan

로컬 실습 서버를 대상으로만 제한된 능동형 스캔을 실행할 수 있습니다.

```powershell
python main.py --target http://192.168.94.128 --scan --mode rules
python main.py --target http://192.168.94.128 --scan --mode ai --cookie "PHPSESSID=xxxxx"
# One page only (does not follow links)
python -m ai_scanner.main --target http://192.168.94.128/notices.php --scan --scan-mode endpoint --mode rules
python -m ai_scanner.main --target "http://192.168.94.128/REDRED/notices.php?mode=write" --scan --scan-mode single --mode rules

```

Active scan scope/performance: `--scan-mode single` analyzes only the specified page, `--scan-mode endpoint` (recommended for a PHP endpoint) follows query/mode variations while keeping the seed path fixed, and `--scan-mode crawl` (default) follows same-origin HTML links within the configured limits. Runtime logs use `[CRAWL]`, `[DISCOVER]`, `[SCOPE-SKIP]`, `[FORM]`, `[PARSE]`, `[RULES]`, `[VERIFICATION]`, `[AI]`, and `[TOTAL]`; AI mode skips exchanges without rule-based candidate evidence.
Use `--max-pages`, `--max-depth`, `--delay-ms`, `--timeout`, and `--max-tests` to cap demo scan cost.

Human-in-the-loop workflow:

1. Active Scan creates `analysis.json`, `diagnostic_guide.md`, and `review.json` in one `active-scan-*` directory.
2. A reviewer edits `review.json` using `CONFIRMED`, `FALSE_POSITIVE`, or `NEW_FINDING` and adds notes/evidence.
3. Run `python -m ai_scanner.main --review results/active-scan-YYYYMMDD-HHMMSS/review.json` to record status, reviewer notes, and evidence paths without editing JSON directly.
4. Run `python -m ai_scanner.main --finalize results/active-scan-YYYYMMDD-HHMMSS/review.json` to read TXT evidence (UTF-8, max 20,000 characters per file, sensitive headers redacted) and create `final_report.md` and `secure_coding_guide.md`.

기본 제한은 `max_depth=3`, `max_pages=50`, 요청 간격 350ms, 입력 테스트 100회입니다. `--max-depth`, `--max-pages`, `--delay-ms`, `--max-tests`로 줄일 수 있습니다. `localhost`, loopback, RFC1918 사설 IP만 허용하며 공인 IP/도메인과 외부 Origin redirect는 거부합니다. logout/delete/remove/destroy 계열 경로는 탐색 및 테스트에서 제외합니다.

Crawler는 동일 Origin의 링크와 HTML form, input/textarea/select/file을 발견합니다. 텍스트 입력에는 제한된 SQLi/XSS 식별용 payload를, 파일 입력에는 `redred_test.txt`와 `redred_test.html`만 사용합니다. 웹셸, 리버스셸, DB 삭제/OS 명령 payload는 사용하지 않습니다.

Active Scan 결과는 다음에 저장됩니다.

```text
results/active-scan-YYYYMMDD-HHMMSS/
  discovered_pages.json
  discovered_inputs.json
  raw_captures/
  findings/finding-001/{input.json,analysis.json,report.md}
  scan_summary.json
  scan_summary.md
```

Active Scanner는 최종 취약점 판정을 하지 않고 각 교환을 기존 `run_pipeline()`으로 전달합니다. 따라서 JSON/raw 입력과 동일한 Rule/AI/Pydantic/보고서 검증 경로를 사용합니다.

multipart 업로드는 `requests`의 `files=` 인자로 전송하며 `Content-Type`을 수동 지정하지 않습니다. 라이브러리가 생성한 boundary가 포함된 실제 요청 헤더를 캡처하고, 일반 form field와 파일 메타데이터를 함께 분석합니다. 개별 업로드 probe가 실패해도 나머지 페이지·입력 테스트는 계속 수행됩니다.
## PDF reports

Markdown remains the source of truth. After a scan, the local renderer creates
`diagnostic_guide.pdf`; after Finalize it creates `final_report.pdf` and
`secure_coding_guide.pdf` beside their Markdown files. PDF rendering never
calls the AI API.

The renderer tries WeasyPrint (if installed), then ReportLab, and finally a
dependency-free PDF fallback. Installing `reportlab` from `requirements.txt`
is recommended on Windows. A Korean TTF such as Malgun Gothic (Windows) or
Nanum/Noto Sans CJK (Linux) is selected automatically when available.
Registered screenshots are embedded when supported; missing images are safely
ignored. TXT evidence stays summarized and is not dumped wholesale into PDFs.

If PDF generation fails, a warning is logged and the Markdown/JSON artifacts
remain valid, so Scan and Finalize still complete.

## KISA Policy Mapping

`policies/kisa_policy_mapping.json` maps the three supported findings to the
Web(웹) checklist in KISA's 「주요정보통신기반시설 기술적 취약점 분석·평가
방법 상세가이드」: SQL 인젝션 (Web item 5), 크로스사이트 스크립팅 (item 11),
and 파일 업로드 (item 22). The official 목차 does not expose a separate item
code for these Web entries, so `policy_item_id` is intentionally `null` rather
than an invented identifier. The mapping is advisory: it enriches candidate
evidence and reports but never changes the Rules or Human Review decision.
