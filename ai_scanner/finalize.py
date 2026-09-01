"""Human-review finalization for scan-level diagnostic artifacts."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

try:
    from .ai_client import create_ai_client
    from .config import ScannerConfig
    from .pdf_reporter import generate_pdf
    from .policies import get_policy_mapping
except ImportError:
    from ai_client import create_ai_client
    from config import ScannerConfig
    from pdf_reporter import generate_pdf
    from policies import get_policy_mapping

LOGGER = logging.getLogger(__name__)

_REMEDIATION = {
    "SQL_INJECTION": ["Prepared Statement 및 PDO/mysqli Parameterized Query 적용", "DB 계정 최소 권한과 SQL 오류 외부 노출 제한", "입력 검증 후 동일 요청을 재검증"],
    "XSS": ["htmlspecialchars() 등 문맥에 맞는 Output Encoding 적용", "Stored/Reflected 위치별 Context-aware Encoding 적용", "CSP와 HttpOnly/Secure Cookie 설정"],
    "FILE_UPLOAD": ["Allowlist 확장자·MIME·파일 내용 검증", "파일명을 랜덤화하고 Web Root 외부에 저장", "업로드 디렉터리 실행 권한 제거·직접 접근 통제·크기 제한"],
}
EVIDENCE_MAX_CHARS = 20_000


def _redact_evidence(text: str) -> str:
    """Mask common session/API secrets before evidence reaches an AI provider."""

    patterns = [
        (r"(?im)^(\s*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|api-key)\s*:\s*).*$", r"\1[REDACTED]"),
        (r"(?i)(PHPSESSID\s*=\s*)[^;\s]+", r"\1[REDACTED]"),
        (r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
        (r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token)[\"']?\s*[:=]\s*[\"']?)[^\"'\s,}]+", r"\1[REDACTED]"),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def _evidence_bundle(root: Path, finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Read reviewer TXT evidence, redact it, and retain a bounded bundle."""

    bundle: list[dict[str, Any]] = []
    for item in finding.get("manual_evidence", []) or []:
        if not isinstance(item, dict):
            continue
        source = str(item.get("file", ""))
        path = Path(source).expanduser()
        path = path.resolve() if path.is_absolute() else (root / path).resolve()
        entry = {"type": item.get("type", "other"), "source": source, "description": item.get("description", "")}
        if path.suffix.casefold() == ".txt" and path.is_file():
            try:
                content = _redact_evidence(path.read_text(encoding="utf-8", errors="replace"))
                if len(content) > EVIDENCE_MAX_CHARS:
                    content = content[:EVIDENCE_MAX_CHARS] + "\n[TRUNCATED]"
                    entry["truncated"] = True
                else:
                    entry["truncated"] = False
                entry["content"] = content
            except OSError as exc:
                entry["error"] = f"evidence read failed: {exc}"
        elif not path.exists():
            entry["error"] = "evidence file not found"
        else:
            entry["content"] = "[NON-TEXT EVIDENCE: path and description retained]"
        bundle.append(entry)
    return bundle


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object expected: {path}")
    return data


def _selected_findings(analysis: dict[str, Any], review: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    by_id = {str(item.get("id")): item for item in analysis.get("findings", []) if isinstance(item, dict)}
    selected: list[dict[str, Any]] = []
    counts = {"confirmed": 0, "false_positive": 0, "new_findings": 0, "pending": 0}
    for item in review.get("findings", []):
        if not isinstance(item, dict):
            continue
        status = str(item.get("review_status", "PENDING")).upper()
        if status == "CONFIRMED":
            counts["confirmed"] += 1
        elif status == "FALSE_POSITIVE":
            counts["false_positive"] += 1
        elif status == "NEW_FINDING":
            counts["new_findings"] += 1
        else:
            counts["pending"] += 1
        if status not in {"CONFIRMED", "NEW_FINDING"}:
            continue
        merged = dict(by_id.get(str(item.get("id")), {}))
        merged.update({key: value for key, value in item.items() if key not in {"review_status"}})
        merged["review_status"] = status
        selected.append(merged)
    return selected, counts


def _final_report(analysis: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = ["# 최종 모의해킹 결과 보고서", "", "## 1. 진단 개요", "", f"- 대상: {analysis.get('target', {}).get('url', '-')}", f"- 최종 확인 Finding: {len(findings)}", "", "## 2. 검증된 취약점", ""]
    if not findings:
        lines.append("수동 검증에서 최종 확정된 취약점이 없습니다.")
    for index, finding in enumerate(findings, 1):
        vuln = finding.get("type") or finding.get("vulnerability_type") or "UNKNOWN"
        lines.extend([f"### 2.{index} {vuln}", "", f"- URI: `{finding.get('uri') or finding.get('path') or '-'}`", f"- Method: `{finding.get('method', '-')}`", f"- Parameter: `{finding.get('parameter') or '-'}`", f"- Severity: `{finding.get('severity', '-')}`", f"- CWE: `{finding.get('cwe') or '-'}`", f"- OWASP: `{finding.get('owasp_category') or '-'}`", f"- 검토 상태: `{finding.get('review_status')}`", "", "#### 수동 검증 메모", str(finding.get("reviewer_note") or "기록된 메모 없음"), "", "#### 수동 증적"])
        for evidence in finding.get("manual_evidence", []) or []:
            lines.append(f"- {evidence}")
        lines.extend(["", "#### 자동 분석 근거", str(finding.get("ai_reason") or "자동 분석 근거는 analysis.json을 참조하십시오."), "", "#### 증적"])
        for evidence in finding.get("manual_evidence", []) or []:
            if isinstance(evidence, dict):
                lines.append(f"- {evidence.get('type', 'other')}: `{evidence.get('file', '-')}` — {evidence.get('description', '')}")
        if not finding.get("manual_evidence"):
            lines.append("- 등록된 수동 증적이 없습니다.")
        for bundle in finding.get("evidence_bundle", []) or []:
            if bundle.get("content") and not str(bundle.get("content", "")).startswith("[NON-TEXT"):
                lines.append(f"- TXT 증적 읽기 완료: `{bundle.get('source', '-')}` ({len(bundle.get('content', ''))}자{' · 일부 생략' if bundle.get('truncated') else ''})")
            elif bundle.get("error"):
                lines.append(f"- 증적 읽기 경고: `{bundle.get('source', '-')}` ({bundle['error']})")
        baseline = finding.get("baseline")
        if isinstance(baseline, dict):
            lines.extend(["", "#### 정상 요청 비교", f"- 상태 코드 변경: {baseline.get('status_changed', '확인되지 않음')}", f"- 응답 길이 차이: {baseline.get('response_length_difference', '확인되지 않음')}", f"- 본문 유사도: {baseline.get('body_similarity', '확인되지 않음')}"])
        verification = finding.get("verification")
        if isinstance(verification, dict) and verification:
            lines.extend(["", "#### Verification 결과", f"- 상태 코드: {verification.get('status_code', verification.get('response_status', '확인되지 않음'))}", f"- 업로드/저장 결과: {verification.get('upload_paths', '별도 경로 정보 없음')}"])
        lines.append("")
    return "\n".join(lines) + "\n"


_REVIEW_STATUS_LABELS = {
    "CONFIRMED": "담당자 검증 완료 / 취약점 확인",
    "FALSE_POSITIVE": "담당자 검증 완료 / 오탐",
    "PENDING": "담당자 미검증 또는 추가 검증 필요",
    "NEW_FINDING": "담당자 수동 발견",
}


def _review_records(analysis: dict[str, Any], review: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge every automatic candidate with its reviewer state.

    The final selected list intentionally remains governed by
    ``_selected_findings``.  This separate view is for transparency: a
    missing review entry is shown as PENDING instead of disappearing.
    """
    review_items = {
        str(item.get("id")): item
        for item in review.get("findings", [])
        if isinstance(item, dict) and item.get("id") is not None
    }
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in analysis.get("findings", []):
        if not isinstance(candidate, dict):
            continue
        finding_id = str(candidate.get("id") or candidate.get("finding_id") or "")
        if not finding_id:
            continue
        merged = dict(candidate)
        reviewer = review_items.get(finding_id, {})
        merged.update(reviewer)
        merged["id"] = finding_id
        merged["review_status"] = str(
            reviewer.get("review_status") or candidate.get("review_status") or "PENDING"
        ).upper()
        records.append(merged)
        seen.add(finding_id)
    # Preserve manually added findings that do not exist in analysis.json.
    for reviewer in review.get("findings", []):
        if not isinstance(reviewer, dict):
            continue
        finding_id = str(reviewer.get("id") or "")
        if finding_id and finding_id not in seen:
            merged = dict(reviewer)
            merged["review_status"] = str(merged.get("review_status") or "PENDING").upper()
            records.append(merged)
    return records


def _report_evidence_paths(finding: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for item in finding.get("manual_evidence", []) or []:
        if isinstance(item, dict):
            source = str(item.get("file") or item.get("path") or "").strip()
            if source:
                description = str(item.get("description") or "").strip()
                paths.append(f"`{source}`" + (f" — {description}" if description else ""))
    return paths or ["등록된 증적 없음"]


def _policy_reference_lines(finding: dict[str, Any]) -> list[str]:
    """Render an optional KISA mapping for traceability in generated reports."""
    policy = finding.get("policy_reference")
    if not isinstance(policy, dict):
        return []
    item_name = policy.get("policy_item_name") or "-"
    item_number = policy.get("policy_item_number")
    item = f"{item_number}. {item_name}" if item_number else str(item_name)
    lines = [
        "",
        "#### 진단 기준 참고",
        f"- 기준 출처: {policy.get('policy_source', '-')}",
        f"- 관련 항목: {item}",
        f"- 점검 목적: {policy.get('inspection_purpose', '-')}",
        "- 점검 기준:",
    ]
    criteria = policy.get("inspection_criteria") or []
    lines.extend(f"  - {criterion}" for criterion in criteria) if criteria else lines.append("  - 등록된 기준 설명 없음")
    mapping = policy.get("indicator_mapping") or {}
    if mapping:
        lines.append("- Scanner Indicator 매핑:")
        lines.extend(f"  - `{key}`: {value}" for key, value in mapping.items())
    recommendations = policy.get("remediation_reference") or []
    if recommendations:
        lines.append("- 대응 권고 참고:")
        lines.extend(f"  - {value}" for value in recommendations)
    return lines


def _final_report_with_review(
    analysis: dict[str, Any],
    final_findings: list[dict[str, Any]],
    review: dict[str, Any],
) -> str:
    """Render review transparency and final findings in separate sections."""
    target = analysis.get("target") if isinstance(analysis.get("target"), dict) else {}
    records = _review_records(analysis, review)
    lines = [
        "# 최종 모의해킹 결과 보고서",
        "",
        "## 1. 진단 개요",
        "",
        f"- 점검 대상: `{target.get('url') or target.get('path') or '-'}`",
        f"- 자동 탐지 후보: {len(records)}건",
        f"- 최종 확정 취약점: {len(final_findings)}건",
        "",
        "## 2. 진단 후보 및 담당자 검토 현황",
        "",
    ]
    if not records:
        lines.append("검토 대상 후보가 없습니다.")
    for index, finding in enumerate(records, 1):
        status = str(finding.get("review_status") or "PENDING").upper()
        label = _REVIEW_STATUS_LABELS.get(status, status)
        vuln = finding.get("type") or finding.get("vulnerability_type") or "UNKNOWN"
        uri = finding.get("uri") or finding.get("path") or "-"
        # Excluded candidates are still reported for auditability, but their
        # scanner ID is intentionally not repeated in the final-vulnerability
        # narrative (the ID remains in review.json as the source of truth).
        display_id = finding.get("id") if status in {"CONFIRMED", "NEW_FINDING"} else f"자동 후보 {index}"
        lines.extend(
            [
                f"### 2.{index} {display_id} · {vuln}",
                "",
                f"- URI: `{uri}`",
                f"- Method: `{finding.get('method') or finding.get('http_method') or '-'}`",
                f"- Parameter: `{finding.get('parameter') or '-'}`",
                f"- 담당자 검토 상태: **{status}** ({label})",
                f"- Confidence: `{finding.get('confidence', '-')}`",
                f"- 검토 메모: {finding.get('reviewer_note') or '등록된 검토 메모 없음'}",
                "- 증적:",
            ]
        )
        lines.extend(f"  - {path}" for path in _report_evidence_paths(finding))
        lines.extend(_policy_reference_lines(finding))
        lines.append("")

    lines.extend(["## 3. 최종 확정 취약점", ""])
    if not final_findings:
        lines.append("담당자 검증 결과 최종 확정된 취약점이 없습니다.")
    for index, finding in enumerate(final_findings, 1):
        vuln = finding.get("type") or finding.get("vulnerability_type") or "UNKNOWN"
        uri = finding.get("uri") or finding.get("path") or "-"
        lines.extend(
            [
                f"### 3.{index} {finding.get('id', '-') } · {vuln}",
                "",
                f"- URI: `{uri}`",
                f"- Method: `{finding.get('method') or finding.get('http_method') or '-'}`",
                f"- Parameter: `{finding.get('parameter') or '-'}`",
                f"- 담당자 최종 판정: **{finding.get('review_status', 'CONFIRMED')}**",
                f"- Severity: `{finding.get('severity') or finding.get('final_severity') or '-'}`",
                f"- CWE: `{finding.get('cwe') or '-'}`",
                f"- OWASP: `{finding.get('owasp_category') or '-'}`",
                f"- 검토 메모: {finding.get('reviewer_note') or '등록된 검토 메모 없음'}",
                "",
                "#### 검증 증적",
            ]
        )
        lines.extend(f"- {path}" for path in _report_evidence_paths(finding))
        lines.extend(_policy_reference_lines(finding))
        if finding.get("ai_reason"):
            lines.extend(["", "#### 자동 분석 참고", str(finding["ai_reason"])])
        lines.append("")
    return "\n".join(lines) + "\n"


def _secure_guide(findings: list[dict[str, Any]], ai_draft: Any | None = None) -> str:
    lines = ["# Secure Coding Guide", "", "수동 검증에서 확인된 취약점에 대한 대응 방안입니다.", ""]
    if ai_draft is not None:
        lines.extend(["## AI 작성 요약", getattr(ai_draft, "executive_summary", ""), ""])
    for index, finding in enumerate(findings, 1):
        vuln = str(finding.get("type") or finding.get("vulnerability_type") or "UNKNOWN").upper()
        lines.extend([f"## {index}. {vuln}", "", f"- 발생 위치: `{finding.get('method', '-')} {finding.get('uri') or finding.get('path') or '-'}`", "", "### 권장 대응방안"])
        lines.extend(f"- {item}" for item in _REMEDIATION.get(vuln, ["검증된 원인에 맞는 입력 검증과 안전한 출력 처리를 적용"]))
        if ai_draft is not None:
            narratives = getattr(ai_draft, "finding_narratives", []) or []
            narrative = next((item for item in narratives if getattr(item, "finding_index", 0) == index), None)
            if narrative is not None:
                lines.extend(["", "### 적용 가이드", getattr(narrative, "overview", "")])
    lines.extend(["", "### 재검증 방법", "수정 후 동일한 Request를 재현하고, 이전에 기록한 수동 증적과 비교하여 취약 동작이 재발하지 않는지 확인합니다."])
    return "\n".join(lines) + "\n"


_SECURE_GUIDANCE = {
    "SQL_INJECTION": {
        "cause": "사용자 입력이 SQL 문장의 구조와 분리되지 않은 상태로 데이터베이스 질의에 사용될 가능성이 있습니다.",
        "impact": ["데이터베이스 정보 조회 또는 변조", "인증·권한 우회", "오류 메시지를 통한 스키마 정보 노출"],
        "remediation": [
            "PDO 또는 mysqli의 Prepared Statement와 parameter binding 사용",
            "DB 계정에 업무에 필요한 최소 권한만 부여",
            "SQL 오류와 상세 DB 예외를 외부 응답에 노출하지 않음",
            "입력 형식·길이 검증을 적용하되 검증만으로 SQL 방어를 대체하지 않음",
        ],
        "example": """```php
$stmt = $pdo->prepare('SELECT * FROM notices WHERE title = :title');
$stmt->execute([':title' => $title]);
```""",
        "recheck": ["동일 조건의 정상 요청과 테스트 요청을 Burp Repeater에서 비교", "SQL 오류·응답 데이터 증가·권한 우회가 재현되지 않는지 확인"],
    },
    "XSS": {
        "cause": "사용자 입력이 출력 문맥에 맞는 인코딩 없이 HTML, 속성 또는 JavaScript 문맥에 삽입될 가능성이 있습니다.",
        "impact": ["다른 사용자의 브라우저에서 스크립트 실행", "세션·화면 정보 탈취 위험", "저장형 XSS의 경우 다수 사용자에게 반복 노출"],
        "remediation": [
            "HTML 본문은 htmlspecialchars($value, ENT_QUOTES, 'UTF-8')로 출력 인코딩",
            "HTML 속성·JavaScript·URL 등 문맥별 Context-aware Encoding 적용",
            "CSP(Content-Security-Policy)로 스크립트 실행 범위 제한",
            "세션 Cookie에 HttpOnly·Secure·SameSite 설정",
        ],
        "example": """```php
echo htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```""",
        "recheck": ["입력 marker가 응답에 반영되는 위치와 인코딩 여부 확인", "Stored/Reflected 경로에서 브라우저 실행 여부와 CSP 적용 여부 확인"],
    },
    "FILE_UPLOAD": {
        "cause": "업로드 파일의 확장자·MIME·내용과 저장 위치에 대한 서버 측 검증이 충분하지 않을 가능성이 있습니다.",
        "impact": ["악성 파일 저장 및 직접 접근", "웹 서버에서 실행 가능한 파일 업로드", "저장 파일을 통한 서비스·정보 노출"],
        "remediation": [
            "허용 목록(allowlist) 기반 확장자·MIME·파일 내용 검증",
            "랜덤 파일명 사용 및 Web Root 외부 저장",
            "업로드 디렉터리의 실행 권한 제거와 직접 접근 통제",
            "파일 크기 제한과 저장 후 재검증 적용",
        ],
        "example": """```php
$allowed = ['text/plain' => 'txt', 'text/html' => 'html'];
$mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['file']['tmp_name']);
if (!isset($allowed[$mime])) { throw new RuntimeException('허용되지 않은 파일입니다.'); }
$name = bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
move_uploaded_file($_FILES['file']['tmp_name'], $outsideWebRoot . '/' . $name);
```""",
        "recheck": ["허용·비허용 확장자와 MIME 조합에 대한 서버 응답 확인", "저장된 경로의 직접 접근 및 서버 실행 가능성이 차단되는지 확인"],
    },
}


def _secure_coding_payload(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build an explicit, auditable payload for the Secure Coding AI call."""
    fields = (
        "id", "type", "vulnerability_type", "uri", "path", "method", "parameter",
        "parameter_location", "severity", "confidence", "review_status", "reviewer_note",
        "manual_evidence", "evidence_bundle", "ai_reason", "rules", "baseline", "verification",
        "policy_reference",
    )
    return [{key: finding.get(key) for key in fields} for finding in findings]


def _secure_guide_detailed(findings: list[dict[str, Any]], ai_draft: Any | None = None) -> str:
    """Render a finding-specific guide even when the AI call is unavailable."""
    lines = [
        "# Secure Coding Guide",
        "",
        "담당자가 CONFIRMED 또는 NEW_FINDING으로 검증한 취약점별 대응 안내입니다.",
        "",
    ]
    narratives = getattr(ai_draft, "finding_narratives", []) if ai_draft is not None else []
    for index, finding in enumerate(findings, 1):
        vuln = str(finding.get("type") or finding.get("vulnerability_type") or "UNKNOWN").upper()
        guidance = _SECURE_GUIDANCE.get(vuln, {
            "cause": "분석 결과와 담당자 검토 내용을 기준으로 입력 처리 또는 출력 처리의 보완이 필요합니다.",
            "impact": ["검증된 증적에 기재된 범위에서 영향도를 재평가"],
            "remediation": ["취약점 유형에 맞는 서버 측 검증과 안전한 출력 처리를 적용"],
            "example": "```php\n// 실제 입력·출력 지점에 맞는 검증 코드를 적용합니다.\n```",
            "recheck": ["수정 후 동일한 Request/Response 조건으로 재검증"],
        })
        finding_id = finding.get("id") or finding.get("finding_id") or f"F-{index:03d}"
        uri = finding.get("uri") or finding.get("path") or "-"
        method = finding.get("method") or finding.get("http_method") or "-"
        parameter = finding.get("parameter") or "-"
        narrative = next((item for item in narratives if getattr(item, "finding_index", 0) == index), None)
        cause = getattr(narrative, "cause", None) if narrative is not None else None
        impact_text = getattr(narrative, "impact", None) if narrative is not None else None
        lines.extend([
            f"## {index}. {finding_id} · {vuln}",
            "",
            "### 취약점 ID / 유형",
            f"- ID: `{finding_id}`",
            f"- 유형: `{vuln}`",
            f"- 담당자 판정: `{finding.get('review_status', 'CONFIRMED')}`",
            "",
            "### 취약 위치",
            f"- URI: `{uri}`",
            f"- Method: `{method}`",
            f"- Parameter: `{parameter}`",
            f"- Severity: `{finding.get('severity') or finding.get('final_severity') or '-'}`",
            f"- Confidence: `{finding.get('confidence', '-')}`",
            "",
            "### 취약 원인",
            str(cause or guidance["cause"]),
            "",
            "### 보안 영향",
        ])
        if impact_text:
            lines.append(str(impact_text))
        lines.extend(f"- {item}" for item in guidance["impact"])
        lines.extend(["", "### 대응 방안"])
        lines.extend(f"- {item}" for item in guidance["remediation"])
        lines.extend(["", "### PHP 시큐어코딩 예시", guidance["example"], "", "### 재검증 방법"])
        lines.extend(f"1. {item}" for item in guidance["recheck"])
        if finding.get("reviewer_note"):
            lines.extend(["", "### 담당자 검토 메모", str(finding["reviewer_note"])])
        bundles = finding.get("evidence_bundle") or []
        if bundles:
            lines.extend(["", "### 검증 증적 참고"])
            for bundle in bundles:
                if isinstance(bundle, dict):
                    lines.append(f"- `{bundle.get('source', '-')}`: {bundle.get('description') or '설명 없음'}")
        lines.extend(_policy_reference_lines(finding))
        lines.extend(["", "---", ""])
    return "\n".join(lines)


def finalize_scan(review_path: str | Path, *, config: ScannerConfig) -> dict[str, Any]:
    """Finalize a review file and create final_report/secure_coding artifacts."""

    started = time.perf_counter()
    review_file = Path(review_path).expanduser().resolve()
    root = review_file.parent
    analysis_file = root / "analysis.json"
    analysis = _load(analysis_file)
    review = _load(review_file)
    findings, counts = _selected_findings(analysis, review)
    for finding in findings:
        if not finding.get("policy_reference"):
            policy = get_policy_mapping(str(finding.get("type") or finding.get("vulnerability_type") or ""))
            if policy:
                finding["policy_reference"] = policy
        finding["evidence_bundle"] = _evidence_bundle(root, finding)
    LOGGER.info("[FINALIZE] confirmed=%d", counts["confirmed"])
    LOGGER.info("[FINALIZE] false_positive=%d", counts["false_positive"])
    LOGGER.info("[FINALIZE] new_findings=%d", counts["new_findings"])
    (root / "final_report.md").write_text(
        _final_report_with_review(analysis, findings, review),
        encoding="utf-8",
    )
    ai_draft = None
    calls = 0
    ai_started = time.perf_counter()
    if findings and config.ai_api_key is not None and config.ai_api_key.get_secret_value():
        try:
            client = create_ai_client(provider=config.ai_provider, api_key=config.ai_api_key.get_secret_value(), model=config.ai_model, base_url=config.ai_base_url, timeout=config.ai_timeout_seconds, max_retries=config.ai_max_retries, max_output_tokens=config.ai_max_output_tokens)
            prompt_path = config.project_dir / "prompts" / "secure_coding_guide.txt"
            instructions = prompt_path.read_text(encoding="utf-8") if prompt_path.exists() else "한국어 Secure Coding Guide를 작성하되 제공된 검증 Finding만 사용하십시오."
            calls = 1
            result = client.generate_report(
                instructions=instructions,
                input_data=json.dumps(
                    {
                        "findings": _secure_coding_payload(findings),
                        "evidence_policy": {"max_chars_per_file": EVIDENCE_MAX_CHARS, "redacted": True},
                    },
                    ensure_ascii=False,
                    default=str,
                ),
            )
            ai_draft = result
        except Exception as exc:
            LOGGER.warning("secure coding AI failed; using deterministic guide: %s", exc)
    (root / "secure_coding_guide.md").write_text(_secure_guide_detailed(findings, ai_draft), encoding="utf-8")
    for markdown_name, pdf_name, report_type in (
        ("final_report.md", "final_report.pdf", "final"),
        ("secure_coding_guide.md", "secure_coding_guide.pdf", "secure_coding"),
    ):
        try:
            pdf_path = generate_pdf(root / markdown_name, root / pdf_name, report_type)
            LOGGER.info("[PDF] %s created: %s", markdown_name, pdf_path)
        except Exception as exc:
            # A renderer problem must not discard the human-reviewed Markdown.
            LOGGER.warning("[WARN] PDF generation failed for %s: %s", markdown_name, exc)
    LOGGER.info("[AI-SECURE-CODING] findings=%d", len(findings))
    LOGGER.info("[AI-SECURE-CODING] calls=%d", calls)
    LOGGER.info("[AI-SECURE-CODING] time=%.3fs", time.perf_counter() - ai_started)
    LOGGER.info("[TOTAL] finalize=%.3fs", time.perf_counter() - started)
    return {
        "root_directory": root,
        "findings": findings,
        "counts": counts,
        "ai_calls": calls,
        "final_report_pdf": root / "final_report.pdf",
        "secure_coding_guide_pdf": root / "secure_coding_guide.pdf",
    }


__all__ = ["finalize_scan"]
