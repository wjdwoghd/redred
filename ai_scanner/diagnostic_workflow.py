"""Aggregate Active Scan evidence into a human-verification work package."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from pydantic import BaseModel

try:
    from .ai_client import create_ai_client
    from .config import ScannerConfig
    from .models import AnalysisDraft
    from .policies import get_policy_mapping
except ImportError:
    from ai_client import create_ai_client
    from config import ScannerConfig
    from models import AnalysisDraft
    from policies import get_policy_mapping

LOGGER = logging.getLogger(__name__)

_VERIFY_STEPS = {
    "SQL_INJECTION": [
        "정상 요청과 테스트 요청을 Burp Repeater에서 재전송하고 상태 코드·응답 길이·오류 메시지를 비교합니다.",
        "입력 문자열만으로 확정하지 말고 DB 오류 또는 재현 가능한 응답 차이를 확인합니다.",
    ],
    "XSS": [
        "입력값이 응답에 반영되는지 확인합니다.",
        "HTML·속성·JavaScript 문맥의 인코딩 여부와 Stored/Reflected 여부를 브라우저와 Burp에서 확인합니다.",
    ],
    "FILE_UPLOAD": [
        "확장자·MIME·파일 내용 검증 결과를 확인합니다.",
        "업로드 성공 여부와 저장 경로의 직접 접근 가능성을 별도 요청으로 확인합니다.",
    ],
}


def _dump(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=False)
    if isinstance(value, dict):
        return {str(k): _dump(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dump(v) for v in value]
    return value


def _target(url: str) -> dict[str, str]:
    parsed = urlsplit(url)
    return {"method": "GET", "url": url, "path": parsed.path or "/"}


def _vuln_name(value: Any) -> str:
    return {"SQL_INJECTION": "SQL Injection", "XSS": "XSS", "FILE_UPLOAD": "File Upload"}.get(str(value or "").upper(), str(value or "미분류"))


def _confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value or 0)))
    except (TypeError, ValueError):
        return 0.0


def _priority(value: float) -> str:
    return "높음" if value >= 0.7 else "일반" if value >= 0.5 else "참고"


def _ko_text(value: Any) -> str:
    text = str(value or "").strip()
    translations = {
        "SQL-like input present": "SQL 문법으로 해석될 수 있는 입력이 포함되었습니다.",
        "SQL-like special characters or operators were present": "SQL 특수문자 또는 연산자가 입력에 포함되었습니다.",
        "database error or strong baseline delta": "데이터베이스 오류 또는 정상 요청과의 큰 응답 차이가 관찰되었습니다.",
        "no strong response confirmation": "응답만으로 확정할 강한 근거는 확인되지 않았습니다.",
        "exact input reflected": "입력값이 응답에 그대로 반영되었습니다.",
        "no executable context": "실행 가능한 XSS 문맥은 확인되지 않았습니다.",
        "dangerous file metadata": "위험한 파일 확장자 또는 MIME 메타데이터가 확인되었습니다.",
        "upload success and path": "업로드 성공과 접근 경로가 함께 확인되었습니다.",
        "reflection context: attribute": "입력값이 HTML 속성 문맥에 반영되었습니다.",
    }
    if text in translations:
        return translations[text]
    return text if any("\uac00" <= char <= "\ud7a3" for char in text) else f"관찰 항목: {text}"


def _candidate_record(outcome: Any, finding: Any) -> dict[str, Any]:
    data = _dump(finding)
    location = data.get("location", {})
    vuln = str(data.get("vulnerability_type", "")).upper()
    record = {
        "type": vuln, "vulnerability_type": vuln,
        "uri": location.get("path", ""), "path": location.get("path", ""),
        "method": location.get("method", "GET"), "parameter": location.get("parameter"),
        "parameter_location": location.get("parameter_location"), "scanner_status": "CANDIDATE",
        "confidence": data.get("confidence", 0.0), "severity": data.get("severity", "INFO"),
        "cwe": data.get("cwe"), "owasp_category": data.get("owasp_category"),
        "rules": _dump(getattr(outcome, "indicators", {})),
        "baseline": _dump(getattr(outcome, "comparison", {})),
        "verification": _dump(getattr(outcome, "response_features", {}).get("verification", {})),
        "evidence": [_dump(data.get("evidence", {}))], "ai_reason": "",
        "recommended_verification": list(_VERIFY_STEPS.get(vuln, ["Burp Suite에서 동일 요청을 재현하고 입력·응답을 확인합니다."])),
        "source_scan_id": str(getattr(getattr(outcome, "analysis", None), "scan_id", "")),
    }
    policy_reference = get_policy_mapping(vuln)
    if policy_reference:
        record["policy_reference"] = policy_reference
    return record


def _deduplicate(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["type"], record["uri"], record["method"], str(record.get("parameter") or ""))
        previous = unique.get(key)
        if previous is None or _confidence(record.get("confidence")) > _confidence(previous.get("confidence")):
            unique[key] = record
    result = list(unique.values())
    for index, record in enumerate(result, 1):
        record["id"] = f"F-{index:03d}"
    return result


def _merge_ai(draft: AnalysisDraft, base: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(item["type"], item["uri"], item["method"], str(item.get("parameter") or "")): item for item in base}
    merged: list[dict[str, Any]] = []
    for finding in draft.findings:
        item = _dump(finding)
        location = item.get("location", {})
        key = (str(item.get("vulnerability_type", "")).upper(), location.get("path", ""), location.get("method", "GET"), str(location.get("parameter") or ""))
        original = by_key.get(key)
        if original is None:
            continue
        record = dict(original)
        record["confidence"] = item.get("confidence", record["confidence"])
        record["severity"] = item.get("severity", record["severity"])
        record["ai_reason"] = item.get("description", "")
        record["evidence"] = list(record.get("evidence", [])) + [{"rationale": item.get("rationale", []), "description": item.get("description", "")}]
        merged.append(record)
    return _deduplicate(merged) if merged else _deduplicate(base)


def build_scan_analysis(*, target: str, outcomes: Iterable[Any], scan_id: str, config: ScannerConfig, mode: str = "rules") -> tuple[dict[str, Any], int, float]:
    """Build one scan-level diagnostic result and make at most one AI call."""

    started = time.perf_counter()
    outcome_list = list(outcomes)
    base = _deduplicate(_candidate_record(outcome, finding) for outcome in outcome_list for finding in getattr(getattr(outcome, "analysis", None), "findings", []))
    records, calls = base, 0
    if mode in {"ai", "auto"} and base and config.ai_api_key is not None and config.ai_api_key.get_secret_value():
        try:
            client = create_ai_client(provider=config.ai_provider, api_key=config.ai_api_key.get_secret_value(), model=config.ai_model, base_url=config.ai_base_url, timeout=config.ai_timeout_seconds, max_retries=config.ai_max_retries, max_output_tokens=config.ai_max_output_tokens)
            prompt_file = config.project_dir / "prompts" / "diagnostic_analysis.txt"
            instructions = prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else "제공된 후보와 HTTP 근거만 사용하여 추가 검증 지침을 작성하십시오. AnalysisDraft JSON만 반환하십시오."
            exchanges = []
            for outcome in outcome_list[:20]:
                capture = getattr(outcome, "scan_input", None)
                if capture is None:
                    continue
                request = _dump(getattr(capture, "request", {}))
                response = _dump(getattr(capture, "response", {}))
                if isinstance(request, dict) and isinstance(request.get("body"), str):
                    request["body"] = request["body"][:8_000]
                if isinstance(response, dict) and isinstance(response.get("body"), str):
                    response["body"] = response["body"][:8_000]
                exchanges.append({"request": request, "response": response})
            calls = 1
            policy_references = {
                str(item["type"]): item["policy_reference"]
                for item in base
                if isinstance(item.get("policy_reference"), dict)
            }
            result = client.analyze(
                instructions=instructions,
                input_data=json.dumps(
                    {
                        "target": _target(target),
                        "candidates": base,
                        "policy_references": policy_references,
                        "exchanges": exchanges,
                    },
                    ensure_ascii=False,
                    default=str,
                ),
            )
            draft = result.parsed if isinstance(result.parsed, AnalysisDraft) else AnalysisDraft.model_validate(result.parsed)
            records = _merge_ai(draft, base)
        except Exception as exc:
            LOGGER.warning("diagnostic AI failed; using rule candidates: %s", exc)
    analysis = {"schema_version": "diagnostic-1.0", "scan_id": scan_id, "generated_at": datetime.now(UTC).isoformat(), "target": _target(target), "analysis_summary": {"finding_count": len(records), "scanner_findings": len(records), "needs_human_verification": bool(records)}, "findings": records, "ai": {"diagnostic_calls": calls, "scope": "candidate guidance only"}}
    return analysis, calls, time.perf_counter() - started


def _render_observations(finding: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for evidence in finding.get("evidence", []) or []:
        if not isinstance(evidence, dict):
            lines.append(f"- {_ko_text(evidence)}")
            continue
        for key, label in (("request_indicators", "Request 특징"), ("response_indicators", "Response 특징")):
            values = evidence.get(key) or []
            if values:
                lines.append(f"- **{label}**")
                lines.extend(f"  - {_ko_text(value)}" for value in values)
        if evidence.get("response_status") is not None:
            lines.append(f"- Response 상태 코드: `{evidence['response_status']}`")
        if evidence.get("response_length") is not None:
            lines.append(f"- Response 길이: `{evidence['response_length']}` bytes")
    if finding.get("ai_reason"):
        lines.append(f"- **AI 분석 의견**: {_ko_text(finding['ai_reason'])}")
    baseline = finding.get("baseline")
    if isinstance(baseline, dict):
        lines.append("- **Baseline 비교**")
        for key, label in (("status_changed", "상태 코드 변경"), ("response_length_difference", "응답 길이 차이"), ("body_similarity", "본문 유사도"), ("redirect_changed", "Redirect 변경"), ("record_count_difference", "레코드 수 차이")):
            if baseline.get(key) is not None:
                lines.append(f"  - {label}: `{baseline[key]}`")
    verification = finding.get("verification")
    if isinstance(verification, dict) and verification:
        lines.append("- **Verification 관찰**")
        for key, label in (("status_code", "상태 코드"), ("response_status", "응답 상태"), ("upload_paths", "업로드 경로")):
            if verification.get(key) is not None:
                value = verification[key]
                if isinstance(value, list):
                    value = ", ".join(str(item) for item in value)
                lines.append(f"  - {label}: `{value}`")
    return lines or ["- 구조화된 세부 관찰값이 충분히 수집되지 않았습니다."]


def _render_policy_reference(finding: dict[str, Any]) -> list[str]:
    """Render optional policy context in the human diagnostic guide."""
    policy = finding.get("policy_reference")
    if not isinstance(policy, dict):
        return []
    item_number = policy.get("policy_item_number")
    item_name = policy.get("policy_item_name") or "-"
    item = f"{item_number}. {item_name}" if item_number else str(item_name)
    lines = [
        "",
        "### 진단 기준 참고",
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
    remediation = policy.get("remediation_reference") or []
    if remediation:
        lines.append("- 대응 권고 참고:")
        lines.extend(f"  - {value}" for value in remediation)
    return lines


def _vulnerability_guide(vulnerability: str) -> list[str]:
    return {"SQL_INJECTION": ["- Prepared Statement 또는 Parameterized Query 적용 여부 확인", "- DB 오류 메시지 외부 노출 여부 확인", "- 정상/테스트 요청의 데이터 범위와 인증 결과 비교"], "XSS": ["- HTML Body·Attribute·JavaScript Context 구분", "- 출력 Encoding 여부 확인", "- Stored/Reflected 여부와 브라우저 실행 가능성 확인"], "FILE_UPLOAD": ["- 확장자·MIME·파일 내용 검증 확인", "- 저장 위치와 Public URL 직접 접근 여부 확인", "- 업로드 디렉터리 실행 권한 및 크기 제한 확인"]}.get(vulnerability, ["- Burp Suite에서 동일 요청을 재현하고 서버 응답을 확인"])


def write_review_artifacts(*, root: Path, analysis: dict[str, Any]) -> None:
    """Write a readable Korean diagnostic guide and editable review JSON."""

    findings = analysis.get("findings", [])
    lines = ["# 취약점 진단 이정표", "", "> 이 문서는 자동 확정 보고서가 아닙니다. AI Scanner가 수집한 근거를 바탕으로 보안담당자가 추가 검증할 후보와 절차를 정리한 문서입니다.", "", "## 진단 요약", "", f"- Target: `{analysis.get('target', {}).get('url', '-')}`", f"- 자동 분석 후보: **{len(findings)}건**", "- 현재 상태: 모든 항목은 수동 검증 전 `CANDIDATE`입니다.", "", "| ID | 예상 취약점 | URI / Method | Parameter | Confidence | 상태 | 우선순위 |", "|---|---|---|---|---:|---|---|"]
    for finding in findings:
        confidence = _confidence(finding.get("confidence"))
        lines.append(f"| {finding.get('id', '-')} | {_vuln_name(finding.get('type'))} | `{finding.get('method', '-')} {finding.get('uri', '-')}` | `{finding.get('parameter') or '-'}` | {confidence:.0%} | CANDIDATE | {_priority(confidence)} |")
    if not findings:
        lines.append("자동 rule 분석에서 검토할 후보가 발견되지 않았습니다.")
    lines.extend(["", "## 공통 검증 원칙", "", "- 자동 분석 결과만으로 취약점을 확정하지 않습니다.", "- 정상 요청과 테스트 요청을 Burp Repeater에서 비교합니다.", "- 재현 여부와 서버 측 처리 결과를 확인한 뒤 `review.json`을 수정합니다.", ""])
    for finding in findings:
        vuln = str(finding.get("type", "")).upper()
        confidence = _confidence(finding.get("confidence"))
        lines.extend([f"## {finding.get('id', '-')} · {_vuln_name(vuln)}", "", "### 의심 위치", "", f"- URI: `{finding.get('uri', '-')}`", f"- HTTP Method: `{finding.get('method', '-')}`", f"- Parameter: `{finding.get('parameter') or '-'}`", f"- Parameter 위치: `{finding.get('parameter_location') or '-'}`", f"- Confidence: **{confidence:.0%}** ({_priority(confidence)})", "- Scanner 상태: `CANDIDATE` / 추가 검증 필요", "", "### Scanner 관찰 결과", ""])
        lines.extend(_render_observations(finding))
        lines.extend(_render_policy_reference(finding))
        lines.extend(["", "### 현재 판단", "", f"{_vuln_name(vuln)} 가능성이 확인되어 추가 검증이 필요합니다. 현재 자료만으로 실제 취약점 존재를 확정하지 않습니다.", "", "### 권장 검증 절차", ""])
        steps = finding.get("recommended_verification") or _VERIFY_STEPS.get(vuln, [])
        lines.extend(f"{index}. {_ko_text(step)}" for index, step in enumerate(steps, 1))
        lines.extend(["", "### 오탐 가능성", "", "- 입력값 반영이나 응답 차이만으로는 취약점이 확정되지 않을 수 있습니다.", "- 인코딩, 서버 측 검증, 권한 및 세션 상태를 함께 확인해야 합니다.", "", "### 취약점별 추가 점검 포인트", ""])
        lines.extend(_vulnerability_guide(vuln))
        lines.extend(["", "---", ""])
    (root / "diagnostic_guide.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    review = {"schema_version": "review-1.0", "target": analysis.get("target", {}), "analysis_file": "analysis.json", "findings": [{"id": item.get("id"), "type": item.get("type"), "uri": item.get("uri"), "method": item.get("method"), "parameter": item.get("parameter"), "review_status": "PENDING", "reviewer_note": "", "manual_evidence": []} for item in findings]}
    (root / "review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


__all__ = ["build_scan_analysis", "write_review_artifacts"]
