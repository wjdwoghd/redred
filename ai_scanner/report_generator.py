"""Generate a Korean Markdown report from validated analysis data.

The analysis object is the source of truth. AI is allowed to improve prose only;
all status, severity, location, evidence and remediation facts are rendered from
the validated object and a deterministic renderer is always available.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field

LOGGER = logging.getLogger(__name__)


class ReportFindingNarrative(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_index: int = Field(ge=1)
    overview: str = Field(min_length=1, max_length=8192)
    normal_request: str = Field(min_length=1, max_length=8192)
    test_request: str = Field(min_length=1, max_length=8192)
    response_comparison: str = Field(min_length=1, max_length=8192)
    cause: str = Field(min_length=1, max_length=8192)
    impact: str = Field(min_length=1, max_length=8192)


class ReportDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    executive_summary: str = Field(min_length=1, max_length=8192)
    finding_narratives: list[ReportFindingNarrative] = Field(max_length=100)
    closing: str = Field(min_length=1, max_length=8192)


class ReportAIClient(Protocol):
    def generate_report(self, *, instructions: str, input_data: str) -> Any: ...


_NAMES = {"SQL_INJECTION": "SQL Injection", "XSS": "XSS", "FILE_UPLOAD": "File Upload"}
_REMEDIATION = {
    "SQL_INJECTION": [
        "Prepared Statement를 사용합니다.",
        "Parameterized Query를 적용하고 사용자 입력을 검증합니다.",
        "DB 계정에 최소 권한을 부여하고 SQL 오류를 외부에 노출하지 않습니다.",
    ],
    "XSS": [
        "출력 위치에 맞는 HTML Encoding과 Context-aware Encoding을 적용합니다.",
        "사용자 입력을 검증하고 안전한 템플릿 출력 경계를 사용합니다.",
        "CSP(Content Security Policy)를 적용하고 세션 쿠키에 HttpOnly를 설정합니다.",
    ],
    "FILE_UPLOAD": [
        "허용 목록 기반 확장자, MIME 및 파일 내용 검증을 수행합니다.",
        "파일명을 랜덤화하고 웹 루트 외부에 저장합니다.",
        "업로드 디렉터리의 실행 권한을 제거하고 파일 크기를 제한합니다.",
    ],
}
_EVIDENCE_KO = {
    "SQL-like input present": "SQL 문법으로 해석될 수 있는 입력이 존재했습니다.",
    "SQL-like special characters or operators were present": "SQL 특수문자 또는 연산자가 입력에 포함되었습니다.",
    "database error or strong baseline delta": "데이터베이스 오류 또는 정상 요청과의 큰 응답 차이가 관찰되었습니다.",
    "no strong response confirmation": "응답만으로 확정할 강한 증거는 확인되지 않았습니다.",
    "exact input reflected": "입력값이 인코딩되지 않은 상태로 응답에 반영되었습니다.",
    "no exact reflection": "입력값의 정확한 반영은 확인되지 않았습니다.",
    "executable HTML/attribute context": "실행 가능한 HTML 또는 속성 문맥이 관찰되었습니다.",
    "no executable context": "실행 가능한 문맥은 확인되지 않았습니다.",
    "dangerous file metadata": "위험한 확장자 또는 MIME 메타데이터가 확인되었습니다.",
    "upload success and path": "업로드 성공과 접근 경로가 함께 확인되었습니다.",
    "Unique XSS canary was supplied": "고유 XSS 테스트 문자열을 입력했습니다.",
    "Multipart file part was captured": "multipart 파일 파트가 수집되었습니다.",
}


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


def _text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    return str(getattr(value, "value", value))


def _inline(value: Any, default: str = "-") -> str:
    return _text(value, default).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _evidence_text(value: Any) -> str:
    text = _text(value, "")
    return _EVIDENCE_KO.get(text, text if re.search(r"[\uac00-\ud7a3]", text) else "분석 지표가 관찰되었습니다.")


def _name(finding: Any) -> str:
    raw = _text(_get(finding, "vulnerability_type"), "UNKNOWN")
    return _NAMES.get(raw, raw)


def _confidence(value: Any) -> str:
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "-"


def _korean(value: Any, fallback: str) -> str:
    """Use a concise Korean sentence instead of leaking untranslated AI/rule text."""
    text = _text(value, "").strip()
    return text if text and re.search(r"[\uac00-\ud7a3]", text) else fallback


def _comparison_sentence(value: Any) -> str:
    if not isinstance(value, Mapping) or not value.get("available"):
        return "정상 요청과 비교할 baseline 응답이 제공되지 않아 응답 차이를 계산하지 않았습니다."
    baseline = value.get("baseline") if isinstance(value.get("baseline"), Mapping) else value
    tested = value.get("test") if isinstance(value.get("test"), Mapping) else value.get("attack", value)
    def pick(section: Mapping[str, Any], nested: str, flat: str) -> Any:
        return section.get(nested) if section.get(nested) is not None else value.get(flat)

    sentence = (
        f"정상 응답은 HTTP {_inline(pick(baseline, 'status_code', 'baseline_status_code'))}, "
        f"{_inline(pick(baseline, 'actual_content_length', 'baseline_content_length'))}바이트이고 테스트 응답은 "
        f"HTTP {_inline(pick(tested, 'status_code', 'test_status_code'))}, {_inline(pick(tested, 'actual_content_length', 'test_content_length'))}바이트입니다. "
        f"응답 길이 차이는 {_inline(value.get('response_length_difference'), '계산 불가')}바이트입니다."
    )
    if value.get("record_count_difference") is not None:
        sentence += f" 추정 레코드 수 차이는 {_inline(value['record_count_difference'])}건입니다."
    if value.get("returned_data_increased"):
        sentence += " 테스트 요청에서 반환 데이터가 증가했습니다."
    if value.get("status_changed"):
        sentence += " HTTP 상태 코드가 변경되었습니다."
    if value.get("body_changed"):
        sentence += " 응답 본문도 변경되었습니다."
    if value.get("new_error_indicators"):
        sentence += " 테스트 응답에서 새로운 오류 지표가 관찰되었습니다."
    return sentence


def _request_sentence(finding: Any, *, normal: bool) -> str:
    location = _get(finding, "location")
    if normal:
        return "제공된 분석 결과에는 정상 요청의 상세 입력값이 별도로 기록되어 있지 않습니다."
    return (
        f"`{_inline(_get(location, 'method'))} {_inline(_get(location, 'path'))}` 요청의 "
        f"`{_inline(_get(location, 'parameter'))}` 파라미터({_inline(_get(location, 'parameter_location'))})를 테스트했습니다."
    )


def _finding_block(index: int, finding: Any, narrative: ReportFindingNarrative | None) -> list[str]:
    location = _get(finding, "location")
    evidence = _get(finding, "evidence")
    rationale = [_evidence_text(item) for item in _items(_get(finding, "rationale")) if item]
    lines = [
        f"### 2.{index} {_name(finding)}", "",
        "#### 취약점 개요", "",
        (narrative.overview if narrative else _korean(_get(finding, "description"), f"{_name(finding)} 가능성이 분석되었습니다.")), "",
        "#### 상세 정보", "",
        f"- 상태: `{_text(_get(finding, 'status'))}`",
        f"- 위험도: `{_text(_get(finding, 'severity'))}`",
        f"- 신뢰도: `{_confidence(_get(finding, 'confidence'))}`",
        f"- 점검 경로: `{_inline(_get(location, 'path'))}`",
        f"- URI: `{_inline(_get(location, 'path'))}`",
        f"- HTTP Method: `{_inline(_get(location, 'method'))}`",
        f"- 취약 Parameter: `{_inline(_get(location, 'parameter'))}`",
        f"- Parameter 위치: `{_inline(_get(location, 'parameter_location'))}`",
        f"- CWE: `{_inline(_get(finding, 'cwe'))}`",
        f"- OWASP: `{_inline(_get(finding, 'owasp_category'))}`", "",
        "#### 판단 근거", "",
    ]
    if not rationale:
        rationale = [_evidence_text(item) for item in _items(_get(evidence, "request_indicators")) + _items(_get(evidence, "response_indicators")) if item]
    lines.extend([f"- {item}" for item in rationale] or ["- 별도 판단 근거가 기록되지 않았습니다."])
    return lines


def _render(analysis: Any, draft: ReportDraft | None, generated_at: datetime | None) -> str:
    target, summary = _get(analysis, "target"), _get(analysis, "analysis_summary")
    metadata = _get(analysis, "metadata")
    findings = list(_get(analysis, "findings", []) or [])
    narratives = {item.finding_index: item for item in (draft.finding_narratives if draft else [])}
    analyzed_at = _get(metadata, "analyzed_at") or generated_at or datetime.now(UTC)
    status = _text(_get(summary, "overall_status"), "NOT_CONFIRMED")
    lines = [
        "# 웹 취약점 진단 보고서", "", "## 1. 진단 개요", "",
        f"- 점검 대상: `{_inline(_get(target, 'url'))}`",
        f"- 점검 URI: `{_inline(_get(target, 'path'))}`",
        f"- HTTP Method: `{_inline(_get(target, 'method'))}`",
        f"- 진단 일시: `{_inline(analyzed_at.isoformat())}`",
        f"- 위험도: `{_text(_get(summary, 'overall_risk'), 'INFO')}`",
        f"- 최종 상태: `{status}`", "", "---", "", "## 2. 취약점 개요", "",
    ]
    if not findings:
        lines += ["analysis.json의 Request/Response에서 확인된 취약점이 없습니다.", ""]
    for index, finding in enumerate(findings, 1):
        lines += _finding_block(index, finding, narratives.get(index)) + [""]
    lines += ["## 3. 상세 수행 내역", "", draft.executive_summary if draft else "분석 결과에 기록된 HTTP 교환과 사전 분석 지표를 기준으로 각 finding을 검토했습니다.", "", "## 4. 정상 요청 분석", ""]
    for index, finding in enumerate(findings, 1):
        lines += [f"### {index}. {_name(finding)}", "", narratives[index].normal_request if index in narratives else _request_sentence(finding, normal=True), ""]
    lines += ["## 5. 테스트 요청 분석", ""]
    for index, finding in enumerate(findings, 1):
        evidence = _get(finding, "evidence")
        lines += [f"### {index}. {_name(finding)}", "", narratives[index].test_request if index in narratives else _request_sentence(finding, normal=False), f"테스트 입력값: `{_inline(_get(evidence, 'request_value'), '기록 없음')}`", ""]
    lines += ["## 6. 응답 비교", ""]
    for index, finding in enumerate(findings, 1):
        evidence = _get(finding, "evidence")
        lines += [f"### {index}. {_name(finding)}", "", narratives[index].response_comparison if index in narratives else _comparison_sentence(_get(evidence, "baseline_comparison")), ""]
    lines += ["## 7. 취약점 발생 원인", ""]
    for index, finding in enumerate(findings, 1):
        lines += [f"### {index}. {_name(finding)}", "", narratives[index].cause if index in narratives else _korean(_get(finding, "cause"), "입력값 처리와 출력 또는 파일 저장 경계에서 충분한 검증이 적용되지 않았을 가능성이 있습니다."), ""]
    lines += ["## 8. 보안 영향", ""]
    for index, finding in enumerate(findings, 1):
        impacts = [str(item) for item in _items(_get(finding, "impact")) if item]
        text = narratives[index].impact if index in narratives else "분석 결과에 기록된 영향은 다음과 같습니다."
        lines += [f"### {index}. {_name(finding)}", "", text] + [f"- {item}" for item in impacts] + [""]
    lines += ["## 9. 대응 방안", ""]
    for index, finding in enumerate(findings, 1):
        vuln = _text(_get(finding, "vulnerability_type"), "UNKNOWN")
        lines += [f"### {index}. {_name(finding)}", "", "- " + "\n- ".join(_REMEDIATION.get(vuln, ["분석 결과에 기록된 취약점 유형에 맞는 대응 방안을 검토합니다."])) , ""]
    lines += ["## 10. 최종 판정", "", f"- 최종 상태: `{status}`", f"- 전체 위험도: `{_text(_get(summary, 'overall_risk'), 'INFO')}`", f"- 발견 건수: `{_inline(_get(summary, 'finding_count'), '0')}`"]
    if draft:
        lines += ["", draft.closing]
    lines.append("")
    return "\n".join(lines)


def validate_report_consistency(report: str, analysis: Any) -> None:
    """Ensure source fields and vulnerability-specific remediation survive rendering."""
    required = ["## 1. 진단 개요", "## 2. 취약점 개요", "## 3. 상세 수행 내역", "## 4. 정상 요청 분석", "## 5. 테스트 요청 분석", "## 6. 응답 비교", "## 7. 취약점 발생 원인", "## 8. 보안 영향", "## 9. 대응 방안", "## 10. 최종 판정"]
    missing = [section for section in required if section not in report]
    if missing or re.search(r"\{['\"]|OrderedDict\(", report):
        raise ValueError("report structure or raw dictionary validation failed")
    summary = _get(analysis, "analysis_summary")
    if _text(_get(summary, "overall_status"), "NOT_CONFIRMED") not in report:
        raise ValueError("report dropped overall status")
    remediation = report.split("## 9. 대응 방안", 1)[1].split("## 10. 최종 판정", 1)[0]
    for finding in list(_get(analysis, "findings", []) or []):
        location = _get(finding, "location")
        for value in (_get(finding, "status"), _get(finding, "severity"), _confidence(_get(finding, "confidence")), _get(finding, "cwe"), _get(finding, "owasp_category"), _get(location, "path"), _get(location, "method"), _get(location, "parameter")):
            if _text(value, "") not in report:
                raise ValueError(f"report dropped source value: {_text(value)}")
        vuln = _text(_get(finding, "vulnerability_type"), "UNKNOWN")
        for term in ({"SQL_INJECTION": ["Prepared Statement", "Parameterized Query", "최소 권한"], "XSS": ["HTML Encoding", "Context-aware Encoding", "CSP"], "FILE_UPLOAD": ["확장자", "MIME", "실행 권한"]}.get(vuln, [])):
            if term not in remediation:
                raise ValueError(f"remediation does not match {vuln}")


def _request_ai_draft(analysis: Any, ai_client: ReportAIClient, prompt: str) -> ReportDraft:
    payload = analysis.model_dump(mode="json") if hasattr(analysis, "model_dump") else analysis
    result = ai_client.generate_report(instructions=prompt, input_data=json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str))
    result = getattr(result, "parsed", result)
    return result if isinstance(result, ReportDraft) else ReportDraft.model_validate(result)


def generate_report(analysis: Any, *, scan_input: Any | None = None, generated_at: datetime | None = None, ai_client: ReportAIClient | None = None, ai_prompt: str = "") -> str:
    """Generate a Korean report, falling back to deterministic prose on AI errors."""
    del scan_input
    draft = None
    if ai_client is not None and ai_prompt.strip():
        try:
            draft = _request_ai_draft(analysis, ai_client, ai_prompt)
            count = len(list(_get(analysis, "findings", []) or []))
            if {item.finding_index for item in draft.finding_narratives} != set(range(1, count + 1)):
                raise ValueError("AI report findings do not match analysis.json")
            if any(not re.search(r"[\uac00-\ud7a3]", text) for text in [draft.executive_summary, draft.closing] + [part for item in draft.finding_narratives for part in (item.overview, item.normal_request, item.test_request, item.response_comparison, item.cause, item.impact)]):
                raise ValueError("AI report prose is not Korean")
        except Exception as exc:
            LOGGER.warning("AI report generation failed; using deterministic report: %s", exc)
            draft = None
    report = _render(analysis, draft, generated_at)
    try:
        validate_report_consistency(report, analysis)
    except Exception:
        if draft is None:
            raise
        report = _render(analysis, None, generated_at)
        validate_report_consistency(report, analysis)
    return report


generate_markdown_report = generate_report

__all__ = ["ReportDraft", "ReportFindingNarrative", "generate_report", "generate_markdown_report", "validate_report_consistency"]
