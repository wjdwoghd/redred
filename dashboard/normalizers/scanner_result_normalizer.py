"""Convert scanner-specific dictionaries into the dashboard's stable model.

TODO(scanner-integration): Add field aliases here when the real AI Scanner output
schema becomes available. Keep scanner-specific keys out of Streamlit components.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from models import Evidence, Finding, ReportArtifacts, ScanResult


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _first(source: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = source.get(key)
        if value is not None and value != "":
            return value
    return default


def _text(value: Any, default: str | None = None) -> str | None:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        text = str(value).strip().replace("%", "")
        number = float(text)
        if "%" in str(value) or number > 1:
            number /= 100
        return max(0.0, min(number, 1.0))
    except (TypeError, ValueError):
        return None


def _score(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _evidence_summary(item: Mapping[str, Any], key: str) -> str | None:
    """Create a compact readable HTTP evidence summary from scanner evidence."""
    values: list[str] = []
    for evidence in _list(item.get("evidence")):
        data = _mapping(evidence)
        if key == "request":
            values.extend(str(value) for value in _list(data.get("request_indicators")))
            if data.get("request_value"):
                values.append(f"value={data['request_value']}")
        else:
            if data.get("response_status") is not None:
                values.append(f"status={data['response_status']}")
            values.extend(str(value) for value in _list(data.get("response_indicators")))
    return "; ".join(dict.fromkeys(values)) or None


def _severity(value: Any) -> str | None:
    text = _text(value)
    return text.upper() if text else None


def _evidence_type(filename: str, explicit: Any = None) -> str:
    if explicit:
        return str(explicit).strip().lower()
    suffix = Path(filename).suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return "screenshot"
    if suffix == ".pdf":
        return "pdf"
    if suffix in {".txt", ".log"}:
        return "log"
    if suffix == ".json":
        return "json"
    return "file"


def _normalize_evidence(raw: Any, finding_id: str | None = None) -> Evidence:
    item = _mapping(raw)
    filename = _text(_first(item, "filename", "name", "file"), "unnamed") or "unnamed"
    evidence_id = _text(_first(item, "evidence_id", "id"), f"evidence-{filename}") or ""
    return Evidence(
        evidence_id=evidence_id,
        finding_id=_text(_first(item, "finding_id", default=finding_id)),
        evidence_type=_evidence_type(filename, _first(item, "evidence_type", "type")),
        filename=Path(filename).name,
        description=_text(_first(item, "description", "memo")),
        local_path=_text(_first(item, "local_path", "path", "file")),
        uploaded_at=_datetime(_first(item, "uploaded_at", "created_at")),
        mime_type=_text(item.get("mime_type")),
        size_bytes=_int(item.get("size_bytes"), 0) or None,
    )


def _has_file_reference(raw: Any) -> bool:
    """Whether an evidence record points to a persisted reviewer file.

    Inline request/response evidence has no filename.  It belongs in the
    Rules/HTTP evidence fields, not in the Dashboard's file evidence table.
    """
    item = _mapping(raw)
    reference = _text(_first(item, "local_path", "path", "file", "filename", "name"))
    return bool(reference and reference.casefold() not in {"unnamed", "none"})


def _normalize_reports(raw: Any) -> ReportArtifacts:
    source = _mapping(raw)

    def path_for(key: str, *aliases: str) -> str | None:
        value = _first(source, key, *aliases)
        if isinstance(value, Mapping):
            value = _first(value, "local_path", "path", "file")
        return _text(value)

    return ReportArtifacts(
        diagnostic_guide=path_for("diagnostic_guide", "diagnostic_guide_pdf"),
        final_report=path_for("final_report", "final_report_pdf"),
        secure_coding_guide=path_for("secure_coding_guide", "secure_coding_guide_pdf"),
    )


def normalize_scan_result(
    raw: Mapping[str, Any],
    *,
    raw_result_path: str | None = None,
    default_scan_id: str | None = None,
    discovered_reports: ReportArtifacts | None = None,
    discovered_evidence: list[Evidence] | None = None,
) -> ScanResult:
    """Normalize a scanner result while tolerating missing and unknown fields."""
    if not isinstance(raw, Mapping):
        raise ValueError("스캔 결과의 최상위 형식은 JSON 객체여야 합니다.")

    target = _mapping(raw.get("target"))
    pipeline = _mapping(raw.get("pipeline"))
    summary = _mapping(_first(raw, "summary", "scan_summary", default={}))
    top_evidence = [
        _normalize_evidence(item)
        for item in _list(raw.get("evidence"))
        if _has_file_reference(item)
    ]
    if discovered_evidence:
        top_evidence.extend(discovered_evidence)

    findings: list[Finding] = []
    for index, value in enumerate(_list(raw.get("findings")), start=1):
        item = _mapping(value)
        finding_id = _text(_first(item, "finding_id", "id"), f"finding-{index}") or f"finding-{index}"
        http = _mapping(item.get("http"))
        classification = _mapping(item.get("classification"))
        judgment = _mapping(item.get("judgment"))
        review = _mapping(item.get("review"))
        baseline = _mapping(_first(item, "baseline_comparison", "baseline", default={}))

        linked = [
            _normalize_evidence(ev, finding_id)
            for ev in _list(item.get("evidence"))
            if _has_file_reference(ev)
        ]
        linked.extend(
            _normalize_evidence(ev, finding_id)
            for ev in _list(item.get("manual_evidence"))
            if _has_file_reference(ev)
        )
        linked.extend(ev for ev in top_evidence if ev.finding_id == finding_id)
        manual_names = {Path(ev.local_path).name for ev in linked if ev.local_path}
        linked.extend(
            ev for ev in (discovered_evidence or [])
            if ev.finding_id == finding_id and ev.filename not in manual_names
        )
        # Some scanner versions put a finding reference in a top-level list.
        for raw_ev in _list(raw.get("evidence")):
            raw_map = _mapping(raw_ev)
            linked_ids = {str(x) for x in _list(raw_map.get("finding_ids"))}
            if finding_id in linked_ids:
                if _has_file_reference(raw_ev):
                    linked.append(_normalize_evidence(raw_ev, finding_id))
        unique_evidence: list[Evidence] = []
        seen_evidence: set[str] = set()
        for evidence in linked:
            evidence_key = f"{evidence.finding_id}:{evidence.filename}"
            if evidence_key not in seen_evidence:
                seen_evidence.add(evidence_key)
                unique_evidence.append(evidence)

        final_severity = _severity(_first(item, "final_severity", default=review.get("final_severity")))
        scanner_status_value = str(_first(item, "scanner_status", "status", default="")).upper()
        if finding_id.upper().startswith("NF-") and not scanner_status_value:
            scanner_status_value = "MANUAL"
        review_default = review.get("status")
        if review_default in (None, "") and scanner_status_value == "CANDIDATE":
            review_default = "PENDING"
        findings.append(
            Finding(
                finding_id=finding_id,
                vulnerability_type=_text(
                    _first(item, "vulnerability_type", "category", "type", "name"), "Unknown"
                ) or "Unknown",
                uri=_text(_first(item, "uri", "url", "path"), "/") or "/",
                http_method=_text(_first(item, "http_method", "method", default=http.get("method"))),
                parameter=_text(_first(item, "parameter", default=http.get("parameter"))),
                parameter_location=_text(
                    _first(item, "parameter_location", default=http.get("parameter_location"))
                ),
                initial_severity=_severity(_first(item, "initial_severity", "severity")),
                final_severity=final_severity,
                confidence=_float(_first(item, "confidence", "confidence_score")),
                scanner_status=_text(
                    _first(item, "scanner_status", "status"),
                    scanner_status_value.lower() if scanner_status_value else "unknown",
                ) or (scanner_status_value.lower() if scanner_status_value else "unknown"),
                review_status=_text(
                    _first(
                        item,
                        "review_status",
                        "verification_status",
                        default=review_default,
                    ),
                    "unverified",
                ) or "unverified",
                priority=_text(item.get("priority")),
                request_summary=_text(
                    _first(
                        item,
                        "request_summary",
                        "http_request_summary",
                        default=http.get("request_summary") or _evidence_summary(item, "request"),
                    )
                ),
                response_summary=_text(
                    _first(
                        item,
                        "response_summary",
                        "http_response_summary",
                        default=http.get("response_summary") or _evidence_summary(item, "response"),
                    )
                ),
                baseline_comparison=dict(baseline) if baseline else None,
                scanner_judgment=_text(
                    _first(
                        item,
                        "scanner_judgment",
                        "initial_assessment",
                        default=judgment.get("scanner"),
                    )
                ),
                reviewer_memo=_text(
                    _first(item, "reviewer_memo", "reviewer_note", default=review.get("memo") or review.get("reviewer_note"))
                ),
                final_judgment=_text(
                    _first(
                        item,
                        "final_judgment",
                        "ai_reanalysis",
                        default=judgment.get("final"),
                    )
                ),
                cwe=_text(_first(item, "cwe", default=classification.get("cwe"))),
                owasp_category=_text(
                    _first(item, "owasp_category", "owasp", default=classification.get("owasp"))
                ),
                cvss=_score(_first(item, "cvss", default=classification.get("cvss"))),
                evidence=unique_evidence,
                summary=_text(item.get("summary")),
                impact=_text(item.get("impact")),
                remediation=_text(item.get("remediation")),
                secure_coding=_text(item.get("secure_coding")),
                analyzed_at=_datetime(item.get("analyzed_at")),
                rules_evidence=dict(_mapping(item.get("rules"))) or None,
                ai_diagnostic_summary=_text(
                    _first(item, "ai_reason", "diagnostic_summary", default=item.get("summary"))
                ),
                recommended_verification=[str(value) for value in _list(item.get("recommended_verification"))],
                policy_reference=dict(_mapping(item.get("policy_reference"))) or None,
            )
        )

    reports = discovered_reports or _normalize_reports(raw.get("reports"))
    scan_id = _text(_first(raw, "scan_id", "id"), default_scan_id or "unknown-scan") or "unknown-scan"
    scan_summary = _mapping(_first(raw, "scan_summary", "summary", default={}))
    ai_data = _mapping(raw.get("ai"))
    return ScanResult(
        scan_id=scan_id,
        target_url=_text(
            _first(raw, "target_url", "base_url", default=_first(target, "base_url", "url")), ""
        ) or "",
        status=_text(_first(raw, "status", default=pipeline.get("status")), "unknown") or "unknown",
        started_at=_datetime(_first(raw, "started_at", default=pipeline.get("started_at"))),
        completed_at=_datetime(_first(raw, "completed_at", default=pipeline.get("completed_at"))),
        findings=findings,
        reports=reports,
        raw_result_path=raw_result_path,
        scanned_pages=_int(_first(raw, "scanned_pages", default=summary.get("scanned_pages"))),
        normal_pages=_int(_first(raw, "normal_pages", default=summary.get("normal_pages"))),
        forms_discovered=_int(_first(raw, "forms_discovered", default=scan_summary.get("forms_discovered"))),
        inputs_tested=_int(_first(raw, "inputs_tested", default=scan_summary.get("inputs_tested"))),
        diagnostic_summary=_text(
            _first(raw, "diagnostic_summary", default=ai_data.get("diagnostic_summary"))
        ) or (
            f"Diagnostic AI calls: {ai_data.get('diagnostic_calls')}"
            if ai_data.get("diagnostic_calls") is not None else None
        ),
    )
