"""Stable dashboard models independent of a concrete scanner implementation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Evidence:
    evidence_id: str = ""
    finding_id: str | None = None
    evidence_type: str = "unknown"
    filename: str = "unnamed"
    description: str | None = None
    local_path: str | None = None
    uploaded_at: datetime | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    # Dashboard-only transient bytes. Filesystem adapters persist them and do
    # not expose them in the normalized scanner result.
    content: bytes | None = None


@dataclass(frozen=True)
class ReportArtifacts:
    diagnostic_guide: str | None = None
    final_report: str | None = None
    secure_coding_guide: str | None = None

    def get(self, report_type: str) -> str | None:
        if report_type not in {
            "diagnostic_guide",
            "final_report",
            "secure_coding_guide",
        }:
            return None
        return getattr(self, report_type)


@dataclass(frozen=True)
class Finding:
    finding_id: str = "unknown-finding"
    vulnerability_type: str = "Unknown"
    uri: str = "/"
    http_method: str | None = None
    parameter: str | None = None
    parameter_location: str | None = None
    initial_severity: str | None = None
    final_severity: str | None = None
    confidence: float | None = None
    scanner_status: str = "unknown"
    review_status: str = "unverified"
    priority: str | None = None
    request_summary: str | None = None
    response_summary: str | None = None
    baseline_comparison: dict[str, Any] | None = None
    scanner_judgment: str | None = None
    reviewer_memo: str | None = None
    final_judgment: str | None = None
    cwe: str | None = None
    owasp_category: str | None = None
    cvss: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    summary: str | None = None
    impact: str | None = None
    remediation: str | None = None
    secure_coding: str | None = None
    analyzed_at: datetime | None = None
    rules_evidence: dict[str, Any] | None = None
    ai_diagnostic_summary: str | None = None
    recommended_verification: list[str] = field(default_factory=list)
    # Optional KISA policy reference attached by the Scanner integration layer.
    policy_reference: dict[str, Any] | None = None


@dataclass(frozen=True)
class ScanResult:
    scan_id: str = "unknown-scan"
    target_url: str = ""
    status: str = "unknown"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    reports: ReportArtifacts = field(default_factory=ReportArtifacts)
    raw_result_path: str | None = None
    scanned_pages: int = 0
    normal_pages: int = 0
    forms_discovered: int = 0
    inputs_tested: int = 0
    diagnostic_summary: str | None = None


@dataclass(frozen=True)
class ReportDownload:
    filename: str
    content: bytes
    mime_type: str = "application/pdf"
