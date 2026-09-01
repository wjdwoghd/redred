"""Strict structured models for AI-assisted vulnerability analysis results."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Iterable, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, field_validator, model_validator

from .http import ParameterLocation, StrictModel


class VulnerabilityType(str, Enum):
    """Vulnerability families in the current REDRED project scope."""

    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    FILE_UPLOAD = "FILE_UPLOAD"


class FindingStatus(str, Enum):
    """Evidence-aware finding state."""

    CONFIRMED = "CONFIRMED"
    POSSIBLE = "POSSIBLE"
    NOT_CONFIRMED = "NOT_CONFIRMED"


class Severity(str, Enum):
    """Risk scale used by findings and aggregate scan summaries."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Target(StrictModel):
    """Request target summarized in the final analysis."""

    method: str = Field(min_length=1, max_length=32)
    url: str = Field(min_length=1, max_length=8_192)
    path: str = Field(min_length=1, max_length=4_096)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("url must be an absolute HTTP or HTTPS URL")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must begin with '/'")
        return value


class FindingLocation(StrictModel):
    """Precise input location associated with a vulnerability finding."""

    parameter: str | None = Field(default=None, max_length=512)
    parameter_location: ParameterLocation
    method: str = Field(min_length=1, max_length=32)
    path: str = Field(min_length=1, max_length=4_096)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must begin with '/'")
        return value


class Evidence(StrictModel):
    """Auditable request, response, and baseline facts behind a finding."""

    request_value: JsonValue = None
    request_indicators: list[str] = Field(default_factory=list, max_length=100)
    response_status: int | None = Field(default=None, ge=100, le=599)
    response_length: int | None = Field(default=None, ge=0)
    response_indicators: list[str] = Field(default_factory=list, max_length=100)
    response_excerpt: str | None = Field(default=None, max_length=4_096)
    baseline_comparison: dict[str, JsonValue] | None = None


class Finding(StrictModel):
    """One validated vulnerability assessment."""

    vulnerability_type: VulnerabilityType
    status: FindingStatus
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    location: FindingLocation
    evidence: Evidence
    description: str = Field(min_length=1, max_length=8_192)
    rationale: list[str] = Field(default_factory=list, max_length=100)
    cause: str = Field(default="확인된 기술적 원인은 캡처 자료만으로 단정할 수 없음", max_length=8_192)
    subtype: str | None = Field(default=None, max_length=128)
    attack_success: bool | None = None
    impact: list[str] = Field(default_factory=list, max_length=100)
    remediation: list[str] = Field(default_factory=list, max_length=100)
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    owasp_category: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_cwe_mapping(self) -> "Finding":
        """Prevent an AI response from assigning an unrelated CWE."""

        expected = {
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.FILE_UPLOAD: "CWE-434",
        }[self.vulnerability_type]
        if self.cwe != expected:
            raise ValueError(f"{self.vulnerability_type.value} must use {expected}")
        return self


class AnalysisSummary(StrictModel):
    """Aggregate result derived deterministically from validated findings."""

    is_vulnerable: bool
    finding_count: int = Field(ge=0)
    confirmed_count: int = Field(default=0, ge=0)
    possible_count: int = Field(default=0, ge=0)
    overall_status: FindingStatus = FindingStatus.NOT_CONFIRMED
    overall_risk: Severity

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> Self:
        """Compute a conservative summary from findings.

        Only ``CONFIRMED`` makes ``is_vulnerable`` true. ``POSSIBLE`` findings
        remain visible and may affect displayed risk, but are never promoted to a
        confirmed vulnerability by aggregation.
        """

        items = list(findings)
        active = [item for item in items if item.status is not FindingStatus.NOT_CONFIRMED]
        overall = max(
            (item.severity for item in active),
            key=lambda severity: _SEVERITY_RANK[severity],
            default=Severity.INFO,
        )
        confirmed = sum(item.status is FindingStatus.CONFIRMED for item in items)
        possible = sum(item.status is FindingStatus.POSSIBLE for item in items)
        overall_status = (
            FindingStatus.CONFIRMED
            if confirmed
            else FindingStatus.POSSIBLE
            if possible
            else FindingStatus.NOT_CONFIRMED
        )
        return cls(
            is_vulnerable=any(item.status is FindingStatus.CONFIRMED for item in items),
            finding_count=len(items),
            confirmed_count=confirmed,
            possible_count=possible,
            overall_status=overall_status,
            overall_risk=overall,
        )


class AnalysisMetadata(StrictModel):
    """Traceability metadata generated by the deterministic pipeline."""

    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    analyzer_version: str = Field(default="1.0.0", min_length=1, max_length=64)
    ai_model: str | None = Field(default=None, max_length=256)
    engine: Literal["AI", "RULE_BASED", "RULE_BASED_FALLBACK"] = "RULE_BASED"
    provider: str | None = Field(default=None, max_length=128)
    prompt_version: str = Field(default="1.0", min_length=1, max_length=64)
    used_ai: bool = False
    input_truncated: bool = False
    warnings: list[str] = Field(default_factory=list, max_length=100)
    redacted_fields: list[str] = Field(default_factory=list, max_length=100)
    fallback_reason: str | None = Field(default=None, max_length=2_048)
    pre_analysis: dict[str, JsonValue] = Field(default_factory=dict)


class AnalysisDraft(StrictModel):
    """Validated AI output before deterministic scan metadata is attached.

    ``target`` and ``analysis_summary`` are accepted for providers that return the
    full requested shape.  The final result always receives a trusted target from
    the parsed request and recomputes its summary from ``findings``.
    """

    target: Target | None = None
    analysis_summary: AnalysisSummary | None = None
    findings: list[Finding] = Field(default_factory=list, max_length=100)

    def computed_summary(self) -> AnalysisSummary:
        """Return the deterministic summary for this draft's findings."""

        return AnalysisSummary.from_findings(self.findings)


class AnalysisResult(StrictModel):
    """Final JSON source of truth for reports and persisted scan artifacts."""

    schema_version: Literal["1.0"] = "1.0"
    scan_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    target: Target
    analysis_summary: AnalysisSummary
    findings: list[Finding] = Field(default_factory=list, max_length=100)
    metadata: AnalysisMetadata = Field(default_factory=AnalysisMetadata)

    @model_validator(mode="after")
    def verify_summary(self) -> "AnalysisResult":
        expected = AnalysisSummary.from_findings(self.findings)
        if self.analysis_summary != expected:
            raise ValueError("analysis_summary must be derived from findings")
        return self

    @classmethod
    def from_draft(
        cls,
        *,
        scan_id: str,
        target: Target,
        draft: AnalysisDraft,
        metadata: AnalysisMetadata | None = None,
    ) -> Self:
        """Create a final result while discarding untrusted aggregate AI fields."""

        return cls(
            scan_id=scan_id,
            target=target,
            analysis_summary=AnalysisSummary.from_findings(draft.findings),
            findings=draft.findings,
            metadata=metadata or AnalysisMetadata(),
        )

    def recalculate_summary(self) -> Self:
        """Return a validated copy whose summary matches its current findings."""

        payload = self.model_dump(exclude={"analysis_summary"})
        return type(self)(
            **payload,
            analysis_summary=AnalysisSummary.from_findings(self.findings),
        )
