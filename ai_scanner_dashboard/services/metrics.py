"""Pure dashboard transformations; no model training is required."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

import pandas as pd

from models import Finding, ScanResult


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
STATUS_LABELS = {
    "unverified": "미검증",
    "verified": "검증 완료",
    "confirmed": "취약점 확정",
    "false_positive": "오탐/제외",
    "reanalysis_required": "재분석 필요",
    "unknown": "확인 필요",
}


@dataclass(frozen=True)
class DashboardMetrics:
    scanned_pages: int
    total_findings: int
    reviewed_findings: int
    false_positives: int
    critical_high: int
    evidence_count: int


def effective_severity(finding: Finding) -> str:
    return (finding.final_severity or finding.initial_severity or "UNKNOWN").upper()


def compute_dashboard_metrics(scan: ScanResult, session_evidence_count: int = 0) -> DashboardMetrics:
    evidence_ids = {item.evidence_id for finding in scan.findings for item in finding.evidence}
    return DashboardMetrics(
        scanned_pages=scan.scanned_pages,
        total_findings=len(scan.findings),
        reviewed_findings=sum(item.review_status not in {"unverified", "unknown", ""} for item in scan.findings),
        false_positives=sum(item.review_status == "false_positive" for item in scan.findings),
        critical_high=sum(effective_severity(item) in {"CRITICAL", "HIGH"} for item in scan.findings),
        evidence_count=len(evidence_ids) + session_evidence_count,
    )


def findings_frame(findings: list[Finding]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "취약점 ID": item.finding_id,
                "취약점 유형": item.vulnerability_type,
                "URI": item.uri,
                "Method": item.http_method or "-",
                "Parameter": item.parameter or "-",
                "1차 위험도": item.initial_severity or "UNKNOWN",
                "최종 위험도": item.final_severity or "판정 전",
                "신뢰도": item.confidence,
                "검토 상태": STATUS_LABELS.get(item.review_status, item.review_status),
                "증적": len(item.evidence),
            }
            for item in findings
        ]
    )


def category_counts(findings: list[Finding]) -> pd.DataFrame:
    counts = Counter(item.vulnerability_type or "Unknown" for item in findings)
    return pd.DataFrame(
        [{"취약점 유형": name, "탐지 건수": count} for name, count in counts.most_common()]
    )


def severity_counts(findings: list[Finding]) -> pd.DataFrame:
    counts = Counter(effective_severity(item) for item in findings)
    return pd.DataFrame(
        [{"위험도": severity, "탐지 건수": counts.get(severity, 0)} for severity in SEVERITY_ORDER]
    )


def severity_comparison(findings: list[Finding]) -> pd.DataFrame:
    rows = []
    for severity in SEVERITY_ORDER:
        rows.append({
            "위험도": severity,
            "판정 시점": "1차 자동 스캔",
            "탐지 건수": sum((item.initial_severity or "UNKNOWN").upper() == severity for item in findings),
        })
        rows.append({
            "위험도": severity,
            "판정 시점": "증적 반영 후",
            "탐지 건수": sum(effective_severity(item) == severity for item in findings),
        })
    return pd.DataFrame(rows)
