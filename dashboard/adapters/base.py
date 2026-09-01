"""Adapter contract used by ScannerService."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping, Sequence

from models import Evidence, ReportArtifacts


class ScannerAdapterError(RuntimeError):
    """Safe scanner boundary error suitable for display in the dashboard."""


class AdapterConfigurationError(ScannerAdapterError):
    """Raised when a selected adapter has not been configured."""


class ScannerAdapter(ABC):
    source_label = "연결 정보 없음"
    is_live_connection = False

    @abstractmethod
    def health_check(self) -> tuple[bool, str]:
        """Return whether this adapter can currently serve results."""

    @abstractmethod
    def run_initial_scan(self, target_url: str) -> Mapping[str, Any]:
        """Start or load the first-stage result, depending on adapter semantics."""

    @abstractmethod
    def submit_review(
        self,
        scan_id: str,
        reviews: Sequence[Mapping[str, Any]],
        evidence: Sequence[Evidence],
    ) -> None:
        """Submit human review data to the scanner boundary."""

    def add_manual_finding(self, scan_id: str, finding: Mapping[str, Any]) -> Mapping[str, Any]:
        """Persist a reviewer-created finding when the adapter supports it."""
        raise ScannerAdapterError("이 연결 방식에서는 수동 Finding 추가를 지원하지 않습니다.")

    @abstractmethod
    def run_reanalysis(self, scan_id: str) -> Mapping[str, Any]:
        """Run or load the evidence-based reanalysis result."""

    @abstractmethod
    def get_scan_result(self, scan_id: str) -> Mapping[str, Any]:
        """Return a raw scanner result."""

    @abstractmethod
    def get_report_artifacts(self, scan_id: str) -> ReportArtifacts:
        """Return report file references without exposing them to the UI."""

    def read_report(self, scan_id: str, report_type: str) -> bytes | None:
        """Read an existing report. Adapters may override with a safe implementation."""
        return None
