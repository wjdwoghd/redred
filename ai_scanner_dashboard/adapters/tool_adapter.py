"""Single integration seam for the future AI Scanner implementation.

This file is deliberately non-operational. Once the scanner code and its exact
input/output contract arrive, implement this adapter (or delegate to CLI/REST)
without changing the Streamlit UI.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from adapters.base import AdapterConfigurationError, ScannerAdapter
from models import Evidence, ReportArtifacts


class ToolScannerAdapter(ScannerAdapter):
    source_label = "연동 대기 · AI Scanner"
    is_live_connection = False

    def _todo(self) -> AdapterConfigurationError:
        return AdapterConfigurationError(
            "실제 AI Scanner 연동 전입니다. adapters/tool_adapter.py의 TODO를 구현해 주세요."
        )

    def health_check(self) -> tuple[bool, str]:
        # TODO(scanner-integration): Verify the real scanner without attacking a target.
        return False, str(self._todo())

    def run_initial_scan(self, target_url: str) -> Mapping[str, Any]:
        # TODO(scanner-integration): Call the scanner's documented initial-scan entrypoint.
        raise self._todo()

    def submit_review(self, scan_id: str, reviews: Sequence[Mapping[str, Any]], evidence: Sequence[Evidence]) -> None:
        # TODO(scanner-integration): Translate reviews/evidence to the scanner contract.
        raise self._todo()

    def run_reanalysis(self, scan_id: str) -> Mapping[str, Any]:
        # TODO(scanner-integration): Call the documented evidence reanalysis entrypoint.
        raise self._todo()

    def get_scan_result(self, scan_id: str) -> Mapping[str, Any]:
        # TODO(scanner-integration): Fetch raw JSON-compatible scanner output.
        raise self._todo()

    def get_report_artifacts(self, scan_id: str) -> ReportArtifacts:
        # TODO(scanner-integration): Map only report files that really exist.
        raise self._todo()
