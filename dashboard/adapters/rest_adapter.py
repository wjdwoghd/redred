"""Reserved REST adapter. It intentionally makes no HTTP requests."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from adapters.base import AdapterConfigurationError, ScannerAdapter
from models import Evidence, ReportArtifacts


class RestScannerAdapter(ScannerAdapter):
    source_label = "연동 대기 · REST"
    is_live_connection = False

    def __init__(self, base_url: str | None, api_key: str | None):
        self.base_url = base_url
        self._api_key = api_key

    def _unavailable(self) -> AdapterConfigurationError:
        if not self.base_url:
            return AdapterConfigurationError("SCANNER_API_BASE_URL이 설정되지 않았습니다.")
        return AdapterConfigurationError(
            "REST API 규격이 아직 확정되지 않아 요청을 보내지 않았습니다. tool_adapter.py의 TODO를 구현해 주세요."
        )

    def health_check(self) -> tuple[bool, str]:
        return False, str(self._unavailable())

    def run_initial_scan(self, target_url: str) -> Mapping[str, Any]:
        raise self._unavailable()

    def submit_review(self, scan_id: str, reviews: Sequence[Mapping[str, Any]], evidence: Sequence[Evidence]) -> None:
        raise self._unavailable()

    def run_reanalysis(self, scan_id: str) -> Mapping[str, Any]:
        raise self._unavailable()

    def get_scan_result(self, scan_id: str) -> Mapping[str, Any]:
        raise self._unavailable()

    def get_report_artifacts(self, scan_id: str) -> ReportArtifacts:
        raise self._unavailable()
