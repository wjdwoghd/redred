"""Reserved CLI adapter. No subprocess is executed until its contract is known."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from adapters.base import AdapterConfigurationError, ScannerAdapter
from models import Evidence, ReportArtifacts


class CliScannerAdapter(ScannerAdapter):
    source_label = "연동 대기 · CLI"
    is_live_connection = False

    def __init__(self, command: str | None):
        self.command = command

    def _unavailable(self) -> AdapterConfigurationError:
        if not self.command:
            return AdapterConfigurationError("SCANNER_CLI_COMMAND가 설정되지 않았습니다.")
        return AdapterConfigurationError(
            "CLI 호출 규격이 아직 확정되지 않아 명령을 실행하지 않았습니다. tool_adapter.py의 TODO를 구현해 주세요."
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
