"""Application service orchestrating adapters and result normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from adapters import (
    CliScannerAdapter,
    FilesystemScannerAdapter,
    MockScannerAdapter,
    RestScannerAdapter,
    ScannerAdapter,
    ScannerAdapterError,
    ToolScannerAdapter,
)
from models import Evidence, ReportDownload, ScanResult
from normalizers import normalize_scan_result
from settings import ScannerSettings


REPORT_FILENAMES = {
    "diagnostic_guide": "diagnostic_guide.pdf",
    "final_report": "final_report.pdf",
    "secure_coding_guide": "secure_coding_guide.pdf",
}


class ScannerService:
    def __init__(self, adapter: ScannerAdapter):
        self.adapter = adapter

    @property
    def source_label(self) -> str:
        return self.adapter.source_label

    @property
    def is_live_connection(self) -> bool:
        return self.adapter.is_live_connection

    def health_check(self) -> tuple[bool, str]:
        return self.adapter.health_check()

    @staticmethod
    def _validate_target_url(target_url: str) -> str:
        parsed = urlparse(target_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ScannerAdapterError("대상 URL은 http:// 또는 https://로 시작하는 올바른 주소여야 합니다.")
        return target_url.strip()

    def _normalize(self, raw: Mapping[str, Any], scan_id: str | None = None) -> ScanResult:
        if isinstance(self.adapter, FilesystemScannerAdapter):
            bundle_raw, raw_path, reports, evidence = self.adapter.load_bundle(scan_id)
            return normalize_scan_result(
                bundle_raw,
                raw_result_path=raw_path,
                default_scan_id=scan_id,
                discovered_reports=reports,
                discovered_evidence=evidence,
            )
        return normalize_scan_result(raw, default_scan_id=scan_id)

    def run_initial_scan(self, target_url: str) -> ScanResult:
        target = self._validate_target_url(target_url)
        raw = self.adapter.run_initial_scan(target)
        return self._normalize(raw)

    def submit_review(
        self,
        scan_id: str,
        reviews: Sequence[Mapping[str, Any]],
        evidence: Sequence[Evidence],
    ) -> None:
        if not reviews:
            raise ScannerAdapterError("한 개 이상의 담당자 검토 의견이 필요합니다.")
        if not evidence:
            raise ScannerAdapterError("한 개 이상의 증적 파일이 필요합니다.")
        self.adapter.submit_review(scan_id, reviews, evidence)

    def run_reanalysis(self, scan_id: str) -> ScanResult:
        raw = self.adapter.run_reanalysis(scan_id)
        return self._normalize(raw, scan_id)

    def get_scan_result(self, scan_id: str) -> ScanResult:
        raw = self.adapter.get_scan_result(scan_id)
        return self._normalize(raw, scan_id)

    def get_report_download(self, scan_id: str, report_type: str) -> ReportDownload | None:
        filename = REPORT_FILENAMES.get(report_type)
        if not filename:
            return None
        content = self.adapter.read_report(scan_id, report_type)
        if not content:
            return None
        return ReportDownload(filename=filename, content=content)


def create_scanner_service(settings: ScannerSettings) -> ScannerService:
    adapters: dict[str, ScannerAdapter] = {
        "mock": MockScannerAdapter(settings.mock_data_path),
        "filesystem": FilesystemScannerAdapter(settings.results_dir),
        "cli": CliScannerAdapter(settings.cli_command),
        "rest": RestScannerAdapter(settings.api_base_url, settings.api_key),
        "tool": ToolScannerAdapter(),
    }
    return ScannerService(adapters[settings.mode])
