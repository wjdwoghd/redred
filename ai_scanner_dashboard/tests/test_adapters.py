from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from adapters import (
    AdapterConfigurationError,
    CliScannerAdapter,
    FilesystemScannerAdapter,
    MockScannerAdapter,
    RestScannerAdapter,
    ScannerAdapterError,
)
from adapters.filesystem_adapter import portable_basename
from models import Evidence
from services import ScannerService


def sample_result(scan_id: str = "scan-1") -> dict:
    return {
        "scan_id": scan_id,
        "target_url": "http://example.test/login.php",
        "status": "completed",
        "scan_summary": {"scanned_pages": 3, "normal_pages": 2},
        "findings": [
            {
                "finding_id": "F-1",
                "vulnerability_type": "SQL Injection",
                "uri": "/login.php",
                "initial_severity": "HIGH",
                "final_severity": "CRITICAL",
                "confidence": 0.91,
            }
        ],
    }


class MockFlowTests(unittest.TestCase):
    def test_initial_review_and_reanalysis_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mock.json"
            path.write_text(json.dumps(sample_result()), encoding="utf-8")
            service = ScannerService(MockScannerAdapter(path))

            initial = service.run_initial_scan("http://example.test/login.php")
            self.assertIsNone(initial.findings[0].final_severity)
            evidence = Evidence(
                evidence_id="E-1",
                finding_id="F-1",
                evidence_type="screenshot",
                filename="proof.png",
                uploaded_at=datetime.now(),
            )
            service.submit_review(
                initial.scan_id,
                [{"finding_id": "F-1", "review_status": "verified", "reviewer_memo": "재현 확인"}],
                [evidence],
            )
            final = service.run_reanalysis(initial.scan_id)
            self.assertEqual(final.status, "reanalysis_completed")
            self.assertEqual(final.findings[0].final_severity, "CRITICAL")
            self.assertEqual(final.findings[0].reviewer_memo, "재현 확인")
            self.assertEqual(final.findings[0].evidence[0].filename, "proof.png")

    def test_reanalysis_requires_review_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mock.json"
            path.write_text(json.dumps(sample_result()), encoding="utf-8")
            service = ScannerService(MockScannerAdapter(path))
            with self.assertRaises(ScannerAdapterError):
                service.submit_review("scan-1", [], [])


class FilesystemTests(unittest.TestCase):
    def test_latest_folder_report_and_read_only_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "active-scan-001"
            latest = root / "active-scan-002"
            old.mkdir()
            latest.mkdir()
            (old / "result.json").write_text(json.dumps(sample_result("active-scan-001")), encoding="utf-8")
            (latest / "scan_result.json").write_text(json.dumps(sample_result("active-scan-002")), encoding="utf-8")
            (latest / "final_report.pdf").write_bytes(b"%PDF-real-test")
            (latest / "proof.png").write_bytes(b"png")

            adapter = FilesystemScannerAdapter(root)
            service = ScannerService(adapter)
            before = sorted(str(item.relative_to(root)) for item in root.rglob("*"))
            result = service.run_initial_scan("http://ignored.test")
            service.submit_review(
                result.scan_id,
                [{"finding_id": "F-1", "reviewer_memo": "확인"}],
                [Evidence(evidence_id="E", finding_id="F-1", filename="e.txt")],
            )
            service.run_reanalysis(result.scan_id)
            after = sorted(str(item.relative_to(root)) for item in root.rglob("*"))

            self.assertEqual(result.scan_id, "active-scan-002")
            self.assertEqual(before, after)
            download = service.get_report_download(result.scan_id, "final_report")
            self.assertIsNotNone(download)
            self.assertEqual(download.content, b"%PDF-real-test")  # type: ignore[union-attr]
            self.assertIsNone(service.get_report_download(result.scan_id, "diagnostic_guide"))

    def test_invalid_json_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            scan = Path(directory) / "active-scan-bad"
            scan.mkdir()
            (scan / "result.json").write_text("not-json", encoding="utf-8")
            with self.assertRaises(ScannerAdapterError):
                FilesystemScannerAdapter(Path(directory)).run_initial_scan("http://example.test")

    def test_windows_and_posix_paths(self):
        self.assertEqual(portable_basename(r"C:\scanner\results\proof.txt"), "proof.txt")
        self.assertEqual(portable_basename("/var/scanner/results/proof.png"), "proof.png")


class SafeConfigurationTests(unittest.TestCase):
    def test_cli_without_command_never_runs_subprocess(self):
        with patch("subprocess.run") as run:
            adapter = CliScannerAdapter(None)
            with self.assertRaises(AdapterConfigurationError):
                adapter.run_initial_scan("http://example.test")
            run.assert_not_called()

    def test_rest_without_url_or_key_never_calls_network(self):
        with patch("urllib.request.urlopen") as urlopen:
            adapter = RestScannerAdapter(None, None)
            with self.assertRaises(AdapterConfigurationError):
                adapter.run_initial_scan("http://example.test")
            urlopen.assert_not_called()

    def test_api_key_is_not_exposed(self):
        secret = "super-secret-key"
        adapter = RestScannerAdapter("https://scanner.invalid", secret)
        with self.assertRaises(AdapterConfigurationError) as context:
            adapter.get_scan_result("scan-1")
        self.assertNotIn(secret, str(context.exception))
        self.assertNotIn(secret, repr(adapter))


if __name__ == "__main__":
    unittest.main()
