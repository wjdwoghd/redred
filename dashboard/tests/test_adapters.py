from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from adapters import (
    AdapterConfigurationError,
    ActiveScannerAdapter,
    CliScannerAdapter,
    FilesystemScannerAdapter,
    MockScannerAdapter,
    RestScannerAdapter,
    ScannerAdapterError,
)
from adapters.filesystem_adapter import portable_basename
from models import Evidence
from services import ScannerService
from settings import ScannerSettings


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
    def test_active_scan_bundle_merges_summary_analysis_review_and_scopes_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "active-scan-20260830-120000"
            root.mkdir()
            (root / "scan_summary.json").write_text(json.dumps({
                "target": "http://127.0.0.1/REDRED/notices.php",
                "pages_scanned": 1,
                "forms_discovered": 1,
                "inputs_tested": 4,
            }), encoding="utf-8")
            (root / "analysis.json").write_text(json.dumps({
                "scan_id": root.name,
                "target": {"url": "http://127.0.0.1/REDRED/notices.php"},
                "findings": [{
                    "id": "F-001", "type": "XSS", "uri": "/notices.php", "method": "POST",
                    "parameter": "title", "severity": "MEDIUM", "confidence": 0.7,
                    "rules": {"input_reflected": True}, "ai_reason": "candidate",
                }],
            }), encoding="utf-8")
            (root / "review.json").write_text(json.dumps({"findings": [{
                "id": "F-001", "review_status": "CONFIRMED", "reviewer_note": "verified",
                "manual_evidence": [{"type": "test_response", "file": "evidence/F-001/test.txt", "description": "response"}],
            }]}), encoding="utf-8")
            evidence_dir = root / "evidence" / "F-001"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "test.txt").write_text("proof", encoding="utf-8")
            # Internal capture files must not be counted as reviewer evidence.
            (root / "raw_captures").mkdir()
            (root / "raw_captures" / "response.txt").write_text("capture", encoding="utf-8")

            result = ScannerService(FilesystemScannerAdapter(Path(directory))).run_initial_scan("http://ignored.test")
            self.assertEqual(result.scanned_pages, 1)
            self.assertEqual(result.forms_discovered, 1)
            self.assertEqual(result.inputs_tested, 4)
            self.assertEqual(result.findings[0].review_status, "CONFIRMED")
            self.assertEqual(result.findings[0].reviewer_memo, "verified")
            self.assertEqual(result.findings[0].ai_diagnostic_summary, "candidate")
            self.assertEqual(len(result.findings[0].evidence), 1)

    def test_filesystem_review_and_evidence_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "active-scan-persist"
            root.mkdir()
            (root / "analysis.json").write_text(json.dumps({"findings": [{"id": "F-1", "type": "XSS"}]}), encoding="utf-8")
            (root / "review.json").write_text(json.dumps({"findings": [{"id": "F-1", "review_status": "PENDING", "reviewer_note": "", "manual_evidence": []}]}), encoding="utf-8")
            adapter = FilesystemScannerAdapter(Path(directory))
            adapter.submit_review(
                "active-scan-persist",
                [{"finding_id": "F-1", "review_status": "CONFIRMED", "reviewer_note": "재현 확인"}],
                [Evidence(evidence_id="E-1", finding_id="F-1", evidence_type="test_response", filename="proof.txt", description="응답", content=b"proof")],
            )
            review = json.loads((root / "review.json").read_text(encoding="utf-8"))
            self.assertEqual(review["findings"][0]["review_status"], "CONFIRMED")
            self.assertEqual(review["findings"][0]["reviewer_note"], "재현 확인")
            self.assertEqual((root / "evidence" / "F-1" / "proof.txt").read_bytes(), b"proof")

    def test_pending_status_is_replaced_by_confirmed_on_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "active-scan-status"
            root.mkdir()
            (root / "analysis.json").write_text(
                json.dumps({"findings": [{"id": "F-001", "type": "XSS"}]}),
                encoding="utf-8",
            )
            (root / "review.json").write_text(
                json.dumps(
                    {"findings": [{"id": "F-001", "review_status": "PENDING", "reviewer_note": "", "manual_evidence": []}]},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            adapter = FilesystemScannerAdapter(Path(directory))
            adapter.submit_review(
                "active-scan-status",
                [{"finding_id": "F-001", "review_status": "CONFIRMED", "reviewer_note": ""}],
                [],
            )
            saved = json.loads((root / "review.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["findings"][0]["review_status"], "CONFIRMED")

    def test_manual_finding_gets_nf_id_and_is_loaded_with_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "active-scan-manual"
            root.mkdir()
            (root / "analysis.json").write_text(
                json.dumps({"findings": [{"id": "F-001", "type": "XSS"}]}),
                encoding="utf-8",
            )
            (root / "review.json").write_text(
                json.dumps({"findings": [{"id": "F-001", "review_status": "PENDING", "manual_evidence": []}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            adapter = FilesystemScannerAdapter(Path(directory))
            first = adapter.add_manual_finding(
                "active-scan-manual",
                {"type": "SQL_INJECTION", "uri": "/resource.php", "method": "GET", "parameter": "keyword", "severity": "HIGH", "reviewer_note": "수동 확인"},
            )
            self.assertEqual(first["id"], "NF-001")
            result = ScannerService(adapter).run_initial_scan("http://ignored.test")
            manual = next(item for item in result.findings if item.finding_id == "NF-001")
            self.assertEqual(manual.review_status, "NEW_FINDING")
            self.assertEqual(manual.scanner_status, "manual")

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
    def test_active_settings_do_not_use_mock_target_and_point_to_scanner_results(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"SCANNER_MODE": "active", "SCANNER_RESULTS_DIR": "", "SCANNER_DEFAULT_TARGET_URL": ""},
            clear=False,
        ):
            settings = ScannerSettings.from_env(Path(directory) / "dashboard")
            self.assertEqual(settings.mode, "active")
            self.assertEqual(settings.default_target_url, "")
            self.assertEqual(settings.results_dir, (Path(directory) / "ai_scanner" / "results").resolve())
            self.assertEqual(settings.scanner_scan_mode, "endpoint")

    def test_active_scanner_selects_directory_created_by_this_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            results.mkdir()
            old = results / "active-scan-old"
            old.mkdir()
            for name, payload in (("analysis.json", {"scan_id": old.name, "findings": []}), ("scan_summary.json", {"target": "http://old/"}), ("review.json", {"findings": []})):
                (old / name).write_text(json.dumps(payload), encoding="utf-8")
            created = results / "active-scan-new"

            def fake_run(command, **kwargs):
                self.assertIn("--scan-mode", command)
                self.assertEqual(command[command.index("--scan-mode") + 1], "single")
                self.assertEqual(command[command.index("--target") + 1], "http://127.0.0.1/REDRED/notices.php")
                created.mkdir()
                (created / "analysis.json").write_text(
                    json.dumps({"scan_id": created.name, "target": {"url": command[command.index("--target") + 1]}, "findings": []}),
                    encoding="utf-8",
                )
                (created / "scan_summary.json").write_text(json.dumps({"target": command[command.index("--target") + 1], "pages_scanned": 1, "forms_discovered": 1, "inputs_tested": 4}), encoding="utf-8")
                (created / "review.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
                return __import__("subprocess").CompletedProcess(command, 0, "", "")

            adapter = ActiveScannerAdapter(Path(results), project_dir=Path(directory), analysis_mode="rules")
            with patch("adapters.active_scanner_adapter.subprocess.run", side_effect=fake_run):
                result = ScannerService(adapter).run_initial_scan("http://127.0.0.1/REDRED/notices.php")
            self.assertEqual(result.scan_id, "active-scan-new")
            self.assertEqual(adapter.last_scan_id, "active-scan-new")

    def test_active_scanner_failure_does_not_fall_back_to_old_result(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            old = results / "active-scan-old"
            old.mkdir(parents=True)
            (old / "analysis.json").write_text(json.dumps({"scan_id": old.name, "findings": []}), encoding="utf-8")
            adapter = ActiveScannerAdapter(Path(results), project_dir=Path(directory))
            failed = __import__("subprocess").CompletedProcess([], 2, "", "connection refused")
            with patch("adapters.active_scanner_adapter.subprocess.run", return_value=failed):
                with self.assertRaises(ScannerAdapterError):
                    ScannerService(adapter).run_initial_scan("http://127.0.0.1/REDRED/notices.php")
            self.assertIsNone(adapter.last_scan_id)

    def test_active_scanner_success_without_new_directory_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            old = results / "active-scan-old"
            old.mkdir(parents=True)
            (old / "analysis.json").write_text(json.dumps({"scan_id": old.name, "findings": []}), encoding="utf-8")
            adapter = ActiveScannerAdapter(Path(results), project_dir=Path(directory))
            completed = __import__("subprocess").CompletedProcess([], 0, "ok", "")
            with patch("adapters.active_scanner_adapter.subprocess.run", return_value=completed):
                with self.assertRaises(ScannerAdapterError):
                    ScannerService(adapter).run_initial_scan("http://127.0.0.1/")
            self.assertIsNone(adapter.last_scan_id)

    def test_stdout_reported_result_wins_over_other_new_complete_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            results.mkdir()
            target = "http://127.0.0.1/REDRED/notices.php"
            reported = results / "active-scan-reported"
            other = results / "active-scan-other"

            def complete(folder: Path, pages: int, url: str) -> None:
                folder.mkdir()
                (folder / "scan_summary.json").write_text(json.dumps({"target": url, "pages_scanned": pages, "forms_discovered": 1, "inputs_tested": 4}), encoding="utf-8")
                (folder / "analysis.json").write_text(json.dumps({"scan_id": folder.name, "findings": []}), encoding="utf-8")
                (folder / "review.json").write_text(json.dumps({"findings": []}), encoding="utf-8")

            def fake_run(command, **kwargs):
                complete(other, 99, target)
                complete(reported, 1, target)
                stdout = f"Active scan summary:\n{reported / 'scan_summary.json'}\n"
                return __import__("subprocess").CompletedProcess(command, 0, stdout, "")

            adapter = ActiveScannerAdapter(results, project_dir=Path(directory), analysis_mode="rules")
            with patch("adapters.active_scanner_adapter.subprocess.run", side_effect=fake_run):
                result = ScannerService(adapter).run_initial_scan(target)
            self.assertEqual(result.scan_id, reported.name)
            self.assertEqual(result.scanned_pages, 1)
            self.assertEqual(result.forms_discovered, 1)
            self.assertEqual(result.inputs_tested, 4)

    def test_incomplete_reported_folder_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            folder = results / "active-scan-empty"
            folder.mkdir(parents=True)
            summary = folder / "scan_summary.json"
            summary.write_text(json.dumps({"target": "http://127.0.0.1/"}), encoding="utf-8")
            adapter = ActiveScannerAdapter(results, project_dir=Path(directory))
            stdout = f"Active scan summary: {summary}"
            completed = __import__("subprocess").CompletedProcess([], 0, stdout, "")
            with patch("adapters.active_scanner_adapter.subprocess.run", return_value=completed):
                with self.assertRaises(ScannerAdapterError):
                    adapter.run_initial_scan("http://127.0.0.1/")

    def test_reported_target_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            folder = results / "active-scan-wrong"
            folder.mkdir(parents=True)
            (folder / "scan_summary.json").write_text(json.dumps({"target": "http://127.0.0.1/other"}), encoding="utf-8")
            (folder / "analysis.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
            (folder / "review.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
            stdout = f"Active scan summary: {folder / 'scan_summary.json'}"
            adapter = ActiveScannerAdapter(results, project_dir=Path(directory))
            with patch("adapters.active_scanner_adapter.subprocess.run", return_value=__import__("subprocess").CompletedProcess([], 0, stdout, "")):
                with self.assertRaises(ScannerAdapterError):
                    adapter.run_initial_scan("http://127.0.0.1/requested")

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
