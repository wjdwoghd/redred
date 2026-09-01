"""Dashboard adapter that runs the repository's bounded REDRED scanner.

The scanner implementation remains in :mod:`ai_scanner`; this adapter only
starts it and binds the exact directory created by that invocation to the
Dashboard result view.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from adapters.filesystem_adapter import FilesystemScannerAdapter
from adapters.base import ScannerAdapterError

LOGGER = logging.getLogger(__name__)


class ActiveScannerAdapter(FilesystemScannerAdapter):
    """Execute ``python -m ai_scanner.main --scan`` and load its new result."""

    source_label = "실제 Scanner 실행"
    is_live_connection = True

    def __init__(
        self,
        results_dir: Path,
        *,
        project_dir: Path | None = None,
        analysis_mode: str = "auto",
        # Keep the adapter's direct-call default backwards compatible.  The
        # Dashboard settings explicitly pass ``endpoint`` by default.
        scan_mode: str = "single",
        cookie: str | None = None,
        timeout_seconds: int = 900,
    ) -> None:
        super().__init__(results_dir)
        self.project_dir = (project_dir or Path(__file__).resolve().parents[2]).expanduser().resolve()
        self.analysis_mode = analysis_mode if analysis_mode in {"rules", "ai", "auto"} else "auto"
        self.scan_mode = scan_mode if scan_mode in {"single", "endpoint", "crawl"} else "single"
        self.cookie = cookie.strip() if cookie and cookie.strip() else None
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.last_scan_id: str | None = None

    def health_check(self) -> tuple[bool, str]:
        entrypoint = self.project_dir / "ai_scanner" / "main.py"
        if not entrypoint.is_file():
            return False, f"Scanner entrypoint not found: {entrypoint}"
        return True, "실제 Scanner 실행 준비 완료"

    def load_bundle(self, scan_id: str | None = None):
        # ScannerService calls load_bundle without an id after run_initial_scan.
        # Pin that call to the directory produced by this invocation rather than
        # accidentally selecting an older mtime-sorted result.
        return super().load_bundle(scan_id or self.last_scan_id)

    @staticmethod
    def _summary_path_from_stdout(stdout: str) -> str | None:
        """Extract the scanner-reported ``scan_summary.json`` path.

        The REDRED CLI prints this path after an active scan.  Supporting both
        Windows and POSIX separators keeps the adapter testable on either host.
        """
        pattern = re.compile(
            r"(?i)(?:[A-Za-z]:[\\/]|/|\\.?[\\/])[^\r\n]*?active-scan-[A-Za-z0-9._-]+[\\/]scan_summary\.json"
        )
        match = pattern.search(stdout or "")
        return match.group(0).strip().rstrip(".,;)") if match else None

    def _complete_scan_folder(self, folder: Path) -> bool:
        """Return true only for a complete active-scan artifact directory."""
        return folder.is_dir() and all((folder / name).is_file() for name in ("scan_summary.json", "analysis.json", "review.json"))

    def _folder_from_reported_path(self, reported: str) -> Path:
        candidate = Path(reported).expanduser()
        if not candidate.is_absolute():
            candidate = (self.project_dir / candidate).resolve()
        else:
            candidate = candidate.resolve()
        try:
            candidate = self._safe(candidate)
        except ScannerAdapterError as exc:
            raise ScannerAdapterError("Scanner reported a result outside the configured results directory") from exc
        folder = candidate.parent
        if not self._complete_scan_folder(folder):
            raise ScannerAdapterError(
                f"Scanner reported an incomplete result folder: {folder.name} "
                "(scan_summary.json, analysis.json and review.json are required)"
            )
        return folder

    @staticmethod
    def _summary_target(summary: Mapping[str, Any]) -> str | None:
        value = summary.get("target")
        if isinstance(value, Mapping):
            value = value.get("url") or value.get("target_url") or value.get("base_url")
        if value in (None, ""):
            value = summary.get("target_url") or summary.get("url")
        return str(value).strip() if value not in (None, "") else None

    def _validate_summary_target(self, folder: Path, target_url: str) -> None:
        summary = self._load_json_file(folder / "scan_summary.json")
        reported_target = self._summary_target(summary)
        if not reported_target or reported_target != target_url.strip():
            raise ScannerAdapterError(
                "Scanner result target does not match the requested URL; "
                "the result was not loaded"
            )

    def run_initial_scan(self, target_url: str) -> Mapping[str, Any]:
        started = time.time()
        before = {path.name for path in self._scan_directories()}
        command = [
            sys.executable,
            "-m",
            "ai_scanner.main",
            "--target",
            target_url,
            "--scan",
            "--scan-mode",
            self.scan_mode,
            "--mode",
            self.analysis_mode,
        ]
        if self.cookie:
            command.extend(["--cookie", self.cookie])
        LOGGER.info("[SCANNER] starting target=%s mode=%s analysis=%s", target_url, self.scan_mode, self.analysis_mode)
        try:
            completed = subprocess.run(
                command,
                cwd=str(self.project_dir),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerAdapterError(f"Scanner timed out after {self.timeout_seconds}s") from exc
        except OSError as exc:
            raise ScannerAdapterError(f"Scanner could not be started: {exc}") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "scanner returned a non-zero exit code").strip()
            if self.cookie:
                detail = detail.replace(self.cookie, "[REDACTED]")
            raise ScannerAdapterError(f"Scanner failed (exit {completed.returncode}): {detail[-1_500:]}")

        # Prefer the exact path printed by the scanner.  This avoids selecting
        # an unrelated folder that happened to have a newer mtime (or an empty
        # folder created by another process during the scan).
        reported = self._summary_path_from_stdout(completed.stdout or "")
        if reported:
            selected = self._folder_from_reported_path(reported)
        else:
            # Without stdout, accept only newly-created *complete* folders. If
            # more than one qualifies, fail closed instead of guessing by mtime.
            new_dirs = [
                path for path in self._scan_directories()
                if path.name not in before and self._complete_scan_folder(path)
            ]
            if len(new_dirs) != 1:
                raise ScannerAdapterError(
                    "Scanner did not identify exactly one complete new active-scan result"
                )
            selected = new_dirs[0]
        self._validate_summary_target(selected, target_url)
        self.last_scan_id = selected.name
        LOGGER.info("[SCANNER] completed scan_id=%s elapsed=%.3fs", self.last_scan_id, time.time() - started)
        raw, _, _ = self._load(self.last_scan_id)
        raw["scan_id"] = self.last_scan_id
        return raw


__all__ = ["ActiveScannerAdapter"]
