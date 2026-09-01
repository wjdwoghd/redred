"""Environment-backed scanner settings with safe, non-secret defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


SUPPORTED_MODES = {"mock", "filesystem", "active", "cli", "rest", "tool"}


def _integer(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class ScannerSettings:
    mode: str
    mock_data_path: Path
    results_dir: Path
    cli_command: str | None
    working_dir: Path | None
    cli_timeout_seconds: int
    api_base_url: str | None
    api_key: str | None = field(repr=False)
    request_timeout_seconds: int
    max_upload_mb: int
    default_target_url: str
    scanner_project_dir: Path = field(default_factory=Path.cwd)
    scanner_analysis_mode: str = "auto"
    scanner_scan_mode: str = "endpoint"
    scanner_cookie: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, base_dir: Path | None = None) -> "ScannerSettings":
        root = (base_dir or Path(__file__).resolve().parent).resolve()
        mode = os.getenv("SCANNER_MODE", "mock").strip().lower()
        if mode not in SUPPORTED_MODES:
            mode = "mock"

        working_dir_value = os.getenv("SCANNER_WORKING_DIR", "").strip()
        configured_results = os.getenv("SCANNER_RESULTS_DIR", "").strip()
        default_results = root.parent / "ai_scanner" / "results"
        if not configured_results:
            configured_results = str(default_results if mode == "active" else root / "sample_results")
        configured_target = os.getenv("SCANNER_DEFAULT_TARGET_URL", "").strip()
        if not configured_target and mode == "mock":
            configured_target = "http://127.0.0.1/REDRED/login.php"
        scanner_mode = os.getenv("SCANNER_ANALYSIS_MODE", "auto").strip().lower()
        if scanner_mode not in {"auto", "ai", "rules"}:
            scanner_mode = "auto"
        scan_scope = os.getenv("SCANNER_SCAN_MODE", "endpoint").strip().lower()
        if scan_scope not in {"single", "endpoint", "crawl"}:
            scan_scope = "endpoint"
        project_value = os.getenv("SCANNER_PROJECT_DIR", "").strip()
        scanner_project = Path(project_value).expanduser() if project_value else root.parent
        return cls(
            mode=mode,
            mock_data_path=Path(
                os.getenv("SCANNER_MOCK_DATA_PATH", str(root / "data" / "mock_scan_result.json"))
            ).expanduser(),
            results_dir=Path(configured_results).expanduser(),
            cli_command=os.getenv("SCANNER_CLI_COMMAND", "").strip() or None,
            working_dir=Path(working_dir_value).expanduser() if working_dir_value else None,
            cli_timeout_seconds=_integer("SCANNER_CLI_TIMEOUT_SECONDS", 300),
            api_base_url=os.getenv("SCANNER_API_BASE_URL", "").strip() or None,
            api_key=os.getenv("SCANNER_API_KEY", "").strip() or None,
            request_timeout_seconds=_integer("SCANNER_REQUEST_TIMEOUT_SECONDS", 30),
            max_upload_mb=_integer("SCANNER_MAX_UPLOAD_MB", 20),
            default_target_url=configured_target,
            scanner_project_dir=scanner_project,
            scanner_analysis_mode=scanner_mode,
            scanner_scan_mode=scan_scope,
            scanner_cookie=os.getenv("SCANNER_COOKIE", "").strip() or None,
        )
