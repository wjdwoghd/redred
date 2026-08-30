"""Environment-backed scanner settings with safe, non-secret defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


SUPPORTED_MODES = {"mock", "filesystem", "cli", "rest", "tool"}


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

    @classmethod
    def from_env(cls, base_dir: Path | None = None) -> "ScannerSettings":
        root = (base_dir or Path(__file__).resolve().parent).resolve()
        mode = os.getenv("SCANNER_MODE", "mock").strip().lower()
        if mode not in SUPPORTED_MODES:
            mode = "mock"

        working_dir_value = os.getenv("SCANNER_WORKING_DIR", "").strip()
        return cls(
            mode=mode,
            mock_data_path=Path(
                os.getenv("SCANNER_MOCK_DATA_PATH", str(root / "data" / "mock_scan_result.json"))
            ).expanduser(),
            results_dir=Path(
                os.getenv("SCANNER_RESULTS_DIR", str(root / "sample_results"))
            ).expanduser(),
            cli_command=os.getenv("SCANNER_CLI_COMMAND", "").strip() or None,
            working_dir=Path(working_dir_value).expanduser() if working_dir_value else None,
            cli_timeout_seconds=_integer("SCANNER_CLI_TIMEOUT_SECONDS", 300),
            api_base_url=os.getenv("SCANNER_API_BASE_URL", "").strip() or None,
            api_key=os.getenv("SCANNER_API_KEY", "").strip() or None,
            request_timeout_seconds=_integer("SCANNER_REQUEST_TIMEOUT_SECONDS", 30),
            max_upload_mb=_integer("SCANNER_MAX_UPLOAD_MB", 20),
            default_target_url=os.getenv(
                "SCANNER_DEFAULT_TARGET_URL", "http://127.0.0.1/REDRED/login.php"
            ).strip(),
        )
