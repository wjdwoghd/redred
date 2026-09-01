"""Safe, deterministic persistence for scan inputs and analysis artifacts."""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel


SCAN_ID_PATTERN = re.compile(r"^scan-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ResultStoreError(RuntimeError):
    """Raised when validated artifacts cannot be persisted safely."""


@dataclass(frozen=True, slots=True)
class ArtifactPaths:
    """Paths created for a completed scan."""

    scan_directory: Path
    input_json: Path
    analysis_json: Path
    report_markdown: Path


def _json_compatible(value: Any) -> Any:
    """Convert Pydantic objects to JSON-compatible Python values."""

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=False)
    return value


class ResultStore:
    """Write one isolated artifact directory per scan identifier."""

    def __init__(self, base_directory: str | Path) -> None:
        self.base_directory = Path(base_directory).expanduser().resolve()

    def paths_for(self, scan_id: str) -> ArtifactPaths:
        """Return traversal-safe paths for ``scan_id``."""

        if not SCAN_ID_PATTERN.fullmatch(scan_id):
            raise ResultStoreError(
                "scan_id must match 'scan-' followed by letters, numbers, '.', '_' or '-'"
            )

        scan_directory = (self.base_directory / scan_id).resolve()
        if scan_directory.parent != self.base_directory:
            raise ResultStoreError("scan_id resolved outside the configured results directory")

        return ArtifactPaths(
            scan_directory=scan_directory,
            input_json=scan_directory / "input.json",
            analysis_json=scan_directory / "analysis.json",
            report_markdown=scan_directory / "report.md",
        )

    def save_all(
        self,
        *,
        scan_id: str,
        scan_input: Any,
        analysis: Any,
        report_markdown: str,
    ) -> ArtifactPaths:
        """Atomically replace each artifact in the scan directory."""

        paths = self.paths_for(scan_id)
        try:
            paths.scan_directory.mkdir(parents=True, exist_ok=True)
            self._write_json(paths.input_json, _json_compatible(scan_input))
            self._write_json(paths.analysis_json, _json_compatible(analysis))
            self._write_text(paths.report_markdown, report_markdown)
        except (OSError, TypeError, ValueError) as exc:
            raise ResultStoreError(
                f"failed to save artifacts under {paths.scan_directory}: {exc}"
            ) from exc
        return paths

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        serialized = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        ResultStore._write_text(path, serialized)

    @staticmethod
    def _write_text(path: Path, text: str) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(text, encoding="utf-8", newline="\n")
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

