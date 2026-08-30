"""Read-only adapter for existing active-scan-* result directories."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence

from adapters.base import ScannerAdapter, ScannerAdapterError
from models import Evidence, ReportArtifacts


REPORT_NAMES = {
    "diagnostic_guide": "diagnostic_guide.pdf",
    "final_report": "final_report.pdf",
    "secure_coding_guide": "secure_coding_guide.pdf",
}
JSON_PRIORITY = ("scan_result.json", "result.json", "review.json")
EVIDENCE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".txt", ".log", ".json", ".pdf"}


def portable_basename(value: str) -> str:
    """Return a safe filename for Windows or POSIX-formatted scanner paths."""
    windows_name = PureWindowsPath(value).name
    posix_name = PurePosixPath(value).name
    return windows_name if len(windows_name) < len(posix_name) else posix_name


class FilesystemScannerAdapter(ScannerAdapter):
    source_label = "결과 조회 모드 · Local Files"
    is_live_connection = False

    def __init__(self, results_dir: Path):
        self.results_dir = results_dir.expanduser().resolve()
        self._reviews: dict[str, list[dict[str, Any]]] = {}
        self._evidence: dict[str, list[Evidence]] = {}

    def _safe(self, path: Path) -> Path:
        resolved = path.resolve()
        try:
            resolved.relative_to(self.results_dir)
        except ValueError as exc:
            raise ScannerAdapterError("결과 폴더 밖의 경로에는 접근할 수 없습니다.") from exc
        return resolved

    def _scan_directories(self) -> list[Path]:
        if not self.results_dir.is_dir():
            return []
        candidates = []
        if self.results_dir.name.startswith("active-scan-"):
            candidates.append(self.results_dir)
        candidates.extend(
            item for item in self.results_dir.iterdir()
            if item.is_dir() and item.name.startswith("active-scan-")
        )
        return sorted(candidates, key=lambda item: (item.stat().st_mtime, item.name), reverse=True)

    def _scan_directory(self, scan_id: str | None = None) -> Path:
        candidates = self._scan_directories()
        if not candidates:
            raise ScannerAdapterError("active-scan-* 결과 폴더를 찾을 수 없습니다.")
        if not scan_id:
            return candidates[0]
        for candidate in candidates:
            if candidate.name == scan_id or candidate.name.removeprefix("active-scan-") == scan_id:
                return candidate
        raise ScannerAdapterError(f"선택한 스캔 결과를 찾을 수 없습니다: {scan_id}")

    def _result_file(self, directory: Path) -> Path:
        files = [self._safe(item) for item in directory.rglob("*.json") if item.is_file()]
        for name in JSON_PRIORITY:
            exact = [item for item in files if item.name.lower() == name]
            if exact:
                return sorted(exact)[0]
        if files:
            return sorted(files)[0]
        raise ScannerAdapterError("스캔 결과 JSON 파일을 찾을 수 없습니다.")

    def _load(self, scan_id: str | None = None) -> tuple[dict[str, Any], Path, Path]:
        directory = self._scan_directory(scan_id)
        result_file = self._result_file(directory)
        try:
            raw = json.loads(result_file.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScannerAdapterError("스캔 결과 JSON을 안전하게 읽을 수 없습니다.") from exc
        if not isinstance(raw, dict):
            raise ScannerAdapterError("스캔 결과 JSON의 최상위 값은 객체여야 합니다.")
        raw.setdefault("scan_id", directory.name)
        return raw, directory, result_file

    def _reports(self, directory: Path) -> ReportArtifacts:
        found: dict[str, str | None] = {key: None for key in REPORT_NAMES}
        for report_type, filename in REPORT_NAMES.items():
            matches = [item for item in directory.rglob(filename) if item.is_file()]
            if matches:
                found[report_type] = str(self._safe(sorted(matches)[0]))
        return ReportArtifacts(**found)

    def discover_evidence(self, directory: Path, result_file: Path) -> list[Evidence]:
        report_names = set(REPORT_NAMES.values())
        evidence = []
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            safe_path = self._safe(path)
            if safe_path == result_file or safe_path.name in report_names:
                continue
            if safe_path.suffix.lower() not in EVIDENCE_SUFFIXES:
                continue
            evidence.append(
                Evidence(
                    evidence_id=f"file-{len(evidence) + 1}",
                    evidence_type=safe_path.suffix.lower().lstrip(".") or "file",
                    filename=portable_basename(str(safe_path)),
                    local_path=str(safe_path),
                    size_bytes=safe_path.stat().st_size,
                )
            )
        return evidence

    def load_bundle(self, scan_id: str | None = None) -> tuple[Mapping[str, Any], str, ReportArtifacts, list[Evidence]]:
        raw, directory, result_file = self._load(scan_id)
        return raw, str(result_file), self._reports(directory), self.discover_evidence(directory, result_file)

    def health_check(self) -> tuple[bool, str]:
        try:
            self._load()
        except ScannerAdapterError as exc:
            return False, str(exc)
        return True, "기존 로컬 결과를 읽을 수 있습니다."

    def run_initial_scan(self, target_url: str) -> Mapping[str, Any]:
        raw, _, _ = self._load()
        return raw

    def submit_review(
        self,
        scan_id: str,
        reviews: Sequence[Mapping[str, Any]],
        evidence: Sequence[Evidence],
    ) -> None:
        self._reviews[scan_id] = [dict(item) for item in reviews]
        self._evidence[scan_id] = list(evidence)

    def run_reanalysis(self, scan_id: str) -> Mapping[str, Any]:
        raw, _, _ = self._load(scan_id)
        return raw

    def get_scan_result(self, scan_id: str) -> Mapping[str, Any]:
        raw, _, _ = self._load(scan_id)
        return raw

    def get_report_artifacts(self, scan_id: str) -> ReportArtifacts:
        directory = self._scan_directory(scan_id)
        return self._reports(directory)

    def read_report(self, scan_id: str, report_type: str) -> bytes | None:
        path_value = self.get_report_artifacts(scan_id).get(report_type)
        if not path_value:
            return None
        path = self._safe(Path(path_value))
        return path.read_bytes() if path.is_file() and path.suffix.lower() == ".pdf" else None
