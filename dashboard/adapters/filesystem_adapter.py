"""Read-only adapter for existing active-scan-* result directories."""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Sequence

from adapters.base import ScannerAdapter, ScannerAdapterError
from models import Evidence, ReportArtifacts


REPORT_NAMES = {
    "diagnostic_guide": "diagnostic_guide.pdf",
    "final_report": "final_report.pdf",
    "secure_coding_guide": "secure_coding_guide.pdf",
}
JSON_PRIORITY = ("analysis.json", "scan_summary.json", "scan_result.json", "result.json", "review.json")
EVIDENCE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".txt", ".log", ".json", ".pdf"}
LOGGER = logging.getLogger(__name__)


def normalize_review_status(value: Any) -> str:
    """Map Dashboard/legacy review values to the scanner's canonical state."""
    raw = str(value or "PENDING").strip().upper()
    return {
        "VERIFIED": "CONFIRMED",
        "CONFIRMED": "CONFIRMED",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
        "FALSE-POSITIVE": "FALSE_POSITIVE",
        "REANALYSIS_REQUIRED": "PENDING",
        "PENDING": "PENDING",
        "NEW_FINDING": "NEW_FINDING",
    }.get(raw, raw)


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

    def _load_json_file(self, path: Path) -> dict[str, Any]:
        """Read one scanner artifact without modifying the result directory."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScannerAdapterError(f"JSON artifact could not be read: {path.name}") from exc
        if not isinstance(raw, dict):
            raise ScannerAdapterError(f"JSON artifact must contain an object: {path.name}")
        return raw

    def _compose_active_bundle(self, directory: Path, primary: Path) -> dict[str, Any]:
        """Merge analysis, summary, and review files into a dashboard view."""
        raw = self._load_json_file(primary)
        analysis_path = directory / "analysis.json"
        summary_path = directory / "scan_summary.json"
        review_path = directory / "review.json"
        if analysis_path.is_file():
            raw = self._load_json_file(analysis_path)
        summary = self._load_json_file(summary_path) if summary_path.is_file() else {}
        review = self._load_json_file(review_path) if review_path.is_file() else {}
        if summary:
            raw["scan_summary"] = summary
            raw["summary"] = summary
            for key in ("target", "pages_scanned", "forms_discovered", "inputs_tested", "http_requests", "errors", "timings"):
                if key in summary and key not in raw:
                    raw[key] = summary[key]
            if "scanned_pages" not in raw and "pages_scanned" in summary:
                raw["scanned_pages"] = summary["pages_scanned"]
        review_by_id = {
            str(item.get("id")): item for item in review.get("findings", [])
            if isinstance(item, dict) and item.get("id")
        }
        merged_findings: list[dict[str, Any]] = []

        def existing_manual_evidence(value: Any) -> list[dict[str, Any]]:
            """Keep only reviewer evidence whose file really exists.

            ``review.json`` stores paths as metadata.  A missing path must not
            become an ``unnamed`` placeholder in the Dashboard evidence list.
            The review document itself remains untouched so the reviewer can
            fix the path later.
            """
            result: list[dict[str, Any]] = []
            if not isinstance(value, list):
                return result
            for evidence in value:
                if not isinstance(evidence, dict):
                    continue
                source = evidence.get("file") or evidence.get("path") or evidence.get("local_path")
                if not source:
                    continue
                candidate = Path(str(source)).expanduser()
                if not candidate.is_absolute():
                    candidate = directory / candidate
                try:
                    candidate = self._safe(candidate)
                except ScannerAdapterError:
                    continue
                if candidate.is_file():
                    result.append(dict(evidence, file=str(candidate)))
            return result

        for item in raw.get("findings", []):
            if not isinstance(item, dict):
                continue
            merged = dict(item)
            reviewer = review_by_id.get(str(item.get("id")))
            if reviewer:
                merged["review"] = dict(reviewer)
                merged["review_status"] = reviewer.get("review_status", "PENDING")
                merged["reviewer_note"] = reviewer.get("reviewer_note", "")
                merged["manual_evidence"] = existing_manual_evidence(reviewer.get("manual_evidence", []))
            merged_findings.append(merged)
        known = {str(item.get("id")) for item in merged_findings}
        for reviewer in review.get("findings", []):
            if isinstance(reviewer, dict) and str(reviewer.get("id")) not in known:
                manual = existing_manual_evidence(reviewer.get("manual_evidence", []))
                merged_findings.append(dict(reviewer, manual_evidence=manual))
        raw["findings"] = merged_findings
        raw["review"] = review
        return raw

    def _load(self, scan_id: str | None = None) -> tuple[dict[str, Any], Path, Path]:
        directory = self._scan_directory(scan_id)
        result_file = self._result_file(directory)
        # Active scans have three sibling artifacts; expose one merged view.
        if any((directory / name).is_file() for name in ("analysis.json", "scan_summary.json", "review.json")):
            raw = self._compose_active_bundle(directory, result_file)
            raw.setdefault("scan_id", directory.name)
            return raw, directory, result_file
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
        """Discover only human evidence, never scanner internal artifacts."""
        report_names = set(REPORT_NAMES.values())
        evidence = []
        evidence_root = directory / "evidence"
        if not evidence_root.is_dir():
            return evidence
        for path in sorted(item for item in evidence_root.rglob("*") if item.is_file()):
            safe_path = self._safe(path)
            if safe_path == result_file or safe_path.name in report_names:
                continue
            if safe_path.suffix.lower() not in EVIDENCE_SUFFIXES:
                continue
            relative = safe_path.relative_to(evidence_root)
            finding_id = relative.parts[0] if len(relative.parts) > 1 else None
            evidence.append(
                Evidence(
                    evidence_id=f"file-{len(evidence) + 1}",
                    finding_id=finding_id,
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
        directory = self._scan_directory(scan_id)
        review_path = directory / "review.json"
        if not review_path.is_file():
            return
        review = self._load_json_file(review_path)
        by_id = {str(item.get("id")): item for item in review.get("findings", []) if isinstance(item, dict)}
        for item in reviews:
            if not isinstance(item, Mapping):
                continue
            finding_id = str(item.get("finding_id") or item.get("id") or "")
            if not finding_id:
                continue
            target = by_id.setdefault(finding_id, {"id": finding_id})
            ui_status = str(item.get("review_status", "PENDING"))
            status = normalize_review_status(ui_status)
            if status not in {"CONFIRMED", "FALSE_POSITIVE", "PENDING", "NEW_FINDING"}:
                continue
            LOGGER.info(
                "[REVIEW] finding_id=%s ui_status=%s scanner_status=%s reviewer_note=%s",
                finding_id,
                ui_status,
                status,
                str(item.get("reviewer_note") or item.get("reviewer_memo") or ""),
            )
            target["review_status"] = status
            target["reviewer_note"] = str(item.get("reviewer_note") or item.get("reviewer_memo") or "")
        for evidence in evidence:
            if not evidence.finding_id or evidence.content is None:
                continue
            safe_finding_id = Path(evidence.finding_id).name
            evidence_dir = directory / "evidence" / safe_finding_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            filename = Path(evidence.filename).name or f"evidence-{evidence.evidence_id}.bin"
            destination = evidence_dir / filename
            if destination.exists() and destination.read_bytes() != evidence.content:
                destination = evidence_dir / f"{destination.stem}-{evidence.evidence_id[:12]}{destination.suffix}"
            destination.write_bytes(evidence.content)
            relative = destination.relative_to(directory).as_posix()
            target = by_id.setdefault(evidence.finding_id, {"id": evidence.finding_id})
            items = target.setdefault("manual_evidence", [])
            record = {"type": evidence.evidence_type, "file": relative, "description": evidence.description or ""}
            if not any(isinstance(old, dict) and old.get("file") == relative for old in items):
                items.append(record)
        review["findings"] = list(by_id.values())
        fd, temporary_name = tempfile.mkstemp(prefix=".review.", suffix=".tmp", dir=str(directory))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(review, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(temporary_name, review_path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

        # Read back the persisted artifact so a UI success cannot mask a
        # stale or malformed review state.
        saved_review = self._load_json_file(review_path)
        saved_by_id = {
            str(item.get("id")): item
            for item in saved_review.get("findings", [])
            if isinstance(item, dict) and item.get("id") is not None
        }
        for item in reviews:
            finding_id = str(item.get("finding_id") or item.get("id") or "")
            if not finding_id:
                continue
            expected = normalize_review_status(item.get("review_status"))
            actual = normalize_review_status(saved_by_id.get(finding_id, {}).get("review_status"))
            LOGGER.info(
                "[REVIEW] persisted finding_id=%s expected_status=%s actual_status=%s",
                finding_id,
                expected,
                actual,
            )
            if actual != expected:
                raise ScannerAdapterError(
                    f"review.json status verification failed for {finding_id}: "
                    f"expected {expected}, got {actual}"
                )

    def add_manual_finding(self, scan_id: str, finding: Mapping[str, Any]) -> Mapping[str, Any]:
        """Append a reviewer-created ``NF-###`` record to review.json.

        analysis.json is intentionally left untouched; the review artifact is
        the source of truth for human findings and finalize already consumes
        NEW_FINDING records from it.
        """
        directory = self._scan_directory(scan_id)
        review_path = directory / "review.json"
        if not review_path.is_file():
            raise ScannerAdapterError("review.json을 찾을 수 없어 수동 Finding을 저장할 수 없습니다.")
        review = self._load_json_file(review_path)
        records = review.setdefault("findings", [])
        if not isinstance(records, list):
            raise ScannerAdapterError("review.json의 findings 형식이 올바르지 않습니다.")
        numbers = []
        for item in records:
            if not isinstance(item, dict):
                continue
            match = re.fullmatch(r"NF-(\d+)", str(item.get("id", "")).upper())
            if match:
                numbers.append(int(match.group(1)))
        finding_id = f"NF-{(max(numbers, default=0) + 1):03d}"
        record = {
            "id": finding_id,
            "type": str(finding.get("type") or "OTHER").upper(),
            "uri": str(finding.get("uri") or "/"),
            "method": str(finding.get("method") or "GET").upper(),
            "parameter": str(finding.get("parameter") or ""),
            "severity": str(finding.get("severity") or "MEDIUM").upper(),
            "review_status": "NEW_FINDING",
            "reviewer_note": str(finding.get("reviewer_note") or ""),
            "manual_evidence": [],
        }
        records.append(record)
        fd, temporary_name = tempfile.mkstemp(prefix=".review.", suffix=".tmp", dir=str(directory))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(review, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            os.replace(temporary_name, review_path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        LOGGER.info("[REVIEW] manual finding created id=%s status=NEW_FINDING", finding_id)
        return record

    def run_reanalysis(self, scan_id: str) -> Mapping[str, Any]:
        directory = self._scan_directory(scan_id)
        if (directory / "analysis.json").is_file() and (directory / "review.json").is_file():
            try:
                import sys
                scanner_root = Path(__file__).resolve().parents[2]
                if str(scanner_root) not in sys.path:
                    sys.path.insert(0, str(scanner_root))
                from ai_scanner.config import ScannerConfig
                from ai_scanner.finalize import finalize_scan
                finalize_scan(directory / "review.json", config=ScannerConfig.from_env(scanner_root / "ai_scanner"))
            except Exception as exc:
                raise ScannerAdapterError(f"Finalize failed: {exc}") from exc
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
