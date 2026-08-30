"""In-memory demonstration adapter. It never calls a server or AI API."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from adapters.base import ScannerAdapter, ScannerAdapterError
from models import Evidence, ReportArtifacts


class MockScannerAdapter(ScannerAdapter):
    source_label = "시연 모드 · Mock Data"
    is_live_connection = False

    def __init__(self, data_path: Path):
        self.data_path = data_path
        self._reviews: dict[str, list[dict[str, Any]]] = {}
        self._evidence: dict[str, list[Evidence]] = {}
        self._targets: dict[str, str] = {}

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.data_path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            return json.loads(self.data_path.read_text(encoding="cp949"))
        except FileNotFoundError as exc:
            raise ScannerAdapterError("모의 스캔 결과 파일을 찾을 수 없습니다.") from exc
        except json.JSONDecodeError as exc:
            raise ScannerAdapterError("모의 스캔 결과 JSON 형식이 올바르지 않습니다.") from exc

    def health_check(self) -> tuple[bool, str]:
        try:
            self._load()
        except ScannerAdapterError as exc:
            return False, str(exc)
        return True, "모의 데이터 준비 완료"

    def run_initial_scan(self, target_url: str) -> Mapping[str, Any]:
        raw = copy.deepcopy(self._load())
        raw["target_url"] = target_url
        raw["status"] = "initial_completed"
        scan_id = str(raw.get("scan_id", "mock-scan"))
        self._targets[scan_id] = target_url
        for finding in raw.get("findings", []):
            if not isinstance(finding, dict):
                continue
            finding["initial_severity"] = finding.get("initial_severity") or finding.get("severity")
            finding["final_severity"] = None
            finding["review_status"] = "unverified"
            finding["verification_status"] = "unverified"
            finding["reviewer_memo"] = None
            finding["final_judgment"] = None
            finding["evidence"] = []
            finding["evidence_ids"] = []
        raw["evidence"] = []
        raw["reports"] = {}
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
        if not self._reviews.get(scan_id) or not self._evidence.get(scan_id):
            raise ScannerAdapterError("담당자 검토와 증적을 먼저 등록해 주세요.")
        raw = copy.deepcopy(self._load())
        raw["scan_id"] = scan_id
        raw["target_url"] = self._targets.get(scan_id, str(raw.get("target_url", "")))
        raw["status"] = "reanalysis_completed"
        reviews = {str(item.get("finding_id")): item for item in self._reviews[scan_id]}
        for finding in raw.get("findings", []):
            if not isinstance(finding, dict):
                continue
            review = reviews.get(str(finding.get("finding_id")), {})
            if review:
                finding["reviewer_memo"] = review.get("reviewer_memo")
                finding["review_status"] = review.get("review_status", "verified")
                finding["verification_status"] = finding["review_status"]
        raw["evidence"] = [
            {
                "evidence_id": item.evidence_id,
                "finding_id": item.finding_id,
                "type": item.evidence_type,
                "filename": item.filename,
                "description": item.description,
                "uploaded_at": item.uploaded_at.isoformat() if item.uploaded_at else None,
                "mime_type": item.mime_type,
                "size_bytes": item.size_bytes,
            }
            for item in self._evidence[scan_id]
        ]
        raw["reports"] = {}
        return raw

    def get_scan_result(self, scan_id: str) -> Mapping[str, Any]:
        raw = self._load()
        if scan_id and str(raw.get("scan_id")) != scan_id:
            raw["scan_id"] = scan_id
        return raw

    def get_report_artifacts(self, scan_id: str) -> ReportArtifacts:
        return ReportArtifacts()
