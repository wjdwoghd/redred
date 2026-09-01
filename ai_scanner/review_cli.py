"""Interactive CLI for recording human verification and evidence paths."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

LOGGER = logging.getLogger(__name__)

EVIDENCE_TYPES = ["baseline_request", "baseline_response", "test_request", "test_response", "screenshot", "db_evidence", "server_evidence", "other"]
EVIDENCE_LABELS = ["Baseline Request", "Baseline Response", "Test Request", "Test Response", "Screenshot", "DB Evidence", "Server Evidence", "Other"]
STATUSES = ["CONFIRMED", "FALSE_POSITIVE", "PENDING", "SKIP"]


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("review JSON must be an object")
    return value


def _save(path: Path, value: dict[str, Any]) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _resolve_evidence(root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    return candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()


def _add_evidence(review: dict[str, Any], finding: dict[str, Any], *, root: Path, ask: Callable[[str], str], tell: Callable[[str], None]) -> None:
    while ask("증적을 추가하시겠습니까? (y/n): ").strip().casefold() in {"y", "yes"}:
        tell("증적 종류:")
        for index, label in enumerate(EVIDENCE_LABELS, 1):
            tell(f"{index}. {label}")
        try:
            selected = int(ask("선택: ").strip()) - 1
            evidence_type = EVIDENCE_TYPES[selected]
        except (ValueError, IndexError):
            tell("[WARN] 올바른 증적 종류가 아닙니다.")
            continue
        file_value = ask("파일 경로: ").strip()
        description = ask("증적 설명: ").strip()
        resolved = _resolve_evidence(root, file_value)
        if resolved.is_file():
            tell(f"[OK] {file_value}")
        else:
            tell(f"[WARN] 파일을 찾을 수 없습니다: {file_value}")
            if ask("그래도 경로를 저장하시겠습니까? (y/n): ").strip().casefold() not in {"y", "yes"}:
                continue
        finding.setdefault("manual_evidence", []).append({"type": evidence_type, "file": file_value, "description": description})


def _review_existing(review: dict[str, Any], analysis: dict[str, Any], *, root: Path, ask: Callable[[str], str], tell: Callable[[str], None]) -> None:
    by_id = {str(item.get("id")): item for item in analysis.get("findings", []) if isinstance(item, dict)}
    for finding in review.setdefault("findings", []):
        if not isinstance(finding, dict):
            continue
        detail = by_id.get(str(finding.get("id")), finding)
        tell("\n========================================")
        tell(str(finding.get("id", "-")))
        tell(f"예상 취약점: {detail.get('type', finding.get('type', '-'))}")
        tell(f"URI: {detail.get('method', finding.get('method', '-'))} {detail.get('uri', finding.get('uri', '-'))}")
        tell(f"Parameter: {detail.get('parameter', finding.get('parameter', '-')) or '-'}")
        confidence = detail.get("confidence")
        if confidence is not None:
            try:
                tell(f"Confidence: {float(confidence):.0%}")
            except (TypeError, ValueError):
                pass
        tell("Scanner 상태: CANDIDATE")
        if detail.get("ai_reason"):
            tell(f"근거: {detail['ai_reason']}")
        recommendations = detail.get("recommended_verification") or []
        if recommendations:
            tell(f"권장 검증: {recommendations[0]}")
        tell("1. CONFIRMED\n2. FALSE_POSITIVE\n3. PENDING\n4. SKIP")
        choice = ask("검증 결과를 선택하세요: ").strip()
        if choice == "4" or choice.upper() == "SKIP":
            continue
        if choice in {"1", "2", "3"}:
            finding["review_status"] = STATUSES[int(choice) - 1]
        elif choice.upper() in STATUSES[:3]:
            finding["review_status"] = choice.upper()
        else:
            tell("[WARN] 허용되지 않은 상태입니다. 기존 상태를 유지합니다.")
            continue
        finding["reviewer_note"] = ask("검증 의견 (없으면 Enter): ").strip()
        _add_evidence(review, finding, root=root, ask=ask, tell=tell)


def _add_new_finding(review: dict[str, Any], *, root: Path, ask: Callable[[str], str], tell: Callable[[str], None]) -> None:
    types = ["SQL_INJECTION", "XSS", "FILE_UPLOAD", "OTHER"]
    tell("취약점 유형: 1. SQL_INJECTION  2. XSS  3. FILE_UPLOAD  4. OTHER")
    try:
        vuln = types[int(ask("선택: ").strip()) - 1]
    except (ValueError, IndexError):
        tell("[WARN] 올바른 취약점 유형이 아닙니다.")
        return
    existing = [str(item.get("id", "")) for item in review.get("findings", []) if isinstance(item, dict)]
    numbers = [int(item.rsplit("-", 1)[1]) for item in existing if item.startswith("MANUAL-") and item.rsplit("-", 1)[1].isdigit()]
    identifier = f"MANUAL-{max(numbers, default=0) + 1:03d}"
    finding = {"id": identifier, "type": vuln, "uri": ask("URI: ").strip(), "method": ask("Method: ").strip().upper() or "GET", "parameter": ask("Parameter: ").strip() or None, "review_status": "NEW_FINDING", "reviewer_note": ask("검증 의견: ").strip(), "manual_evidence": []}
    _add_evidence(review, finding, root=root, ask=ask, tell=tell)
    review.setdefault("findings", []).append(finding)
    tell(f"[OK] {identifier} 추가")


def review_scan(review_path: str | Path, *, ask: Callable[[str], str] = input, tell: Callable[[str], None] = print) -> dict[str, Any]:
    """Interactively update a review JSON and return the saved document."""

    path = Path(review_path).expanduser().resolve()
    review = _load(path)
    analysis_path = path.parent / str(review.get("analysis_file", "analysis.json"))
    analysis = _load(analysis_path) if analysis_path.exists() else {"findings": []}
    while True:
        tell("\n1. 기존 Finding 검토\n2. 새 Finding 추가\n3. 종료")
        choice = ask("선택: ").strip()
        if choice == "1":
            _review_existing(review, analysis, root=path.parent, ask=ask, tell=tell)
            _save(path, review)
        elif choice == "2":
            _add_new_finding(review, root=path.parent, ask=ask, tell=tell)
            _save(path, review)
        elif choice == "3":
            _save(path, review)
            break
        else:
            tell("[WARN] 올바른 메뉴를 선택하세요.")
    return review


__all__ = ["review_scan"]
