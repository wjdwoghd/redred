"""Read-only helpers for downloading persisted reviewer evidence."""

from __future__ import annotations

import io
import mimetypes
import re
import zipfile
from pathlib import Path
from typing import Iterable, Sequence

from models import Evidence, Finding


_PLACEHOLDER_NAMES = {"", "unnamed", "none"}
_ARCHIVE_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
FINAL_REVIEW_STATUSES = frozenset({"CONFIRMED", "NEW_FINDING"})


def _safe_filename(value: str | None) -> str | None:
    """Return a basename safe to use in a browser download or ZIP member."""
    name = Path(value or "").name.strip()
    if name.casefold() in _PLACEHOLDER_NAMES:
        return None
    return name or None


def read_evidence_bytes(evidence: Evidence) -> bytes | None:
    """Read persisted evidence without changing or moving its source file."""
    if not _safe_filename(evidence.filename):
        return None
    if evidence.local_path:
        try:
            source = Path(evidence.local_path)
            if source.is_file():
                return source.read_bytes()
        except OSError:
            return None
    if evidence.content is not None:
        return bytes(evidence.content)
    return None


def downloadable_evidence(finding: Finding) -> list[tuple[Evidence, bytes]]:
    """Return readable, real evidence for one finding."""
    result: list[tuple[Evidence, bytes]] = []
    for evidence in finding.evidence:
        filename = _safe_filename(evidence.filename)
        if not filename:
            continue
        content = read_evidence_bytes(evidence)
        if content is not None:
            result.append((evidence, content))
    return result


def evidence_mime_type(evidence: Evidence) -> str:
    """Choose a stable MIME type for an individual download."""
    if evidence.mime_type:
        return evidence.mime_type
    return mimetypes.guess_type(evidence.filename or "")[0] or "application/octet-stream"


def _archive_component(value: str | None, fallback: str) -> str:
    """Sanitize a Finding ID while preserving its visible identifier."""
    raw = (value or fallback).strip()
    safe = _ARCHIVE_UNSAFE.sub("_", raw).strip("._")
    return safe or fallback


def build_evidence_zip(
    findings: Sequence[Finding] | Iterable[Finding],
    *,
    allowed_statuses: frozenset[str] = FINAL_REVIEW_STATUSES,
) -> bytes | None:
    """Build an in-memory ZIP for final findings only.

    Archive paths are ``<finding-id>/<filename>``. Duplicate names receive a
    numeric suffix. ``None`` means no eligible readable evidence exists.
    """
    members: list[tuple[str, bytes]] = []
    for finding in findings:
        status = (finding.review_status or "").strip().upper()
        if status not in allowed_statuses:
            continue
        finding_dir = _archive_component(finding.finding_id, "finding")
        used_names: set[str] = set()
        for evidence, content in downloadable_evidence(finding):
            filename = _safe_filename(evidence.filename)
            if not filename:
                continue
            stem = Path(filename).stem
            suffix = Path(filename).suffix
            candidate = filename
            counter = 2
            while candidate.casefold() in used_names:
                candidate = f"{stem}-{counter}{suffix}"
                counter += 1
            used_names.add(candidate.casefold())
            members.append((f"{finding_dir}/{candidate}", content))

    if not members:
        return None
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for archive_name, content in members:
            archive.writestr(archive_name, content)
    return output.getvalue()


__all__ = [
    "FINAL_REVIEW_STATUSES",
    "build_evidence_zip",
    "downloadable_evidence",
    "evidence_mime_type",
    "read_evidence_bytes",
]
