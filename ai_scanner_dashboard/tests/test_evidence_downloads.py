from __future__ import annotations

import io
import zipfile
from pathlib import Path

from models import Evidence, Finding
from services.evidence_downloads import build_evidence_zip, downloadable_evidence


def _finding(finding_id: str, status: str, evidence: list[Evidence]) -> Finding:
    return Finding(finding_id=finding_id, vulnerability_type="XSS", review_status=status, evidence=evidence)


def test_zip_keeps_finding_ids_and_excludes_non_final_statuses(tmp_path: Path) -> None:
    confirmed_file = tmp_path / "request.txt"
    confirmed_file.write_bytes(b"baseline request")
    false_file = tmp_path / "false.txt"
    false_file.write_bytes(b"false positive evidence")
    pending_file = tmp_path / "pending.txt"
    pending_file.write_bytes(b"pending evidence")

    data = build_evidence_zip(
        [
            _finding("F-001", "CONFIRMED", [Evidence(filename="request.txt", local_path=str(confirmed_file))]),
            _finding("F-002", "FALSE_POSITIVE", [Evidence(filename="false.txt", local_path=str(false_file))]),
            _finding("F-003", "PENDING", [Evidence(filename="pending.txt", local_path=str(pending_file))]),
            _finding("NF-001", "NEW_FINDING", [Evidence(filename="proof.txt", content=b"manual proof")]),
        ]
    )

    assert data is not None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert set(archive.namelist()) == {"F-001/request.txt", "NF-001/proof.txt"}
        assert archive.read("F-001/request.txt") == b"baseline request"
        assert archive.read("NF-001/proof.txt") == b"manual proof"

    assert confirmed_file.read_bytes() == b"baseline request"


def test_unreadable_or_placeholder_evidence_is_not_downloaded(tmp_path: Path) -> None:
    real_file = tmp_path / "proof.log"
    real_file.write_bytes(b"ok")
    finding = _finding(
        "F-004",
        "CONFIRMED",
        [
            Evidence(filename="unnamed", local_path=str(real_file)),
            Evidence(filename="missing.txt", local_path=str(tmp_path / "missing.txt")),
            Evidence(filename="proof.log", local_path=str(real_file)),
        ],
    )
    files = downloadable_evidence(finding)
    assert [(item.filename, content) for item, content in files] == [("proof.log", b"ok")]


def test_duplicate_names_get_safe_suffix(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    data = build_evidence_zip(
        [_finding("F-005", "CONFIRMED", [
            Evidence(filename="proof.txt", local_path=str(first)),
            Evidence(filename="proof.txt", local_path=str(second)),
        ])]
    )
    assert data is not None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert set(archive.namelist()) == {"F-005/proof.txt", "F-005/proof-2.txt"}
