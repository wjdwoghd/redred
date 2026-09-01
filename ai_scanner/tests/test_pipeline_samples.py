"""Offline end-to-end tests for the three presentation captures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config import ScannerConfig
from models import AnalysisResult
from pipeline import run_pipeline


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "vulnerability"),
    [
        ("sql_injection.json", "SQL_INJECTION"),
        ("xss.json", "XSS"),
        ("file_upload.json", "FILE_UPLOAD"),
    ],
)
def test_sample_pipeline_is_offline_and_structured(tmp_path: Path, filename: str, vulnerability: str) -> None:
    config = ScannerConfig.from_env(ROOT)
    outcome = run_pipeline(
        ROOT / "samples" / filename,
        config=config,
        mode="rules",
        output_directory=tmp_path,
    )

    assert outcome.analysis.analysis_summary.is_vulnerable is True
    assert any(item.vulnerability_type.value == vulnerability for item in outcome.analysis.findings)
    persisted = json.loads(outcome.artifacts.analysis_json.read_text(encoding="utf-8"))
    validated = AnalysisResult.model_validate(persisted)
    assert validated.analysis_summary.finding_count == len(validated.findings)
    assert outcome.artifacts.input_json.exists()
    assert outcome.artifacts.report_markdown.exists()

