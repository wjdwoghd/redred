"""Report rendering and AI fallback tests."""

from __future__ import annotations

import json
from pathlib import Path

from models import AnalysisResult
from report_generator import generate_report


ROOT = Path(__file__).resolve().parents[1]


def _analysis() -> AnalysisResult:
    path = ROOT / "results" / "scan-20260827-sqli-001" / "analysis.json"
    return AnalysisResult.model_validate(json.loads(path.read_text(encoding="utf-8")))


def test_report_has_human_sections_and_no_raw_dictionary() -> None:
    report = generate_report(_analysis())
    assert all(f"## {index}." in report for index in range(1, 11))
    assert "HTTP 200" in report
    assert "{'" not in report
    assert "Boolean-based SQL injection confirmed" not in report
    assert "Exposure of additional database rows" not in report
    assert "HTML Encoding" not in report
    assert "File Upload" not in report


def test_report_ai_failure_falls_back_to_deterministic() -> None:
    class FailingClient:
        def generate_report(self, **kwargs):
            raise RuntimeError("provider unavailable")

    report = generate_report(_analysis(), ai_client=FailingClient(), ai_prompt="report")
    assert "## 9. 대응 방안" in report
    assert "Prepared Statement" in report
    assert "Parameterized Query" in report
