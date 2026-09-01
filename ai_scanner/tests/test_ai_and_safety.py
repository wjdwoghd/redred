"""AI adapter boundary tests that never call a remote provider."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ai_client import AIClientResult, OpenAIResponsesClient, analysis_draft_json_schema
from config import ScannerConfig
from indicator_detector import detect_indicators
from models import (
    AnalysisDraft,
    Evidence,
    Finding,
    FindingLocation,
    FindingStatus,
    ParameterLocation,
    Severity,
    VulnerabilityType,
)
from parameter_extractor import extract_parameters
from pipeline import run_pipeline
from request_parser import load_scan_input
from response_analyzer import analyze_response
from sanitizer import json_for_ai
from vulnerability_analyzer import VulnerabilityAnalyzer


ROOT = Path(__file__).resolve().parents[1]


def _sqli_finding(status: FindingStatus = FindingStatus.CONFIRMED) -> Finding:
    return Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        status=status,
        severity=Severity.HIGH,
        confidence=0.99,
        location=FindingLocation(parameter="keyword", parameter_location=ParameterLocation.QUERY, method="GET", path="/department_resources.php"),
        evidence=Evidence(request_value="' OR 1=1 -- ", response_status=200),
        description="test finding",
        rationale=["test"],
        cause="test",
        impact=["test"],
        remediation=["test"],
        cwe="CWE-89",
        owasp_category="Injection",
    )


def test_ai_result_is_capped_by_rule_policy() -> None:
    scan = load_scan_input(ROOT / "samples" / "sql_injection.json")
    candidates = extract_parameters(scan.request)
    response_features = analyze_response(scan.response, request=scan.request, input_values=candidates)
    # No baseline delta is supplied, so SQL-like input alone is only POSSIBLE.
    indicators = detect_indicators(request=scan.request, candidates=candidates, response_features=response_features, comparison={})
    fake = type("Fake", (), {"analyze": lambda self, **kwargs: AIClientResult(parsed=AnalysisDraft(findings=[_sqli_finding()]), model="fake")})()
    result = VulnerabilityAnalyzer(mode="ai", ai_client=fake, prompt="test").analyze(
        scan, candidates=candidates, response_features=response_features, comparison={}, indicators=indicators
    )
    assert result.findings[0].status is FindingStatus.POSSIBLE
    assert result.analysis_summary.is_vulnerable is False


def test_auto_provider_failure_is_explicit_fallback() -> None:
    scan = load_scan_input(ROOT / "samples" / "xss.json")
    candidates = extract_parameters(scan.request)
    response_features = analyze_response(scan.response, request=scan.request, input_values=candidates)
    indicators = detect_indicators(request=scan.request, candidates=candidates, response_features=response_features, comparison={})
    class Failing:
        def analyze(self, **kwargs):
            raise RuntimeError("provider unavailable")
    result = VulnerabilityAnalyzer(mode="auto", ai_client=Failing(), prompt="test").analyze(
        scan, candidates=candidates, response_features=response_features, comparison={}, indicators=indicators
    )
    assert result.metadata.engine == "RULE_BASED_FALLBACK"
    assert result.metadata.fallback_reason


def test_sensitive_candidate_value_is_masked_for_ai() -> None:
    serialized, metadata = json_for_ai({"candidates": [{"name": "PHPSESSID", "value": "secret"}]})
    assert "secret" not in serialized
    assert metadata["redacted_fields"]


def test_no_finding_is_a_valid_not_confirmed_result() -> None:
    from models import HTTPRequest, HTTPResponse, ScanInput

    scan = ScanInput(
        scan_id="scan-no-finding-001",
        request=HTTPRequest(method="GET", url="http://192.168.94.128/health", headers={}, body=""),
        response=HTTPResponse(status_code=200, headers={"Content-Type": "text/plain"}, body="ok"),
    )
    candidates = extract_parameters(scan.request)
    response_features = analyze_response(scan.response, request=scan.request, input_values=candidates)
    indicators = detect_indicators(request=scan.request, candidates=candidates, response_features=response_features, comparison={})
    result = VulnerabilityAnalyzer(mode="rules").analyze(
        scan, candidates=candidates, response_features=response_features, comparison={}, indicators=indicators
    )
    assert result.findings == []
    assert result.analysis_summary.overall_status is FindingStatus.NOT_CONFIRMED
    assert result.analysis_summary.overall_risk is Severity.INFO


def test_responses_payload_uses_flat_strict_json_schema() -> None:
    """The Responses API must receive the schema object under text.format.schema."""

    class FakeResponses:
        def __init__(self) -> None:
            self.kwargs = None

        def create(self, **kwargs):
            self.kwargs = kwargs
            return SimpleNamespace(
                id="resp-test",
                status="completed",
                model="fake-model",
                output_text='{"target":null,"analysis_summary":null,"findings":[]}',
                output=[],
            )

    fake_responses = FakeResponses()
    client = OpenAIResponsesClient(
        api_key="test-key",
        model="fake-model",
        client=SimpleNamespace(responses=fake_responses),
    )
    result = client.analyze(instructions="return structured JSON", input_data={"ok": True})

    assert result.parsed.model_dump(mode="json") == AnalysisDraft(findings=[]).model_dump(mode="json")
    response_format = fake_responses.kwargs["text"]["format"]
    assert set(response_format) == {"type", "name", "schema", "strict"}
    assert response_format["type"] == "json_schema"
    assert response_format["name"] == "AnalysisDraft"
    assert response_format["strict"] is True
    schema = response_format["schema"]
    assert schema == analysis_draft_json_schema()
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["$defs"]["Evidence"]["additionalProperties"] is False
