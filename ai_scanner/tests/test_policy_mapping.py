from __future__ import annotations

import json
from types import SimpleNamespace

from pydantic import SecretStr

from config import ScannerConfig
from diagnostic_workflow import build_scan_analysis, write_review_artifacts
from models import AnalysisDraft, Evidence, Finding, FindingLocation, FindingStatus, Severity, VulnerabilityType
from policies import get_policy_mapping, load_policy_mapping


def _finding(vulnerability_type: VulnerabilityType) -> Finding:
    cwe = {
        VulnerabilityType.SQL_INJECTION: "CWE-89",
        VulnerabilityType.XSS: "CWE-79",
        VulnerabilityType.FILE_UPLOAD: "CWE-434",
    }[vulnerability_type]
    return Finding(
        vulnerability_type=vulnerability_type,
        status=FindingStatus.POSSIBLE,
        severity=Severity.MEDIUM,
        confidence=0.5,
        location=FindingLocation(parameter="input", parameter_location="query", method="GET", path="/test.php"),
        evidence=Evidence(response_status=200),
        description="candidate",
        cwe=cwe,
        owasp_category="Injection",
    )


def test_kisa_policy_mapping_loads_three_supported_types():
    mapping = load_policy_mapping()
    assert mapping["SQL_INJECTION"]["policy_item_name"] == "SQL 인젝션"
    assert mapping["SQL_INJECTION"]["policy_item_number"] == 5
    assert mapping["XSS"]["policy_item_name"] == "크로스사이트 스크립팅"
    assert mapping["XSS"]["policy_item_number"] == 11
    assert mapping["FILE_UPLOAD"]["policy_item_name"] == "파일 업로드"
    assert mapping["FILE_UPLOAD"]["policy_item_number"] == 22
    assert mapping["SQL_INJECTION"]["policy_item_id"] is None


def test_unknown_type_and_missing_policy_file_are_safe(tmp_path):
    assert get_policy_mapping("UNKNOWN") is None
    assert load_policy_mapping(tmp_path / "missing.json") == {}


def test_policy_reference_is_added_to_candidate_and_ai_payload(tmp_path, monkeypatch):
    finding = _finding(VulnerabilityType.XSS)
    outcome = SimpleNamespace(
        indicators={"input_reflected": True},
        comparison={"response_length_difference": 10},
        response_features={},
        analysis=SimpleNamespace(scan_id="scan-policy", findings=[finding]),
        scan_input=None,
    )
    captured: list[dict] = []

    class FakeClient:
        def analyze(self, **kwargs):
            captured.append(json.loads(kwargs["input_data"]))
            return SimpleNamespace(parsed=AnalysisDraft(findings=[finding]))

    monkeypatch.setattr("diagnostic_workflow.create_ai_client", lambda **kwargs: FakeClient())
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path, "ai_api_key": SecretStr("test-key")})
    analysis, calls, _ = build_scan_analysis(
        target="http://192.168.1.10/test.php",
        outcomes=[outcome],
        scan_id="scan-policy",
        config=config,
        mode="ai",
    )
    assert calls == 1
    assert analysis["findings"][0]["policy_reference"]["policy_item_number"] == 11
    assert captured[0]["policy_references"]["XSS"]["policy_item_name"] == "크로스사이트 스크립팅"
    write_review_artifacts(root=tmp_path, analysis=analysis)
    guide = (tmp_path / "diagnostic_guide.md").read_text(encoding="utf-8")
    assert "진단 기준 참고" in guide
    assert "크로스사이트 스크립팅" in guide
