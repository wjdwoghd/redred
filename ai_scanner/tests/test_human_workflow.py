import json
from types import SimpleNamespace
from pydantic import SecretStr

from diagnostic_workflow import build_scan_analysis, write_review_artifacts
from finalize import finalize_scan
from config import ScannerConfig
from models import AnalysisDraft, Evidence, Finding, FindingLocation, FindingStatus, Severity, VulnerabilityType
from review_cli import review_scan


def test_finalize_uses_confirmed_and_new_finding_only(tmp_path) -> None:
    analysis = {
        "target": {"method": "GET", "url": "http://192.168.1.10/notices.php", "path": "/notices.php"},
        "findings": [
            {"id": "F-001", "type": "XSS", "uri": "/notices.php", "method": "POST", "parameter": "title", "severity": "HIGH", "cwe": "CWE-79", "owasp_category": "Injection", "ai_reason": "reflection"},
            {"id": "F-002", "type": "SQL_INJECTION", "uri": "/resource.php", "method": "GET", "parameter": "keyword", "severity": "HIGH", "cwe": "CWE-89", "owasp_category": "Injection"},
        ],
    }
    review = {
        "target": analysis["target"],
        "findings": [
            {"id": "F-001", "review_status": "CONFIRMED", "reviewer_note": "재현", "manual_evidence": ["Burp 증적"]},
            {"id": "F-002", "review_status": "FALSE_POSITIVE", "reviewer_note": "인코딩", "manual_evidence": []},
            {"id": "MANUAL-001", "type": "FILE_UPLOAD", "uri": "/upload.php", "method": "POST", "parameter": "file", "review_status": "NEW_FINDING", "reviewer_note": "수동 확인", "manual_evidence": ["접근 확인"]},
        ],
    }
    (tmp_path / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
    (tmp_path / "review.json").write_text(json.dumps(review), encoding="utf-8")
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path})
    result = finalize_scan(tmp_path / "review.json", config=config)
    assert [item["id"] for item in result["findings"]] == ["F-001", "MANUAL-001"]
    assert (tmp_path / "final_report.md").exists()
    assert (tmp_path / "secure_coding_guide.md").exists()
    assert (tmp_path / "final_report.pdf").exists()
    assert (tmp_path / "secure_coding_guide.pdf").exists()
    assert "F-002" not in (tmp_path / "final_report.md").read_text(encoding="utf-8")


def test_diagnostic_ai_is_called_once_for_many_candidates(tmp_path, monkeypatch) -> None:
    finding = Finding(
        vulnerability_type=VulnerabilityType.XSS,
        status=FindingStatus.POSSIBLE,
        severity=Severity.MEDIUM,
        confidence=0.6,
        location=FindingLocation(parameter="title", parameter_location="query", method="GET", path="/notices.php"),
        evidence=Evidence(response_status=200),
        description="reflection candidate",
        cwe="CWE-79",
        owasp_category="Injection",
    )
    outcome = SimpleNamespace(
        indicators={"input_reflected": True},
        comparison={"available": True},
        response_features={},
        analysis=SimpleNamespace(scan_id="scan-1", findings=[finding]),
    )
    calls = []

    class FakeClient:
        def analyze(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(parsed=AnalysisDraft(findings=[finding]))

    monkeypatch.setattr("diagnostic_workflow.create_ai_client", lambda **kwargs: FakeClient())
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path, "ai_api_key": SecretStr("test-key")})
    analysis, count, _ = build_scan_analysis(target="http://192.168.1.10/notices.php", outcomes=[outcome, outcome], scan_id="active-test", config=config, mode="ai")
    assert count == 1
    assert len(calls) == 1
    assert analysis["findings"][0]["scanner_status"] == "CANDIDATE"


def test_review_cli_saves_status_note_and_evidence(tmp_path) -> None:
    analysis = {"findings": [{"id": "F-001", "type": "XSS", "uri": "/notices.php", "method": "POST", "parameter": "title", "confidence": 0.6}]}
    review = {"analysis_file": "analysis.json", "findings": [{"id": "F-001", "type": "XSS", "review_status": "PENDING", "manual_evidence": []}]}
    (tmp_path / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review), encoding="utf-8")
    evidence = tmp_path / "evidence" / "F-001" / "test_request.txt"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("GET /notices.php HTTP/1.1", encoding="utf-8")
    answers = iter(["1", "1", "재현 확인", "y", "3", "evidence/F-001/test_request.txt", "테스트 요청", "n", "3"])
    review_scan(review_path, ask=lambda prompt: next(answers), tell=lambda message: None)
    saved = json.loads(review_path.read_text(encoding="utf-8"))
    assert saved["findings"][0]["review_status"] == "CONFIRMED"
    assert saved["findings"][0]["reviewer_note"] == "재현 확인"
    assert saved["findings"][0]["manual_evidence"][0]["type"] == "test_request"


def test_finalize_reads_and_redacts_txt_evidence(tmp_path) -> None:
    (tmp_path / "analysis.json").write_text(json.dumps({"target": {"url": "http://192.168.1.10", "path": "/", "method": "GET"}, "findings": [{"id": "F-001", "type": "XSS", "uri": "/", "method": "GET", "parameter": "q"}]}), encoding="utf-8")
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("Cookie: PHPSESSID=secret\nAuthorization: Bearer secret-token\n" + "A" * 25000, encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps({"findings": [{"id": "F-001", "review_status": "CONFIRMED", "manual_evidence": [{"type": "test_response", "file": "evidence.txt", "description": "응답"}]}]}), encoding="utf-8")
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path})
    result = finalize_scan(review_path, config=config)
    bundle = result["findings"][0]["evidence_bundle"][0]
    assert "secret" not in bundle["content"]
    assert "[REDACTED]" in bundle["content"]
    assert bundle["truncated"] is True
    assert "[TRUNCATED]" in bundle["content"]


def test_final_report_keeps_review_overview_without_evidence_gate(tmp_path) -> None:
    analysis = {
        "target": {"url": "http://192.168.1.10/notices.php"},
        "findings": [
            {"id": "F-001", "type": "XSS", "uri": "/notices.php", "method": "POST", "parameter": "title"},
            {"id": "F-002", "type": "SQL_INJECTION", "uri": "/resource.php", "method": "GET", "parameter": "keyword"},
        ],
    }
    review = {
        "findings": [
            {"id": "F-001", "review_status": "CONFIRMED", "reviewer_note": "수동 확인", "manual_evidence": []},
            {"id": "F-002", "review_status": "PENDING", "reviewer_note": "추가 확인 필요", "manual_evidence": []},
        ]
    }
    (tmp_path / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review), encoding="utf-8")
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path})
    finalize_scan(review_path, config=config)
    report = (tmp_path / "final_report.md").read_text(encoding="utf-8")
    assert "진단 후보 및 담당자 검토 현황" in report
    assert "최종 확정 취약점" in report
    assert "등록된 증적 없음" in report
    assert "담당자 검증 완료 / 취약점 확인" in report
    assert "담당자 미검증 또는 추가 검증 필요" in report


def test_secure_guide_is_finding_specific_when_ai_unavailable(tmp_path) -> None:
    analysis = {
        "target": {"url": "http://192.168.1.10/login.php"},
        "findings": [{
            "id": "F-001", "type": "SQL_INJECTION", "uri": "/login.php",
            "method": "POST", "parameter": "username", "severity": "HIGH",
            "confidence": 0.91, "ai_reason": "DB 오류와 응답 차이",
        }],
    }
    review = {"findings": [{
        "id": "F-001", "review_status": "CONFIRMED",
        "reviewer_note": "Burp Repeater에서 재현 확인", "manual_evidence": [],
    }]}
    (tmp_path / "analysis.json").write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review, ensure_ascii=False), encoding="utf-8")
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path, "ai_api_key": None})
    finalize_scan(review_path, config=config)
    guide = (tmp_path / "secure_coding_guide.md").read_text(encoding="utf-8")
    assert "F-001" in guide
    assert "`/login.php`" in guide
    assert "`POST`" in guide
    assert "username" in guide
    assert "Prepared Statement" in guide
    assert "parameter binding" in guide
    assert "취약 원인" in guide
    assert "보안 영향" in guide
    assert "PHP 시큐어코딩 예시" in guide
    assert "재검증 방법" in guide


def test_secure_coding_ai_receives_confirmed_finding_context(tmp_path, monkeypatch) -> None:
    analysis = {
        "target": {"url": "http://192.168.1.10/upload.php"},
        "findings": [{
            "id": "F-009", "type": "FILE_UPLOAD", "uri": "/upload.php",
            "method": "POST", "parameter": "attachment", "severity": "HIGH",
            "confidence": 0.88, "ai_reason": "업로드 경로가 응답에 노출됨",
            "rules": {"upload_path_detected": True}, "baseline": {"available": True},
        }],
    }
    review = {"findings": [{
        "id": "F-009", "review_status": "CONFIRMED",
        "reviewer_note": "저장 경로 접근 확인", "manual_evidence": [],
    }]}
    (tmp_path / "analysis.json").write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review, ensure_ascii=False), encoding="utf-8")
    captured = []

    class FailingClient:
        def generate_report(self, **kwargs):
            captured.append(json.loads(kwargs["input_data"]))
            raise RuntimeError("test fallback")

    monkeypatch.setattr("finalize.create_ai_client", lambda **kwargs: FailingClient())
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path, "ai_api_key": SecretStr("test-key")})
    finalize_scan(review_path, config=config)
    payload = captured[0]["findings"][0]
    for key in ("id", "type", "uri", "method", "parameter", "severity", "confidence", "review_status", "reviewer_note", "evidence_bundle", "ai_reason", "rules", "baseline"):
        assert key in payload
    assert payload["review_status"] == "CONFIRMED"


def test_policy_reference_is_included_in_final_artifacts(tmp_path) -> None:
    analysis = {
        "target": {"url": "http://192.168.1.10/resource.php"},
        "findings": [{
            "id": "F-001", "type": "SQL_INJECTION", "uri": "/resource.php",
            "method": "GET", "parameter": "keyword", "severity": "HIGH",
            "confidence": 0.8,
            "policy_reference": {
                "policy_source": "KISA",
                "policy_item_name": "SQL 인젝션",
                "policy_item_number": 5,
                "inspection_purpose": "SQL 질의 영향 여부 확인",
                "inspection_criteria": ["정상·시험 응답 비교"],
                "indicator_mapping": {"sql_error_detected": "SQL 오류"},
                "remediation_reference": ["Prepared Statement"],
            },
        }],
    }
    review = {"findings": [{"id": "F-001", "review_status": "CONFIRMED", "manual_evidence": []}]}
    (tmp_path / "analysis.json").write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(review, ensure_ascii=False), encoding="utf-8")
    config = ScannerConfig.from_env().model_copy(update={"project_dir": tmp_path, "ai_api_key": None})
    finalize_scan(review_path, config=config)
    final_report = (tmp_path / "final_report.md").read_text(encoding="utf-8")
    secure_guide = (tmp_path / "secure_coding_guide.md").read_text(encoding="utf-8")
    assert "진단 기준 참고" in final_report
    assert "SQL 인젝션" in final_report
    assert "Prepared Statement" in secure_guide
