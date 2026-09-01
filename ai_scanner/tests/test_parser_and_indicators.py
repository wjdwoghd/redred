"""Focused tests for candidate extraction and conservative evidence ceilings."""

from __future__ import annotations

from models import HTTPRequest, HTTPResponse, ParameterLocation
from parameter_extractor import extract_parameters
from response_analyzer import analyze_response
from comparator import compare_responses
from indicator_detector import detect_indicators


def test_query_duplicate_and_blank_values_are_preserved() -> None:
    request = HTTPRequest(
        method="GET",
        url="http://192.168.94.128/search?q=&q=two",
        headers={},
        parameters={},
        body="",
    )
    candidates = extract_parameters(request)
    query_values = [item.value for item in candidates if item.location is ParameterLocation.QUERY]
    assert query_values == ["", "two"]


def test_sql_indicator_needs_response_evidence_for_confirmation() -> None:
    request = HTTPRequest(
        method="GET",
        url="http://192.168.94.128/search?q=%27%20OR%201%3D1%20--%20",
        headers={},
        body="",
    )
    candidates = extract_parameters(request)
    response = analyze_response(HTTPResponse(status_code=200, headers={}, body="one result"), request=request, input_values=candidates)
    indicators = detect_indicators(request=request, candidates=candidates, response_features=response, comparison={})
    assert indicators["max_status"]["SQL_INJECTION"] == "POSSIBLE"


def test_baseline_comparison_exposes_status_length_and_error_delta() -> None:
    baseline = HTTPResponse(status_code=200, headers={}, body="<p>one</p>")
    attack = HTTPResponse(status_code=500, headers={}, body="SQL syntax error: query failed")
    comparison = compare_responses(baseline, attack)
    assert comparison["status_changed"] is True
    assert comparison["sql_error_appeared"] is True
    assert comparison["response_length_difference"] > 0

