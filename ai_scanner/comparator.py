"""Baseline/test HTTP response comparison utilities."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from difflib import SequenceMatcher
import re
from typing import Any

try:  # Package import and ``python main.py`` execution are both supported.
    from .response_analyzer import (
        analyze_response,
        get_response_body_text,
        utf8_content_length,
    )
except ImportError:  # pragma: no cover - exercised when used as loose scripts
    from response_analyzer import (  # type: ignore
        analyze_response,
        get_response_body_text,
        utf8_content_length,
    )


def _normalise_body(body: str, limit: int) -> str:
    """Normalise whitespace and cap work performed by SequenceMatcher."""
    return re.sub(r"\s+", " ", body[:limit]).strip()


def _marker_specs(markers: Any) -> list[tuple[str, str]]:
    if markers is None:
        return []
    if isinstance(markers, Mapping):
        return [(str(name), str(value)) for name, value in markers.items()]
    if isinstance(markers, str):
        return [(markers, markers)]
    if isinstance(markers, Iterable):
        return [(str(value), str(value)) for value in markers]
    return [(str(markers), str(markers))]


class ResponseComparator:
    """Compare a normal response with an attack/test response.

    Differences are signals only.  The comparator never labels a vulnerability.
    Byte lengths are calculated from the body's real UTF-8 representation.
    """

    def __init__(self, *, similarity_char_limit: int = 200_000) -> None:
        if similarity_char_limit <= 0:
            raise ValueError("similarity_char_limit must be positive")
        self.similarity_char_limit = similarity_char_limit

    def compare(
        self,
        baseline_response: Any,
        test_response: Any,
        *,
        markers: Any | None = None,
    ) -> dict[str, Any]:
        baseline_body = get_response_body_text(baseline_response)
        test_body = get_response_body_text(test_response)
        baseline_features = analyze_response(baseline_response)
        test_features = analyze_response(test_response)

        baseline_length = utf8_content_length(baseline_response)
        test_length = utf8_content_length(test_response)
        length_difference = test_length - baseline_length
        change_ratio = (
            length_difference / baseline_length if baseline_length else None
        )

        left = _normalise_body(baseline_body, self.similarity_char_limit)
        right = _normalise_body(test_body, self.similarity_char_limit)
        similarity = SequenceMatcher(None, left, right, autojunk=True).ratio()

        baseline_errors = set(baseline_features["error_indicators"])
        test_errors = set(test_features["error_indicators"])
        new_errors = sorted(test_errors - baseline_errors)
        resolved_errors = sorted(baseline_errors - test_errors)

        baseline_records = baseline_features["record_count"]
        test_records = test_features["record_count"]
        record_difference = (
            test_records - baseline_records
            if baseline_records is not None and test_records is not None
            else None
        )

        marker_comparison: list[dict[str, Any]] = []
        for name, marker in _marker_specs(markers):
            baseline_count = baseline_body.count(marker)
            test_count = test_body.count(marker)
            marker_comparison.append(
                {
                    "name": name,
                    "marker": marker,
                    "baseline_count": baseline_count,
                    "test_count": test_count,
                    "difference": test_count - baseline_count,
                    "changed": baseline_count != test_count,
                    "appeared": baseline_count == 0 and test_count > 0,
                    "disappeared": baseline_count > 0 and test_count == 0,
                }
            )

        baseline_redirect = {
            "detected": baseline_features["redirect_detected"],
            "location": baseline_features["redirect_location"],
        }
        test_redirect = {
            "detected": test_features["redirect_detected"],
            "location": test_features["redirect_location"],
        }
        redirect_changed = baseline_redirect != test_redirect
        significant_length_change = abs(length_difference) >= max(
            100, round(baseline_length * 0.20)
        )

        return {
            "available": True,
            "baseline": {
                "status_code": baseline_features["status_code"],
                "actual_content_length": baseline_length,
                "redirect": baseline_redirect,
                "error_indicators": sorted(baseline_errors),
                "record_count": baseline_records,
            },
            "test": {
                "status_code": test_features["status_code"],
                "actual_content_length": test_length,
                "redirect": test_redirect,
                "error_indicators": sorted(test_errors),
                "record_count": test_records,
            },
            # "attack" is an alias retained for callers using that terminology.
            "attack": {
                "status_code": test_features["status_code"],
                "actual_content_length": test_length,
                "redirect": test_redirect,
                "error_indicators": sorted(test_errors),
                "record_count": test_records,
            },
            "status_changed": baseline_features["status_code"] != test_features["status_code"],
            "baseline_status_code": baseline_features["status_code"],
            "test_status_code": test_features["status_code"],
            "attack_status_code": test_features["status_code"],
            "baseline_content_length": baseline_length,
            "test_content_length": test_length,
            "attack_content_length": test_length,
            "response_length_difference": length_difference,
            "absolute_response_length_difference": abs(length_difference),
            "response_length_change_ratio": change_ratio,
            "significant_length_change": significant_length_change,
            "body_similarity": round(similarity, 6),
            "similarity": round(similarity, 6),
            "body_changed": baseline_body != test_body,
            "similarity_input_truncated": (
                len(baseline_body) > self.similarity_char_limit
                or len(test_body) > self.similarity_char_limit
            ),
            "redirect_changed": redirect_changed,
            "redirect_location_changed": (
                baseline_features["redirect_location"]
                != test_features["redirect_location"]
            ),
            "new_error_indicators": new_errors,
            "resolved_error_indicators": resolved_errors,
            "error_message_changed": bool(new_errors or resolved_errors),
            "sql_error_appeared": (
                test_features["sql_error_detected"]
                and not baseline_features["sql_error_detected"]
            ),
            "baseline_record_count": baseline_records,
            "test_record_count": test_records,
            "attack_record_count": test_records,
            "record_count_difference": record_difference,
            "record_count_changed": record_difference not in (None, 0),
            "returned_data_increased": bool(
                record_difference is not None and record_difference > 0
            ),
            "marker_comparison": marker_comparison,
            "marker_changed": any(item["changed"] for item in marker_comparison),
            "new_markers": [item["name"] for item in marker_comparison if item["appeared"]],
            "missing_markers": [
                item["name"] for item in marker_comparison if item["disappeared"]
            ],
        }


def compare_responses(
    baseline_response: Any,
    test_response: Any,
    *,
    markers: Any | None = None,
    similarity_char_limit: int = 200_000,
) -> dict[str, Any]:
    """Functional API for :class:`ResponseComparator`."""
    return ResponseComparator(similarity_char_limit=similarity_char_limit).compare(
        baseline_response, test_response, markers=markers
    )


__all__ = ["ResponseComparator", "compare_responses"]
