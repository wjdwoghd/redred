"""Conservative, explainable pre-analysis indicator detection."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

try:
    from .models import ParameterCandidate
except ImportError:  # direct script execution
    from models import ParameterCandidate


SQL_PAYLOAD = re.compile(
    r"(?:'|\"|\b(?:or|and|union|select|sleep|benchmark|order\s+by)\b|--\s|/\*)",
    re.I,
)
DANGEROUS_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".pl", ".py", ".sh", ".exe"}
EXECUTABLE_MIME = re.compile(r"(?:php|javascript|x-httpd|octet-stream|x-sh|msdownload|jsp|asp)", re.I)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        return dict(value.model_dump(mode="json"))
    return {}


def _candidate_dict(candidate: Any) -> dict[str, Any]:
    data = _as_dict(candidate)
    if not data:
        data = {
            "name": getattr(candidate, "name", ""),
            "location": getattr(getattr(candidate, "location", ""), "value", getattr(candidate, "location", "")),
            "value": getattr(candidate, "value", ""),
            "filename": getattr(candidate, "filename", None),
            "content_type": getattr(candidate, "content_type", None),
            "size": getattr(candidate, "size", None),
        }
    location = data.get("location")
    data["location"] = getattr(location, "value", location)
    return data


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return str(value) if value is not None else ""


def _max_status(value: str) -> str:
    return "CONFIRMED" if value == "CONFIRMED" else "POSSIBLE" if value == "POSSIBLE" else "NOT_CONFIRMED"


def detect_indicators(
    *,
    request: Any,
    candidates: Iterable[Any],
    response_features: Mapping[str, Any],
    comparison: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return rule signals and a per-vulnerability evidence ceiling.

    This function never claims a vulnerability.  ``max_status`` is an explicit
    ceiling used later to prevent a language model from over-promoting a finding.
    """

    candidate_data = [_candidate_dict(item) for item in candidates]
    comparison = dict(comparison or {})
    response = dict(response_features)
    verification = response.get("verification")
    verification = dict(verification) if isinstance(verification, Mapping) else {}
    reflections = list(response.get("reflections", []) or [])
    reflections.extend(verification.get("reflections", []) or [])
    request_headers = _as_dict(getattr(request, "headers", {})) or _as_dict(request).get("headers", {})
    request_headers = {str(key).casefold(): _text(value) for key, value in request_headers.items()}
    content_type = request_headers.get("content-type", "")
    body = _text(getattr(request, "body", _as_dict(request).get("body", "")))

    sql_candidates = [
        item
        for item in candidate_data
        if not re.search(r"<\s*(?:script|img|svg|iframe)\b", _text(item.get("value")), re.I)
        and SQL_PAYLOAD.search(_text(item.get("value")))
    ]
    sql_error = bool(response.get("sql_error_detected"))
    strong_sql_delta = bool(
        comparison.get("sql_error_appeared")
        or (
            comparison.get("returned_data_increased")
            and comparison.get("record_count_difference", 0) >= 2
            and comparison.get("significant_length_change")
        )
    )
    sql_max = "CONFIRMED" if sql_candidates and (sql_error or strong_sql_delta) else "POSSIBLE" if sql_candidates else "NOT_CONFIRMED"

    xss_exact = [item for item in reflections if item.get("match_type") == "exact"]
    xss_executable = [item for item in xss_exact if item.get("executable")]
    xss_max = "CONFIRMED" if xss_executable else "POSSIBLE" if xss_exact else "NOT_CONFIRMED"

    file_candidates = [item for item in candidate_data if item.get("location") == "file" or item.get("filename")]
    dangerous_files: list[dict[str, Any]] = []
    for item in file_candidates:
        filename = _text(item.get("filename") or item.get("value"))
        extension = "." + filename.rsplit(".", 1)[-1].casefold() if "." in filename.rsplit("/", 1)[-1] else ""
        mime = _text(item.get("content_type"))
        if extension in DANGEROUS_EXTENSIONS or EXECUTABLE_MIME.search(mime):
            dangerous_files.append({**item, "extension": extension, "mime_executable": bool(EXECUTABLE_MIME.search(mime))})
    multipart_detected = "multipart/form-data" in content_type.casefold() or bool(file_candidates)
    upload_success = bool(response.get("upload_success_detected") or verification.get("upload_success_detected"))
    upload_path = bool(response.get("upload_path_detected") or verification.get("upload_path_detected"))
    upload_max = (
        "CONFIRMED"
        if multipart_detected and dangerous_files and upload_success and upload_path
        else "POSSIBLE"
        if dangerous_files or upload_success or upload_path
        else "NOT_CONFIRMED"
    )

    request_features = {
        "candidate_count": len(candidate_data),
        "sql_payload_candidates": [item.get("name") for item in sql_candidates],
        "multipart_detected": multipart_detected,
        "file_candidates": [
            {key: item.get(key) for key in ("name", "filename", "content_type", "size", "location")}
            for item in file_candidates
        ],
        "dangerous_file_candidates": dangerous_files,
    }
    response_features_out = {
        key: response.get(key)
        for key in (
            "status_code", "actual_content_length", "sql_error_detected", "sql_error_indicators",
            "input_reflected", "exact_input_reflected", "encoded_input_reflected",
            "reflection_contexts", "xss_executable_reflection_detected", "reflections",
            "upload_success_detected", "upload_path_detected", "upload_paths", "upload_indicators",
            "record_count", "record_count_indicators", "db_like_data_detected",
        )
        if key in response
    }
    if verification:
        response_features_out["verification"] = verification
    return {
        "sql_error_detected": sql_error,
        "sql_payload_detected": bool(sql_candidates),
        "input_reflected": bool(response.get("input_reflected") or verification.get("input_reflected")),
        "exact_input_reflected": bool(response.get("exact_input_reflected") or verification.get("exact_input_reflected")),
        "encoded_input_reflected": bool(response.get("encoded_input_reflected") or verification.get("encoded_input_reflected")),
        "xss_executable_reflection_detected": bool(response.get("xss_executable_reflection_detected") or verification.get("xss_executable_reflection_detected")),
        "response_length_difference": comparison.get("response_length_difference"),
        "status_changed": comparison.get("status_changed"),
        "redirect_changed": comparison.get("redirect_changed"),
        "record_count_difference": comparison.get("record_count_difference"),
        "upload_request_detected": multipart_detected,
        "dangerous_file_extension": bool(dangerous_files),
        "mime_extension_mismatch": any(item.get("mime_executable") for item in dangerous_files),
        "upload_path_detected": upload_path,
        "upload_paths": list(dict.fromkeys((response.get("upload_paths", []) or []) + (verification.get("upload_paths", []) or []))),
        "server_execution_hint": False,
        "request_features": request_features,
        "response_features": response_features_out,
        "comparison": comparison,
        "evidence_policy": {
            "SQL_INJECTION": {"max_status": sql_max, "reasons": ["SQL-like input present" if sql_candidates else "no SQL-like input", "database error or strong baseline delta" if strong_sql_delta else "no strong response confirmation"]},
            "XSS": {"max_status": xss_max, "reasons": ["exact input reflected" if xss_exact else "no exact reflection", "executable HTML/attribute context" if xss_executable else "no executable context"]},
            "FILE_UPLOAD": {"max_status": upload_max, "reasons": ["dangerous file metadata" if dangerous_files else "no dangerous file metadata", "upload success and path" if upload_success and upload_path else "no combined success/path evidence"]},
        },
        "max_status": {"SQL_INJECTION": sql_max, "XSS": xss_max, "FILE_UPLOAD": upload_max},
    }


class IndicatorDetector:
    """Object-oriented wrapper for dependency injection and future extensions."""

    def detect(self, **kwargs: Any) -> dict[str, Any]:
        return detect_indicators(**kwargs)


__all__ = ["IndicatorDetector", "detect_indicators"]
