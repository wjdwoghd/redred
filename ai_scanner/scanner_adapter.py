"""Adapter boundary for Burp/custom scanner envelopes.

The analysis engine consumes the canonical ``ScanInput`` shape. Scanner
implementations can change their export format here without touching the
parser, rules, AI client, or report generation.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    """Map common scanner aliases to canonical request fields."""

    result = dict(value)
    aliases = {
        "query": "query_parameters",
        "query_params": "query_parameters",
        "post_params": "parameters",
        "form": "parameters",
        "json": "body",
        "json_body": "body",
        "uploaded_files": "files",
    }
    for source, target in aliases.items():
        if source in result and target not in result:
            result[target] = result[source]
    return result


def normalize_scanner_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a ``ScanInput``-compatible dictionary from common envelopes.

    Canonical ``request``/``response`` payloads are preserved. Other scanners
    may use ``http_request/http_response`` or put request fields at the top
    level; both forms are normalized here.
    """

    if not isinstance(payload, Mapping):
        raise TypeError("scanner payload must be a mapping")
    if isinstance(payload.get("request"), Mapping) and isinstance(payload.get("response"), Mapping):
        result = dict(payload)
        result["request"] = _request(payload["request"])
        return result

    request = payload.get("http_request") or payload.get("attack_request")
    response = payload.get("http_response") or payload.get("attack_response")
    if not isinstance(request, Mapping):
        request = {
            key: payload[key]
            for key in ("method", "url", "path", "headers", "parameters", "body", "files", "multipart")
            if key in payload
        }
    if not isinstance(response, Mapping):
        response = {
            key: payload[key]
            for key in ("status_code", "headers", "body", "content_length", "redirect_url")
            if key in payload
        }
    if not request or not response:
        raise ValueError("scanner payload must contain request/response exchanges")

    result = {key: payload[key] for key in ("schema_version", "scan_id", "capture_type") if key in payload}
    result["request"] = _request(request)
    result["response"] = dict(response)
    for name in ("baseline", "verification"):
        if isinstance(payload.get(name), Mapping):
            result[name] = dict(payload[name])
    return result


__all__ = ["normalize_scanner_payload"]
