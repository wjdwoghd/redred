"""Normalize user-controlled HTTP inputs into auditable candidates."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit

try:
    from .models import HTTPRequest, ParameterCandidate, ParameterLocation
    from .models.http import scalar_text
    from .request_parser import parse_json_body, parse_multipart_request, parse_urlencoded_body
    from .sanitizer import is_sensitive_name, truncate_text
except ImportError:  # direct script execution
    from models import HTTPRequest, ParameterCandidate, ParameterLocation
    from models.http import scalar_text
    from request_parser import parse_json_body, parse_multipart_request, parse_urlencoded_body
    from sanitizer import is_sensitive_name, truncate_text


_IGNORED_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "host",
    "pragma",
    "upgrade-insecure-requests",
}


def _content_type(request: HTTPRequest) -> str:
    return (request.header("content-type") or "").casefold()


def _walk_json(value: Any, pointer: str = "") -> list[tuple[str, Any, str]]:
    if isinstance(value, Mapping):
        result: list[tuple[str, Any, str]] = []
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            result.extend(_walk_json(child, f"{pointer}/{escaped}"))
        return result
    if isinstance(value, list):
        result = []
        for index, child in enumerate(value):
            result.extend(_walk_json(child, f"{pointer}/{index}"))
        return result
    return [(pointer.rsplit("/", 1)[-1] or "body", value, pointer or "/")]


class ParameterExtractor:
    """Extract query, form, JSON, cookie, header, path and upload candidates."""

    def __init__(self, *, max_value_chars: int = 2_048, max_multipart_preview_chars: int = 2_048) -> None:
        self.max_value_chars = max_value_chars
        self.max_multipart_preview_chars = max_multipart_preview_chars

    def extract(self, request: HTTPRequest) -> list[ParameterCandidate]:
        candidates: list[ParameterCandidate] = []
        seen: set[tuple[str, str, str]] = set()

        def add(
            name: str,
            location: ParameterLocation,
            value: Any,
            *,
            json_pointer: str | None = None,
            content_type: str | None = None,
            filename: str | None = None,
            size: int | None = None,
            allow_duplicate: bool = False,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            if value is None:
                value = ""
            if isinstance(value, (bytes, bytearray)):
                value = bytes(value).decode("utf-8", errors="replace")
            if isinstance(value, str):
                value, truncated = truncate_text(value, self.max_value_chars)
            else:
                truncated = False
            key = (name, location.value, scalar_text(value))
            if not allow_duplicate and key in seen:
                return
            seen.add(key)
            candidates.append(
                ParameterCandidate(
                    name=name,
                    location=location,
                    value=value,
                    json_pointer=json_pointer,
                    content_type=content_type,
                    filename=filename,
                    size=size,
                    is_sensitive=is_sensitive_name(name),
                    truncated=truncated,
                    metadata=metadata or {},
                )
            )

        # Parse the actual URL first. parse_qsl preserves duplicate and blank values.
        for name, value in parse_qsl(urlsplit(request.url).query, keep_blank_values=True):
            add(name, ParameterLocation.QUERY, value, allow_duplicate=True)
        for name, value in request.query_parameters.items():
            add(name, ParameterLocation.QUERY, value)

        query_names = {name for name, _ in parse_qsl(urlsplit(request.url).query, keep_blank_values=True)}
        legacy_location = ParameterLocation.FORM if request.method in {"POST", "PUT", "PATCH"} else ParameterLocation.QUERY
        for name, value in request.parameters.items():
            # The URL is authoritative when a normalized legacy field overlaps
            # it; retaining both would make reflection evidence ambiguous.
            if name in query_names:
                continue
            add(name, legacy_location, value)

        for name, value in request.path_parameters.items():
            add(name, ParameterLocation.PATH, value)

        # Cookie header and normalized cookie map are both accepted.
        cookies = dict(request.cookies)
        cookie_header = request.header("cookie") or ""
        for fragment in cookie_header.split(";"):
            name, marker, value = fragment.strip().partition("=")
            if marker:
                cookies.setdefault(name.strip(), value)
        for name, value in cookies.items():
            add(name, ParameterLocation.COOKIE, value)

        for name, value in request.headers.items():
            lower = name.casefold()
            if lower in _IGNORED_HEADERS or lower in {"cookie", "authorization", "proxy-authorization"}:
                continue
            # User-controlled/common proxy headers are useful; arbitrary transport
            # headers are noisy and are intentionally left out.
            if lower in {"user-agent", "referer", "origin"} or lower.startswith("x-"):
                add(name, ParameterLocation.HEADER, value)

        content_type = _content_type(request)
        body = request.body
        if "application/json" in content_type or isinstance(body, (dict, list)):
            parsed = parse_json_body(body)
            if parsed is not None:
                for name, value, pointer in _walk_json(parsed):
                    add(name, ParameterLocation.JSON, value, json_pointer=pointer, content_type=content_type)
        elif "application/x-www-form-urlencoded" in content_type:
            for name, value in parse_urlencoded_body(body):
                add(name, ParameterLocation.FORM, value, allow_duplicate=True, content_type=content_type)

        if "multipart/form-data" in content_type:
            parts, parsed_files = parse_multipart_request(
                request, max_preview_chars=self.max_multipart_preview_chars
            )
            for part in parts:
                if part.get("filename"):
                    add(
                        str(part["name"]), ParameterLocation.FILE, part.get("value", ""),
                        filename=str(part["filename"]), content_type=part.get("content_type"),
                        size=part.get("size"), metadata={"multipart": True},
                    )
                else:
                    add(
                        str(part["name"]), ParameterLocation.MULTIPART, part.get("value", ""),
                        content_type=part.get("content_type"), metadata={"multipart": True},
                    )
            for uploaded in [*request.files, *parsed_files]:
                add(
                    uploaded.field_name, ParameterLocation.FILE,
                    uploaded.content_preview or uploaded.filename,
                    filename=uploaded.filename,
                    content_type=uploaded.content_type,
                    size=uploaded.size,
                    metadata={"extension": uploaded.extension, "multipart": True},
                )
        elif body not in (None, "", {}):
            # Keep an opaque body candidate for scanner adapters that use a custom
            # content type, while never treating it as a parsed parameter.
            add("body", ParameterLocation.BODY, body, content_type=content_type or None)

        return candidates


def extract_parameters(request: HTTPRequest, *, max_value_chars: int = 2_048) -> list[ParameterCandidate]:
    """Functional extraction API used by the pipeline and future Burp adapters."""

    return ParameterExtractor(max_value_chars=max_value_chars).extract(request)


__all__ = ["ParameterExtractor", "extract_parameters"]
