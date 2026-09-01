"""Parse Burp-style raw HTTP files into the canonical scanner input model."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

try:
    from .exceptions import InputError, InputFileError, InputValidationError, RequestParseError
    from .models import HTTPExchange, HTTPRequest, HTTPResponse, ScanInput, FileMetadata
    from .request_parser import parse_multipart_body
except ImportError:  # direct ``python main.py`` execution
    from exceptions import InputError, InputFileError, InputValidationError, RequestParseError
    from models import HTTPExchange, HTTPRequest, HTTPResponse, ScanInput, FileMetadata
    from request_parser import parse_multipart_body


def _read(path: str | Path, max_bytes: int) -> bytes:
    source = Path(path)
    try:
        data = source.read_bytes()
    except (OSError, UnicodeError) as exc:
        raise InputFileError(f"unable to read raw HTTP file {source}: {exc}") from exc
    if len(data) > max_bytes:
        raise InputFileError(f"raw HTTP file {source} exceeds {max_bytes} bytes")
    return data


def _split_message(data: bytes) -> tuple[str, dict[str, str], bytes]:
    """Split a raw HTTP message and unfold simple continuation headers."""

    marker = b"\r\n\r\n" if b"\r\n\r\n" in data else b"\n\n"
    head, _, body = data.partition(marker)
    lines = re.split(rb"\r?\n", head)
    if not lines or not lines[0].strip():
        raise RequestParseError("raw HTTP message has no start line")
    start = lines[0].decode("iso-8859-1").strip()
    headers: dict[str, str] = {}
    current: str | None = None
    for raw_line in lines[1:]:
        line = raw_line.decode("iso-8859-1")
        if line[:1] in {" ", "\t"} and current:
            headers[current] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        if not separator:
            continue
        name = name.strip()
        if not name:
            continue
        # Preserve the first spelling while combining duplicate headers.
        current = next((key for key in headers if key.casefold() == name.casefold()), name)
        headers[current] = (headers.get(current, "") + (", " if current in headers else "") + value.strip())
    return start, headers, body


def _header(headers: dict[str, str], name: str, default: str = "") -> str:
    return next((value for key, value in headers.items() if key.casefold() == name.casefold()), default)


def _body_text(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def parse_raw_request(raw: str | bytes) -> HTTPRequest:
    """Parse one raw request, including query/cookie/body metadata."""

    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    start, headers, body = _split_message(data)
    parts = start.split(None, 2)
    if len(parts) != 3 or parts[2].upper() not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0"}:
        raise RequestParseError("request start line must be METHOD target HTTP/version")
    method, target = parts[0].upper(), parts[1]
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlsplit(target)
        path = parsed.path or "/"
        url = target
    else:
        path = target.split("?", 1)[0] or "/"
        host = _header(headers, "Host")
        if not host:
            raise RequestParseError("raw request requires a Host header for relative targets")
        scheme = _header(headers, "X-Forwarded-Proto", "http").split(",", 1)[0].strip() or "http"
        url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
        parsed = urlsplit(url)

    query_parameters: dict[str, Any] = {}
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        query_parameters[name] = value
    cookies: dict[str, str] = {}
    for fragment in _header(headers, "Cookie").split(";"):
        name, marker, value = fragment.strip().partition("=")
        if marker and name:
            cookies[name] = value

    content_type = _header(headers, "Content-Type")
    body_value: Any = _body_text(body)
    parameters: dict[str, Any] = {}
    if "application/x-www-form-urlencoded" in content_type.casefold():
        parameters = dict(parse_qsl(_body_text(body), keep_blank_values=True))
    elif "application/json" in content_type.casefold():
        try:
            body_value = json.loads(_body_text(body))
        except json.JSONDecodeError:
            # Keep malformed JSON as evidence rather than discarding the body.
            body_value = _body_text(body)

    files: list[FileMetadata] = []
    multipart: list[dict[str, Any]] = []
    if "multipart/form-data" in content_type.casefold():
        try:
            parsed_parts, parsed_files = parse_multipart_body(body_value, content_type)
            multipart = parsed_parts
            files = parsed_files
        except RequestParseError:
            raise
        except Exception as exc:
            raise RequestParseError(f"unable to parse multipart request: {exc}") from exc

    request_data: dict[str, Any] = {
        "method": method,
        "url": url,
        "path": path,
        "headers": headers,
        "query_parameters": query_parameters,
        "parameters": parameters,
        "cookies": cookies,
        "body": body_value,
    }
    if multipart:
        request_data["multipart"] = multipart
    if files:
        request_data["files"] = files
    try:
        return HTTPRequest.model_validate(request_data)
    except Exception as exc:
        raise RequestParseError(f"raw request does not match HTTPRequest: {exc}") from exc


def parse_raw_response(raw: str | bytes) -> HTTPResponse:
    """Parse status, headers, body and byte content length from a raw response."""

    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    start, headers, body = _split_message(data)
    parts = start.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        raise RequestParseError("response start line must be HTTP/version status")
    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise RequestParseError("response status code is not an integer") from exc
    try:
        return HTTPResponse(
            status_code=status_code,
            headers=headers,
            body=_body_text(body),
            content_length=len(body),
        )
    except Exception as exc:
        raise RequestParseError(f"raw response does not match HTTPResponse: {exc}") from exc


def load_raw_scan_input(
    request_path: str | Path,
    response_path: str | Path,
    *,
    baseline_request_path: str | Path | None = None,
    baseline_response_path: str | Path | None = None,
    verification_request_path: str | Path | None = None,
    verification_response_path: str | Path | None = None,
    max_file_bytes: int = 5_000_000,
) -> ScanInput:
    """Load raw files and return a validated ``ScanInput``."""

    pairs = {
        "baseline": (baseline_request_path, baseline_response_path),
        "verification": (verification_request_path, verification_response_path),
    }
    for name, (request_file, response_file) in pairs.items():
        if bool(request_file) != bool(response_file):
            raise InputValidationError(f"{name} request and response must be supplied together")

    def exchange(request_file: str | Path, response_file: str | Path) -> HTTPExchange:
        return HTTPExchange(
            request=parse_raw_request(_read(request_file, max_file_bytes)),
            response=parse_raw_response(_read(response_file, max_file_bytes)),
        )

    try:
        attack = exchange(request_path, response_path)
        values: dict[str, Any] = {
            "capture_type": "captured",
            "request": attack.request,
            "response": attack.response,
        }
        if baseline_request_path and baseline_response_path:
            values["baseline"] = exchange(baseline_request_path, baseline_response_path)
        if verification_request_path and verification_response_path:
            values["verification"] = exchange(verification_request_path, verification_response_path)
        return ScanInput.model_validate(values)
    except (InputError, RequestParseError):
        raise
    except Exception as exc:
        raise InputValidationError(f"raw HTTP input validation failed: {exc}") from exc


__all__ = ["load_raw_scan_input", "parse_raw_request", "parse_raw_response"]
