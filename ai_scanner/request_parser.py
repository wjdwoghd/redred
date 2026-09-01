"""Input JSON loading and safe parsing of HTTP body encodings."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

try:
    from .exceptions import InputFileError, InputValidationError, RequestParseError
    from .models import FileMetadata, HTTPRequest, ScanInput
except ImportError:  # direct ``python main.py`` execution
    from exceptions import InputFileError, InputValidationError, RequestParseError
    from models import FileMetadata, HTTPRequest, ScanInput


def load_scan_input(path: str | Path, *, max_file_bytes: int = 5_000_000) -> ScanInput:
    """Read and validate one capture JSON file without executing its contents."""

    source = Path(path)
    try:
        size = source.stat().st_size
        if size > max_file_bytes:
            raise InputFileError(
                f"input file is {size} bytes; limit is {max_file_bytes} bytes"
            )
        raw = source.read_text(encoding="utf-8")
    except InputFileError:
        raise
    except (OSError, UnicodeError) as exc:
        raise InputFileError(f"unable to read input file {source}: {exc}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputValidationError(f"input is not valid JSON: {exc}") from exc
    try:
        return ScanInput.model_validate(document)
    except Exception as exc:
        raise InputValidationError(f"input does not match the capture schema: {exc}") from exc


def body_text(body: Any) -> str:
    """Render a body as bounded textual data for parsers."""

    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"))


def parse_urlencoded_body(body: Any) -> list[tuple[str, str]]:
    """Parse URL-encoded form data, preserving duplicate and blank values."""

    return parse_qsl(body_text(body), keep_blank_values=True, strict_parsing=False)


def parse_json_body(body: Any) -> Any | None:
    """Decode a JSON body when it is supplied as text; return None on failure."""

    if isinstance(body, (dict, list)):
        return body
    text = body_text(body).strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _header_value(headers: dict[str, str], name: str) -> str | None:
    wanted = name.casefold()
    return next((value for key, value in headers.items() if key.casefold() == wanted), None)


def parse_multipart_body(
    body: Any,
    content_type: str | None,
    *,
    max_preview_chars: int = 2_048,
) -> tuple[list[dict[str, Any]], list[FileMetadata]]:
    """Parse multipart metadata and short text previews without retaining binaries."""

    if not content_type or "multipart/form-data" not in content_type.casefold():
        return [], []
    match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;\s]+))", content_type, re.I)
    if not match:
        raise RequestParseError("multipart content type has no boundary")
    boundary = (match.group(1) or match.group(2)).encode("utf-8", errors="replace")
    raw = body_text(body).encode("utf-8", errors="replace")
    delimiter = b"--" + boundary
    parts: list[dict[str, Any]] = []
    files: list[FileMetadata] = []
    for chunk in raw.split(delimiter)[1:]:
        chunk = chunk.strip(b"\r\n-")
        if not chunk:
            continue
        header_blob, separator, value_blob = chunk.partition(b"\r\n\r\n")
        if not separator:
            header_blob, separator, value_blob = chunk.partition(b"\n\n")
        if not separator:
            continue
        headers: dict[str, str] = {}
        for line in header_blob.decode("utf-8", errors="replace").splitlines():
            key, marker, value = line.partition(":")
            if marker:
                headers[key.strip().casefold()] = value.strip()
        disposition = headers.get("content-disposition", "")
        name_match = re.search(r"(?:^|;)\s*name=\"?([^\";]+)", disposition, re.I)
        if not name_match:
            continue
        name = name_match.group(1)
        filename_match = re.search(r"filename=\"?([^\";]+)", disposition, re.I)
        value_bytes = value_blob.rstrip(b"\r\n")
        filename = filename_match.group(1) if filename_match else None
        content_type_part = headers.get("content-type")
        if filename:
            preview = value_bytes[:max_preview_chars].decode("utf-8", errors="replace")
            files.append(
                FileMetadata(
                    field_name=name,
                    filename=filename,
                    content_type=content_type_part,
                    size=len(value_bytes),
                    content_preview=preview,
                    truncated=len(value_bytes) > max_preview_chars,
                )
            )
            parts.append(
                {
                    "name": name,
                    "filename": filename,
                    "content_type": content_type_part,
                    "size": len(value_bytes),
                    "value": preview,
                    "truncated": len(value_bytes) > max_preview_chars,
                }
            )
        else:
            value = value_bytes[:max_preview_chars].decode("utf-8", errors="replace")
            parts.append(
                {
                    "name": name,
                    "value": value,
                    "content_type": content_type_part,
                    "truncated": len(value_bytes) > max_preview_chars,
                }
            )
    return parts, files


def parse_multipart_request(
    request: HTTPRequest, *, max_preview_chars: int = 2_048
) -> tuple[list[dict[str, Any]], list[FileMetadata]]:
    """Convenience wrapper around a canonical request model."""

    return parse_multipart_body(
        request.body,
        request.header("content-type"),
        max_preview_chars=max_preview_chars,
    )

