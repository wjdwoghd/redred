"""Convert requests responses into canonical HTTP models and raw artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import requests

try:
    from .models import FileMetadata, HTTPRequest, HTTPResponse
except ImportError:
    from models import FileMetadata, HTTPRequest, HTTPResponse


def request_model(method: str, url: str, *, headers: dict[str, str] | None = None, data: Any = None, files: dict[str, tuple[str, bytes, str]] | None = None) -> HTTPRequest:
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    # Keep ordinary multipart fields alongside file metadata.
    parameters = data if isinstance(data, dict) else {}
    metadata: list[FileMetadata] = []
    if files:
        for field, value in files.items():
            filename, content, content_type = value
            metadata.append(FileMetadata(field_name=field, filename=filename, content_type=content_type, size=len(content), sha256=hashlib.sha256(content).hexdigest(), content_preview=content[:256].decode("utf-8", errors="replace"), truncated=len(content) > 256))
    body: Any = ""
    if files:
        body = "[multipart body omitted]"
    elif method.upper() != "GET" and isinstance(data, dict):
        body = urlencode(data)
    elif method.upper() != "GET":
        body = data
    return HTTPRequest(method=method, url=url, path=parsed.path or "/", headers=headers or {}, query_parameters=query, parameters=parameters, body=body, files=metadata)


def response_model(response: requests.Response) -> HTTPResponse:
    body = response.content[:2_000_000].decode(response.encoding or "utf-8", errors="replace")
    return HTTPResponse(status_code=response.status_code, headers={str(k): str(v) for k, v in response.headers.items()}, body=body, content_length=len(response.content), redirect_url=response.headers.get("Location"))


def raw_request_text(request: HTTPRequest) -> str:
    """Serialize metadata-safe request text for audit storage."""
    lines = [f"{request.method} {urlsplit(request.url).path or '/'}{'?' + urlsplit(request.url).query if urlsplit(request.url).query else ''} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in request.headers.items())
    lines.append("")
    if isinstance(request.body, str):
        lines.append(request.body if "multipart" not in request.body else "[multipart body omitted]")
    return "\n".join(lines)


def raw_response_text(response: HTTPResponse) -> str:
    lines = [f"HTTP/1.1 {response.status_code}"]
    lines.extend(f"{key}: {value}" for key, value in response.headers.items())
    lines.extend(["", str(response.body or "")])
    return "\n".join(lines)


__all__ = ["raw_request_text", "raw_response_text", "request_model", "response_model"]
