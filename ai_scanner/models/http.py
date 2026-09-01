"""Validated HTTP data models used by the scanner input boundary."""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import PurePath
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

MAX_HEADER_COUNT = 256
MAX_HEADER_NAME_CHARS = 256
MAX_HEADER_VALUE_CHARS = 16_384
MAX_PARAMETER_COUNT = 1_000
MAX_BODY_CHARS = 2_000_000
MAX_FILE_COUNT = 100
MAX_FILE_PREVIEW_CHARS = 4_096

_HTTP_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class StrictModel(BaseModel):
    """Base model that rejects undeclared data instead of silently dropping it."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ParameterLocation(str, Enum):
    """Supported user-controlled input locations."""

    QUERY = "query"
    FORM = "form"
    JSON = "json"
    COOKIE = "cookie"
    HEADER = "header"
    MULTIPART = "multipart"
    FILE = "file"
    PATH = "path"
    BODY = "body"
    URL = "url"
    UNKNOWN = "unknown"


def _json_size(value: JsonValue) -> int:
    """Return a stable UTF-8 size estimate for a JSON-compatible value."""

    if isinstance(value, str):
        return len(value.encode("utf-8"))
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _validate_headers(headers: dict[str, str]) -> dict[str, str]:
    if len(headers) > MAX_HEADER_COUNT:
        raise ValueError(f"at most {MAX_HEADER_COUNT} headers are allowed")
    for name, value in headers.items():
        if not name or len(name) > MAX_HEADER_NAME_CHARS or not _HTTP_TOKEN.fullmatch(name):
            raise ValueError(f"invalid HTTP header name: {name!r}")
        if len(value) > MAX_HEADER_VALUE_CHARS:
            raise ValueError(f"header {name!r} exceeds {MAX_HEADER_VALUE_CHARS} characters")
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise ValueError("HTTP headers must not contain CR or LF characters")
    return headers


class FileMetadata(StrictModel):
    """Safe metadata for an uploaded file; full binary contents are not accepted."""

    field_name: str = Field(min_length=1, max_length=256)
    filename: str = Field(min_length=1, max_length=512)
    content_type: str | None = Field(default=None, max_length=256)
    size: int | None = Field(default=None, ge=0, le=1_000_000_000)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    extension: str | None = Field(default=None, max_length=32)
    server_filename: str | None = Field(default=None, max_length=512)
    upload_path: str | None = Field(default=None, max_length=2_048)
    accessible_url: str | None = Field(default=None, max_length=4_096)
    content_preview: str | None = Field(default=None, max_length=MAX_FILE_PREVIEW_CHARS)
    truncated: bool = False

    @model_validator(mode="after")
    def infer_extension(self) -> "FileMetadata":
        """Populate a normalized extension without altering the evidence filename."""

        if self.extension is None:
            suffix = PurePath(self.filename.replace("\\", "/")).suffix
            object.__setattr__(self, "extension", suffix.lower() if suffix else None)
        elif self.extension and not self.extension.startswith("."):
            object.__setattr__(self, "extension", f".{self.extension.lower()}")
        elif self.extension:
            object.__setattr__(self, "extension", self.extension.lower())
        return self


class MultipartPart(StrictModel):
    """Structured representation of one multipart form-data part."""

    name: str = Field(min_length=1, max_length=256)
    value: str | None = Field(default=None, max_length=MAX_FILE_PREVIEW_CHARS)
    filename: str | None = Field(default=None, min_length=1, max_length=512)
    content_type: str | None = Field(default=None, max_length=256)
    size: int | None = Field(default=None, ge=0, le=1_000_000_000)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    truncated: bool = False


class ParameterCandidate(StrictModel):
    """A normalized user-input candidate extracted from an HTTP request."""

    name: str = Field(min_length=1, max_length=512)
    location: ParameterLocation
    value: JsonValue
    json_pointer: str | None = Field(default=None, max_length=2_048)
    content_type: str | None = Field(default=None, max_length=256)
    filename: str | None = Field(default=None, max_length=512)
    size: int | None = Field(default=None, ge=0, le=1_000_000_000)
    is_sensitive: bool = False
    truncated: bool = False
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class HTTPRequest(StrictModel):
    """Canonical request representation accepted from Burp or custom scanners."""

    method: str = Field(min_length=1, max_length=32)
    url: str = Field(min_length=1, max_length=8_192)
    path: str | None = Field(default=None, max_length=4_096)
    headers: dict[str, str] = Field(default_factory=dict)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    query_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    path_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body: JsonValue | None = None
    multipart: list[MultipartPart] = Field(default_factory=list, max_length=MAX_FILE_COUNT)
    files: list[FileMetadata] = Field(default_factory=list, max_length=MAX_FILE_COUNT)

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        value = value.strip().upper()
        if not _HTTP_TOKEN.fullmatch(value):
            raise ValueError("method must be a valid HTTP token")
        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("url must be an absolute HTTP or HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("credentials embedded in the URL are not allowed")
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return _validate_headers(value)

    @field_validator("parameters", "query_parameters", "path_parameters")
    @classmethod
    def validate_parameter_count(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if len(value) > MAX_PARAMETER_COUNT:
            raise ValueError(f"at most {MAX_PARAMETER_COUNT} parameters are allowed")
        return value

    @field_validator("cookies")
    @classmethod
    def validate_cookies(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > MAX_PARAMETER_COUNT:
            raise ValueError(f"at most {MAX_PARAMETER_COUNT} cookies are allowed")
        return value

    @field_validator("body")
    @classmethod
    def validate_body_size(cls, value: JsonValue | None) -> JsonValue | None:
        if value is not None and _json_size(value) > MAX_BODY_CHARS:
            raise ValueError(f"request body exceeds the {MAX_BODY_CHARS}-byte safety limit")
        return value

    @model_validator(mode="after")
    def derive_and_validate_path(self) -> "HTTPRequest":
        parsed_path = urlsplit(self.url).path or "/"
        if self.path is None:
            self.path = parsed_path
        elif not self.path.startswith("/"):
            raise ValueError("path must begin with '/'")
        return self

    def header(self, name: str) -> str | None:
        """Return a header value using case-insensitive HTTP matching."""

        wanted = name.casefold()
        return next((value for key, value in self.headers.items() if key.casefold() == wanted), None)


class HTTPResponse(StrictModel):
    """Canonical HTTP response representation used for evidence analysis."""

    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue | None = ""
    content_length: int | None = Field(default=None, ge=0, le=2_000_000_000)
    redirect_url: str | None = Field(default=None, max_length=8_192)

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return _validate_headers(value)

    @field_validator("body")
    @classmethod
    def validate_body_size(cls, value: JsonValue | None) -> JsonValue | None:
        if value is not None and _json_size(value) > MAX_BODY_CHARS:
            raise ValueError(f"response body exceeds the {MAX_BODY_CHARS}-byte safety limit")
        return value

    @model_validator(mode="after")
    def infer_metadata(self) -> "HTTPResponse":
        if self.content_length is None and self.body is not None:
            self.content_length = _json_size(self.body)
        if self.redirect_url is None:
            for name, value in self.headers.items():
                if name.casefold() == "location":
                    self.redirect_url = value
                    break
        return self

    def header(self, name: str) -> str | None:
        """Return a response header value using case-insensitive matching."""

        wanted = name.casefold()
        return next((value for key, value in self.headers.items() if key.casefold() == wanted), None)


def scalar_text(value: Any) -> str:
    """Render a candidate value consistently for display and de-duplication."""

    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
