"""Top-level scanner input models and safe scan identifier generation."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import uuid4

from typing import Literal

from pydantic import Field, field_validator

from .http import HTTPRequest, HTTPResponse, StrictModel

_SAFE_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def generate_scan_id() -> str:
    """Generate a filesystem-safe, collision-resistant scan identifier."""

    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"scan-{timestamp}-{uuid4().hex[:8]}"


class HTTPExchange(StrictModel):
    """One complete HTTP request/response exchange."""

    request: HTTPRequest
    response: HTTPResponse


class ScanInput(StrictModel):
    """Attack/test exchange with an optional normal baseline exchange.

    ``request`` and ``response`` intentionally remain at the top level so the
    initial JSON shape is simple.  A baseline, when present, is nested as one
    complete :class:`HTTPExchange`.
    """

    schema_version: Literal["1.0"] = "1.0"
    scan_id: str = Field(default_factory=generate_scan_id, min_length=1, max_length=64)
    capture_type: Literal["captured", "synthetic_fixture"] = "captured"
    request: HTTPRequest
    response: HTTPResponse
    baseline: HTTPExchange | None = None
    verification: HTTPExchange | None = None

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id(cls, value: str) -> str:
        if not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", value):
            raise ValueError(
                "scan_id must contain only ASCII letters, digits, '_' or '-', "
                "must begin with a letter/digit, and be at most 64 characters"
            )
        if value in {".", ".."}:
            raise ValueError("scan_id must not be a relative path segment")
        return value

    @property
    def attack(self) -> HTTPExchange:
        """Return the top-level test request and response as an exchange."""

        return HTTPExchange(request=self.request, response=self.response)
