"""Build safe baseline/test HTTP requests from discovered forms."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

try:
    from .form_discovery import DiscoveredForm
except ImportError:
    from form_discovery import DiscoveredForm


@dataclass(frozen=True, slots=True)
class BuiltRequest:
    method: str
    url: str
    kwargs: dict[str, Any]
    values: dict[str, str]


def form_values(form: DiscoveredForm, overrides: dict[str, str] | None = None) -> dict[str, str]:
    values = {item.name: item.default_value for item in form.inputs if item.input_type not in {"submit", "button", "reset", "image", "file"}}
    values.update(overrides or {})
    return values


def build_form_request(form: DiscoveredForm, values: dict[str, str], *, files: dict[str, tuple[str, bytes, str]] | None = None) -> BuiltRequest:
    url = urljoin(form.url, form.action)
    method = form.method.upper()
    kwargs: dict[str, Any] = {"timeout": 10.0, "allow_redirects": False}
    if method == "GET":
        parsed = urlsplit(url)
        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        existing.update(values)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(existing), parsed.fragment))
    elif files:
        # Do not set Content-Type here. requests prepares the multipart body
        # and boundary when ``files=`` is present.
        kwargs["data"], kwargs["files"] = values, files
    else:
        kwargs["data"] = values
    return BuiltRequest(method=method, url=url, kwargs=kwargs, values=values)


def send(session: requests.Session, built: BuiltRequest) -> requests.Response:
    """Send one already-scoped request; callers enforce target and limits."""

    return session.request(built.method, built.url, **built.kwargs)


__all__ = ["BuiltRequest", "build_form_request", "form_values", "send"]
