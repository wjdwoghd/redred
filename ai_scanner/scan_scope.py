"""Local-only target and same-origin redirect policy."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when a target or redirect is outside the training scope."""


def _allowed_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_loopback or ip.is_private


def validate_target(url: str) -> str:
    """Validate an HTTP(S) URL resolves only to localhost/private addresses."""

    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("target must be an absolute HTTP or HTTPS URL")
    host = parsed.hostname
    if host.casefold() == "localhost":
        return url.rstrip("/") or url
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ScopeError(f"unable to resolve target host {host!r}") from exc
    if not addresses or not all(_allowed_address(address) for address in addresses):
        raise ScopeError("public/external targets are not allowed; use localhost or RFC1918 private IP")
    return url.rstrip("/") or url


def same_origin(base_url: str, candidate_url: str) -> bool:
    """Return true only for the same scheme, host and effective port."""

    base, candidate = urlsplit(base_url), urlsplit(candidate_url)
    if not base.hostname or not candidate.hostname:
        return False
    if base.scheme.casefold() != candidate.scheme.casefold() or base.hostname.casefold() != candidate.hostname.casefold():
        return False
    base_port = base.port or (443 if base.scheme.casefold() == "https" else 80)
    candidate_port = candidate.port or (443 if candidate.scheme.casefold() == "https" else 80)
    return base_port == candidate_port


def allowed_redirect(base_url: str, location: str) -> str | None:
    """Resolve a redirect and reject external origins."""

    from urllib.parse import urljoin

    candidate = urljoin(base_url, location)
    return candidate if same_origin(base_url, candidate) else None


__all__ = ["ScopeError", "allowed_redirect", "same_origin", "validate_target"]
