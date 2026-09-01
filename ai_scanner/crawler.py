"""Bounded, same-origin crawler used by the active scanner."""

from __future__ import annotations

import time
import logging
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

try:
    from .form_discovery import DiscoveredForm, discover_html
    from .scan_scope import allowed_redirect, same_origin, validate_target
except ImportError:
    from form_discovery import DiscoveredForm, discover_html
    from scan_scope import allowed_redirect, same_origin, validate_target


_DESTRUCTIVE = ("logout", "delete", "remove", "destroy", "signout", "admin/delete")
LOGGER = logging.getLogger(__name__)


def canonicalize_url(url: str) -> str:
    """Return a stable URL key so equivalent links are visited once."""

    parsed = urlsplit(url)
    scheme = parsed.scheme.casefold()
    host = (parsed.hostname or "").casefold()
    port = parsed.port
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    # Query ordering does not change the resource identity for crawling.  Keep
    # duplicate keys, but sort them to collapse equivalent permutations.
    query_items = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_items, doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def _endpoint_identity(url: str) -> str:
    """Return a crawl identity for one endpoint function.

    Detail identifiers commonly produce an unbounded set of equivalent pages
    (``mode=view&id=1``/``id=2``).  Keep the mode/action and all other query
    values, but collapse an ``id`` value when a mode/action is present.
    """

    normalized = canonicalize_url(url)
    parsed = urlsplit(normalized)
    items = parse_qsl(parsed.query, keep_blank_values=True)
    keys = {key.casefold() for key, _ in items}
    if "id" in keys and ("mode" in keys or "action" in keys):
        items = [(key, "<id>" if key.casefold() == "id" else value) for key, value in items]
        items = sorted(items)
        normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(items, doseq=True), ""))
    return normalized


@dataclass(frozen=True, slots=True)
class CrawledPage:
    url: str
    depth: int
    status_code: int
    headers: dict[str, str]
    body: str
    request_method: str = "GET"


@dataclass(frozen=True, slots=True)
class CrawlResult:
    target: str
    pages: tuple[CrawledPage, ...]
    forms: tuple[DiscoveredForm, ...]
    errors: tuple[str, ...]
    requests_sent: int = 0


def is_destructive_url(url: str) -> bool:
    """Identify endpoints that may mutate/delete state and must not be crawled."""

    parsed = urlsplit(url)
    lowered = parsed.path.casefold()
    if any(token in lowered for token in _DESTRUCTIVE):
        return True
    query = "&".join(f"{key}={value}" for key, value in parse_qsl(parsed.query, keep_blank_values=True)).casefold()
    return any(token in query for token in ("action=delete", "action=remove", "action=destroy", "logout", "delete=", "remove="))


class WebCrawler:
    """Use one requests.Session with strict page/depth/delay limits.

    ``scan_mode="endpoint"`` follows only query/action variations on the
    seed path; ``single`` and ``crawl`` retain their original semantics.
    """

    def __init__(self, session: requests.Session, *, max_depth: int = 3, max_pages: int = 50, delay_ms: int = 350, timeout: float = 10.0) -> None:
        self.session, self.max_depth, self.max_pages = session, max_depth, max_pages
        self.delay_seconds, self.timeout = max(0, delay_ms) / 1000.0, timeout

    def crawl(self, target: str, *, follow_links: bool = True, scan_mode: str | None = None) -> CrawlResult:
        target = validate_target(target)
        # ``follow_links`` is retained for callers of the original crawler;
        # active scans may now request the stricter endpoint scope explicitly.
        mode = scan_mode or ("crawl" if follow_links else "single")
        if mode not in {"single", "endpoint", "crawl"}:
            raise ValueError("scan_mode must be single, endpoint or crawl")
        seed = urlsplit(canonicalize_url(target))
        seed_path = seed.path or "/"
        if mode == "endpoint":
            LOGGER.info("[SCOPE] mode=endpoint seed_path=%s", seed_path)
        queue: deque[tuple[str, int]] = deque([(target, 0)])
        visited: set[str] = set()
        endpoint_seen: set[str] = set()
        pages: list[CrawledPage] = []
        forms: list[DiscoveredForm] = []
        errors: list[str] = []
        requests_sent = 0
        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            normalized = canonicalize_url(url)
            path = urlsplit(normalized).path or "/"
            if mode == "endpoint" and path != seed_path:
                LOGGER.info("[SCOPE-SKIP] %s reason=different_path", path)
                continue
            identity = _endpoint_identity(normalized) if mode == "endpoint" else normalized
            if normalized in visited or (mode == "endpoint" and identity in endpoint_seen) or depth > self.max_depth or not same_origin(target, url) or is_destructive_url(url):
                continue
            visited.add(normalized)
            if mode == "endpoint":
                endpoint_seen.add(identity)
            LOGGER.info("[CRAWL] %s / processed %d", url, len(pages))
            try:
                request_url = url
                redirect_hops = 0
                while True:
                    requests_sent += 1
                    response = self.session.get(request_url, timeout=self.timeout, allow_redirects=False)
                    location = next((value for key, value in response.headers.items() if key.casefold() == "location"), "")
                    # Single-page mode still resolves same-origin redirects so
                    # an authenticated target can expose its final HTML form.
                    # The redirect chain is not treated as additional pages.
                    if not follow_links and 300 <= response.status_code < 400 and location and redirect_hops < 5:
                        redirected = allowed_redirect(target, location)
                        if redirected and not is_destructive_url(redirected):
                            request_url = redirected
                            redirect_hops += 1
                            continue
                    break
                headers = {str(k): str(v) for k, v in response.headers.items()}
                body = response.content[:2_000_000].decode(response.encoding or "utf-8", errors="replace")
                final_url = response.url or request_url
                LOGGER.info("[HTTP] GET %s status=%s final_url=%s cookie_sent=%s response_length=%d", url, response.status_code, final_url, bool(self.session.headers.get("Cookie")), len(response.content))
                page = CrawledPage(url=final_url, depth=depth, status_code=response.status_code, headers=headers, body=body)
                pages.append(page)
                should_follow = mode != "single"
                if should_follow and 300 <= response.status_code < 400 and headers.get("Location"):
                    redirected = allowed_redirect(target, headers["Location"])
                    if redirected and (mode != "endpoint" or (urlsplit(canonicalize_url(redirected)).path or "/") == seed_path) and depth < self.max_depth:
                        queue.append((redirected, depth + 1))
                content_type = next((value for key, value in headers.items() if key.casefold() == "content-type"), "")
                if "text/html" in content_type.casefold() or "<html" in body[:1000].casefold() or "<form" in body.casefold():
                    links, discovered_forms = discover_html(body, final_url)
                    page_forms = discovered_forms
                    if mode == "endpoint":
                        # Do not merely avoid queuing a different-path form:
                        # its inputs must not reach the active probe stage
                        # either.  Endpoint scope is enforced at discovery.
                        scoped_forms: list[DiscoveredForm] = []
                        for form in discovered_forms:
                            form_path = urlsplit(canonicalize_url(form.action)).path or "/"
                            if form_path != seed_path:
                                LOGGER.info("[SCOPE-SKIP] %s reason=different_path", form_path)
                            else:
                                scoped_forms.append(form)
                        page_forms = scoped_forms
                    LOGGER.info("[FORM] forms_found=%d html_contains_form=%s", len(page_forms), "<form" in body.casefold())
                    for discovered_form in page_forms:
                        LOGGER.info("[FORM] method=%s action=%s inputs=%s", discovered_form.method, discovered_form.action, ",".join(item.name for item in discovered_form.inputs))
                    forms.extend(page_forms)
                    for link in links if should_follow else ():
                        candidate = canonicalize_url(link)
                        candidate_path = urlsplit(candidate).path or "/"
                        if not same_origin(target, candidate) or is_destructive_url(candidate):
                            continue
                        if mode == "endpoint" and candidate_path != seed_path:
                            LOGGER.info("[SCOPE-SKIP] %s reason=different_path", candidate_path)
                            continue
                        if depth < self.max_depth:
                            LOGGER.info("[DISCOVER] %s -> %s", urlsplit(normalized).path or "/", candidate)
                            queue.append((candidate, depth + 1))
                    # A form action is also an endpoint variation.  Enqueue it
                    # for discovery (GET) while the form itself remains an
                    # input for the existing active probe pipeline.
                    for discovered_form in page_forms if should_follow else ():
                        candidate = canonicalize_url(discovered_form.action)
                        candidate_path = urlsplit(candidate).path or "/"
                        if not same_origin(target, candidate) or is_destructive_url(candidate):
                            continue
                        if mode == "endpoint" and candidate_path != seed_path:
                            LOGGER.info("[SCOPE-SKIP] %s reason=different_path", candidate_path)
                            continue
                        if depth < self.max_depth:
                            LOGGER.info("[DISCOVER] %s -> %s", urlsplit(normalized).path or "/", candidate)
                            queue.append((candidate, depth + 1))
            except requests.RequestException as exc:
                errors.append(f"{url}: {exc}")
            if queue and self.delay_seconds:
                time.sleep(self.delay_seconds)
        unique_forms: dict[tuple[str, str, str, tuple[str, ...]], DiscoveredForm] = {}
        for form in forms:
            action_key = canonicalize_url(form.action)
            if mode == "endpoint":
                action_key = _endpoint_identity(action_key)
            key = (form.method, action_key, form.enctype, tuple(item.name for item in form.inputs))
            unique_forms.setdefault(key, form)
        return CrawlResult(target=target, pages=tuple(pages), forms=tuple(unique_forms.values()), errors=tuple(errors), requests_sent=requests_sent)


__all__ = ["CrawledPage", "CrawlResult", "WebCrawler", "canonicalize_url", "is_destructive_url"]
