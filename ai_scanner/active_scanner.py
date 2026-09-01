"""Bounded active scanner for the local REDRED training server.

This module performs discovery and low-impact probes only.  It never decides a
finding itself; every captured exchange is sent through the existing pipeline.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

try:
    from .config import ScannerConfig
    from .crawler import CrawlResult, WebCrawler, is_destructive_url
    from .diagnostic_workflow import build_scan_analysis, write_review_artifacts
    from .form_discovery import DiscoveredForm, DiscoveredInput
    from .models import HTTPExchange, HTTPRequest, HTTPResponse, ScanInput
    from .pipeline import PipelineOutcome, run_pipeline
    from .pdf_reporter import generate_pdf
    from .request_builder import build_form_request, form_values, send
    from .scan_capture import raw_request_text, raw_response_text, request_model, response_model
    from .scan_scope import ScopeError, same_origin, validate_target
except ImportError:
    from config import ScannerConfig
    from crawler import CrawlResult, WebCrawler, is_destructive_url
    from diagnostic_workflow import build_scan_analysis, write_review_artifacts
    from form_discovery import DiscoveredForm, DiscoveredInput
    from models import HTTPExchange, HTTPRequest, HTTPResponse, ScanInput
    from pipeline import PipelineOutcome, run_pipeline
    from pdf_reporter import generate_pdf
    from request_builder import build_form_request, form_values, send
    from scan_capture import raw_request_text, raw_response_text, request_model, response_model
    from scan_scope import ScopeError, same_origin, validate_target


LOGGER = logging.getLogger(__name__)
SQL_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<img src=x onerror=alert('REDRED_XSS_TEST_001')>"


@dataclass(frozen=True, slots=True)
class ActiveScanOptions:
    max_depth: int = 3
    max_pages: int = 50
    delay_ms: int = 350
    timeout: float = 10.0
    max_tests: int = 100
    # single: seed page only; endpoint: same path/query functions; crawl:
    # bounded same-origin traversal.
    scan_mode: str = "crawl"


@dataclass(frozen=True, slots=True)
class ActiveScanResult:
    root_directory: Path
    crawl: CrawlResult
    summary: dict[str, Any]
    outcomes: tuple[PipelineOutcome, ...]


def _cookie_header(value: str | None) -> dict[str, str]:
    return {"Cookie": value.strip()} if value and value.strip() else {}


def _safe_form(form: DiscoveredForm, target: str) -> bool:
    return same_origin(target, form.action) and not is_destructive_url(form.action)


def _headers_for(form: DiscoveredForm, files: bool = False) -> dict[str, str]:
    # Multipart Content-Type (including boundary) is supplied by requests.
    return {} if files else {"Content-Type": form.enctype}


def _prepared_headers(response: requests.Response, fallback: dict[str, str]) -> dict[str, str]:
    """Use the actual prepared request headers, including multipart boundary."""
    prepared = getattr(response, "request", None)
    headers = getattr(prepared, "headers", None)
    if headers:
        return {str(key): str(value) for key, value in headers.items()}
    return fallback


class ActiveScanner:
    """Discover pages/forms, issue bounded probes, and delegate analysis."""

    def __init__(self, *, config: ScannerConfig, options: ActiveScanOptions | None = None) -> None:
        self.config = config
        self.options = options or ActiveScanOptions()
        self._probe_requests = 0
        if self.options.scan_mode not in {"single", "endpoint", "crawl"}:
            raise ValueError("scan_mode must be single, endpoint or crawl")
        if self.options.max_depth < 0 or self.options.max_pages <= 0 or self.options.max_tests <= 0 or self.options.timeout <= 0:
            raise ValueError("active scan limits must be positive")

    def scan(self, target: str, *, mode: str | None = None, cookie: str | None = None) -> ActiveScanResult:
        total_started = time.perf_counter()
        target = validate_target(target)
        self._probe_requests = 0
        session = requests.Session()
        session.headers.update({"User-Agent": "REDRED-ActiveScanner/1.0", **_cookie_header(cookie)})
        crawl_started = time.perf_counter()
        crawl = WebCrawler(
            session,
            max_depth=self.options.max_depth,
            max_pages=self.options.max_pages,
            delay_ms=self.options.delay_ms,
            timeout=self.options.timeout,
        ).crawl(
            target,
            follow_links=self.options.scan_mode != "single",
            scan_mode=self.options.scan_mode,
        )
        crawl_seconds = time.perf_counter() - crawl_started
        LOGGER.info("[CRAWL] completed: %d pages, %d forms (%.3fs)", len(crawl.pages), len(crawl.forms), crawl_seconds)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        root = (self.config.results_dir / f"active-scan-{timestamp}").resolve()
        (root / "raw_captures").mkdir(parents=True, exist_ok=True)
        (root / "findings").mkdir(parents=True, exist_ok=True)
        (root / "discovered_pages.json").write_text(json.dumps([{"url": p.url, "depth": p.depth, "status_code": p.status_code} for p in crawl.pages], ensure_ascii=False, indent=2), encoding="utf-8")
        (root / "discovered_inputs.json").write_text(json.dumps([form.as_dict() for form in crawl.forms], ensure_ascii=False, indent=2), encoding="utf-8")
        outcomes: list[PipelineOutcome] = []
        dedup: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        active_errors: list[str] = list(crawl.errors)
        tested = 0
        for form in crawl.forms:
            if tested >= self.options.max_tests or not _safe_form(form, target):
                continue
            candidates = [item for item in form.inputs if item.input_type not in {"submit", "button", "reset", "image", "hidden"}]
            for field in candidates:
                if tested >= self.options.max_tests:
                    break
                try:
                    probe_outcomes = self._probe_form(session, target, form, field, root, tested, mode)
                except requests.RequestException as exc:
                    LOGGER.warning("active probe failed for %s %s: %s", form.method, form.action, exc)
                    active_errors.append(f"{form.action} {field.name}: {exc}")
                    continue
                except Exception as exc:
                    message = f"{form.action} {field.name}: {exc}"
                    active_errors.append(message)
                    if field.input_type == "file":
                        LOGGER.warning("[!] File upload test skipped: multipart build failed (%s)", exc)
                    else:
                        LOGGER.warning("active probe skipped: %s", exc)
                    continue
                tested += len(probe_outcomes)
                if not probe_outcomes:
                    continue
                for outcome in probe_outcomes:
                    outcomes.append(outcome)
                    for finding in outcome.analysis.findings:
                        key = (finding.vulnerability_type.value, finding.location.path, finding.location.method, finding.location.parameter or "")
                        candidate = {"type": finding.vulnerability_type.value, "path": finding.location.path, "method": finding.location.method, "parameter": finding.location.parameter, "severity": finding.severity.value, "status": finding.status.value, "confidence": finding.confidence}
                        previous = dedup.get(key)
                        rank = {"NOT_CONFIRMED": 0, "POSSIBLE": 1, "CONFIRMED": 2}
                        if previous is None or rank.get(candidate["status"], 0) > rank.get(previous["status"], 0):
                            dedup[key] = candidate
        findings = list(dedup.values())
        diagnostic_analysis, diagnostic_calls, diagnostic_elapsed = build_scan_analysis(
            target=target,
            outcomes=outcomes,
            scan_id=root.name,
            config=self.config,
            mode=mode or self.config.effective_mode,
        )
        (root / "analysis.json").write_text(json.dumps(diagnostic_analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        write_review_artifacts(root=root, analysis=diagnostic_analysis)
        try:
            diagnostic_pdf = generate_pdf(root / "diagnostic_guide.md", root / "diagnostic_guide.pdf", "diagnostic")
            LOGGER.info("[PDF] diagnostic guide created: %s", diagnostic_pdf)
        except Exception as exc:
            # Markdown/JSON are the source artifacts; PDF is best-effort only.
            LOGGER.warning("[WARN] PDF generation failed: %s", exc)
        for finding in diagnostic_analysis.get("findings", []):
            if finding.get("id"):
                (root / "evidence" / str(finding["id"])).mkdir(parents=True, exist_ok=True)
        LOGGER.info("[AI-DIAGNOSTIC] candidates=%d", len(diagnostic_analysis["findings"]))
        LOGGER.info("[AI-DIAGNOSTIC] calls=%d", diagnostic_calls)
        LOGGER.info("[AI-DIAGNOSTIC] time=%.3fs", diagnostic_elapsed)
        counts = defaultdict(int)
        for item in findings:
            counts[item["status"].lower()] += 1
        total_seconds = time.perf_counter() - total_started
        summary = {"target": target, "scan_mode": self.options.scan_mode, "pages_scanned": len(crawl.pages), "forms_discovered": len(crawl.forms), "inputs_tested": tested, "http_requests": crawl.requests_sent + self._probe_requests, "findings": {"confirmed": counts["confirmed"], "possible": counts["possible"]}, "vulnerabilities": findings, "errors": active_errors, "diagnostic_ai_calls": diagnostic_calls, "timings": {"crawl_seconds": round(crawl_seconds, 3), "diagnostic_seconds": round(diagnostic_elapsed, 3), "total_seconds": round(total_seconds, 3)}}
        LOGGER.info("[TOTAL] active scan %.3fs (pages=%d forms=%d inputs=%d)", total_seconds, len(crawl.pages), len(crawl.forms), tested)
        (root / "scan_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        (root / "scan_summary.md").write_text(self._summary_markdown(summary), encoding="utf-8")
        return ActiveScanResult(root_directory=root, crawl=crawl, summary=summary, outcomes=tuple(outcomes))

    def _probe_form(self, session: requests.Session, target: str, form: DiscoveredForm, field: DiscoveredInput, root: Path, index: int, mode: str | None) -> list[PipelineOutcome]:
        baseline_values = form_values(form)
        if not baseline_values.get(field.name) and field.input_type != "file":
            baseline_values[field.name] = "test"
        files = None
        if field.input_type == "file":
            files = {field.name: ("redred_test.txt", b"REDRED_UPLOAD_TEST_001\n", "text/plain")}
        baseline = build_form_request(form, baseline_values, files=files)
        baseline_response = send(session, baseline)
        self._probe_requests += 1
        capture_headers = {str(k): str(v) for k, v in session.headers.items()}
        capture_headers.update(_headers_for(form, bool(files)))
        baseline_model = request_model(baseline.method, baseline.url, headers=_prepared_headers(baseline_response, capture_headers), data=baseline_values, files=files)
        probes: list[tuple[dict[str, str], dict[str, tuple[str, bytes, str]] | None]] = []
        if field.input_type == "file":
            probes.append((dict(baseline_values), {field.name: ("redred_test.html", b"REDRED_UPLOAD_TEST_001", "text/html")}))
        elif field.input_type in {"text", "search", "textarea"}:
            sql_values = dict(baseline_values)
            sql_values[field.name] = SQL_PAYLOAD
            xss_values = dict(baseline_values)
            xss_values[field.name] = XSS_PAYLOAD
            probes.extend([(sql_values, None), (xss_values, None)])
        else:
            return []
        results: list[PipelineOutcome] = []
        for probe_number, (test_values, test_files) in enumerate(probes):
            test = build_form_request(form, test_values, files=test_files)
            test_response = send(session, test)
            self._probe_requests += 1
            verification: HTTPExchange | None = None
            if test_values.get(field.name) == XSS_PAYLOAD and form.method.upper() == "POST":
                verify_url = form.action
                if same_origin(target, verify_url) and not is_destructive_url(verify_url):
                    verify = session.get(verify_url, timeout=self.options.timeout, allow_redirects=False)
                    self._probe_requests += 1
                    verification = HTTPExchange(request=request_model("GET", verify_url, headers=dict(session.headers)), response=response_model(verify))
            if field.input_type == "file":
                # Only follow an explicit same-origin upload path exposed by the
                # response; never guess a filesystem path or cross an origin.
                body = test_response.content[:2_000_000].decode(test_response.encoding or "utf-8", errors="replace")
                location = test_response.headers.get("Location", "")
                match = re.search(r"(?:(?:https?://[^\s\"'<>]+)|(?:/?uploads?/[\w.\-/]+)|(?:/?files?/[\w.\-/]+))", body + " " + location, re.I)
                if match:
                    verify_url = urljoin(test.url, match.group(0))
                    if same_origin(target, verify_url):
                        verify = session.get(verify_url, timeout=self.options.timeout, allow_redirects=False)
                        self._probe_requests += 1
                        verification = HTTPExchange(request=request_model("GET", verify_url, headers=dict(session.headers)), response=response_model(verify))
            test_headers = {str(k): str(v) for k, v in session.headers.items()}
            test_headers.update(_headers_for(form, bool(test_files)))
            test_model = request_model(test.method, test.url, headers=_prepared_headers(test_response, test_headers), data=test_values, files=test_files)
            scan = ScanInput(scan_id=f"scan-active-{index + probe_number + 1:04d}", request=test_model, response=response_model(test_response), baseline=HTTPExchange(request=baseline_model, response=response_model(baseline_response)), verification=verification)
            capture_dir = root / "raw_captures" / f"capture-{index + probe_number + 1:04d}"
            capture_dir.mkdir(parents=True, exist_ok=True)
            (capture_dir / "request.txt").write_text(raw_request_text(test_model), encoding="utf-8")
            (capture_dir / "response.txt").write_text(raw_response_text(scan.response), encoding="utf-8")
            finding_dir = root / "findings" / f"finding-{index + probe_number + 1:03d}"
            # Active probes are evaluated locally first.  The scan-level
            # diagnostic aggregation performs at most one AI call.
            outcome = run_pipeline(scan, config=self.config, mode="rules", output_directory=finding_dir)
            nested = outcome.artifacts.scan_directory
            if nested != finding_dir and nested.exists():
                for artifact in nested.iterdir():
                    shutil.move(str(artifact), str(finding_dir / artifact.name))
                nested.rmdir()
            results.append(outcome)
        return results

    @staticmethod
    def _summary_markdown(summary: dict[str, Any]) -> str:
        lines = ["# Active Scan 요약", "", f"- 대상: `{summary['target']}`", f"- 탐색 페이지: `{summary['pages_scanned']}`", f"- 발견 Form: `{summary['forms_discovered']}`", f"- 테스트 입력: `{summary['inputs_tested']}`", f"- CONFIRMED: `{summary['findings']['confirmed']}`", f"- POSSIBLE: `{summary['findings']['possible']}`", "", "## Findings", ""]
        for finding in summary["vulnerabilities"]:
            lines.append(f"- `{finding['status']}` {finding['type']} — `{finding['method']} {finding['path']}` / `{finding['parameter'] or '-'}` ({finding['severity']})")
        if not summary["vulnerabilities"]:
            lines.append("확인된 Finding이 없습니다.")
        return "\n".join(lines) + "\n"


__all__ = ["ActiveScanOptions", "ActiveScanResult", "ActiveScanner"]
