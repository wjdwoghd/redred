"""Offline active scanner integration tests using a local mock server."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from active_scanner import ActiveScanOptions, ActiveScanner
from config import ScannerConfig
from scan_scope import ScopeError, validate_target


class _Handler(BaseHTTPRequestHandler):
    def _reply(self, body: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        query = parse_qs(urlsplit(self.path).query)
        value = query.get("keyword", [""])[0]
        self._reply(f"<html><a href='/other'>other</a><form method='get' action='/echo'><input name='keyword'></form><p>{value}</p></html>")

    def do_POST(self) -> None:  # noqa: N802
        self._reply("<html><form method='post' action='/echo'><input name='title'></form></html>")

    def log_message(self, *_args: object) -> None:
        return


def test_scope_rejects_public_target() -> None:
    try:
        validate_target("https://example.com")
    except ScopeError:
        pass
    else:
        raise AssertionError("public target was accepted")


def test_active_scanner_crawls_and_creates_summary(tmp_path, monkeypatch) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = ScannerConfig.from_env()
        config = config.model_copy(update={"results_dir": tmp_path})
        result = ActiveScanner(config=config, options=ActiveScanOptions(max_depth=1, max_pages=3, delay_ms=0, max_tests=2)).scan(f"http://127.0.0.1:{server.server_port}", mode="rules")
        assert result.summary["pages_scanned"] >= 1
        assert result.summary["forms_discovered"] >= 1
        assert (result.root_directory / "scan_summary.json").exists()
        assert (result.root_directory / "discovered_inputs.json").exists()
        assert (result.root_directory / "analysis.json").exists()
        assert (result.root_directory / "diagnostic_guide.md").exists()
        assert (result.root_directory / "diagnostic_guide.pdf").exists()
        assert (result.root_directory / "review.json").exists()
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_single_page_scan_does_not_follow_links(tmp_path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = ScannerConfig.from_env().model_copy(update={"results_dir": tmp_path})
        result = ActiveScanner(
            config=config,
            options=ActiveScanOptions(scan_mode="single", max_depth=3, max_pages=50, delay_ms=0, max_tests=1),
        ).scan(f"http://127.0.0.1:{server.server_port}/", mode="rules")
        assert result.summary["scan_mode"] == "single"
        assert result.summary["pages_scanned"] == 1
    finally:
        server.shutdown()
        thread.join(timeout=2)
