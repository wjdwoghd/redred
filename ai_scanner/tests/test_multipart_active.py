"""Regression tests for requests multipart boundary handling."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import requests

from active_scanner import ActiveScanOptions, ActiveScanner
from config import ScannerConfig
from form_discovery import DiscoveredForm, DiscoveredInput
from request_builder import build_form_request, send
from scan_capture import request_model


def test_requests_generates_boundary_and_preserves_normal_fields() -> None:
    session = requests.Session()
    files = {"file": ("redred_test.txt", b"REDRED SAFE UPLOAD TEST", "text/plain")}
    form = DiscoveredForm("http://127.0.0.1:1/", "POST", "http://127.0.0.1:1/upload", (DiscoveredInput("department_id", default_value="7"), DiscoveredInput("title", default_value="demo"), DiscoveredInput("file", "file")), "multipart/form-data")
    built = build_form_request(form, {"department_id": "7", "title": "demo"}, files=files)
    request_kwargs = {key: value for key, value in built.kwargs.items() if key not in {"timeout", "allow_redirects"}}
    prepared = requests.Request(built.method, built.url, **request_kwargs).prepare()
    content_type = prepared.headers.get("Content-Type", "")
    assert content_type.startswith("multipart/form-data; boundary=")
    assert b'name="department_id"' in prepared.body
    assert b'name="title"' in prepared.body
    assert b'filename="redred_test.txt"' in prepared.body
    model = request_model(built.method, built.url, headers=dict(prepared.headers), data={"department_id": "7", "title": "demo"}, files=files)
    assert model.parameters == {"department_id": "7", "title": "demo"}
    assert model.files[0].extension == ".txt"


class _UploadHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<form method='post' enctype='multipart/form-data'><input name='title'><input type='file' name='file'></form>"
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b"uploaded")

    def log_message(self, *_args: object) -> None:
        return


def test_upload_probe_error_does_not_abort_scan(tmp_path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UploadHandler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        config = ScannerConfig.from_env().model_copy(update={"results_dir": tmp_path})
        scanner = ActiveScanner(config=config, options=ActiveScanOptions(max_depth=1, max_pages=2, delay_ms=0, max_tests=2))
        original = scanner._probe_form
        def fail_once(*args, **kwargs):
            scanner._probe_form = original
            raise ValueError("multipart build failed")
        scanner._probe_form = fail_once
        result = scanner.scan(f"http://127.0.0.1:{server.server_port}", mode="rules")
        assert result.summary["pages_scanned"] >= 1
        assert any("multipart build failed" in item for item in result.summary["errors"])
        assert (result.root_directory / "scan_summary.json").exists()
    finally:
        server.shutdown(); thread.join(timeout=2)
