"""Raw Burp-style request/response parsing tests."""

from __future__ import annotations

from pathlib import Path

from models import ParameterLocation
from raw_http_parser import load_raw_scan_input, parse_raw_request, parse_raw_response
from parameter_extractor import extract_parameters


def test_raw_request_extracts_query_cookie_and_form() -> None:
    request = parse_raw_request(
        "GET /department_resources.php?dept=marketing&keyword=test HTTP/1.1\r\n"
        "Host: 192.168.94.128\r\nCookie: PHPSESSID=abc123\r\n\r\n"
    )
    assert request.url == "http://192.168.94.128/department_resources.php?dept=marketing&keyword=test"
    candidates = extract_parameters(request)
    assert {item.name for item in candidates} >= {"dept", "keyword", "PHPSESSID"}
    assert request.cookies["PHPSESSID"] == "abc123"


def test_raw_json_and_multipart_metadata() -> None:
    json_request = parse_raw_request(
        "POST /api HTTP/1.1\nHost: 192.168.94.128\nContent-Type: application/json\n\n"
        '{"title":"hello","count":1}'
    )
    assert json_request.body == {"title": "hello", "count": 1}
    multipart = parse_raw_request(
        "POST /upload.php HTTP/1.1\r\nHost: 192.168.94.128\r\n"
        "Content-Type: multipart/form-data; boundary=----X\r\n\r\n"
        "------X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"proof.php\"\r\n"
        "Content-Type: application/x-php\r\n\r\n<?php echo 1; ?>\r\n------X--\r\n"
    )
    assert multipart.files[0].filename == "proof.php"
    assert multipart.files[0].content_type == "application/x-php"
    assert multipart.files[0].size is not None
    assert multipart.files[0].extension == ".php"
    assert all(item.location in {ParameterLocation.FILE, ParameterLocation.MULTIPART} for item in extract_parameters(multipart) if item.name == "file")


def test_raw_response_and_exchange_loader(tmp_path: Path) -> None:
    request_path = tmp_path / "raw_request.txt"
    response_path = tmp_path / "raw_response.txt"
    request_path.write_text("GET /health HTTP/1.1\r\nHost: 192.168.94.128\r\n\r\n", encoding="utf-8")
    response_path.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
    response = parse_raw_response(response_path.read_bytes())
    assert response.status_code == 200
    assert response.content_length == 2
    scan = load_raw_scan_input(request_path, response_path)
    assert scan.request.path == "/health"
    assert scan.response.body == "ok"
