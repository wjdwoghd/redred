"""Rule-based feature extraction from HTTP responses.

Inputs may be dictionaries, Pydantic models, or plain attribute objects.  The
module intentionally has no dependency on the project's model package and all
public results are JSON-serialisable dictionaries.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from html import escape as html_escape, unescape as html_unescape
import json
import re
from typing import Any
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit


SQL_ERRORS = (
    ("generic_sql_syntax_error", r"\bSQL\s+(?:syntax|query)\s+error\b"),
    ("mysql_syntax_error", r"you have an error in your sql syntax"),
    ("mariadb_error", r"mariadb server version"),
    ("sqlstate", r"SQLSTATE\s*\[[0-9A-Z]+\]"),
    ("mysqli_error", r"mysqli_sql_exception|mysqli?_query\s*\(\)|mysql_(?:fetch|query)"),
    ("postgresql_error", r"postgresql.*?error|pg_query\s*\(\)|syntax error at or near"),
    ("sqlite_error", r"sqlite3?\.(?:OperationalError|DatabaseError)|SQLite error"),
    ("sql_server_error", r"unclosed quotation mark|ODBC SQL Server Driver|OLE DB Provider"),
    ("oracle_error", r"\bORA-[0-9]{4,5}\b|quoted string not properly terminated"),
    ("database_error", r"unknown column|column .*? does not exist|database query failed"),
)
GENERIC_ERRORS = (
    ("php_fatal_error", r"\bFatal error\s*:"),
    ("php_warning", r"\bWarning\s*:.*?\.php\b"),
    ("stack_trace", r"\bStack trace\s*:"),
    ("uncaught_exception", r"\bUncaught (?:Exception|Error)\b"),
)
UPLOAD_SUCCESS = (
    ("upload_success_message", r"upload(?:ed)?\s+(?:successfully|complete|succeeded)|file\s+(?:was\s+)?uploaded"),
    ("korean_upload_success_message", r"업로드\s*(?:성공|완료)|파일(?:이|을)?\s*(?:업로드|저장)(?:되었|됐)"),
)
XSS_TOKEN = re.compile(
    r"<\s*/?\s*script\b|<\s*(?:img|svg|iframe|object|details|video|audio)\b|"
    r"\bon[a-z]{3,}\s*=|javascript\s*:|(?:alert|confirm|prompt)\s*\(|"
    r"document\.(?:cookie|domain|location)",
    re.I,
)
UPLOAD_PATHS = (
    re.compile(r"https?://[^\s\"'<>]+?/(?:uploads?|uploaded|files?|attachments?|media)/[^\s\"'<>?#]+", re.I),
    re.compile(r"(?<![\w])(?:\.\.?/|/)?(?:uploads?|uploaded|files?|attachments?|media)/[\w.()@%+~!$&=,;\-/]+", re.I),
    re.compile(r"\b[A-Za-z]:\\[^\r\n\"'<>]*?\\(?:uploads?|files?)\\[^\r\n\"'<>]+", re.I),
)
DB_KEYS = {
    "id", "user id", "user_id", "username", "email", "password", "department",
    "dept", "name", "role", "title", "content", "created at", "created_at",
}


def as_mapping(value: Any) -> Mapping[str, Any]:
    """Return a mapping for dict/Pydantic-like objects, otherwise an empty one."""
    if isinstance(value, Mapping):
        return value
    for method_name in ("model_dump", "dict"):
        method = getattr(value, method_name, None)
        if callable(method):
            try:
                dumped = method()
            except TypeError:
                continue
            if isinstance(dumped, Mapping):
                return dumped
    return {}


def get_field(value: Any, key: str, default: Any = None) -> Any:
    mapping = as_mapping(value)
    return mapping[key] if key in mapping else getattr(value, key, default)


def _unwrap(value: Any, section: str, own_fields: tuple[str, ...]) -> Any:
    mapping = as_mapping(value)
    if section in mapping and not any(key in mapping for key in own_fields):
        return mapping[section]
    return value


def normalize_headers(headers: Any) -> dict[str, str]:
    if isinstance(headers, Mapping):
        items = headers.items()
    elif isinstance(headers, Iterable) and not isinstance(headers, (str, bytes, bytearray)):
        items = headers
    else:
        return {}
    result: dict[str, str] = {}
    for item in items:
        try:
            key, value = item
        except (TypeError, ValueError):
            continue
        result[str(key).strip().lower()] = str(value).strip()
    return result


def get_response_body_text(response: Any) -> str:
    response = _unwrap(response, "response", ("body", "content", "status_code"))
    body = get_field(response, "body", get_field(response, "content", ""))
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(body or "")


def utf8_content_length(response_or_body: Any) -> int:
    """Return the real byte length; never trust a supplied content_length field."""
    value = _unwrap(response_or_body, "response", ("body", "content", "status_code"))
    mapping = as_mapping(value)
    if mapping or hasattr(value, "body") or hasattr(value, "content"):
        value = get_field(value, "body", get_field(value, "content", ""))
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError):
            value = str(value or "")
    return len(value.encode("utf-8", errors="replace"))


def get_status_code(response: Any) -> int | None:
    response = _unwrap(response, "response", ("body", "status_code", "headers"))
    raw = get_field(response, "status_code", get_field(response, "status", None))
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def get_redirect_location(response: Any) -> str | None:
    response = _unwrap(response, "response", ("body", "status_code", "headers"))
    explicit = get_field(response, "redirect_url", None)
    if explicit:
        return str(explicit)
    return normalize_headers(get_field(response, "headers", {})).get("location")


def _flatten(value: Any, name: str, location: str) -> list[dict[str, str]]:
    mapping = as_mapping(value)
    if mapping:
        if "value" in mapping:
            raw = get_field(value, "value", "")
            return [] if raw is None or isinstance(raw, (bytes, bytearray)) else [{
                "name": str(get_field(value, "name", name or "value")),
                "location": str(get_field(value, "location", get_field(value, "parameter_location", location))),
                "value": str(raw),
            }]
        result: list[dict[str, str]] = []
        for key, child in mapping.items():
            result.extend(_flatten(child, f"{name}.{key}" if name else str(key), location))
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for index, child in enumerate(value):
            result.extend(_flatten(child, f"{name}[{index}]", location))
        return result
    if value is None or isinstance(value, (bytes, bytearray)):
        return []
    return [{"name": name or "value", "location": location, "value": str(value)}]


def collect_input_candidates(
    request: Any | None = None, input_values: Any | None = None, *, max_value_chars: int = 4096
) -> list[dict[str, str]]:
    """Collect explicit extractor output, with a small request-parsing fallback."""
    found: list[dict[str, str]] = []
    if input_values is not None:
        if isinstance(input_values, Iterable) and not isinstance(input_values, (str, bytes, bytearray, Mapping)):
            for item in input_values:
                found.extend(_flatten(item, "", "input"))
        else:
            found.extend(_flatten(input_values, "", "input"))
    if request is not None:
        request = _unwrap(request, "request", ("method", "url", "parameters", "body"))
        for field, location in (
            ("parameters", "query_or_form"), ("query_parameters", "query"),
            ("post_parameters", "body"), ("cookies", "cookie"),
            ("json_body", "json"), ("multipart", "multipart"), ("files", "file"),
        ):
            raw = get_field(request, field, None)
            if raw is not None:
                found.extend(_flatten(raw, "", location))
        url = str(get_field(request, "url", ""))
        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            found.append({"name": name, "location": "query", "value": value})
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in found:
        value = item.get("value", "")
        key = (item.get("name", "value"), item.get("location", "unknown"), value)
        if not value or len(value) > max_value_chars or "\x00" in value or key in seen:
            continue
        seen.add(key)
        result.append({"name": key[0], "location": key[1], "value": value})
    return result


def _encoded_variants(value: str) -> set[str]:
    escaped = html_escape(value, quote=True)
    variants = {
        escaped, html_escape(value, quote=False), quote(value, safe=""), quote_plus(value, safe=""),
        json.dumps(value, ensure_ascii=True)[1:-1], escaped.replace("&#x27;", "&#39;"),
        escaped.replace("&#x27;", "&apos;"),
    }
    return {item for item in variants if item and item != value}


def _context(body: str, start: int, end: int, value: str) -> tuple[str, bool]:
    lower = body.lower()
    if lower.rfind("<script", 0, start + 1) > lower.rfind("</script", 0, start + 1):
        return "javascript", bool(XSS_TOKEN.search(value))
    opening, closing = body.rfind("<", 0, start + 1), body.rfind(">", 0, start + 1)
    next_close = body.find(">", max(start, opening))
    if opening > closing and next_close >= end:
        tag = body[opening : next_close + 1]
        if re.search(r"\bon[a-z]{3,}\s*=|(?:href|src)\s*=\s*['\"]?javascript\s*:", tag, re.I):
            return "javascript", True
        breakout = bool(re.search(r"['\"]\s*[^>]*\bon[a-z]{3,}\s*=", value, re.I))
        return "attribute", breakout
    if "<" in value and ">" in value:
        executable = bool(re.search(r"<\s*script\b|<\s*(?:img|svg|iframe|object|details)\b[^>]*\bon\w+\s*=", value, re.I | re.S))
        return "html", executable
    return "text", False


def _reflections(body: str, candidates: list[dict[str, str]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in candidates:
        value = item["value"]
        for match_type, needles in (("exact", {value}), ("encoded", _encoded_variants(value))):
            for needle in needles:
                offset = 0
                while (index := body.find(needle, offset)) >= 0:
                    context, executable = _context(body, index, index + len(needle), value)
                    if match_type == "encoded":
                        context, executable = "encoded", False
                    result.append({
                        "name": item["name"], "location": item["location"],
                        "value": value[:512], "match_type": match_type, "context": context,
                        "executable": executable, "offset": index,
                    })
                    offset = index + max(1, len(needle))
    return result


def _matches(body: str, signatures: tuple[tuple[str, str], ...]) -> list[str]:
    return [label for label, pattern in signatures if re.search(pattern, body, re.I | re.S)]


def estimate_record_count(body: str) -> tuple[int | None, list[str]]:
    """Estimate returned DB-like records from JSON arrays or HTML table rows."""
    counts: list[int] = []
    indicators: list[str] = []
    try:
        parsed = json.loads(body) if body.lstrip().startswith(("[", "{")) else None
    except json.JSONDecodeError:
        parsed = None
    def walk(node: Any) -> None:
        if isinstance(node, list):
            objects = [entry for entry in node if isinstance(entry, Mapping)]
            if objects:
                counts.append(len(objects)); indicators.append("json_record_array")
                keys = {str(key).lower() for entry in objects for key in entry}
                if keys & DB_KEYS:
                    indicators.append("database_like_json_keys")
            for child in node[:1000]:
                walk(child)
        elif isinstance(node, Mapping):
            for child in node.values():
                walk(child)
    if parsed is not None:
        walk(parsed)
    rows = re.findall(r"<tr\b[^>]*>(.*?)</tr\s*>", body, re.I | re.S)
    data_rows = [row for row in rows if re.search(r"<td\b", row, re.I)]
    if rows:
        counts.append(len(data_rows)); indicators.append("html_table_rows")
        headers = re.sub(r"<[^>]+>", " ", " ".join(re.findall(r"<th\b[^>]*>(.*?)</th\s*>", body, re.I | re.S))).lower()
        if any(key.replace("_", " ") in headers for key in DB_KEYS):
            indicators.append("database_like_table_headers")
    return (max(counts), list(dict.fromkeys(indicators))) if counts else (None, [])


def _upload(body: str, status: int | None, location: str | None) -> tuple[bool, list[str], list[str]]:
    labels = _matches(body, UPLOAD_SUCCESS)
    paths = [html_unescape(match.group(0)).rstrip(".,;:)]}") for pattern in UPLOAD_PATHS for match in pattern.finditer(body)]
    if location and re.search(r"(?:^|/)(?:uploads?|uploaded|files?|attachments?|media)/", location, re.I):
        paths.append(location); labels.append("redirect_to_upload_path")
    paths = list(dict.fromkeys(paths))
    if paths:
        labels.append("upload_path_exposed")
    if status == 201 and paths:
        labels.append("http_created_with_upload_path")
    success = bool(_matches(body, UPLOAD_SUCCESS) or (status == 201 and paths))
    return success, paths, list(dict.fromkeys(labels))


class ResponseAnalyzer:
    """Extract conservative SQL, XSS, upload, redirect, and size indicators."""
    def __init__(self, *, max_body_chars: int = 500_000) -> None:
        if max_body_chars <= 0:
            raise ValueError("max_body_chars must be positive")
        self.max_body_chars = max_body_chars

    def analyze(self, response: Any, *, request: Any | None = None, input_values: Any | None = None) -> dict[str, Any]:
        response = _unwrap(response, "response", ("body", "status_code", "headers"))
        body = get_response_body_text(response)
        inspected = body[: self.max_body_chars]
        status, location = get_status_code(response), get_redirect_location(response)
        headers = normalize_headers(get_field(response, "headers", {}))
        actual = utf8_content_length(response)
        try:
            declared = int(headers["content-length"]) if "content-length" in headers else None
        except ValueError:
            declared = None
        sql_errors = _matches(inspected, SQL_ERRORS)
        errors = list(dict.fromkeys(sql_errors + _matches(inspected, GENERIC_ERRORS)))
        record_count, record_indicators = estimate_record_count(inspected)
        candidates = collect_input_candidates(request, input_values)
        reflections = _reflections(inspected, candidates)
        exact = [item for item in reflections if item["match_type"] == "exact"]
        encoded = [item for item in reflections if item["match_type"] == "encoded"]
        executable = [item for item in exact if item["executable"]]
        upload_success, upload_paths, upload_indicators = _upload(inspected, status, location)
        db_like = bool(record_count and any(item.startswith("database_like") for item in record_indicators))
        return {
            "status_code": status, "content_type": headers.get("content-type"),
            "actual_content_length": actual, "calculated_content_length": actual,
            "declared_content_length": declared,
            "content_length_mismatch": declared is not None and declared != actual,
            "body_truncated_for_analysis": len(body) > self.max_body_chars,
            "body_excerpt": inspected[:4096],
            "redirect_detected": bool(status is not None and 300 <= status < 400),
            "redirect_location": location,
            "sql_error_detected": bool(sql_errors), "sql_error_indicators": sql_errors,
            "error_detected": bool(errors), "error_indicators": errors, "error_messages": errors,
            "record_count": record_count, "returned_record_count": record_count,
            "record_count_indicators": record_indicators,
            "db_like_data_detected": db_like, "db_data_detected": db_like,
            "db_data_indicators": record_indicators if db_like else [],
            "input_reflected": bool(reflections), "exact_input_reflected": bool(exact),
            "encoded_input_reflected": bool(encoded),
            "reflection_contexts": sorted({item["context"] for item in reflections}),
            "reflections": reflections, "reflected_inputs": reflections,
            "xss_executable_reflection_detected": bool(executable),
            "executable_reflections": executable,
            "upload_success_detected": upload_success,
            "upload_path_detected": bool(upload_paths), "upload_paths": upload_paths,
            "upload_indicators": upload_indicators,
        }


def analyze_response(response: Any, *, request: Any | None = None, input_values: Any | None = None, max_body_chars: int = 500_000) -> dict[str, Any]:
    """Functional API for :class:`ResponseAnalyzer`."""
    return ResponseAnalyzer(max_body_chars=max_body_chars).analyze(response, request=request, input_values=input_values)


__all__ = [
    "ResponseAnalyzer", "analyze_response", "as_mapping", "collect_input_candidates",
    "estimate_record_count", "get_field", "get_redirect_location", "get_response_body_text",
    "get_status_code", "normalize_headers", "utf8_content_length",
]
