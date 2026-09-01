"""Redaction and size limiting for data sent to external AI providers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


SENSITIVE_KEY_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
}
SENSITIVE_FIELD_HINTS = {"password", "passwd", "secret", "token", "session", "sessid", "csrf"}
MASK = "[REDACTED]"


def is_sensitive_name(name: str) -> bool:
    """Return whether a header/field name commonly contains a secret."""

    normalized = name.casefold().replace("_", "-")
    return normalized in SENSITIVE_KEY_NAMES or any(
        hint in normalized for hint in SENSITIVE_FIELD_HINTS
    )


def truncate_text(value: str, max_chars: int) -> tuple[str, bool]:
    """Truncate a text value and report whether truncation occurred."""

    if len(value) <= max_chars:
        return value, False
    return value[:max_chars] + "…[TRUNCATED]", True


def sanitize_value(
    value: Any,
    *,
    max_chars: int,
    mask_sensitive: bool = True,
    key_hint: str = "",
    redacted_fields: list[str] | None = None,
    path: str = "$",
) -> tuple[Any, bool]:
    """Recursively mask likely secrets and cap all string values."""

    changed = False
    if mask_sensitive and is_sensitive_name(key_hint):
        if redacted_fields is not None:
            redacted_fields.append(path)
        return MASK, True
    if isinstance(value, str):
        return truncate_text(value, max_chars)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        candidate_name = str(value.get("name", "")) if "name" in value else ""
        for key, child in value.items():
            child_key = str(key)
            sensitive_candidate_value = child_key == "value" and is_sensitive_name(candidate_name)
            child_value, child_changed = sanitize_value(
                child,
                max_chars=max_chars,
                mask_sensitive=mask_sensitive,
                key_hint=candidate_name if mask_sensitive and sensitive_candidate_value else child_key,
                redacted_fields=redacted_fields,
                path=f"{path}.{key}",
            )
            result[str(key)] = child_value
            changed = changed or child_changed
        return result, changed
    if isinstance(value, list):
        result = []
        for index, child in enumerate(value):
            child_value, child_changed = sanitize_value(
                child,
                max_chars=max_chars,
                mask_sensitive=mask_sensitive,
                redacted_fields=redacted_fields,
                path=f"{path}[{index}]",
            )
            result.append(child_value)
            changed = changed or child_changed
        return result, changed
    if isinstance(value, tuple):
        sanitized, changed = sanitize_value(
            list(value),
            max_chars=max_chars,
            mask_sensitive=mask_sensitive,
            redacted_fields=redacted_fields,
            path=path,
        )
        return sanitized, changed
    return value, False


def sanitize_for_ai(
    payload: Any,
    *,
    max_chars: int = 20_000,
    mask_sensitive: bool = True,
) -> tuple[Any, dict[str, Any]]:
    """Return a JSON-safe, redacted and size-limited copy of an evidence payload."""

    redacted: list[str] = []
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json", exclude_none=False)
    sanitized, truncated = sanitize_value(
        payload,
        max_chars=max_chars,
        mask_sensitive=mask_sensitive,
        redacted_fields=redacted,
    )
    return sanitized, {
        "input_truncated": truncated,
        "redacted_fields": sorted(set(redacted)),
    }


def json_for_ai(payload: Any, *, max_chars: int = 20_000, mask_sensitive: bool = True) -> tuple[str, dict[str, Any]]:
    """Serialize sanitized evidence deterministically for a provider request."""

    sanitized, metadata = sanitize_for_ai(
        payload, max_chars=max_chars, mask_sensitive=mask_sensitive
    )
    try:
        serialized = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
        if len(serialized) > max_chars:
            # Keep a valid JSON envelope rather than cutting through braces or
            # UTF-8 characters. The detailed evidence remains in input.json.
            serialized = json.dumps(
                {
                    "truncated_payload": serialized[:max_chars],
                    "warning": "AI payload exceeded the configured character limit",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            metadata["input_truncated"] = True
        return serialized, metadata
    except (TypeError, ValueError) as exc:
        raise ValueError(f"AI payload is not JSON serializable: {exc}") from exc
