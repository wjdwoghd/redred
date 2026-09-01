"""Policy references used to enrich scanner evidence without changing rules."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Mapping

LOGGER = logging.getLogger(__name__)
DEFAULT_MAPPING_PATH = Path(__file__).with_name("kisa_policy_mapping.json")


def load_policy_mapping(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Load policy mappings safely; a missing/corrupt optional file is non-fatal."""

    mapping_path = Path(path) if path else DEFAULT_MAPPING_PATH
    try:
        value = json.loads(mapping_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("policy mapping unavailable (%s): %s", mapping_path, exc)
        return {}
    if not isinstance(value, Mapping):
        LOGGER.warning("policy mapping must be a JSON object: %s", mapping_path)
        return {}
    return {
        str(key).upper(): dict(item)
        for key, item in value.items()
        if isinstance(item, Mapping)
    }


def get_policy_mapping(vulnerability_type: str | None, *, path: str | Path | None = None) -> dict[str, Any] | None:
    """Return one policy reference, or ``None`` for unknown types."""

    if not vulnerability_type:
        return None
    value = load_policy_mapping(path).get(str(vulnerability_type).upper())
    return dict(value) if value else None


__all__ = ["DEFAULT_MAPPING_PATH", "get_policy_mapping", "load_policy_mapping"]
