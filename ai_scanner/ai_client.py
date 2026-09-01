"""AI provider abstraction and OpenAI Responses API adapter.

The OpenAI SDK is imported only when :class:`OpenAIResponsesClient` is
constructed.  Rule-only scans therefore do not require the optional SDK or an
API key.  Provider failures are operational errors and are never translated
into vulnerability findings here.
"""

from __future__ import annotations

import importlib
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Protocol, runtime_checkable

try:  # Package execution: ``python -m ai_scanner.main``
    from .exceptions import AIClientError, AIResponseError, ConfigurationError
except ImportError:  # Script execution: ``python main.py`` from ai_scanner/
    from exceptions import AIClientError, AIResponseError, ConfigurationError

if TYPE_CHECKING:
    from pydantic import BaseModel


@dataclass(frozen=True, slots=True)
class AIClientResult:
    """Validated provider result plus non-sensitive request diagnostics."""

    parsed: "BaseModel"
    request_id: str | None = None
    response_id: str | None = None
    model: str | None = None
    status: str = "completed"


@runtime_checkable
class AIClient(Protocol):
    """Minimal provider interface consumed by the vulnerability analyzer."""

    def analyze(
        self,
        *,
        instructions: str,
        input_data: str | Mapping[str, Any],
    ) -> AIClientResult:
        """Return one schema-validated analysis draft."""


def _load_analysis_draft() -> type["BaseModel"]:
    """Resolve AnalysisDraft for both package and direct-script execution."""

    candidates = (
        "ai_scanner.models.analysis",
        "models.analysis",
    )
    errors: list[str] = []
    for module_name in candidates:
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            errors.append(f"{module_name}: {exc}")
            continue
        model_type = getattr(module, "AnalysisDraft", None)
        if model_type is not None:
            return model_type
    raise AIClientError(
        "AnalysisDraft model is unavailable; tried " + "; ".join(errors)
    )


def _load_report_draft() -> type["BaseModel"]:
    """Resolve the report prose schema without importing it at module load."""

    candidates = ("ai_scanner.report_generator", "report_generator")
    errors: list[str] = []
    for module_name in candidates:
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            errors.append(f"{module_name}: {exc}")
            continue
        model_type = getattr(module, "ReportDraft", None)
        if model_type is not None:
            return model_type
    raise AIClientError("ReportDraft model is unavailable; tried " + "; ".join(errors))


def _serialize_input(value: str | Mapping[str, Any]) -> str:
    """Serialize structured evidence deterministically without ASCII escaping."""

    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise AIClientError(f"AI input is not JSON serializable: {exc}") from exc


def _find_refusal(response: Any) -> str | None:
    """Extract a refusal from Responses API output without relying on SDK internals."""

    for output_item in getattr(response, "output", ()) or ():
        for content_item in getattr(output_item, "content", ()) or ():
            if getattr(content_item, "type", None) == "refusal":
                refusal = getattr(content_item, "refusal", None)
                if refusal:
                    return str(refusal)
    return None


def _nullable(schema: dict[str, Any]) -> dict[str, Any]:
    """Build a nullable JSON Schema fragment without an untyped ``{}``."""

    return {"anyOf": [schema, {"type": "null"}]}


def _comparison_schema() -> dict[str, Any]:
    """Return the fixed comparison shape accepted in AI evidence.

    The runtime comparator intentionally returns a richer Python dictionary.
    OpenAI Structured Outputs does not allow arbitrary object keys, so the AI
    response uses this compact, documented subset.  The complete comparator
    output is still included in the AI input and remains available to rules
    mode findings.
    """

    integer = {"type": "integer"}
    number = {"type": "number"}
    string_array = {"type": "array", "items": {"type": "string"}}
    properties: dict[str, dict[str, Any]] = {
        "available": {"type": "boolean"},
        "status_changed": {"type": "boolean"},
        "baseline_status_code": _nullable(deepcopy(integer)),
        "test_status_code": _nullable(deepcopy(integer)),
        "baseline_content_length": _nullable(deepcopy(integer)),
        "test_content_length": _nullable(deepcopy(integer)),
        "response_length_difference": _nullable(deepcopy(integer)),
        "significant_length_change": {"type": "boolean"},
        "body_similarity": _nullable(deepcopy(number)),
        "body_changed": {"type": "boolean"},
        "redirect_changed": {"type": "boolean"},
        "new_error_indicators": string_array,
        "sql_error_appeared": {"type": "boolean"},
        "record_count_difference": _nullable(deepcopy(integer)),
        "returned_data_increased": {"type": "boolean"},
        "marker_changed": {"type": "boolean"},
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def _normalise_openai_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Convert Pydantic's schema into the Responses strict JSON Schema subset.

    ``JsonValue`` is intentionally broad in the persisted Pydantic model and
    therefore appears as an empty schema (``{}``).  An empty schema has no
    ``type`` and is rejected by Structured Outputs.  AI evidence only needs a
    scalar request value, so references to it are replaced by a typed scalar
    union.  Arbitrary dictionaries are rejected by the API as well; the one
    such field (``baseline_comparison``) receives a fixed object shape.
    """

    result = deepcopy(schema)
    defs = result.get("$defs")
    if isinstance(defs, dict) and "JsonValue" in defs:
        defs["JsonValue"] = {
            "anyOf": [
                {"type": "string"},
                {"type": "number"},
                {"type": "boolean"},
                {"type": "null"},
            ]
        }

    evidence = defs.get("Evidence") if isinstance(defs, dict) else None
    if isinstance(evidence, dict):
        evidence_properties = evidence.get("properties")
        if isinstance(evidence_properties, dict):
            evidence_properties["baseline_comparison"] = _nullable(_comparison_schema())

    def visit(node: Any) -> Any:
        if not isinstance(node, dict):
            return node
        if node == {}:
            # Defensive fallback for any future unconstrained Pydantic type.
            return {"type": "string"}
        if "$ref" in node:
            # Responses Structured Outputs rejects siblings such as
            # ``{"$ref": "...", "default": ...}``; references must stand
            # alone.  Defaults are not needed because Pydantic applies them
            # after the model output is parsed.
            return {"$ref": node["$ref"]}
        if isinstance(node.get("$defs"), dict):
            node["$defs"] = {
                name: visit(definition) for name, definition in node["$defs"].items()
            }
        if isinstance(node.get("properties"), dict):
            properties = node["properties"]
            node["properties"] = {key: visit(value) for key, value in properties.items()}
            node["required"] = list(properties)
            node["additionalProperties"] = False
        elif node.get("type") == "object":
            node["properties"] = {}
            node["required"] = []
            node["additionalProperties"] = False
        if isinstance(node.get("items"), dict):
            node["items"] = visit(node["items"])
        if isinstance(node.get("anyOf"), list):
            node["anyOf"] = [visit(value) for value in node["anyOf"]]
        if isinstance(node.get("allOf"), list):
            node["allOf"] = [visit(value) for value in node["allOf"]]
        return node

    return visit(result)


def _validate_openai_schema(node: Any, *, path: tuple[str, ...] = ()) -> None:
    """Validate strict-object invariants throughout a schema tree."""

    if not isinstance(node, dict):
        raise AIClientError(f"schema node at {path or ('root',)} must be an object")
    if "$ref" in node:
        return
    if "anyOf" in node:
        variants = node["anyOf"]
        if not isinstance(variants, list) or not variants:
            raise AIClientError(f"schema anyOf at {path} must be a non-empty list")
        for index, variant in enumerate(variants):
            _validate_openai_schema(variant, path=(*path, "anyOf", str(index)))
    if node.get("type") == "object":
        properties = node.get("properties")
        if not isinstance(properties, dict):
            raise AIClientError(f"object schema at {path} must define properties")
        if node.get("additionalProperties") is not False:
            raise AIClientError(f"object schema at {path} must set additionalProperties=false")
        if set(node.get("required", ())) != set(properties):
            raise AIClientError(f"object schema at {path} must require every property")
        for name, child in properties.items():
            _validate_openai_schema(child, path=(*path, "properties", name))
    elif node.get("type") == "array":
        if not isinstance(node.get("items"), dict):
            raise AIClientError(f"array schema at {path} must define items")
        _validate_openai_schema(node["items"], path=(*path, "items"))
    elif "anyOf" not in node and "type" not in node and "enum" not in node:
        raise AIClientError(f"schema node at {path} has no type or reference")

    defs = node.get("$defs")
    if isinstance(defs, dict):
        for name, definition in defs.items():
            _validate_openai_schema(definition, path=(*path, "$defs", name))


def analysis_draft_json_schema() -> dict[str, Any]:
    """Return the exact schema placed in ``text.format.schema``.

    This public helper is also used by tests and diagnostics to ensure the
    payload contains the schema object itself, not the outer ``name/type``
    wrapper.
    """

    analysis_draft = _load_analysis_draft()
    raw_schema = analysis_draft.model_json_schema()
    schema = _normalise_openai_schema(raw_schema)
    if schema.get("type") != "object":
        raise AIClientError("AnalysisDraft schema root must have type=object")
    if not isinstance(schema.get("properties"), dict):
        raise AIClientError("AnalysisDraft schema root must define properties")
    if schema.get("additionalProperties") is not False:
        raise AIClientError("AnalysisDraft schema root must set additionalProperties=false")
    if set(schema.get("required", ())) != set(schema["properties"]):
        raise AIClientError("AnalysisDraft schema root required fields are incomplete")
    _validate_openai_schema(schema)
    return schema


class OpenAIResponsesClient:
    """OpenAI Responses API implementation using Pydantic Structured Outputs."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str | None = None,
        timeout: float = 90.0,
        max_retries: int = 2,
        max_output_tokens: int = 8_000,
        client: Any | None = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ConfigurationError("AI_API_KEY is required when AI mode is enabled")
        if not model or not model.strip():
            raise ConfigurationError("AI_MODEL is required when AI mode is enabled")
        if timeout <= 0:
            raise ConfigurationError("AI timeout must be greater than zero")
        if max_retries < 0:
            raise ConfigurationError("AI max_retries cannot be negative")
        if max_output_tokens <= 0:
            raise ConfigurationError("AI max_output_tokens must be greater than zero")

        self.model = model.strip()
        self.max_output_tokens = max_output_tokens

        if client is None:
            try:
                openai_module = importlib.import_module("openai")
                openai_type = getattr(openai_module, "OpenAI")
            except (ImportError, AttributeError) as exc:
                raise ConfigurationError(
                    "The OpenAI SDK is required for AI mode; install requirements.txt"
                ) from exc
            try:
                client = openai_type(
                    api_key=api_key.strip(),
                    base_url=base_url.strip() if base_url and base_url.strip() else None,
                    timeout=timeout,
                    max_retries=max_retries,
                )
            except Exception as exc:  # SDK validates transport configuration.
                raise ConfigurationError(f"Failed to initialize OpenAI client: {exc}") from exc
        self._client = client

    def analyze(
        self,
        *,
        instructions: str,
        input_data: str | Mapping[str, Any],
    ) -> AIClientResult:
        """Call Responses Structured Outputs and validate ``AnalysisDraft``.

        The payload deliberately uses the current Responses API shape:
        ``text.format = {type, name, schema, strict}``.  ``schema`` contains
        only the JSON Schema object (whose root is ``type=object``), rather
        than the Chat Completions-era ``json_schema`` wrapper.
        """

        if not instructions.strip():
            raise AIClientError("AI instructions cannot be empty")

        analysis_draft = _load_analysis_draft()
        schema = analysis_draft_json_schema()
        try:
            response = self._client.responses.create(
                model=self.model,
                instructions=instructions,
                input=_serialize_input(input_data),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "AnalysisDraft",
                        "schema": schema,
                        "strict": True,
                    }
                },
                max_output_tokens=self.max_output_tokens,
                store=False,
            )
        except Exception as exc:
            request_id = getattr(exc, "request_id", None)
            suffix = f" (request_id={request_id})" if request_id else ""
            raise AIClientError(f"OpenAI Responses request failed{suffix}: {exc}") from exc

        request_id = getattr(response, "_request_id", None) or getattr(
            response, "request_id", None
        )
        status = str(getattr(response, "status", "completed") or "completed")
        response_id = getattr(response, "id", None)

        if status == "incomplete":
            details = getattr(response, "incomplete_details", None)
            reason = getattr(details, "reason", None) or "unknown reason"
            raise AIResponseError(
                f"OpenAI response was incomplete ({reason}, request_id={request_id or 'unknown'})"
            )
        if status != "completed":
            raise AIResponseError(
                f"OpenAI response status was {status!r} (request_id={request_id or 'unknown'})"
            )

        refusal = _find_refusal(response)
        if refusal:
            raise AIResponseError(
                f"OpenAI refused the analysis (request_id={request_id or 'unknown'}): {refusal}"
            )

        output_text = getattr(response, "output_text", None)
        if not output_text:
            raise AIResponseError(
                "OpenAI returned no structured output text "
                f"(request_id={request_id or 'unknown'})"
            )
        try:
            parsed = analysis_draft.model_validate(json.loads(output_text))
        except Exception as exc:
            raise AIResponseError(
                "OpenAI structured output failed AnalysisDraft validation "
                f"(request_id={request_id or 'unknown'}): {exc}"
            ) from exc

        return AIClientResult(
            parsed=parsed,
            request_id=str(request_id) if request_id else None,
            response_id=str(response_id) if response_id else None,
            model=str(getattr(response, "model", self.model) or self.model),
            status=status,
        )

    def generate_report(
        self,
        *,
        instructions: str,
        input_data: str,
    ) -> "BaseModel":
        """Generate a strictly structured Korean report narrative draft."""

        if not instructions.strip():
            raise AIClientError("report instructions cannot be empty")
        report_draft = _load_report_draft()
        schema = _normalise_openai_schema(report_draft.model_json_schema())
        _validate_openai_schema(schema)
        try:
            response = self._client.responses.create(
                model=self.model,
                instructions=instructions,
                input=input_data,
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "ReportDraft",
                        "schema": schema,
                        "strict": True,
                    }
                },
                max_output_tokens=self.max_output_tokens,
                store=False,
            )
        except Exception as exc:
            request_id = getattr(exc, "request_id", None)
            suffix = f" (request_id={request_id})" if request_id else ""
            raise AIClientError(f"OpenAI report request failed{suffix}: {exc}") from exc

        request_id = getattr(response, "_request_id", None) or getattr(response, "request_id", None)
        status = str(getattr(response, "status", "completed") or "completed")
        if status == "incomplete":
            details = getattr(response, "incomplete_details", None)
            reason = getattr(details, "reason", None) or "unknown reason"
            raise AIResponseError(f"OpenAI report response was incomplete ({reason}, request_id={request_id or 'unknown'})")
        if status != "completed":
            raise AIResponseError(f"OpenAI report response status was {status!r} (request_id={request_id or 'unknown'})")
        refusal = _find_refusal(response)
        if refusal:
            raise AIResponseError(f"OpenAI refused report generation (request_id={request_id or 'unknown'}): {refusal}")
        output_text = getattr(response, "output_text", None)
        if not output_text:
            raise AIResponseError(f"OpenAI returned no report output text (request_id={request_id or 'unknown'})")
        try:
            return report_draft.model_validate(json.loads(output_text))
        except Exception as exc:
            raise AIResponseError(f"OpenAI report output failed ReportDraft validation (request_id={request_id or 'unknown'}): {exc}") from exc


def create_ai_client(
    *,
    provider: str,
    api_key: str,
    model: str,
    base_url: str | None = None,
    timeout: float = 90.0,
    max_retries: int = 2,
    max_output_tokens: int = 8_000,
) -> AIClient:
    """Build the configured provider without exposing provider details upstream."""

    normalized = provider.strip().lower()
    if normalized != "openai":
        raise ConfigurationError(f"Unsupported AI provider: {provider!r}")
    return OpenAIResponsesClient(
        api_key=api_key,
        model=model,
        base_url=base_url,
        timeout=timeout,
        max_retries=max_retries,
        max_output_tokens=max_output_tokens,
    )


# Backwards-friendly name for callers that prefer the provider-first spelling.
OpenAIClient = OpenAIResponsesClient


__all__ = [
    "AIClient",
    "AIClientResult",
    "OpenAIClient",
    "OpenAIResponsesClient",
    "analysis_draft_json_schema",
    "create_ai_client",
]
