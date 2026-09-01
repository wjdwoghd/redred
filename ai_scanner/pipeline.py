"""End-to-end orchestration for capture parsing, analysis, and reporting."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .ai_client import create_ai_client
    from .comparator import compare_responses
    from .config import ScannerConfig
    from .exceptions import ConfigurationError
    from .indicator_detector import detect_indicators
    from .parameter_extractor import extract_parameters
    from .report_generator import generate_report
    from .request_parser import load_scan_input
    from .result_store import ArtifactPaths, ResultStore
    from .response_analyzer import analyze_response
    from .vulnerability_analyzer import VulnerabilityAnalyzer
except ImportError:  # direct script execution from ai_scanner/
    from ai_client import create_ai_client
    from comparator import compare_responses
    from config import ScannerConfig
    from exceptions import ConfigurationError
    from indicator_detector import detect_indicators
    from parameter_extractor import extract_parameters
    from report_generator import generate_report
    from request_parser import load_scan_input
    from result_store import ArtifactPaths, ResultStore
    from response_analyzer import analyze_response
    from vulnerability_analyzer import VulnerabilityAnalyzer


LOGGER = logging.getLogger(__name__)


class _MeasuredAIClient:
    """Forwarding client that records logical Responses API calls and time."""

    def __init__(self, client: Any) -> None:
        self.client = client
        self.calls = 0
        self.elapsed = 0.0

    def _call(self, method: str, **kwargs: Any) -> Any:
        started = time.perf_counter()
        self.calls += 1
        try:
            return getattr(self.client, method)(**kwargs)
        finally:
            self.elapsed += time.perf_counter() - started

    def analyze(self, **kwargs: Any) -> Any:
        return self._call("analyze", **kwargs)

    def generate_report(self, **kwargs: Any) -> Any:
        return self._call("generate_report", **kwargs)


@dataclass(frozen=True, slots=True)
class PipelineOutcome:
    """Validated analysis and the files produced for it."""

    scan_input: Any
    candidates: list[Any]
    response_features: dict[str, Any]
    comparison: dict[str, Any]
    indicators: dict[str, Any]
    analysis: Any
    artifacts: ArtifactPaths


def _read_prompt(config: ScannerConfig) -> str:
    try:
        return config.vulnerability_prompt_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        LOGGER.warning("vulnerability prompt unavailable; using a minimal prompt: %s", exc)
        return "Return only the requested structured vulnerability analysis JSON."


def _read_report_prompt(config: ScannerConfig) -> str:
    """Load the AI report prose prompt; deterministic rendering remains available."""

    try:
        return config.report_prompt_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        LOGGER.warning("report prompt unavailable; using deterministic report: %s", exc)
        return ""


def run_pipeline(
    input_path: str | Path | Any,
    *,
    config: ScannerConfig,
    mode: str | None = None,
    output_directory: str | Path | None = None,
) -> PipelineOutcome:
    """Run every pipeline stage for one local HTTP capture."""

    total_started = time.perf_counter()
    selected_mode = mode or config.effective_mode
    if selected_mode not in {"auto", "ai", "rules"}:
        raise ConfigurationError("mode must be auto, ai or rules")
    # Raw CLI input is parsed into ScanInput before entering the pipeline;
    # canonical JSON paths continue using the original loader unchanged.
    parse_started = time.perf_counter()
    scan_input = input_path if hasattr(input_path, "request") and hasattr(input_path, "response") else load_scan_input(input_path, max_file_bytes=config.max_input_file_bytes)
    candidates = extract_parameters(
        scan_input.request, max_value_chars=config.max_parameter_value_chars
    )
    LOGGER.info("[PARSE] %.3fs (%d parameters)", time.perf_counter() - parse_started, len(candidates))
    rules_started = time.perf_counter()
    response_features = analyze_response(
        scan_input.response,
        request=scan_input.request,
        input_values=candidates,
        max_body_chars=config.max_response_body_chars,
    )
    verification_count = 0
    verification_started = time.perf_counter()
    if scan_input.verification is not None:
        verification_count = 1
        response_features = {
            **response_features,
            "verification": analyze_response(
                scan_input.verification.response,
                request=scan_input.verification.request,
                input_values=candidates,
                max_body_chars=config.max_response_body_chars,
            ),
        }
    LOGGER.info("[VERIFICATION] requests=%d %.3fs", verification_count, time.perf_counter() - verification_started)
    if scan_input.baseline is not None:
        markers = [
            str(candidate.value)
            for candidate in candidates
            if isinstance(candidate.value, str) and 1 <= len(candidate.value) <= 256
        ]
        comparison = compare_responses(
            scan_input.baseline.response,
            scan_input.response,
            markers=markers,
            similarity_char_limit=config.max_comparison_body_chars,
        )
    else:
        comparison = {
            "available": False,
            "status_changed": False,
            "response_length_difference": None,
            "body_similarity": None,
            "redirect_changed": False,
            "record_count_difference": None,
            "new_error_indicators": [],
            "notes": ["baseline exchange was not supplied"],
        }
    indicators = detect_indicators(
        request=scan_input.request,
        candidates=candidates,
        response_features=response_features,
        comparison=comparison,
    )
    LOGGER.info("[RULES] %.3fs", time.perf_counter() - rules_started)

    ai_client = None
    if selected_mode in {"auto", "ai"}:
        if config.ai_api_key is not None and config.ai_api_key.get_secret_value():
            ai_client = _MeasuredAIClient(create_ai_client(
                provider=config.ai_provider,
                api_key=config.ai_api_key.get_secret_value(),
                model=config.ai_model,
                base_url=config.ai_base_url,
                timeout=config.ai_timeout_seconds,
                max_retries=config.ai_max_retries,
                max_output_tokens=config.ai_max_output_tokens,
            ))
        elif selected_mode == "ai":
            config.require_api_key()

    analyzer = VulnerabilityAnalyzer(
        mode=selected_mode,
        ai_client=ai_client,
        prompt=_read_prompt(config),
        max_ai_retries=config.ai_parse_retries,
        mask_sensitive_values=config.mask_sensitive_values,
        max_ai_chars=min(config.max_response_body_chars, 20_000),
    )
    analysis = analyzer.analyze(
        scan_input,
        candidates=candidates,
        response_features=response_features,
        comparison=comparison,
        indicators=indicators,
    )
    report_started = time.perf_counter()
    report = generate_report(
        analysis,
        scan_input=scan_input,
        ai_client=ai_client if selected_mode in {"auto", "ai"} and getattr(analysis.metadata, "used_ai", False) else None,
        ai_prompt=_read_report_prompt(config) if selected_mode in {"auto", "ai"} and getattr(analysis.metadata, "used_ai", False) else "",
    )
    LOGGER.info("[REPORT] %.3fs", time.perf_counter() - report_started)
    if isinstance(ai_client, _MeasuredAIClient):
        LOGGER.info("[AI] API calls=%d %.3fs", ai_client.calls, ai_client.elapsed)
    else:
        LOGGER.info("[AI] API calls=0 0.000s (not requested or unavailable)")
    store = ResultStore(output_directory or config.results_dir)
    artifacts = store.save_all(
        scan_id=analysis.scan_id,
        scan_input=scan_input,
        analysis=analysis,
        report_markdown=report,
    )
    LOGGER.info("[TOTAL] pipeline %.3fs", time.perf_counter() - total_started)
    return PipelineOutcome(
        scan_input=scan_input,
        candidates=candidates,
        response_features=response_features,
        comparison=comparison,
        indicators=indicators,
        analysis=analysis,
        artifacts=artifacts,
    )


__all__ = ["PipelineOutcome", "run_pipeline"]
