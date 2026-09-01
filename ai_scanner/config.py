"""Environment-backed configuration for the independent AI scanner package."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

try:  # python-dotenv is an optional import until dependencies are installed.
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - exercised only in minimal environments.
    load_dotenv = None  # type: ignore[assignment]

try:
    from .exceptions import ConfigurationError
except ImportError:  # Support ``python main.py`` from inside ai_scanner.
    from exceptions import ConfigurationError


class ScannerConfig(BaseModel):
    """Validated runtime settings loaded from ``ai_scanner/.env``."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    ai_api_key: SecretStr | None = None
    ai_model: str = Field(default="gpt-5-mini", min_length=1, max_length=256)
    ai_provider: str = Field(default="openai", min_length=1, max_length=64)
    mode: Literal["auto", "ai", "rules"] = "auto"
    ai_base_url: str | None = Field(default=None, max_length=2_048)
    ai_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    ai_max_retries: int = Field(default=2, ge=0, le=10)
    ai_max_output_tokens: int = Field(default=8_000, ge=256, le=64_000)
    ai_parse_retries: int = Field(default=1, ge=0, le=3)
    offline_mode: bool = False
    mask_sensitive_values: bool = True
    max_input_file_bytes: int = Field(default=5_000_000, ge=1_024, le=100_000_000)
    max_request_body_chars: int = Field(default=30_000, ge=1_000, le=1_000_000)
    max_response_body_chars: int = Field(default=60_000, ge=1_000, le=2_000_000)
    max_file_preview_chars: int = Field(default=2_048, ge=128, le=4_096)
    max_comparison_body_chars: int = Field(default=50_000, ge=1_000, le=500_000)
    max_parameter_value_chars: int = Field(default=2_048, ge=128, le=100_000)
    project_dir: Path
    results_dir: Path
    vulnerability_prompt_path: Path
    report_prompt_path: Path

    @property
    def api_key(self) -> SecretStr | None:
        """Compatibility alias used by provider-specific client adapters."""

        return self.ai_api_key

    @property
    def model(self) -> str:
        """Compatibility alias for the configured AI model name."""

        return self.ai_model

    @property
    def effective_mode(self) -> Literal["auto", "ai", "rules"]:
        """Resolve legacy ``OFFLINE_MODE`` into the explicit analysis mode."""

        return "rules" if self.offline_mode else self.mode

    @classmethod
    def from_env(cls, project_dir: str | Path | None = None) -> "ScannerConfig":
        """Load ``.env`` without overriding already-exported environment values."""

        base = Path(project_dir).resolve() if project_dir else Path(__file__).resolve().parent
        dotenv_path = base / ".env"
        if load_dotenv is not None:
            load_dotenv(dotenv_path=dotenv_path, override=False)

        def env_bool(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            if raw is None or not raw.strip():
                return default
            normalized = raw.strip().casefold()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
            raise ConfigurationError(f"{name} must be a boolean value")

        def env_int(name: str, default: int) -> int:
            raw = os.getenv(name)
            if raw is None or not raw.strip():
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise ConfigurationError(f"{name} must be an integer") from exc

        def env_float(name: str, default: float) -> float:
            raw = os.getenv(name)
            if raw is None or not raw.strip():
                return default
            try:
                return float(raw)
            except ValueError as exc:
                raise ConfigurationError(f"{name} must be numeric") from exc

        raw_key = os.getenv("AI_API_KEY", "").strip()
        raw_base_url = os.getenv("AI_BASE_URL", "").strip()
        try:
            raw_mode = os.getenv("AI_MODE", "auto").strip().casefold() or "auto"
            if raw_mode not in {"auto", "ai", "rules"}:
                raise ConfigurationError("AI_MODE must be one of auto, ai or rules")
            offline = env_bool("OFFLINE_MODE", False)
            return cls(
                ai_api_key=SecretStr(raw_key) if raw_key else None,
                ai_model=os.getenv("AI_MODEL", "gpt-5-mini").strip() or "gpt-5-mini",
                ai_provider=os.getenv("AI_PROVIDER", "openai").strip() or "openai",
                mode=raw_mode,
                ai_base_url=raw_base_url or None,
                ai_timeout_seconds=env_float("AI_TIMEOUT_SECONDS", 60.0),
                ai_max_retries=env_int("AI_MAX_RETRIES", 2),
                ai_max_output_tokens=env_int("AI_MAX_OUTPUT_TOKENS", 8_000),
                ai_parse_retries=env_int("AI_PARSE_RETRIES", 1),
                offline_mode=offline,
                mask_sensitive_values=env_bool("MASK_SENSITIVE_VALUES", True),
                max_input_file_bytes=env_int("MAX_INPUT_FILE_BYTES", 5_000_000),
                max_request_body_chars=env_int("MAX_REQUEST_BODY_CHARS", 30_000),
                max_response_body_chars=env_int("MAX_RESPONSE_BODY_CHARS", 60_000),
                max_file_preview_chars=env_int("MAX_FILE_PREVIEW_CHARS", 2_048),
                max_comparison_body_chars=env_int("MAX_COMPARISON_BODY_CHARS", 50_000),
                max_parameter_value_chars=env_int("MAX_PARAMETER_VALUE_CHARS", 2_048),
                project_dir=base,
                results_dir=base / "results",
                vulnerability_prompt_path=base / "prompts" / "vulnerability_analysis.txt",
                report_prompt_path=base / "prompts" / "report_generation.txt",
            )
        except ValidationError as exc:
            raise ConfigurationError(f"invalid scanner configuration: {exc}") from exc

    def require_api_key(self) -> str:
        """Return the API key or raise a clear configuration error."""

        if self.ai_api_key is None or not self.ai_api_key.get_secret_value():
            raise ConfigurationError(
                "AI_API_KEY is required unless the scanner is run in offline mode"
            )
        return self.ai_api_key.get_secret_value()


Settings = ScannerConfig
Config = ScannerConfig


@lru_cache(maxsize=1)
def get_settings() -> ScannerConfig:
    """Return the process-wide validated configuration instance."""

    return ScannerConfig.from_env()


get_config = get_settings
