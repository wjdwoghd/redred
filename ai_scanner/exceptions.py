"""REDRED scanner exception hierarchy.

Operational errors intentionally use a separate hierarchy from vulnerability
findings so callers never mistake a pipeline failure for a security result.
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for expected scanner pipeline failures."""


class ConfigurationError(ScannerError):
    """Raised when scanner configuration is invalid or incomplete."""


class InputError(ScannerError):
    """Base class for input loading and validation failures."""


class InputFileError(InputError):
    """Raised when an input JSON file cannot be read safely."""


class InputValidationError(InputError):
    """Raised when input JSON does not match the ScanInput schema."""


class RequestParseError(InputError):
    """Raised when request-specific content cannot be parsed."""


class AIClientError(ScannerError):
    """Raised when communication with an AI provider fails."""


class AIResponseError(AIClientError):
    """Raised when an AI response cannot be decoded or validated."""


class AnalysisValidationError(ScannerError):
    """Raised when a structured analysis is inconsistent or invalid."""


class StorageError(ScannerError):
    """Raised when a scanner artifact cannot be persisted."""


class ReportGenerationError(ScannerError):
    """Raised when a report cannot be rendered from valid analysis data."""
