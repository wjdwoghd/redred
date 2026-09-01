"""Public Pydantic contracts for captures and structured analysis."""

from .analysis import (
    AnalysisDraft,
    AnalysisMetadata,
    AnalysisResult,
    AnalysisSummary,
    Evidence,
    Finding,
    FindingLocation,
    FindingStatus,
    Severity,
    Target,
    VulnerabilityType,
)
from .http import (
    FileMetadata,
    HTTPRequest,
    HTTPResponse,
)

# HTTPExchange and ScanInput live in scan_input to keep the capture boundary
# separate from individual request/response models.
from .http import MultipartPart, ParameterCandidate, ParameterLocation
from .scan_input import HTTPExchange, ScanInput, generate_scan_id

__all__ = [
    "AnalysisDraft", "AnalysisMetadata", "AnalysisResult", "AnalysisSummary",
    "Evidence", "Finding", "FindingLocation", "FindingStatus", "Severity",
    "Target", "VulnerabilityType", "FileMetadata", "HTTPRequest", "HTTPResponse",
    "HTTPExchange", "MultipartPart", "ParameterCandidate", "ParameterLocation",
    "ScanInput", "generate_scan_id",
]
