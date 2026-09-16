"""SIDIK: Secret Identification and Dependency Inspection Kit.

A lightweight static security analyzer for Python detecting hardcoded secrets
and vulnerable dependencies with context-aware analysis and zero data leakage benchmarking.
"""

from sidik.core import SecurityScanner, SidikScanner
from sidik.models import Finding, ScanReport, SeverityLevel, ConfidenceScore
from sidik.i18n import t, set_language, get_current_language

__version__ = "1.0.0"
__tool_name__ = "SIDIK"
__full_name__ = "Secret Identification and Dependency Inspection Kit"

__all__ = [
    "SecurityScanner",
    "SidikScanner",
    "Finding",
    "ScanReport",
    "SeverityLevel",
    "ConfidenceScore",
    "t",
    "set_language",
    "get_current_language",
    "__version__",
    "__tool_name__",
    "__full_name__"
]
