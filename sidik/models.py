"""Data models and structures for SIDIK: Secret Identification and Dependency Inspection Kit."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional
import time


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceScore(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Represents an individual security finding (secret or dependency vulnerability)."""
    id: str
    finding_type: str  # "secret" or "dependency"
    category: str      # e.g., "API_KEY", "PRIVATE_KEY", "VULNERABLE_DEPENDENCY"
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: ConfidenceScore = ConfidenceScore.MEDIUM
    risk_score: int = 50  # 0-100 composite risk priority score
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, SeverityLevel) else self.severity
        d["confidence"] = self.confidence.value if isinstance(self.confidence, ConfidenceScore) else self.confidence
        return d


@dataclass
class ScanSummary:
    """Represents high-level metrics of an analyzer execution."""
    target_path: str
    total_files_scanned: int = 0
    total_secrets_found: int = 0
    total_vulnerabilities_found: int = 0
    scan_duration_seconds: float = 0.0
    peak_memory_mb: float = 0.0
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report encompassing summary and granular findings."""
    summary: ScanSummary
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings]
        }
