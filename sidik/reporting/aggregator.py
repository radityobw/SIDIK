"""Aggregates and deduplicates findings, calculates metrics, and builds scan reports."""

from typing import List, Set
from sidik.models import Finding, ScanSummary, ScanReport


class FindingAggregator:
    """Consolidates findings from secret and dependency analyzers."""

    def __init__(self, target_path: str):
        self.target_path = target_path
        self.findings: List[Finding] = []
        self._seen_signatures: Set[str] = set()
        self.total_files_scanned = 0

    def add_findings(self, new_findings: List[Finding]) -> None:
        """Adds findings, dropping any duplicates based on file, line, and category."""
        for f in new_findings:
            sig = f"{f.finding_type}:{f.category}:{f.file_path}:{f.line_number}:{f.title}"
            if sig not in self._seen_signatures:
                self._seen_signatures.add(sig)
                self.findings.append(f)

    def set_files_scanned_count(self, count: int) -> None:
        self.total_files_scanned = count

    def build_report(self, duration_seconds: float, peak_memory_mb: float) -> ScanReport:
        """Constructs final structured ScanReport."""
        secrets_count = sum(1 for f in self.findings if f.finding_type == "secret")
        vulnerabilities_count = sum(1 for f in self.findings if f.finding_type == "dependency")

        summary = ScanSummary(
            target_path=self.target_path,
            total_files_scanned=self.total_files_scanned,
            total_secrets_found=secrets_count,
            total_vulnerabilities_found=vulnerabilities_count,
            scan_duration_seconds=round(duration_seconds, 4),
            peak_memory_mb=round(peak_memory_mb, 2)
        )

        return ScanReport(summary=summary, findings=self.findings)
