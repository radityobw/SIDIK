"""Core unified security scanner orchestrating secret detection and dependency analysis."""

import os
import time
import tracemalloc
from typing import List, Optional
from sidik.models import ScanReport
from sidik.secret_detector.detector import SecretDetector
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer, MANIFEST_FILENAMES
from sidik.reporting.aggregator import FindingAggregator


class SecurityScanner:
    """SIDIK (Secret Identification and Dependency Inspection Kit) core security analyzer."""

    def __init__(
        self,
        enable_secret_scan: bool = True,
        enable_dependency_scan: bool = True,
        enable_context: bool = True,
        enable_entropy: bool = True,
        custom_vulnerability_db: Optional[str] = None
    ):
        self.enable_secret_scan = enable_secret_scan
        self.enable_dependency_scan = enable_dependency_scan
        self.secret_detector = SecretDetector(enable_context=enable_context, enable_entropy=enable_entropy)
        self.dependency_analyzer = DependencyAnalyzer()

    def scan_path(self, target_path: str) -> ScanReport:
        """Executes unified security scan against a file or directory path."""
        target_path = os.path.abspath(target_path)
        aggregator = FindingAggregator(target_path=target_path)

        tracemalloc.start()
        start_time = time.perf_counter()
        files_scanned = 0

        if os.path.isfile(target_path):
            files_scanned = 1
            filename = os.path.basename(target_path).lower()
            if self.enable_secret_scan and target_path.endswith((".py", ".env", ".cfg", ".ini", ".json", ".yaml", ".yml")):
                aggregator.add_findings(self.secret_detector.scan_file(target_path))
            if self.enable_dependency_scan and any(filename == m or filename.endswith("requirements.txt") for m in MANIFEST_FILENAMES):
                aggregator.add_findings(self.dependency_analyzer.scan_manifest_file(target_path))
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for f in files:
                    full_path = os.path.join(root, f)
                    f_lower = f.lower()
                    scanned_this_file = False

                    # Secret scanning for code/config files
                    if self.enable_secret_scan and f_lower.endswith((".py", ".env", ".cfg", ".ini", ".json", ".yaml", ".yml", ".txt")):
                        findings = self.secret_detector.scan_file(full_path)
                        aggregator.add_findings(findings)
                        scanned_this_file = True

                    # Dependency scanning for manifests
                    if self.enable_dependency_scan and any(f_lower == m or f_lower.endswith("requirements.txt") for m in MANIFEST_FILENAMES):
                        dep_findings = self.dependency_analyzer.scan_manifest_file(full_path)
                        aggregator.add_findings(dep_findings)
                        scanned_this_file = True

                    if scanned_this_file:
                        files_scanned += 1

        duration = time.perf_counter() - start_time
        _, peak_mem_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        aggregator.set_files_scanned_count(files_scanned)
        peak_mb = peak_mem_bytes / (1024 * 1024)
        return aggregator.build_report(duration_seconds=duration, peak_memory_mb=peak_mb)


# Alias for branded usage
SidikScanner = SecurityScanner
