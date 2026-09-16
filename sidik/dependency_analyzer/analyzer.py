"""Dependency security analyzer orchestrator."""

import os
from typing import List, Optional
from sidik.models import Finding, SeverityLevel, ConfidenceScore
from sidik.dependency_analyzer.parsers import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_poetry_lock,
    parse_setup_py,
    DependencySpec
)
from sidik.dependency_analyzer.database import VulnerabilityDatabase
from sidik.dependency_analyzer.matcher import is_version_vulnerable
from sidik.i18n import get_dependency_remediation


MANIFEST_FILENAMES = {
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "Pipfile": parse_pipfile,
    "poetry.lock": parse_poetry_lock,
    "setup.py": parse_setup_py
}


class DependencyAnalyzer:
    """Scans dependency manifests for vulnerable packages against advisory database."""

    def __init__(self, db: Optional[VulnerabilityDatabase] = None):
        self.db = db or VulnerabilityDatabase()

    def scan_manifest_file(self, file_path: str) -> List[Finding]:
        """Scans a single dependency manifest file for known vulnerabilities."""
        if not os.path.isfile(file_path):
            return []

        filename = os.path.basename(file_path)
        parser = None
        for supported_name, p_func in MANIFEST_FILENAMES.items():
            if filename.lower() == supported_name.lower() or filename.lower().endswith(supported_name.lower()):
                parser = p_func
                break

        if not parser:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        specs: List[DependencySpec] = parser(content)
        findings: List[Finding] = []

        for spec in specs:
            advisories = self.db.get_advisories(spec.package_name)
            for adv in advisories:
                vuln, reason = is_version_vulnerable(spec.specifier, adv["vulnerable_specifier"])
                if vuln:
                    finding_id = f"DEP-{adv['cve']}-{abs(hash(file_path + spec.package_name + spec.specifier)) % 100000:05d}"
                    manifest_name = os.path.basename(file_path)
                    fixed_ver = adv.get("fixed_version")
                    remediation = get_dependency_remediation(
                        package_name=spec.package_name,
                        cve_id=adv["cve"],
                        fixed_version=fixed_ver,
                        manifest_file=manifest_name
                    )

                    findings.append(Finding(
                        id=finding_id,
                        finding_type="dependency",
                        category="VULNERABLE_DEPENDENCY",
                        title=f"Vulnerable Dependency: {spec.package_name} ({adv['cve']})",
                        description=adv["summary"],
                        file_path=file_path,
                        line_number=spec.line_number if spec.line_number > 0 else None,
                        snippet=spec.raw_line.strip(),
                        severity=SeverityLevel(adv.get("severity", "HIGH")),
                        confidence=ConfidenceScore.HIGH,
                        remediation=remediation,
                        metadata={
                            "package": spec.package_name,
                            "declared_version": spec.specifier,
                            "cve": adv["cve"],
                            "advisory_id": adv["id"],
                            "vulnerable_specifier": adv["vulnerable_specifier"],
                            "fixed_version": adv.get("fixed_version"),
                            "details": adv.get("details", ""),
                            "matching_reason": reason
                        }
                    ))

        return findings

    def scan_directory(self, dir_path: str) -> List[Finding]:
        """Finds and scans all dependency manifests within a directory tree."""
        findings: List[Finding] = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.lower() in MANIFEST_FILENAMES or file.lower().endswith("requirements.txt"):
                    full_path = os.path.join(root, file)
                    findings.extend(self.scan_manifest_file(full_path))
        return findings
