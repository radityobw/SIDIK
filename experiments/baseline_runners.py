"""Baseline scanners for comparative experimental evaluation (RQ3)."""

import os
import sys
import re
import json
import subprocess
from typing import List, Dict, Any
from sidik.secret_detector.patterns import SECRET_PATTERNS


class BaselineRegexSecretScanner:
    """Standard Regex-only Secret Scanner (Baseline A).
    
    Represents conventional secret detection relying exclusively on regular
    expression matching without entropy validation or context-aware filtering.
    """

    def __init__(self):
        self.patterns = SECRET_PATTERNS

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.isfile(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for line_num, line in enumerate(lines, start=1):
            for rule in self.patterns:
                matches = rule["pattern"].finditer(line)
                for match in matches:
                    candidate = match.group(1) if match.groups() else match.group(0)
                    if candidate:
                        findings.append({
                            "rule_id": rule["id"],
                            "category": rule["category"],
                            "candidate": candidate,
                            "line": line_num
                        })
        return findings


class PipAuditBaselineScanner:
    """Pip-Audit CLI Scanner (Baseline B for Python SCA) with caching for speed."""

    _cache: Dict[str, List[Dict[str, Any]]] = {}

    @classmethod
    def scan_requirements_file(cls, file_path: str) -> List[Dict[str, Any]]:
        """Executes pip-audit via subprocess on requirements.txt file with result caching."""
        if file_path in cls._cache:
            return cls._cache[file_path]

        findings = []
        if not os.path.isfile(file_path):
            return findings

        cmd = [sys.executable, "-m", "pip_audit", "-r", file_path, "--format", "json"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            if res.stdout:
                data = json.loads(res.stdout)
                for dep in data.get("dependencies", []):
                    vulns = dep.get("vulns", [])
                    for v in vulns:
                        findings.append({
                            "package": dep.get("name"),
                            "version": dep.get("version"),
                            "cve": v.get("id"),
                            "description": v.get("description")
                        })
        except Exception:
            pass

        cls._cache[file_path] = findings
        return findings
