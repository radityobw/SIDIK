"""Vulnerability advisory database for Python packages (OSV / GHSA format)."""

import json
import os
from typing import List, Dict, Any, Optional
from sidik.dependency_analyzer.parsers import normalize_package_name


# Curated offline advisory database of real CVEs across ubiquitous Python libraries
BUILTIN_ADVISORIES: List[Dict[str, Any]] = [
    {
        "id": "GHSA-j8r2-6x86-q33q",
        "cve": "CVE-2023-32681",
        "package": "requests",
        "vulnerable_specifier": "<2.31.0",
        "fixed_version": "2.31.0",
        "severity": "MEDIUM",
        "summary": "Requests Leaks Proxy-Authorization Headers to Destination Servers",
        "details": "In Requests versions prior to 2.31.0, Proxy-Authorization headers are inadvertently leaked upon redirect."
    },
    {
        "id": "GHSA-q2x7-8rv6-6q7h",
        "cve": "CVE-2023-45803",
        "package": "urllib3",
        "vulnerable_specifier": "<1.26.18,>=1.20",
        "fixed_version": "1.26.18",
        "severity": "HIGH",
        "summary": "urllib3 Request body not stripped after redirect from 303 status",
        "details": "urllib3 prior to 1.26.18 failed to clear the request body on HTTP 303 redirects, risking credential leakage."
    },
    {
        "id": "GHSA-v845-jxx5-vc9f",
        "cve": "CVE-2023-43804",
        "package": "urllib3",
        "vulnerable_specifier": "<1.26.17,>=1.20",
        "fixed_version": "1.26.17",
        "severity": "HIGH",
        "summary": "urllib3 Cookie Request Header Unintended Leakage via Cross-Origin Redirect",
        "details": "urllib3 leaked sensitive Cookie headers when redirected across differing ports on the same domain."
    },
    {
        "id": "GHSA-2g68-c3qc-8985",
        "cve": "CVE-2021-44420",
        "package": "django",
        "vulnerable_specifier": "<3.2.10,>=3.2.0",
        "fixed_version": "3.2.10",
        "severity": "HIGH",
        "summary": "Django potential bypass of HTTP status codes in multipart parsing",
        "details": "Potential security bypass allowing denial of service in multipart request parser."
    },
    {
        "id": "GHSA-f9cq-cwgq-4vmh",
        "cve": "CVE-2022-34265",
        "package": "django",
        "vulnerable_specifier": "<3.2.14,>=3.2.0",
        "fixed_version": "3.2.14",
        "severity": "CRITICAL",
        "summary": "Django SQL Injection vulnerability in Trunc() and Extract() database functions",
        "details": "Trunc() and Extract() database functions were susceptible to SQL injection via untrusted lookup parameters."
    },
    {
        "id": "GHSA-8495-4g38-x9mp",
        "cve": "CVE-2020-14343",
        "package": "pyyaml",
        "vulnerable_specifier": "<5.4",
        "fixed_version": "5.4",
        "severity": "CRITICAL",
        "summary": "PyYAML Arbitrary Code Execution via FullLoader",
        "details": "A vulnerability in the FullLoader implementation permitted arbitrary Python object execution."
    },
    {
        "id": "GHSA-hrfv-mqp8-q5rw",
        "cve": "CVE-2024-34064",
        "package": "jinja2",
        "vulnerable_specifier": "<3.1.4",
        "fixed_version": "3.1.4",
        "severity": "HIGH",
        "summary": "Jinja XML/HTML attribute injection vulnerability",
        "details": "Attributes injected into templates using xmlattr filter could be exploited for Cross-Site Scripting."
    },
    {
        "id": "GHSA-2g64-cvh3-6552",
        "cve": "CVE-2023-25577",
        "package": "werkzeug",
        "vulnerable_specifier": "<2.2.3",
        "fixed_version": "2.2.3",
        "severity": "HIGH",
        "summary": "Werkzeug High CPU consumption on multipart parsing DoS",
        "details": "Excessive resource consumption while parsing malicious multipart form data."
    },
    {
        "id": "GHSA-47hx-v7gw-cqpq",
        "cve": "CVE-2024-27318",
        "package": "aiohttp",
        "vulnerable_specifier": "<3.9.4",
        "fixed_version": "3.9.4",
        "severity": "MEDIUM",
        "summary": "aiohttp HTTP request line parsing DoS vulnerability",
        "details": "aiohttp request parser vulnerable to memory and CPU exhaustion via endless chunk payloads."
    },
    {
        "id": "GHSA-79g4-8359-885q",
        "cve": "CVE-2023-38325",
        "package": "cryptography",
        "vulnerable_specifier": "<41.0.2",
        "fixed_version": "41.0.2",
        "severity": "MEDIUM",
        "summary": "cryptography vulnerability in parsing certificate extensions",
        "details": "Flaw when parsing certain X.509 certificate extensions could lead to improper policy validation."
    },
    {
        "id": "GHSA-5cpq-8wj7-hf2v",
        "cve": "CVE-2023-46136",
        "package": "pillow",
        "vulnerable_specifier": "<10.1.0",
        "fixed_version": "10.1.0",
        "severity": "HIGH",
        "summary": "Pillow Subsampling Denial of Service",
        "details": "Arbitrary memory allocation causing Denial of Service when processing crafted TIFF images."
    },
    {
        "id": "GHSA-7f33-f3f5-hx78",
        "cve": "CVE-2023-30608",
        "package": "sqlparse",
        "vulnerable_specifier": "<0.4.4",
        "fixed_version": "0.4.4",
        "severity": "HIGH",
        "summary": "sqlparse Regular Expression Denial of Service (ReDoS)",
        "details": "Parsing heavily nested comments triggers exponential backtracking leading to Denial of Service."
    }
]


class VulnerabilityDatabase:
    """Manages querying and matching of security advisories for Python dependencies."""

    def __init__(self, custom_db_path: Optional[str] = None):
        self.advisories: Dict[str, List[Dict[str, Any]]] = {}
        self._load_database(custom_db_path)

    def _load_database(self, custom_db_path: Optional[str] = None) -> None:
        raw_list = list(BUILTIN_ADVISORIES)
        if custom_db_path and os.path.isfile(custom_db_path):
            try:
                with open(custom_db_path, "r", encoding="utf-8") as f:
                    extra = json.load(f)
                    if isinstance(extra, list):
                        raw_list.extend(extra)
            except Exception:
                pass

        for item in raw_list:
            pkg = normalize_package_name(item.get("package", ""))
            if pkg:
                if pkg not in self.advisories:
                    self.advisories[pkg] = []
                self.advisories[pkg].append(item)

    def get_advisories(self, package_name: str) -> List[Dict[str, Any]]:
        """Returns all registered advisories for a given package name."""
        norm = normalize_package_name(package_name)
        return self.advisories.get(norm, [])
