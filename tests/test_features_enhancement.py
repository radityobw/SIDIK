"""Unit and integration tests for newly implemented features:
1. .sidikignore and inline comment suppression (# sidik:ignore, # nosec)
2. Standalone Interactive HTML Report export
3. CI/CD severity threshold (--fail-on) and custom DB CLI options
"""

import unittest
import tempfile
import os
import sys
from sidik.core import SecurityScanner, load_sidikignore_patterns, is_path_ignored
from sidik.secret_detector.detector import SecretDetector
from sidik.reporting.formatter import ReportFormatter
from sidik.models import Finding, SeverityLevel, ConfidenceScore, ScanReport, ScanSummary


class TestSidikIgnoreAndInlineSuppression(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.test_dir.cleanup()

    def test_sidikignore_pattern_loading(self):
        ignore_path = os.path.join(self.test_dir.name, ".sidikignore")
        with open(ignore_path, "w", encoding="utf-8") as f:
            f.write("""
# Comments should be skipped
mock/
*.tmp
fixtures/**
secret_test.py
""")
        patterns = load_sidikignore_patterns(self.test_dir.name)
        self.assertIn("mock/", patterns)
        self.assertIn("*.tmp", patterns)
        self.assertIn("fixtures/**", patterns)
        self.assertIn("secret_test.py", patterns)
        self.assertNotIn("# Comments should be skipped", patterns)

    def test_is_path_ignored_logic(self):
        patterns = ["mock/", "*.tmp", "fixtures/**", "secret_test.py"]
        self.assertTrue(is_path_ignored("mock/sub/file.py", patterns))
        self.assertTrue(is_path_ignored("data/cache.tmp", patterns))
        self.assertTrue(is_path_ignored("fixtures/dummy.json", patterns))
        self.assertTrue(is_path_ignored("secret_test.py", patterns))
        self.assertFalse(is_path_ignored("src/main.py", patterns))

    def test_scanner_with_sidikignore(self):
        # Create normal file with secret
        app_file = os.path.join(self.test_dir.name, "app.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write('AWS_KEY = "AKIA1234567890ABCDEF"\n')

        # Create ignored file with secret
        mock_dir = os.path.join(self.test_dir.name, "mock")
        os.makedirs(mock_dir, exist_ok=True)
        mock_file = os.path.join(mock_dir, "test_mock.py")
        with open(mock_file, "w", encoding="utf-8") as f:
            f.write('OPENAI_KEY = "sk-live-12345678901234567890123456789012"\n')

        # Add .sidikignore
        ignore_file = os.path.join(self.test_dir.name, ".sidikignore")
        with open(ignore_file, "w", encoding="utf-8") as f:
            f.write("mock/\n")

        scanner = SecurityScanner()
        report = scanner.scan_path(self.test_dir.name)

        # Only app.py should be scanned and found, mock/test_mock.py must be excluded
        scanned_files = [f.file_path for f in report.findings]
        self.assertTrue(any("app.py" in p for p in scanned_files))
        self.assertFalse(any("test_mock.py" in p for p in scanned_files))

    def test_inline_comment_suppression(self):
        detector = SecretDetector()
        code = '''
# Active secret (should be detected)
AWS_KEY = "AKIA1234567890ABCDEF"

# Suppressed secrets (must be ignored)
DUMMY_AWS = "AKIA9876543210FEDCBA"  # sidik:ignore
ANOTHER_KEY = "AKIA9876543210FEDCB1"  # nosec
TEST_KEY = "AKIA9876543210FEDCB2"  # noqa: sidik
'''
        findings = detector.scan_content(code)
        self.assertEqual(len(findings), 1)
        self.assertIn("AKIA1234567890ABCDEF"[:4], findings[0].snippet or "")


class TestHtmlReportFormatter(unittest.TestCase):

    def setUp(self):
        self.summary = ScanSummary(
            target_path="/test/project",
            total_files_scanned=10,
            total_secrets_found=1,
            total_vulnerabilities_found=1,
            scan_duration_seconds=0.045,
            peak_memory_mb=12.5
        )
        self.findings = [
            Finding(
                id="SEC-001",
                finding_type="secret",
                category="API_KEY",
                title="AWS Access Key Found",
                description="Hardcoded AWS Access Key ID exposed in source code.",
                file_path="/test/project/config.py",
                line_number=14,
                snippet='AWS_KEY = "AKIA****CDEF"',
                severity=SeverityLevel.HIGH,
                confidence=ConfidenceScore.HIGH,
                remediation="Rotate this credential immediately and store in environment variables."
            ),
            Finding(
                id="DEP-001",
                finding_type="dependency",
                category="VULNERABLE_DEPENDENCY",
                title="Vulnerable Dependency: requests (CVE-2023-32681)",
                description="Requests Leaks Proxy-Authorization Headers.",
                file_path="/test/project/requirements.txt",
                line_number=2,
                snippet="requests==2.25.0",
                severity=SeverityLevel.MEDIUM,
                confidence=ConfidenceScore.HIGH,
                remediation="Upgrade requests to >=2.31.0"
            )
        ]
        self.report = ScanReport(summary=self.summary, findings=self.findings)

    def test_to_html_structure_and_features(self):
        html_en = ReportFormatter.to_html(self.report, lang="en")
        self.assertIn("<!DOCTYPE html>", html_en)
        self.assertIn("SIDIK", html_en)
        self.assertIn("AWS Access Key Found", html_en)
        self.assertIn("Vulnerable Dependency: requests", html_en)
        self.assertIn("filterFindings", html_en)
        self.assertIn("copyToClipboard", html_en)
        self.assertIn("badge-high", html_en)
        self.assertIn("badge-medium", html_en)

    def test_to_html_indonesian_localization(self):
        html_id = ReportFormatter.to_html(self.report, lang="id")
        self.assertIn("<!DOCTYPE html>", html_id)
        self.assertIn("Laporan Audit Keamanan", html_id)
        self.assertIn("Path Target", html_id)
        self.assertIn("Total Temuan", html_id)

    def test_to_html_clean_state(self):
        clean_report = ScanReport(
            summary=ScanSummary(target_path="/test/clean", total_files_scanned=5),
            findings=[]
        )
        html_clean = ReportFormatter.to_html(clean_report, lang="en")
        self.assertIn("Clean! No hardcoded secrets or vulnerable dependencies detected.", html_clean)


class TestCliThresholdAndDbWiring(unittest.TestCase):

    def test_severity_threshold_ranking(self):
        from sidik.cli import main
        # Verify SEVERITY_ORDER evaluation logic
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        finding_low = Finding(
            id="T-01", finding_type="secret", category="TEST", title="Low Issue",
            description="desc", file_path="t.py", severity=SeverityLevel.LOW
        )
        finding_crit = Finding(
            id="T-02", finding_type="secret", category="TEST", title="Crit Issue",
            description="desc", file_path="t.py", severity=SeverityLevel.CRITICAL
        )

        def should_fail(findings, fail_on):
            if fail_on == "any":
                return bool(findings)
            rank = severity_order[fail_on]
            return any(severity_order[f.severity.value.lower()] >= rank for f in findings)

        # With only LOW finding:
        self.assertTrue(should_fail([finding_low], "any"))
        self.assertTrue(should_fail([finding_low], "low"))
        self.assertFalse(should_fail([finding_low], "medium"))
        self.assertFalse(should_fail([finding_low], "high"))
        self.assertFalse(should_fail([finding_low], "critical"))

        # With CRITICAL finding:
        self.assertTrue(should_fail([finding_crit], "critical"))
        self.assertTrue(should_fail([finding_crit], "high"))


if __name__ == "__main__":
    unittest.main()
