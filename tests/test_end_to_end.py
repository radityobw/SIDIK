"""Integration tests for end-to-end scanner execution and reporting."""

import unittest
import tempfile
import os
import json
from sidik.core import SecurityScanner, SidikScanner
from sidik.reporting.formatter import ReportFormatter


class TestEndToEndScan(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()

        # Create dummy vulnerable app files
        self.code_file = os.path.join(self.test_dir.name, "app.py")
        with open(self.code_file, "w", encoding="utf-8") as f:
            f.write("""
import os
# Sample app code
AWS_KEY = "AKIA9876543210FEDCBA"
USER_PASS = "SuperSecurePassword123!"

def connect():
    pass
""")

        self.req_file = os.path.join(self.test_dir.name, "requirements.txt")
        with open(self.req_file, "w", encoding="utf-8") as f:
            f.write("""
requests==2.25.0
urllib3==1.26.5
""")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_full_pipeline_scan(self):
        scanner = SidikScanner(enable_secret_scan=True, enable_dependency_scan=True)
        report = scanner.scan_path(self.test_dir.name)

        self.assertGreaterEqual(report.summary.total_files_scanned, 2)
        self.assertGreaterEqual(report.summary.total_secrets_found, 1)
        self.assertGreaterEqual(report.summary.total_vulnerabilities_found, 1)

        # Check remediation is populated in findings
        for f in report.findings:
            self.assertIsNotNone(f.remediation, f"Finding {f.id} should have remediation guidance")

        # Check JSON formatting
        json_output = ReportFormatter.to_json(report)
        data = json.loads(json_output)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertIn("remediation", data["findings"][0])

        # Check Markdown formatting with SIDIK header and remediation
        md_output = ReportFormatter.to_markdown(report)
        self.assertIn("SIDIK: Secret Identification and Dependency Inspection Kit", md_output)
        self.assertIn("Remediation:", md_output)

        # Check CSV formatting
        csv_output = ReportFormatter.to_csv(report)
        self.assertIn("Finding_ID,Type,Category,Severity", csv_output)
        self.assertIn("Remediation", csv_output)


if __name__ == "__main__":
    unittest.main()
