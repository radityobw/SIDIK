"""Unit tests for Internationalization (i18n) in SIDIK."""

import unittest
from sidik.i18n import (
    t,
    set_language,
    get_current_language,
    TRANSLATIONS,
    SUPPORTED_LANGUAGES,
    get_secret_remediation,
    get_dependency_remediation,
)
from sidik.models import Finding, ScanSummary, ScanReport, SeverityLevel, ConfidenceScore
from sidik.reporting.formatter import ReportFormatter
from sidik.secret_detector.patterns import SECRET_PATTERNS


class TestI18n(unittest.TestCase):
    def setUp(self):
        # Reset language to default "id" before each test
        set_language("id")

    def tearDown(self):
        set_language("id")

    def test_translations_dictionary_integrity(self):
        """Ensure all translation keys have valid, non-empty 'id' and 'en' translations."""
        self.assertGreater(len(TRANSLATIONS), 30)
        for key, lang_map in TRANSLATIONS.items():
            for lang in SUPPORTED_LANGUAGES:
                self.assertIn(lang, lang_map, f"Missing '{lang}' translation for key '{key}'")
                self.assertIsInstance(lang_map[lang], str, f"Translation for '{key}' in '{lang}' must be str")
                self.assertGreater(len(lang_map[lang].strip()), 0, f"Translation for '{key}' in '{lang}' cannot be empty")

    def test_language_getter_setter(self):
        """Test getting and setting active language."""
        self.assertEqual(get_current_language(), "id")
        set_language("en")
        self.assertEqual(get_current_language(), "en")
        # Unsupported language should be ignored
        set_language("fr")
        self.assertEqual(get_current_language(), "en")
        set_language("id")
        self.assertEqual(get_current_language(), "id")

    def test_translation_helper(self):
        """Test t() helper function with default and explicit language."""
        set_language("id")
        self.assertEqual(t("btn_browse_folder"), "Pilih Folder")
        self.assertEqual(t("btn_browse_folder", lang="en"), "Browse Folder")

        set_language("en")
        self.assertEqual(t("btn_browse_folder"), "Browse Folder")
        self.assertEqual(t("btn_browse_folder", lang="id"), "Pilih Folder")

        # Fallback to key itself if not found
        self.assertEqual(t("non_existent_key_xyz"), "non_existent_key_xyz")

    def test_secret_remediations_all_rules(self):
        """Verify all 12 secret rules have remediation text in both 'id' and 'en'."""
        for pattern in SECRET_PATTERNS:
            rule_id = pattern["id"]
            rem_id = get_secret_remediation(rule_id, lang="id")
            rem_en = get_secret_remediation(rule_id, lang="en")
            self.assertIsInstance(rem_id, str)
            self.assertIsInstance(rem_en, str)
            self.assertGreater(len(rem_id), 10, f"Remediation id for {rule_id} is too short")
            self.assertGreater(len(rem_en), 10, f"Remediation en for {rule_id} is too short")

    def test_dependency_remediation_generation(self):
        """Test generation of dependency remediation recommendations in 'id' and 'en'."""
        rem_id = get_dependency_remediation(
            package_name="requests",
            cve_id="CVE-2018-18074",
            fixed_version="2.20.0",
            manifest_file="requirements.txt",
            lang="id",
        )
        self.assertIn("Perbarui dependensi 'requests'", rem_id)
        self.assertIn("pip install --upgrade requests>=2.20.0", rem_id)
        self.assertIn("CVE-2018-18074", rem_id)

        rem_en = get_dependency_remediation(
            package_name="requests",
            cve_id="CVE-2018-18074",
            fixed_version="2.20.0",
            manifest_file="requirements.txt",
            lang="en",
        )
        self.assertIn("Upgrade dependency 'requests'", rem_en)
        self.assertIn("pip install --upgrade requests>=2.20.0", rem_en)
        self.assertIn("CVE-2018-18074", rem_en)

    def test_report_formatter_bilingual_markdown(self):
        """Test Markdown report generation in both Indonesian and English."""
        report = ScanReport(
            summary=ScanSummary(
                target_path="test_project",
                total_files_scanned=1,
                total_secrets_found=1,
                total_vulnerabilities_found=0,
                scan_duration_seconds=0.012,
                peak_memory_mb=0.15,
            ),
            findings=[
                Finding(
                    id="SEC-001",
                    finding_type="secret",
                    category="Cloud Credential",
                    title="AWS Access Key",
                    description="AWS Access Key ID terdeteksi",
                    file_path="config.py",
                    line_number=10,
                    snippet="AKIAIOSFODNN7EXAMPLE",
                    severity=SeverityLevel.CRITICAL,
                    confidence=ConfidenceScore.HIGH,
                    remediation="Cabut kunci AWS segera dari AWS IAM Console.",
                )
            ],
        )

        md_id = ReportFormatter.to_markdown(report, lang="id")
        self.assertIn("## Ringkasan Eksekutif", md_id)
        self.assertIn("## Temuan Keamanan", md_id)
        self.assertIn("Rekomendasi Perbaikan:", md_id)
        self.assertIn("Cabut kunci AWS segera", md_id)

        md_en = ReportFormatter.to_markdown(report, lang="en")
        self.assertIn("## Summary", md_en)
        self.assertIn("## Findings", md_en)
        self.assertIn("Remediation:", md_en)

    def test_report_formatter_bilingual_console_summary(self):
        """Test Console summary in both Indonesian and English."""
        report = ScanReport(
            summary=ScanSummary(
                target_path="test_project",
                total_files_scanned=5,
                total_secrets_found=0,
                total_vulnerabilities_found=0,
                scan_duration_seconds=0.005,
                peak_memory_mb=0.1,
            ),
            findings=[],
        )

        console_id = ReportFormatter.to_console_summary(report, lang="id")
        self.assertIn("SIDIK: Secret Identification and Dependency Inspection Kit", console_id)
        self.assertIn("Berkas Dipindai", console_id)
        self.assertIn("Bersih! Tidak ditemukan masalah keamanan", console_id)

        console_en = ReportFormatter.to_console_summary(report, lang="en")
        self.assertIn("SIDIK: Secret Identification and Dependency Inspection Kit", console_en)
        self.assertIn("Files Scanned", console_en)
        self.assertIn("Clean! No security issues detected", console_en)


if __name__ == "__main__":
    unittest.main()
