"""Unit tests for secret detector engine, entropy calculations, and context filtering."""

import unittest
from sidik.secret_detector.detector import SecretDetector
from sidik.secret_detector.entropy import calculate_shannon_entropy


class TestSecretDetector(unittest.TestCase):

    def setUp(self):
        self.detector = SecretDetector(enable_context=True, enable_entropy=True)

    def test_shannon_entropy_calculation(self):
        low_ent = calculate_shannon_entropy("aaaaaaaa")
        high_ent = calculate_shannon_entropy("8fA3k9Z!qP0xLw2@")
        self.assertLess(low_ent, 1.0)
        self.assertGreater(high_ent, 3.5)

    def test_detect_aws_access_key(self):
        # AWS documentation official sample should be suppressed as placeholder
        code_doc = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
        findings_doc = self.detector.scan_content(code_doc)
        self.assertEqual(len(findings_doc), 0)

        # Real-like AWS Key with sufficient entropy
        code_real = "aws_key = 'AKIAJ2M4K8P9Q3R7W5T1'"
        findings = self.detector.scan_content(code_real)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "API_KEY")
        self.assertEqual(findings[0].metadata["rule_id"], "SEC001")

    def test_detect_openai_key(self):
        code = "client_secret = 'sk-proj-uW8vB2xY9zQpLmK3jH5gD7sA1rT0oPqVwXyZ'"
        findings = self.detector.scan_content(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "API_KEY")

    def test_detect_database_uri(self):
        code = "DB_URL = 'postgres://appuser:V3ryStr0ngPassword99!@db.internal:5432/appdb'"
        findings = self.detector.scan_content(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "DB_CREDENTIAL")

    def test_filter_benign_placeholders(self):
        dummy_code = """
        API_KEY = 'your_api_key_here'
        mock_secret = 'dummy_secret_value'
        uuid_val = '123e4567-e89b-12d3-a456-426614174000'
        password = 'password'
        """
        findings = self.detector.scan_content(dummy_code)
        self.assertEqual(len(findings), 0)

    def test_ablation_mode(self):
        # With context disabled, dummy key should trigger regex
        code = "api_key = 'sk-dummysecret1234567890abcdef1234'"
        detector_no_context = SecretDetector(enable_context=False, enable_entropy=False)
        findings = detector_no_context.scan_content(code)
        self.assertGreaterEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
