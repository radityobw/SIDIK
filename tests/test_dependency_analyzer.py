"""Unit tests for dependency analyzer, manifest parsers, and vulnerability matching."""

import unittest
from sidik.dependency_analyzer.parsers import (
    parse_requirements_txt,
    parse_pyproject_toml,
    parse_pipfile,
    parse_poetry_lock
)
from sidik.dependency_analyzer.matcher import is_version_vulnerable
from sidik.dependency_analyzer.analyzer import DependencyAnalyzer


class TestDependencyAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = DependencyAnalyzer()

    def test_parse_requirements(self):
        content = """
        # Core requirements
        requests==2.25.1
        urllib3>=1.26.0,<1.26.18
        django==3.2.5
        flask # unpinned
        """
        specs = parse_requirements_txt(content)
        self.assertEqual(len(specs), 4)
        self.assertEqual(specs[0].package_name, "requests")
        self.assertEqual(specs[0].specifier, "==2.25.1")
        self.assertEqual(specs[3].specifier, "*")

    def test_parse_pyproject_pep621(self):
        content = """
        [project]
        dependencies = [
            "requests==2.25.1",
            "jinja2<3.1.4"
        ]
        """
        specs = parse_pyproject_toml(content)
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].package_name, "requests")

    def test_vulnerability_matching(self):
        # requests 2.25.1 is vulnerable to CVE-2023-32681 (<2.31.0)
        is_vuln, reason = is_version_vulnerable("==2.25.1", "<2.31.0")
        self.assertTrue(is_vuln)

        # requests 2.31.0 is safe
        is_vuln_safe, _ = is_version_vulnerable("==2.31.0", "<2.31.0")
        self.assertFalse(is_vuln_safe)

    def test_vulnerability_matching_with_ranges(self):
        # urllib3 1.26.17 is safe for CVE-2023-43804 (<1.26.17)
        is_vuln, _ = is_version_vulnerable("==1.26.17", "<1.26.17,>=1.20")
        self.assertFalse(is_vuln)

        # urllib3 1.26.10 is vulnerable
        is_vuln_bad, _ = is_version_vulnerable("==1.26.10", "<1.26.17,>=1.20")
        self.assertTrue(is_vuln_bad)

    def test_parse_setup_py(self):
        content = """
        from setuptools import setup
        setup(
            name="demo-pkg",
            install_requires=[
                "requests==2.25.1",
                "django>=3.2.0,<3.2.14"
            ]
        )
        """
        from sidik.dependency_analyzer.parsers import parse_setup_py
        specs = parse_setup_py(content)
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].package_name, "requests")
        self.assertEqual(specs[1].package_name, "django")


if __name__ == "__main__":
    unittest.main()

