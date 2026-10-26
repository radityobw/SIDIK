"""Unit tests for OSV import, advisory database loading, and CVE deduplication."""

import json
import os
import tempfile
import unittest

from sidik.dependency_analyzer.analyzer import DependencyAnalyzer
from sidik.dependency_analyzer.database import VulnerabilityDatabase
from sidik.dependency_analyzer.matcher import normalize_version_specifier
from sidik.dependency_analyzer.osv_import import (
    build_database,
    convert_osv_record,
    cvss3_base_score,
    events_to_specifiers,
    extract_severity,
)


def _record(**overrides):
    rec = {
        "id": "PYSEC-2099-1",
        "aliases": ["CVE-2099-0001"],
        "summary": "Demo flaw",
        "details": "Longer text",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "Demo_Pkg"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.4.2"}]}],
        }],
    }
    rec.update(overrides)
    return rec


class TestOsvConversion(unittest.TestCase):

    def test_events_introduced_and_fixed(self):
        out = events_to_specifiers([{"introduced": "1.0"}, {"fixed": "1.4.2"}])
        self.assertEqual(out, [(">=1.0,<1.4.2", "1.4.2")])

    def test_events_introduced_zero_has_no_lower_bound(self):
        out = events_to_specifiers([{"introduced": "0"}, {"fixed": "2.0"}])
        self.assertEqual(out, [("<2.0", "2.0")])

    def test_events_last_affected_and_open_ended(self):
        out = events_to_specifiers([{"introduced": "0"}, {"last_affected": "1.5"}])
        self.assertEqual(out, [("<=1.5", None)])
        open_ended = events_to_specifiers([{"introduced": "3.0"}])
        self.assertEqual(open_ended, [(">=3.0", None)])

    def test_events_multiple_intervals(self):
        out = events_to_specifiers([
            {"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.3"},
        ])
        self.assertEqual([s for s, _ in out], ["<1.2", ">=2.0,<2.3"])

    def test_invalid_version_is_skipped(self):
        self.assertEqual(events_to_specifiers([{"introduced": "0"}, {"fixed": "not a version"}]), [])

    def test_convert_record_normalizes_name_and_picks_cve(self):
        advisories, source = convert_osv_record(_record())
        self.assertEqual(len(advisories), 1)
        adv = advisories[0]
        self.assertEqual(adv["package"], "demo-pkg")
        self.assertEqual(adv["cve"], "CVE-2099-0001")
        self.assertEqual(adv["vulnerable_specifier"], ">=1.0,<1.4.2")
        self.assertEqual(adv["fixed_version"], "1.4.2")
        self.assertEqual(source, "default")

    def test_convert_skips_withdrawn_and_other_ecosystems(self):
        self.assertEqual(convert_osv_record(_record(withdrawn="2024-01-01T00:00:00Z"))[0], [])
        npm = _record()
        npm["affected"][0]["package"]["ecosystem"] = "npm"
        self.assertEqual(convert_osv_record(npm)[0], [])

    def test_severity_sources(self):
        self.assertEqual(extract_severity({"database_specific": {"severity": "MODERATE"}}),
                         ("MEDIUM", "database_specific"))
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(extract_severity({"severity": [{"type": "CVSS_V3", "score": vec}]}),
                         ("CRITICAL", "cvss_v3"))
        self.assertEqual(extract_severity({}), ("MEDIUM", "default"))

    def test_cvss3_known_scores(self):
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"), 7.2)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertIsNone(cvss3_base_score("CVSS:4.0/AV:N"))
        self.assertIsNone(cvss3_base_score("garbage"))

    def test_build_database_metadata(self):
        payload = build_database([_record(), _record(id="X", withdrawn="2024")], "unit", "abc")
        meta = payload["metadata"]
        self.assertEqual(meta["osv_record_count"], 2)
        self.assertEqual(meta["skipped_record_count"], 1)
        self.assertEqual(meta["advisory_count"], 1)
        self.assertEqual(meta["package_count"], 1)


class TestDatabaseLoading(unittest.TestCase):

    def _write(self, data) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.remove, path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def test_builtin_only(self):
        db = VulnerabilityDatabase(include_osv=False)
        self.assertIsNone(db._advisories)  # lazy until first access  # pyright: ignore[reportPrivateUsage]
        self.assertTrue(db.get_advisories("Requests"))
        self.assertEqual(db.advisory_count, 12)

    def test_custom_payload_object_and_dedupe(self):
        advisories, _ = convert_osv_record(_record())
        path = self._write({"metadata": {}, "advisories": advisories + advisories})
        db = VulnerabilityDatabase(path, include_osv=False)
        self.assertEqual(len(db.get_advisories("demo_pkg")), 1)

    def test_custom_plain_list_still_supported(self):
        advisories, _ = convert_osv_record(_record())
        db = VulnerabilityDatabase(self._write(advisories), include_osv=False)
        self.assertEqual(len(db.get_advisories("demo-pkg")), 1)

    def test_bad_custom_file_logs_warning(self):
        path = self._write({"unexpected": 1})
        with self.assertLogs("sidik.dependency_analyzer.database", level="WARNING"):
            VulnerabilityDatabase(path, include_osv=False).get_advisories("x")

    def test_missing_custom_file_logs_warning(self):
        with self.assertLogs("sidik.dependency_analyzer.database", level="WARNING"):
            VulnerabilityDatabase("does-not-exist.json", include_osv=False).get_advisories("x")


class TestAnalyzerWithOsv(unittest.TestCase):

    def test_same_cve_from_two_advisory_ids_reported_once(self):
        a1, _ = convert_osv_record(_record(id="PYSEC-2099-1"))
        a2, _ = convert_osv_record(_record(id="GHSA-aaaa-bbbb-cccc"))
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.remove, path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(a1 + a2, f)
        req_fd, req = tempfile.mkstemp(suffix="requirements.txt")
        os.close(req_fd)
        self.addCleanup(os.remove, req)
        with open(req, "w", encoding="utf-8") as f:
            f.write("demo-pkg==1.2.0\n")
        analyzer = DependencyAnalyzer(VulnerabilityDatabase(path, include_osv=False))
        findings = analyzer.scan_manifest_file(req)
        self.assertEqual(len(findings), 1)

    def test_tilde_specifier_has_upper_bound(self):
        self.assertEqual(normalize_version_specifier("~1.2.3"), ">=1.2.3,<1.3.0")


if __name__ == "__main__":
    unittest.main()
