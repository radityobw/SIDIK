"""Conversion of Google OSV (PyPI ecosystem) advisories into the SIDIK offline database format.

The OSV schema expresses affected versions as ordered ``introduced`` / ``fixed`` /
``last_affected`` events. SIDIK stores one PEP 440 specifier per record (for example
``>=1.0,<1.4.2``), so every event interval becomes its own advisory record.
"""

import argparse
import hashlib
import io
import json
import math
import os
import sys
import time
import urllib.request
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from sidik.dependency_analyzer.parsers import normalize_package_name

OSV_PYPI_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
DEFAULT_OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "pypi_advisories.json"
)
MAX_DETAILS_CHARS = 400

SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}
DEFAULT_SEVERITY = "MEDIUM"

_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup function (Appendix A of the specification)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Computes the CVSS v3.x base score from a vector string, or None when unparseable."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: Dict[str, str] = {}
    for part in parts[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val
    try:
        scope_changed = metrics["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}
        iss = 1 - (
            (1 - _CVSS_CIA[metrics["C"]])
            * (1 - _CVSS_CIA[metrics["I"]])
            * (1 - _CVSS_CIA[metrics["A"]])
        )
        exploitability = (
            8.22 * _CVSS_AV[metrics["AV"]] * _CVSS_AC[metrics["AC"]]
            * privileges[metrics["PR"]] * _CVSS_UI[metrics["UI"]]
        )
    except KeyError:
        return None
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def extract_severity(record: Dict[str, Any]) -> Tuple[str, str]:
    """Returns (severity, source) where source is 'database_specific', 'cvss_v3' or 'default'."""
    db_specific = record.get("database_specific")
    if isinstance(db_specific, dict):
        label = str(db_specific.get("severity", "")).upper()
        if label in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[label], "database_specific"
    for entry in record.get("severity", []) or []:
        if isinstance(entry, dict) and str(entry.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base_score(str(entry.get("score", "")))
            if score is not None:
                return score_to_severity(score), "cvss_v3"
    return DEFAULT_SEVERITY, "default"


def events_to_specifiers(events: List[Dict[str, Any]]) -> List[Tuple[str, Optional[str]]]:
    """Turns OSV range events into (PEP 440 specifier, fixed_version) pairs."""
    intervals: List[Tuple[str, Optional[str], Optional[str]]] = []  # (introduced, upper clause, fixed)
    current: Optional[str] = None
    for event in events:
        if "introduced" in event:
            if current is not None:
                intervals.append((current, None, None))
            current = str(event["introduced"])
        elif "fixed" in event:
            intervals.append((current if current is not None else "0", "<" + str(event["fixed"]), str(event["fixed"])))
            current = None
        elif "last_affected" in event:
            intervals.append((current if current is not None else "0", "<=" + str(event["last_affected"]), None))
            current = None
    if current is not None:
        intervals.append((current, None, None))

    results: List[Tuple[str, Optional[str]]] = []
    for introduced, upper, fixed in intervals:
        clauses: List[str] = []
        if introduced != "0":
            clauses.append(">=" + introduced)
        if upper:
            clauses.append(upper)
        specifier = ",".join(clauses) if clauses else ">=0"
        try:
            SpecifierSet(specifier)
        except InvalidSpecifier:
            continue
        results.append((specifier, fixed))
    return results


def _pick_cve(record: Dict[str, Any]) -> str:
    record_id = str(record.get("id", ""))
    if record_id.startswith("CVE-"):
        return record_id
    for alias in record.get("aliases", []) or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return record_id


def _summary_and_details(record: Dict[str, Any]) -> Tuple[str, str]:
    details = str(record.get("details", "") or "").strip()
    summary = str(record.get("summary", "") or "").strip()
    if not summary and details:
        summary = details.splitlines()[0][:160]
    if len(details) > MAX_DETAILS_CHARS:
        details = details[:MAX_DETAILS_CHARS].rstrip() + "..."
    return summary, details


def convert_osv_record(record: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    """Converts one OSV record into SIDIK advisories. Returns (advisories, severity_source)."""
    if record.get("withdrawn"):
        return [], "default"
    record_id = str(record.get("id", ""))
    if not record_id:
        return [], "default"

    severity, severity_source = extract_severity(record)
    cve = _pick_cve(record)
    summary, details = _summary_and_details(record)

    advisories: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for affected in record.get("affected", []) or []:
        package = affected.get("package") or {}
        if str(package.get("ecosystem", "")).lower() != "pypi":
            continue
        name = normalize_package_name(str(package.get("name", "")))
        if not name:
            continue
        for rng in affected.get("ranges", []) or []:
            if str(rng.get("type", "")).upper() != "ECOSYSTEM":
                continue
            for specifier, fixed in events_to_specifiers(rng.get("events", []) or []):
                key = (name, specifier)
                if key in seen:
                    continue
                seen.add(key)
                advisories.append({
                    "id": record_id,
                    "cve": cve,
                    "package": name,
                    "vulnerable_specifier": specifier,
                    "fixed_version": fixed,
                    "severity": severity,
                    "summary": summary,
                    "details": details,
                })
    return advisories, severity_source


def build_database(records: Iterable[Dict[str, Any]], source: str, source_sha256: str) -> Dict[str, Any]:
    """Builds the on-disk payload (metadata plus sorted advisory list) from OSV records."""
    advisories: List[Dict[str, Any]] = []
    record_count = 0
    skipped = 0
    severity_sources: Dict[str, int] = {"database_specific": 0, "cvss_v3": 0, "default": 0}
    for record in records:
        record_count += 1
        converted, sev_source = convert_osv_record(record)
        if not converted:
            skipped += 1
            continue
        severity_sources[sev_source] += len(converted)
        advisories.extend(converted)

    advisories.sort(key=lambda a: (a["package"], a["id"], a["vulnerable_specifier"]))
    return {
        "metadata": {
            "source": source,
            "source_sha256": source_sha256,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "osv_record_count": record_count,
            "skipped_record_count": skipped,
            "advisory_count": len(advisories),
            "package_count": len({a["package"] for a in advisories}),
            "severity_sources": severity_sources,
        },
        "advisories": advisories,
    }


def read_zip_records(zip_bytes: bytes) -> Iterable[Dict[str, Any]]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(data, dict):
                yield data


def download_osv_zip(url: str = OSV_PYPI_URL, timeout: int = 180) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        return response.read()


def write_database(payload: Dict[str, Any], output_path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))


def import_osv(input_zip: Optional[str] = None, output_path: str = DEFAULT_OUTPUT_PATH,
               url: str = OSV_PYPI_URL) -> Dict[str, Any]:
    """Downloads (or reads) the OSV PyPI archive and writes the SIDIK database. Returns metadata."""
    if input_zip:
        with open(input_zip, "rb") as f:
            raw = f.read()
        source = os.path.basename(input_zip)
    else:
        raw = download_osv_zip(url)
        source = url
    payload = build_database(read_zip_records(raw), source, hashlib.sha256(raw).hexdigest())
    write_database(payload, output_path)
    return payload["metadata"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Import the Google OSV PyPI dump into the SIDIK offline database")
    parser.add_argument("--input", default=None, help="Local all.zip path (skips download)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="Output JSON path")
    parser.add_argument("--url", default=OSV_PYPI_URL, help="OSV archive URL")
    args = parser.parse_args(argv)
    try:
        meta = import_osv(args.input, args.output, args.url)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(meta, indent=2))
    print(f"Saved: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
