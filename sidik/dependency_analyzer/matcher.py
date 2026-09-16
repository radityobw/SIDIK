"""Semantic version evaluation and CVE advisory matching using packaging specifiers."""

import re
from typing import Tuple, Optional
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier


def normalize_version_specifier(raw_spec: str) -> str:
    """Normalizes poetry / pipenv symbols (e.g. ^, ~) into PEP 440 specifiers."""
    spec = raw_spec.strip()
    if not spec or spec == "*":
        return ""

    # Poetry caret: ^1.2.3 -> >=1.2.3, <2.0.0
    if spec.startswith("^"):
        v_str = spec[1:].strip()
        try:
            v = Version(v_str)
            next_major = v.major + 1
            return f">={v_str},<{next_major}.0.0"
        except InvalidVersion:
            return f">={v_str}"

    # Poetry tilde: ~1.2.3 -> >=1.2.3, <1.3.0
    if spec.startswith("~") and not spec.startswith("~="):
        v_str = spec[1:].strip()
        try:
            v = Version(v_str)
            next_minor = v.minor + 1
            return f">={v_str},{v.major}.{next_minor}.0"
        except InvalidVersion:
            return f">={v_str}"

    # Plain version without operator: "2.25.1" -> "==2.25.1"
    if re.match(r"^[0-9]+(?:\.[0-9a-zA-Z]+)*$", spec):
        return f"=={spec}"

    return spec


def extract_concrete_version(specifier_str: str) -> Optional[str]:
    """Attempts to extract a single concrete version from pinned specifiers."""
    match = re.search(r"==\s*([0-9a-zA-Z\.\-]+)", specifier_str)
    if match:
        return match.group(1)
    # Check for direct number
    match_direct = re.match(r"^([0-9]+(?:\.[0-9a-zA-Z]+)+)$", specifier_str.strip())
    if match_direct:
        return match_direct.group(1)
    return None


def is_version_vulnerable(declared_spec: str, vulnerable_spec: str) -> Tuple[bool, str]:
    """Evaluates whether the declared dependency version satisfies the vulnerable specifier constraint.
    
    Returns:
        (is_vulnerable: bool, matched_reason: str)
    """
    norm_declared = normalize_version_specifier(declared_spec)
    if not norm_declared:
        # Wildcard or unpinned dependency: considered risky
        return True, f"Unpinned dependency '*' matches vulnerable envelope {vulnerable_spec}"

    try:
        vuln_spec_set = SpecifierSet(vulnerable_spec)
    except InvalidSpecifier:
        return False, f"Invalid vulnerability specifier: {vulnerable_spec}"

    # Case 1: Exact version pinned (e.g. requests==2.25.0)
    concrete = extract_concrete_version(norm_declared)
    if concrete:
        try:
            v = Version(concrete)
            if v in vuln_spec_set:
                return True, f"Concrete version {concrete} is within vulnerable range ({vulnerable_spec})"
            else:
                return False, f"Version {concrete} is outside vulnerable range ({vulnerable_spec})"
        except InvalidVersion:
            pass

    # Case 2: Range specification (e.g. >=2.20.0, <2.28.0)
    try:
        declared_spec_set = SpecifierSet(norm_declared)
        # Check if lower bound or sample points are in the vulnerable set
        for spec in declared_spec_set:
            if spec.operator in (">=", "==", "~="):
                try:
                    sample_v = Version(spec.version)
                    if sample_v in vuln_spec_set:
                        return True, f"Declared bound '{spec.operator}{spec.version}' intersects with {vulnerable_spec}"
                except InvalidVersion:
                    continue
    except InvalidSpecifier:
        pass

    return False, "Not vulnerable"
