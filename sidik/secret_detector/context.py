"""Context-aware filtering and confidence scoring to suppress false positives in secret detection."""

import re
from typing import Dict, Any, Tuple
from sidik.models import ConfidenceScore


# Known false positive indicator words
BENIGN_KEYWORDS = {
    "example", "dummy", "sample", "placeholder", "mock", "fake",
    "your_key", "your_token", "your_api_key", "your_secret", "my_secret",
    "changeme", "change_me", "replace_me", "todo", "my_password"
}

# Trivial sequences that are not real secrets
TRIVIAL_CANDIDATES = {
    "123456", "12345678", "123456789", "1234567890", "password", "password123",
    "admin", "admin123", "root", "toor", "qwerty", "abcdef", "abcdef123456"
}

# AWS official documentation example key
AWS_DOC_SAMPLE = "AKIAIOSFODNN7EXAMPLE"

# Regex to detect standard UUIDs (typically entity identifiers, not secret credentials)
UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Git SHA-1 hash pattern (often commit references)
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def is_placeholder_or_mock(candidate: str, surrounding_line: str) -> Tuple[bool, str]:
    """Determines whether a candidate secret is merely a placeholder or test mock."""
    cand_lower = candidate.lower()
    line_lower = surrounding_line.lower()

    # Exact match against AWS official documentation example key
    if candidate == AWS_DOC_SAMPLE:
        return True, "AWS official documentation example key (AKIAIOSFODNN7EXAMPLE)"

    # Trivial passwords/tokens
    if cand_lower in TRIVIAL_CANDIDATES:
        return True, f"Matched trivial/default value: '{cand_lower}'"

    # Direct placeholder keyword in candidate or variable context
    for indicator in BENIGN_KEYWORDS:
        if indicator in cand_lower or f"_{indicator}" in line_lower or f"{indicator}_" in line_lower:
            return True, f"Matched benign keyword: '{indicator}'"

    # UUID check
    if UUID_PATTERN.match(candidate):
        return True, "Candidate matches standard UUID format."

    # Git SHA check
    if GIT_SHA_PATTERN.match(candidate) and ("commit" in line_lower or "sha" in line_lower or "rev" in line_lower):
        return True, "Candidate matches git commit SHA-1."

    # Repetitive sequences (e.g., 'aaaaaaa', '111111')
    if len(candidate) >= 8 and len(set(candidate)) <= 2:
        return True, "Trivial character repetition detected."

    return False, ""


def evaluate_line_context(candidate: str, line: str, rule: Dict[str, Any], entropy: float) -> Tuple[bool, ConfidenceScore, Dict[str, Any]]:
    """Evaluates lexical context around the candidate to determine validity and assign confidence."""
    metadata = {
        "entropy": entropy,
        "is_comment": False,
        "context_clues": []
    }

    stripped_line = line.strip()
    if stripped_line.startswith("#"):
        metadata["is_comment"] = True
        metadata["context_clues"].append("contained_in_comment")

    # Placeholder filter
    is_mock, reason = is_placeholder_or_mock(candidate, line)
    if is_mock:
        metadata["context_clues"].append(f"filtered_placeholder: {reason}")
        return False, ConfidenceScore.LOW, metadata

    # Check minimum entropy constraint if defined
    min_entropy = rule.get("min_entropy", 2.5)
    if entropy < min_entropy:
        metadata["context_clues"].append(f"low_entropy: {entropy} < {min_entropy}")
        return False, ConfidenceScore.LOW, metadata

    # Positive context cues
    positive_keywords = {"api_key", "secret", "token", "password", "passwd", "auth", "private_key", "db_uri", "credential", "url"}
    line_words = set(re.findall(r"[a-zA-Z0-9_]+", line.lower()))
    has_positive_context = bool(positive_keywords.intersection(line_words))

    if has_positive_context:
        metadata["context_clues"].append("positive_keyword_context")

    # Deterministic tokens with specific prefixes
    deterministic_prefixes = ("AKIA", "ghp_", "github_pat_", "sk_live_", "sk-proj-", "sk-", "xoxb-", "xoxp-", "-----BEGIN")
    if any(candidate.startswith(pfx) for pfx in deterministic_prefixes):
        confidence = ConfidenceScore.HIGH
    elif has_positive_context and entropy >= 3.2:
        confidence = ConfidenceScore.HIGH
    elif has_positive_context or entropy >= 3.0:
        confidence = ConfidenceScore.MEDIUM
    else:
        confidence = ConfidenceScore.LOW

    return True, confidence, metadata
