"""Secret detector engine coordinating regex matching, entropy validation, and context filtering."""

import os
from typing import List, Optional, Dict, Any
from sidik.models import Finding, SeverityLevel, ConfidenceScore
from sidik.secret_detector.patterns import SECRET_PATTERNS
from sidik.secret_detector.entropy import calculate_shannon_entropy
from sidik.secret_detector.context import evaluate_line_context
from sidik.i18n import get_secret_remediation


def mask_secret(secret: str) -> str:
    """Masks secret value for safe reporting."""
    if len(secret) <= 6:
        return "*" * len(secret)
    prefix_len = min(4, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    masked_len = len(secret) - prefix_len - suffix_len
    return secret[:prefix_len] + ("*" * masked_len) + secret[-suffix_len:]


class SecretDetector:
    """Core secret detection scanner with configurable ablation options."""

    def __init__(self, enable_context: bool = True, enable_entropy: bool = True):
        self.enable_context = enable_context
        self.enable_entropy = enable_entropy
        self.patterns = SECRET_PATTERNS

    def scan_content(self, content: str, file_path: str = "memory") -> List[Finding]:
        """Scans source code content string and returns all identified secret findings."""
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            line_findings: List[Finding] = []
            matched_specific_rule = False

            # First pass: check specific rules (SEC001 - SEC011)
            for rule in self.patterns:
                if rule["id"] == "SEC012":
                    continue  # Run generic in second pass if no specific match

                matches = rule["pattern"].finditer(line)
                for match in matches:
                    candidate = match.group(1) if match.groups() else match.group(0)
                    if not candidate:
                        continue

                    entropy = calculate_shannon_entropy(candidate)
                    is_valid = True
                    confidence = ConfidenceScore.MEDIUM
                    meta: Dict[str, Any] = {
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "raw_entropy": entropy
                    }

                    if self.enable_entropy and not self.enable_context:
                        min_ent = rule.get("min_entropy", 2.0)
                        if entropy < min_ent:
                            is_valid = False
                    elif self.enable_context:
                        is_valid, confidence, context_meta = evaluate_line_context(
                            candidate=candidate,
                            line=line,
                            rule=rule if self.enable_entropy else {"min_entropy": 0.0},
                            entropy=entropy
                        )
                        meta.update(context_meta)

                    if is_valid:
                        matched_specific_rule = True
                        finding_id = f"SEC-{rule['id']}-{abs(hash(file_path + str(line_num) + candidate)) % 100000:05d}"
                        line_findings.append(Finding(
                            id=finding_id,
                            finding_type="secret",
                            category=rule["category"],
                            title=f"{rule['name']} Found",
                            description=rule["description"],
                            file_path=file_path,
                            line_number=line_num,
                            snippet=f"Line {line_num}: {line.replace(candidate, mask_secret(candidate)).strip()}",
                            severity=SeverityLevel(rule["severity"]),
                            confidence=confidence,
                            remediation=get_secret_remediation(rule["id"]) or rule.get("remediation"),
                            metadata=meta
                        ))

            # Second pass: Generic secret rule (SEC012) if no specific rule matched on this line
            if not matched_specific_rule:
                generic_rule = next((r for r in self.patterns if r["id"] == "SEC012"), None)
                if generic_rule:
                    matches = generic_rule["pattern"].finditer(line)
                    for match in matches:
                        candidate = match.group(1) if match.groups() else match.group(0)
                        if not candidate:
                            continue

                        entropy = calculate_shannon_entropy(candidate)
                        is_valid = True
                        confidence = ConfidenceScore.MEDIUM
                        meta = {
                            "rule_id": generic_rule["id"],
                            "rule_name": generic_rule["name"],
                            "raw_entropy": entropy
                        }

                        if self.enable_entropy and not self.enable_context:
                            if entropy < generic_rule.get("min_entropy", 3.2):
                                is_valid = False
                        elif self.enable_context:
                            is_valid, confidence, context_meta = evaluate_line_context(
                                candidate=candidate,
                                line=line,
                                rule=generic_rule if self.enable_entropy else {"min_entropy": 0.0},
                                entropy=entropy
                            )
                            meta.update(context_meta)

                        if is_valid:
                            finding_id = f"SEC-{generic_rule['id']}-{abs(hash(file_path + str(line_num) + candidate)) % 100000:05d}"
                            line_findings.append(Finding(
                                id=finding_id,
                                finding_type="secret",
                                category=generic_rule["category"],
                                title=f"{generic_rule['name']} Found",
                                description=generic_rule["description"],
                                file_path=file_path,
                                line_number=line_num,
                                snippet=f"Line {line_num}: {line.replace(candidate, mask_secret(candidate)).strip()}",
                                severity=SeverityLevel(generic_rule["severity"]),
                                confidence=confidence,
                                remediation=get_secret_remediation(generic_rule["id"]) or generic_rule.get("remediation"),
                                metadata=meta
                            ))

            findings.extend(line_findings)

        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scans a single local file for hardcoded secrets."""
        if not os.path.isfile(file_path):
            return []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_content(content, file_path=file_path)
        except Exception:
            return []
