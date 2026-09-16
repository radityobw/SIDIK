"""Dataset builder script to create standardized ground truth datasets for Secrets and Dependencies."""

import os
import json
import random

random.seed(42)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRETS_DIR = os.path.join(BASE_DIR, "secrets")
DEPS_DIR = os.path.join(BASE_DIR, "dependencies")
GT_DIR = os.path.join(BASE_DIR, "ground_truth")

os.makedirs(GT_DIR, exist_ok=True)
for split in ["dev", "val", "test"]:
    os.makedirs(os.path.join(SECRETS_DIR, split), exist_ok=True)
    os.makedirs(os.path.join(DEPS_DIR, split), exist_ok=True)


# ==========================================
# 1. SECRET SAMPLES GENERATOR
# ==========================================

POSITIVE_SECRET_TEMPLATES = [
    ("AWS_KEY", "AKIA{rand_upper_16}", "API_KEY", "AWS Access Key ID", "SEC001"),
    ("OPENAI_KEY", "sk-proj-{rand_alphanumeric_48}", "API_KEY", "OpenAI Secret API Key", "SEC003"),
    ("STRIPE_KEY", "sk_live_{rand_alphanumeric_24}", "API_KEY", "Stripe Live API Key", "SEC004"),
    ("GITHUB_PAT", "ghp_{rand_alphanumeric_36}", "ACCESS_TOKEN", "GitHub Personal Access Token", "SEC005"),
    ("SLACK_TOKEN", "xoxb-123456789012-987654321098-{rand_alphanumeric_24}", "ACCESS_TOKEN", "Slack Bot Token", "SEC007"),
    ("DB_CONNECTION", "postgres://dbadmin:{rand_alphanumeric_16}@postgres.prod.corp.net:5432/main_db", "DB_CREDENTIAL", "Database Connection URI", "SEC010"),
    ("APP_PASSWORD", "{rand_complex_pass_18}", "PASSWORD", "Hardcoded Password", "SEC009"),
    ("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY", "RSA Private Key", "SEC011"),
    ("JWT_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "ACCESS_TOKEN", "JWT Token", "SEC008"),
    ("CLIENT_SECRET", "{rand_alphanumeric_32}", "GENERIC_SECRET", "Generic High-Entropy Secret", "SEC012")
]

NEGATIVE_SECRET_TEMPLATES = [
    ("MOCK_AWS", "aws_access_key = 'AKIAIOSFODNN7EXAMPLE'", "Placeholder AWS Key"),
    ("MOCK_OPENAI", "openai_key = 'sk-proj-your_openai_api_key_here'", "Placeholder API Key"),
    ("MOCK_PASSWORD", "user_password = 'changeme'", "Trivial Password"),
    ("SAMPLE_UUID", "transaction_id = 'c9a646d3-9c61-4cc9-bc77-c99e4f58b090'", "UUID Identifier"),
    ("GIT_COMMIT", "last_commit_sha = 'e8b7c3d2a1f0987654321fedcba09876543210ab'", "Git Commit SHA-1"),
    ("NORMAL_CONFIG", "MAX_RETRIES = 5\nTIMEOUT_SECONDS = 30\nDEBUG = False", "Normal Configuration"),
    ("TEST_DUMMY", "dummy_secret_token = 'dummy_token_value_for_testing'", "Test Data"),
    ("DOC_EXAMPLE", "# Example usage:\n# client = Client(api_key='YOUR_API_KEY')", "Documentation Comment"),
    ("DEFAULT_URL", "public_url = 'https://api.github.com/v1/events'", "Public URL"),
    ("HEX_COLOR", "primary_color = '#FFFFFF'\nsecondary_color = '#1A2B3C'", "Color Constants")
]

def generate_rand_str(length: int, chars: str) -> str:
    return "".join(random.choices(chars, k=length))

def build_secret_sample(template_idx: int, is_positive: bool, sample_id: str) -> tuple:
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    complex_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%^&*_"

    if is_positive:
        name, raw_tpl, category, title, rule_id = POSITIVE_SECRET_TEMPLATES[template_idx % len(POSITIVE_SECRET_TEMPLATES)]
        val = raw_tpl.format(
            rand_upper_16=generate_rand_str(16, upper),
            rand_alphanumeric_48=generate_rand_str(48, alphanumeric),
            rand_alphanumeric_24=generate_rand_str(24, alphanumeric),
            rand_alphanumeric_36=generate_rand_str(36, alphanumeric),
            rand_alphanumeric_16=generate_rand_str(16, alphanumeric),
            rand_alphanumeric_32=generate_rand_str(32, alphanumeric),
            rand_complex_pass_18=generate_rand_str(18, complex_chars)
        )
        if category == "PASSWORD":
            code = f"user_password = '{val}'"
        elif category == "DB_CREDENTIAL":
            code = f"DATABASE_URI = '{val}'"
        elif category == "PRIVATE_KEY":
            code = f'SSL_PRIVATE_KEY = """{val}"""'
        elif category == "GENERIC_SECRET":
            code = f"auth_secret_key = '{val}'"
        else:
            code = f"{name.lower()} = '{val}'"

        gt = {
            "sample_id": sample_id,
            "ground_truth": True,
            "category": category,
            "expected_rule": rule_id,
            "title": title
        }
        return code, gt
    else:
        name, code, desc = NEGATIVE_SECRET_TEMPLATES[template_idx % len(NEGATIVE_SECRET_TEMPLATES)]
        gt = {
            "sample_id": sample_id,
            "ground_truth": False,
            "category": "BENIGN",
            "expected_rule": None,
            "title": desc
        }
        return code, gt


# ==========================================
# 2. DEPENDENCY SAMPLES GENERATOR
# ==========================================

VULN_DEP_CASES = [
    ("requests", "==2.25.1", "GHSA-j8r2-6x86-q33q", "CVE-2023-32681"),
    ("urllib3", "==1.26.10", "GHSA-q2x7-8rv6-6q7h", "CVE-2023-45803"),
    ("django", "==3.2.5", "GHSA-f9cq-cwgq-4vmh", "CVE-2022-34265"),
    ("pyyaml", "==5.3.1", "GHSA-8495-4g38-x9mp", "CVE-2020-14343"),
    ("jinja2", "==3.1.2", "GHSA-hrfv-mqp8-q5rw", "CVE-2024-34064"),
    ("werkzeug", "==2.2.0", "GHSA-2g64-cvh3-6552", "CVE-2023-25577"),
    ("aiohttp", "==3.9.1", "GHSA-47hx-v7gw-cqpq", "CVE-2024-27318"),
    ("cryptography", "==41.0.0", "GHSA-79g4-8359-885q", "CVE-2023-38325"),
    ("pillow", "==10.0.0", "GHSA-5cpq-8wj7-hf2v", "CVE-2023-46136"),
    ("sqlparse", "==0.4.3", "GHSA-7f33-f3f5-hx78", "CVE-2023-30608")
]

SAFE_DEP_CASES = [
    ("requests", "==2.32.3", "Up-to-date requests"),
    ("urllib3", "==2.2.1", "Modern urllib3 v2"),
    ("django", "==4.2.13", "Patched LTS Django"),
    ("pyyaml", "==6.0.1", "Patched PyYAML"),
    ("jinja2", "==3.1.4", "Patched Jinja2"),
    ("werkzeug", "==3.0.3", "Patched Werkzeug"),
    ("aiohttp", "==3.9.5", "Patched aiohttp"),
    ("cryptography", "==42.0.7", "Patched cryptography"),
    ("pillow", "==10.3.0", "Patched Pillow"),
    ("sqlparse", "==0.5.0", "Patched sqlparse")
]


def build_dependency_sample(idx: int, is_vulnerable: bool, manifest_format: str, sample_id: str) -> tuple:
    if is_vulnerable:
        pkg, spec, adv_id, cve = VULN_DEP_CASES[idx % len(VULN_DEP_CASES)]
        gt = {
            "sample_id": sample_id,
            "ground_truth": True,
            "package": pkg,
            "declared_spec": spec,
            "cve": cve,
            "advisory_id": adv_id
        }
    else:
        pkg, spec, desc = SAFE_DEP_CASES[idx % len(SAFE_DEP_CASES)]
        gt = {
            "sample_id": sample_id,
            "ground_truth": False,
            "package": pkg,
            "declared_spec": spec,
            "cve": None,
            "advisory_id": None
        }

    # Format into manifest syntax
    if manifest_format == "requirements.txt":
        content = f"# Generated requirements\n{pkg}{spec}\n"
    elif manifest_format == "pyproject.toml":
        clean_spec = spec.replace("==", "")
        content = f'[project]\nname = "app-{sample_id}"\nversion = "0.1.0"\ndependencies = [\n    "{pkg}{spec}"\n]\n'
    elif manifest_format == "Pipfile":
        content = f'[[source]]\nurl = "https://pypi.org/simple"\nname = "pypi"\n\n[packages]\n{pkg} = "{spec.replace("==", "")}"\n'
    else:  # poetry.lock
        version_val = spec.replace("==", "")
        content = f'[[package]]\nname = "{pkg}"\nversion = "{version_val}"\ndescription = "Package {pkg}"\ncategory = "main"\noptional = false\npython-versions = "*"\n'

    return content, gt


# ==========================================
# MAIN GENERATION ROUTINE
# ==========================================

def main():
    splits_config = {
        "dev": {"pos_sec": 15, "neg_sec": 15, "pos_dep": 10, "neg_dep": 10},
        "val": {"pos_sec": 15, "neg_sec": 15, "pos_dep": 10, "neg_dep": 10},
        "test": {"pos_sec": 50, "neg_sec": 50, "pos_dep": 30, "neg_dep": 30}
    }

    all_secret_gt = []
    all_dep_gt = []

    for split, counts in splits_config.items():
        # 1. Generate Secrets
        for i in range(counts["pos_sec"]):
            sid = f"sec_{split}_pos_{i+1:03d}"
            code, gt = build_secret_sample(i, is_positive=True, sample_id=sid)
            gt["split"] = split
            filename = f"{sid}.py"
            file_path = os.path.join(SECRETS_DIR, split, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            gt["file_path"] = os.path.relpath(file_path, BASE_DIR).replace("\\", "/")
            all_secret_gt.append(gt)

        for i in range(counts["neg_sec"]):
            sid = f"sec_{split}_neg_{i+1:03d}"
            code, gt = build_secret_sample(i, is_positive=False, sample_id=sid)
            gt["split"] = split
            filename = f"{sid}.py"
            file_path = os.path.join(SECRETS_DIR, split, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            gt["file_path"] = os.path.relpath(file_path, BASE_DIR).replace("\\", "/")
            all_secret_gt.append(gt)

        # 2. Generate Dependencies
        formats = ["requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"]
        for i in range(counts["pos_dep"]):
            sid = f"dep_{split}_pos_{i+1:03d}"
            fmt = formats[i % len(formats)]
            code, gt = build_dependency_sample(i, is_vulnerable=True, manifest_format=fmt, sample_id=sid)
            gt["split"] = split
            gt["manifest_type"] = fmt
            dir_sample = os.path.join(DEPS_DIR, split, sid)
            os.makedirs(dir_sample, exist_ok=True)
            file_path = os.path.join(dir_sample, fmt)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            gt["file_path"] = os.path.relpath(file_path, BASE_DIR).replace("\\", "/")
            all_dep_gt.append(gt)

        for i in range(counts["neg_dep"]):
            sid = f"dep_{split}_neg_{i+1:03d}"
            fmt = formats[i % len(formats)]
            code, gt = build_dependency_sample(i, is_vulnerable=False, manifest_format=fmt, sample_id=sid)
            gt["split"] = split
            gt["manifest_type"] = fmt
            dir_sample = os.path.join(DEPS_DIR, split, sid)
            os.makedirs(dir_sample, exist_ok=True)
            file_path = os.path.join(dir_sample, fmt)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            gt["file_path"] = os.path.relpath(file_path, BASE_DIR).replace("\\", "/")
            all_dep_gt.append(gt)

    # Save Ground Truth JSON
    with open(os.path.join(GT_DIR, "secrets_ground_truth.json"), "w", encoding="utf-8") as f:
        json.dump(all_secret_gt, f, indent=2)

    with open(os.path.join(GT_DIR, "dependencies_ground_truth.json"), "w", encoding="utf-8") as f:
        json.dump(all_dep_gt, f, indent=2)

    print(f"Dataset generated successfully:")
    print(f"  - Secrets: {len(all_secret_gt)} samples (Test: 100, Dev: 30, Val: 30)")
    print(f"  - Dependencies: {len(all_dep_gt)} cases (Test: 60, Dev: 20, Val: 20)")


if __name__ == "__main__":
    main()
