"""Curated regular expression rules for secret detection across 6 security categories."""

import re
from typing import List, Dict, Any


SECRET_PATTERNS: List[Dict[str, Any]] = [
    # 1. API Keys
    {
        "id": "SEC001",
        "name": "AWS Access Key ID",
        "category": "API_KEY",
        "pattern": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "severity": "CRITICAL",
        "min_entropy": 2.5,
        "description": "Amazon Web Services Access Key ID detected.",
        "remediation": "Segera nonaktifkan dan rotasi Access Key di AWS IAM Management Console. Pindahkan kunci ke environment variable (AWS_ACCESS_KEY_ID) atau gunakan IAM Roles / AWS Secrets Manager."
    },
    {
        "id": "SEC002",
        "name": "Google API Key",
        "category": "API_KEY",
        "pattern": re.compile(r"(?<![A-Za-z0-9_\-])(AIza[0-9A-Za-z_\-]{35})(?![A-Za-z0-9_\-])"),
        "severity": "HIGH",
        "min_entropy": 3.0,
        "description": "Google Cloud / Firebase API Key detected.",
        "remediation": "Batasi otorisasi API key pada Google Cloud Console (HTTP referrers / IP restrictions). Pindahkan kunci ke environment variable atau Google Secret Manager."
    },
    {
        "id": "SEC003",
        "name": "OpenAI API Key",
        "category": "API_KEY",
        "pattern": re.compile(r"(?<![A-Za-z0-9_\-])(sk-(?:proj-)?[a-zA-Z0-9_\-]{32,64})(?![A-Za-z0-9_\-])"),
        "severity": "CRITICAL",
        "min_entropy": 3.0,
        "description": "OpenAI Secret API Key detected.",
        "remediation": "Segera cabut (revoke) kunci API di OpenAI API Dashboard (platform.openai.com). Simpan kunci baru di environment variable OPENAI_API_KEY dan akses menggunakan os.getenv('OPENAI_API_KEY')."
    },
    {
        "id": "SEC004",
        "name": "Stripe Live API Key",
        "category": "API_KEY",
        "pattern": re.compile(r"(?<![A-Za-z0-9])(sk_live_[0-9a-zA-Z]{24,34})(?![A-Za-z0-9])"),
        "severity": "CRITICAL",
        "min_entropy": 3.0,
        "description": "Stripe Live Secret Key detected.",
        "remediation": "Segera cabut API key di Stripe Dashboard (Developers > API keys) untuk mencegah transaksi tidak sah. Terapkan Restricted Key dan simpan di environment variable."
    },

    # 2. Access Tokens
    {
        "id": "SEC005",
        "name": "GitHub Personal Access Token",
        "category": "ACCESS_TOKEN",
        "pattern": re.compile(r"(?<![A-Za-z0-9])(ghp_[0-9a-zA-Z]{36})(?![A-Za-z0-9])"),
        "severity": "CRITICAL",
        "min_entropy": 3.0,
        "description": "GitHub Personal Access Token (classic) detected.",
        "remediation": "Segera cabut Personal Access Token di GitHub Settings > Developer settings. Gunakan GitHub Actions Secrets untuk alur CI/CD atau credential helper lokal."
    },
    {
        "id": "SEC006",
        "name": "GitHub Fine-Grained Token",
        "category": "ACCESS_TOKEN",
        "pattern": re.compile(r"(?<![A-Za-z0-9])(github_pat_[0-9a-zA-Z_]{82})(?![A-Za-z0-9])"),
        "severity": "CRITICAL",
        "min_entropy": 3.2,
        "description": "GitHub Fine-Grained Personal Access Token detected.",
        "remediation": "Segera cabut Fine-Grained Token di GitHub Settings > Developer settings. Batasi scope repositori dan masa berlaku token ke batas minimum yang diperlukan."
    },
    {
        "id": "SEC007",
        "name": "Slack API / Bot Token",
        "category": "ACCESS_TOKEN",
        "pattern": re.compile(r"(?<![A-Za-z0-9])(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})(?![A-Za-z0-9])"),
        "severity": "HIGH",
        "min_entropy": 2.8,
        "description": "Slack Bot/User Access Token detected.",
        "remediation": "Segera cabut token di konsol manajemen aplikasi Slack (api.slack.com/apps). Simpan token pada environment variable atau secret manager, bukan dalam kode sumber."
    },
    {
        "id": "SEC008",
        "name": "JSON Web Token (JWT)",
        "category": "ACCESS_TOKEN",
        "pattern": re.compile(r"(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-.+/=]{10,})(?![A-Za-z0-9_\-])"),
        "severity": "MEDIUM",
        "min_entropy": 3.0,
        "description": "Signed JSON Web Token (JWT) detected.",
        "remediation": "Jangan menyimpan token JWT aktif secara statis di repositori. Jika token ini aktif di produksi, segera rotasi kunci penandatangan (signing secret / private key)."
    },

    # 3. Passwords
    {
        "id": "SEC009",
        "name": "Hardcoded Password Assignment",
        "category": "PASSWORD",
        "pattern": re.compile(r"""(?i)(?:password|passwd|pwd|db_pass|user_pass)\s*(?:=|:=|:)\s*['"]([^'"]{6,64})['"]"""),
        "severity": "HIGH",
        "min_entropy": 2.0,
        "description": "Hardcoded password assignment detected in source code.",
        "remediation": "Jangan menuliskan kata sandi langsung di kode sumber. Pindahkan kata sandi ke berkas konfigurasi rahasia (.env terdaftar di .gitignore) dan lakukan reset kata sandi sekarang."
    },

    # 4. Database Credentials
    {
        "id": "SEC010",
        "name": "Database Connection URI with Credential",
        "category": "DB_CREDENTIAL",
        "pattern": re.compile(r"""((?:postgres|postgresql|mysql|mongodb|redis|mssql)://[a-zA-Z0-9_.\-]+:[^@\s'"]+@[a-zA-Z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9_.\-]+)"""),
        "severity": "CRITICAL",
        "min_entropy": 2.0,
        "description": "Database connection URI containing plaintext embedded credentials.",
        "remediation": "Jangan menyematkan kredensial plaintext dalam URI koneksi di kode. Pisahkan ke environment variable (misal DATABASE_URL) dan lakukan rotasi kata sandi database."
    },

    # 5. Private Keys
    {
        "id": "SEC011",
        "name": "Asymmetric Private Key Block",
        "category": "PRIVATE_KEY",
        "pattern": re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"),
        "severity": "CRITICAL",
        "min_entropy": 0.0,
        "description": "Cryptographic Private Key header block detected.",
        "remediation": "Kunci privat ini harus dianggap telah disusupi (compromised). Segera buat pasangan kunci baru, cabut kunci lama dari server tujuan, dan jangan simpan di git."
    },

    # 6. Generic High-Entropy Secret
    {
        "id": "SEC012",
        "name": "Generic High-Entropy Secret Candidate",
        "category": "GENERIC_SECRET",
        "pattern": re.compile(r"""(?i)(?:secret|api_?key|auth_?token|client_?secret|access_?token)\s*(?:=|:=|:)\s*['"]([a-zA-Z0-9_\-+=/]{16,128})['"]"""),
        "severity": "MEDIUM",
        "min_entropy": 3.2,
        "description": "Generic variable assignment indicating a potential high-entropy secret string.",
        "remediation": "Tinjau nilai variabel ini. Jika merupakan kredensial riil, lakukan rotasi segera dan migrasikan nilai rahasia ke environment variable atau secret manager."
    }
]
