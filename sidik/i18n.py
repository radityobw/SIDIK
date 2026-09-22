"""Internationalization (i18n) module for SIDIK.
Provides complete bilingual support (Bahasa Indonesia & English) for GUI, CLI, and Reporting.
"""

from typing import Dict, Any, Optional

# Supported languages
LANG_ID = "id"
LANG_EN = "en"
SUPPORTED_LANGUAGES = [LANG_ID, LANG_EN]
DEFAULT_LANGUAGE = LANG_ID

# Current active language in memory
_current_lang = DEFAULT_LANGUAGE


def get_current_language() -> str:
    """Returns the currently active language code ('id' or 'en')."""
    return _current_lang


def set_language(lang: str) -> None:
    """Sets the active language code."""
    global _current_lang
    if lang in SUPPORTED_LANGUAGES:
        _current_lang = lang


TRANSLATIONS: Dict[str, Dict[str, str]] = {
    # Header & App Identity
    "app_title": {
        "id": "SIDIK",
        "en": "SIDIK"
    },
    "app_subtitle": {
        "id": "- Secret Identification and Dependency Inspection Kit (Python)",
        "en": "- Secret Identification and Dependency Inspection Kit (Python)"
    },
    "app_version": {
        "id": "v1.0 (Research Edition)",
        "en": "v1.0 (Research Edition)"
    },
    "lang_toggle_btn": {
        "id": "English (EN)",
        "en": "Bahasa Indonesia (ID)"
    },

    # Navigation Tabs
    "tab_scanner": {
        "id": "  🔍 Dashboard Pemindai  ",
        "en": "  🔍 Scanner Dashboard  "
    },
    "tab_research": {
        "id": "  📊 Visualisasi & Hasil Riset  ",
        "en": "  📊 Research Metrics & Figures  "
    },
    "tab_about": {
        "id": "  ℹ️ Tentang Instrumen Riset  ",
        "en": "  ℹ️ About SIDIK  "
    },

    # Scanner Controls
    "target_label": {
        "id": "Target Path:",
        "en": "Target Path:"
    },
    "btn_browse_folder": {
        "id": "Pilih Folder",
        "en": "Browse Folder"
    },
    "btn_browse_file": {
        "id": "Pilih Berkas",
        "en": "Browse File"
    },
    "opt_secret": {
        "id": "Hardcoded Secrets",
        "en": "Hardcoded Secrets"
    },
    "opt_dep": {
        "id": "Dependensi Rentan",
        "en": "Vulnerable Dependencies"
    },
    "opt_context": {
        "id": "Filter Konteks",
        "en": "Context-Aware Filter"
    },
    "opt_entropy": {
        "id": "Entropi Shannon",
        "en": "Shannon Entropy"
    },
    "btn_scan": {
        "id": "▶  Mulai Pemindaian",
        "en": "▶  Start Security Scan"
    },
    "btn_scanning": {
        "id": "⏳ Memindai...",
        "en": "⏳ Scanning..."
    },
    "btn_export": {
        "id": "💾 Ekspor Laporan",
        "en": "💾 Export Report"
    },
    "btn_save_chart": {
        "id": "📊 Simpan Grafik",
        "en": "📊 Save Chart"
    },
    "btn_view_chart": {
        "id": "📊 Lihat Grafik →",
        "en": "📊 View Chart →"
    },

    # Quick Presets
    "preset_secrets": {
        "id": "📁 Sampel Secrets",
        "en": "📁 Test Secrets"
    },
    "preset_deps": {
        "id": "📦 Sampel Dependensi",
        "en": "📦 Test Manifests"
    },
    "preset_root": {
        "id": "🔍 Seluruh Repositori",
        "en": "🔍 Project Root"
    },

    # Live Search & Multi-Dimensional Filters
    "search_placeholder": {
        "id": "🔍 Cari temuan (rule ID, nama berkas, CVE, kata kunci)...",
        "en": "🔍 Search findings (rule ID, filename, CVE, keyword)..."
    },
    "filter_severity_label": {
        "id": "Tingkat Bahaya:",
        "en": "Severity:"
    },
    "filter_type_label": {
        "id": "Tipe Temuan:",
        "en": "Type:"
    },
    "filter_all": {
        "id": "Semua Tingkat Bahaya",
        "en": "All Severities"
    },
    "filter_all_types": {
        "id": "Semua Tipe Temuan",
        "en": "All Finding Types"
    },
    "filter_type_secret": {
        "id": "Secrets Saja",
        "en": "Secrets Only"
    },
    "filter_type_dep": {
        "id": "Dependensi Saja",
        "en": "Dependencies Only"
    },
    "showing_findings": {
        "id": "Menampilkan {visible} dari {total} temuan",
        "en": "Showing {visible} of {total} findings"
    },
    "btn_clear_filter": {
        "id": "Reset Filter",
        "en": "Reset Filter"
    },

    # Severity Tiles
    "tile_crit": {
        "id": "Kritis",
        "en": "Critical"
    },
    "tile_high": {
        "id": "Tinggi",
        "en": "High"
    },
    "tile_med": {
        "id": "Sedang",
        "en": "Medium"
    },
    "tile_low": {
        "id": "Rendah",
        "en": "Low"
    },
    "tile_total": {
        "id": "Total Temuan",
        "en": "Total Findings"
    },

    # Metric Tiles
    "tile_files": {
        "id": "Berkas Dipindai",
        "en": "Files Scanned"
    },
    "tile_secrets": {
        "id": "Secrets Ditemukan",
        "en": "Secrets Found"
    },
    "tile_deps": {
        "id": "Kerentanan Dependensi",
        "en": "Vulnerable Deps"
    },
    "tile_time": {
        "id": "Waktu Eksekusi",
        "en": "Execution Time"
    },
    "tile_mem": {
        "id": "Konsumsi Memori",
        "en": "Peak Memory"
    },

    # Findings Table Columns
    "col_id": {
        "id": "ID Temuan",
        "en": "Finding ID"
    },
    "col_type": {
        "id": "Tipe",
        "en": "Type"
    },
    "col_category": {
        "id": "Kategori",
        "en": "Category"
    },
    "col_severity": {
        "id": "Tingkat Bahaya",
        "en": "Severity"
    },
    "col_confidence": {
        "id": "Confidence",
        "en": "Confidence"
    },
    "col_location": {
        "id": "Lokasi",
        "en": "Location"
    },
    "col_detail": {
        "id": "Judul & Deskripsi",
        "en": "Title & Description"
    },

    # Details & Remediation Panel
    "detail_panel_title": {
        "id": "Detail Temuan & Rekomendasi Perbaikan:",
        "en": "Finding Details & Remediation Guidance:"
    },
    "lbl_finding_id": {
        "id": "ID Temuan:",
        "en": "Finding ID:"
    },
    "lbl_type_category": {
        "id": "Tipe/Kategori:",
        "en": "Type/Category:"
    },
    "lbl_severity": {
        "id": "Tingkat Bahaya:",
        "en": "Severity Level:"
    },
    "lbl_location": {
        "id": "Lokasi Berkas:",
        "en": "File Location:"
    },
    "lbl_line": {
        "id": "Baris:",
        "en": "Line:"
    },
    "lbl_description": {
        "id": "Deskripsi:",
        "en": "Description:"
    },
    "lbl_code_snippet": {
        "id": "Potongan Kode:",
        "en": "Code Snippet:"
    },
    "lbl_remediation_header": {
        "id": "[REKOMENDASI PERBAIKAN]",
        "en": "[REMEDIATION GUIDANCE]"
    },
    "lbl_technical_metadata": {
        "id": "Metadata Teknis:",
        "en": "Technical Metadata:"
    },
    "btn_copy_remediation": {
        "id": "📋 Salin Remediasi",
        "en": "📋 Copy Remediation"
    },
    "btn_copy_snippet": {
        "id": "📋 Salin Kode",
        "en": "📋 Copy Snippet"
    },
    "toast_copied": {
        "id": "✅ Tersalin ke clipboard!",
        "en": "✅ Copied to clipboard!"
    },
    "export_format_choice": {
        "id": "Pilih format berkas laporan yang ingin diekspor:",
        "en": "Select the export format for the assessment report:"
    },

    # Status Bar & Messages
    "status_ready": {
        "id": "Siap memindai.",
        "en": "Ready to scan."
    },
    "progress_collecting": {
        "id": "Menyiapkan dan mengindeks berkas...",
        "en": "Preparing and indexing codebase files..."
    },
    "progress_scanning": {
        "id": "Memindai [{current}/{total}]: {file}",
        "en": "Scanning [{current}/{total}]: {file}"
    },
    "progress_complete": {
        "id": "✓ Pemindaian 100% selesai ({total} berkas)",
        "en": "✓ Scan 100% complete ({total} files)"
    },
    "status_scanning": {
        "id": "Sedang memindai: {target}",
        "en": "Scanning: {target}"
    },
    "status_completed": {
        "id": "Pemindaian selesai dalam {duration}s. Total temuan: {count}.",
        "en": "Scan completed in {duration}s. Total findings: {count}."
    },
    "status_failed": {
        "id": "Gagal memindai: {error}",
        "en": "Scan failed: {error}"
    },
    "msg_clean": {
        "id": "[OK] Tidak ditemukan kerentanan atau kebocoran kredensial pada target.",
        "en": "[OK] Clean! No security issues or hardcoded secrets detected in target."
    },
    "msg_findings_prompt": {
        "id": "[i] Ditemukan {count} temuan keamanan. Klik salah satu baris temuan pada tabel di atas untuk meninjau detail teknis & rekomendasi perbaikan.",
        "en": "[i] Discovered {count} security findings. Click any row in the table above to review technical details & remediation guidance."
    },
    "dialog_target_not_found_title": {
        "id": "Target Tidak Ditemukan",
        "en": "Target Not Found"
    },
    "dialog_target_not_found_body": {
        "id": "Path target '{target}' tidak valid atau tidak ditemukan.",
        "en": "Target path '{target}' does not exist or is invalid."
    },
    "dialog_scan_error_title": {
        "id": "Kesalahan Pemindaian",
        "en": "Scan Error"
    },
    "dialog_export_title": {
        "id": "Simpan Laporan Pemindaian",
        "en": "Save Scan Assessment Report"
    },
    "dialog_export_success_title": {
        "id": "Laporan Disimpan",
        "en": "Report Saved"
    },
    "dialog_export_success_body": {
        "id": "Laporan berhasil disimpan ke:\n{path}",
        "en": "Assessment report saved successfully to:\n{path}"
    },
    "dialog_export_error_title": {
        "id": "Gagal Menyimpan",
        "en": "Export Failed"
    },

    # Research Tab (Tab 2)
    "research_panel_title": {
        "id": "Hasil Evaluasi Empiris (RQ1 - RQ4)",
        "en": "Empirical Evaluation Results (RQ1 - RQ4)"
    },
    "bundle_select_label": {
        "id": "Pilih Sesi / Bundel Riset:",
        "en": "Select Research Session / Bundle:"
    },
    "bundle_benchmark": {
        "id": "🔬 Benchmark Riset (Paper)",
        "en": "🔬 Research Benchmark (Paper)"
    },
    "fig_nav_rq1": {
        "id": "RQ1: Deteksi Secret",
        "en": "RQ1: Secret Detection"
    },
    "fig_nav_rq2": {
        "id": "RQ2: Dependensi",
        "en": "RQ2: Dependencies"
    },
    "fig_nav_rq3": {
        "id": "RQ3: Distribusi",
        "en": "RQ3: Distribution"
    },
    "fig_nav_rq4": {
        "id": "RQ4: Performa",
        "en": "RQ4: Performance"
    },
    "fig_nav_bundle": {
        "id": "📊 Master Bundle",
        "en": "📊 Master Bundle"
    },
    "btn_open_folder": {
        "id": "📂 Buka Folder",
        "en": "📂 Open Folder"
    },
    "status_bundle_saved": {
        "id": "✓ Bundel Fig 1–4 tersimpan: {name}",
        "en": "✓ Fig 1–4 bundle saved: {name}"
    },
    "bundle_scan_details_title": {
        "id": "Metrik Empiris Sesi Scan Terpilih",
        "en": "Selected Scan Empirical Metrics"
    },
    "chart_select_label": {
        "id": "Pilih Grafik Visualisasi:",
        "en": "Select Visualization Figure:"
    },
    "chart_not_found": {
        "id": "Grafik '{name}' belum dibuat.\nJalankan experiments/generate_charts.py.",
        "en": "Figure '{name}' not found.\nRun experiments/generate_charts.py to generate."
    },
    "research_metrics_summary": {
        "id": (
            "📌 Uji Efektivitas Secret (RQ1 & RQ3):\n"
            "  • Proposed Precision:  1.0000 (100%)\n"
            "  • Proposed Recall:     0.9000 (90%)\n"
            "  • Proposed F1-Score:   0.9474\n"
            "  • Proposed MCC:        0.9045\n"
            "  • False Alarm (FP):    0 kasus (FPR: 0%)\n"
            "  • Baseline Regex FP:   10 kasus (FPR: 20%)\n\n"
            "📌 Uji Analisis Dependensi (RQ2):\n"
            "  • Precision:           1.0000 (100%)\n"
            "  • Recall:              1.0000 (100%)\n"
            "  • F1-Score:            1.0000\n"
            "  • Format: req, toml, Pipfile, lock\n\n"
            "📌 Benchmark Performa (RQ4):\n"
            "  • Secret Scan Time:    ~30.2 ms\n"
            "  • Dependency Scan:     ~19.3 ms\n"
            "  • Total Runtime:       ~49.5 ms\n"
            "  • Peak Memory:         ~0.25 MB\n"
        ),
        "en": (
            "📌 Secret Detection Effectiveness (RQ1 & RQ3):\n"
            "  • Proposed Precision:  1.0000 (100%)\n"
            "  • Proposed Recall:     0.9000 (90%)\n"
            "  • Proposed F1-Score:   0.9474\n"
            "  • Proposed MCC:        0.9045\n"
            "  • False Alarm (FP):    0 cases (FPR: 0%)\n"
            "  • Baseline Regex FP:   10 cases (FPR: 20%)\n\n"
            "📌 Dependency Analysis Evaluation (RQ2):\n"
            "  • Precision:           1.0000 (100%)\n"
            "  • Recall:              1.0000 (100%)\n"
            "  • F1-Score:            1.0000\n"
            "  • Manifests: req, toml, Pipfile, lock, setup\n\n"
            "📌 Performance Benchmark (RQ4):\n"
            "  • Secret Scan Time:    ~30.2 ms\n"
            "  • Dependency Scan:     ~19.3 ms\n"
            "  • Total Runtime:       ~49.5 ms\n"
            "  • Peak Memory:         ~0.25 MB\n"
        )
    },

    # About Tab (Tab 3)
    "about_features_text": {
        "id": (
            "Fitur & Karakteristik Utama:\n"
            "  1. Deteksi Secret Multi-Lapisan: Regex heuristik + verifikasi entropi Shannon + filter konteks leksikal.\n"
            "  2. Eliminasi Alarm Palsu: Mampu membedakan string acak/dummy/mock dari kredensial riil (FPR 0.0000).\n"
            "  3. SCA Multi-Manifest Luring: Mendukung requirements.txt, pyproject.toml, Pipfile, poetry.lock, setup.py.\n"
            "  4. Basis Data Advisori Komprehensif: Pencocokan kerentanan CVE luring instan berbasis specifier semantik.\n"
            "  5. Efisiensi Komputasi Tinggi: Rata-rata durasi pemindaian ~49.5 ms dengan konsumsi memori < 1 MB.\n"
            "  6. Native Cross-Platform: Mendukung Windows, Linux, dan macOS tanpa dependensi eksternal berat.\n\n"
            "Aset Identitas & Desain:\n"
            "  • Logo & Icon: Tersimpan pada folder logo/ (format transparan, solid, multi-resolusi .ico, dan hi-res).\n"
            "  • Lisensi: Hak Cipta Terbuka di bawah Lisensi MIT untuk Riset Akademik & Industri."
        ),
        "en": (
            "Key Features & Architecture:\n"
            "  1. Multi-Layer Secret Detection: Regex heuristics + Shannon entropy verification + lexical context filtering.\n"
            "  2. False Positive Elimination: Accurately differentiates mock/dummy tokens from true credentials (FPR 0.0000).\n"
            "  3. Offline Multi-Manifest SCA: Supports requirements.txt, pyproject.toml, Pipfile, poetry.lock, setup.py.\n"
            "  4. Comprehensive Offline Advisory DB: Instant CVE vulnerability matching using semantic version specifiers.\n"
            "  5. High Computational Efficiency: Mean runtime latency ~49.5 ms with peak memory overhead < 1 MB.\n"
            "  6. Native Cross-Platform: Fully compatible with Windows, Linux, and macOS without heavy dependencies.\n\n"
            "Visual Branding & Licensing:\n"
            "  • Logo & Assets: Located under logo/ (nobg transparent, glow rim dark theme, multi-res .ico, and 3264px hi-res).\n"
            "  • License: Open Source under MIT License for Academic Research & Industrial Security."
        )
    },

    # Reporting Headers (Markdown & Console)
    "report_title": {
        "id": "🛡️ SIDIK: Secret Identification and Dependency Inspection Kit",
        "en": "🛡️ SIDIK: Secret Identification and Dependency Inspection Kit"
    },
    "report_subtitle": {
        "id": "### Laporan Otomatis Analisis Keamanan & Audit Kerentanan",
        "en": "### Automated Security Assessment & Vulnerability Audit Report"
    },
    "report_summary_heading": {
        "id": "## Ringkasan Eksekutif",
        "en": "## Executive Summary"
    },
    "report_findings_heading": {
        "id": "## Temuan Keamanan",
        "en": "## Security Findings"
    },
    "report_detailed_heading": {
        "id": "### Rincian Temuan & Rekomendasi",
        "en": "### Detailed Findings & Remediation"
    },
    "report_clean_message": {
        "id": "*Tidak ditemukan kerentanan atau kebocoran kredensial pada target pemindaian.*",
        "en": "*No security vulnerabilities or secret leaks detected in target.*"
    }
}


# Curated Remediation Translations for All Secret Rules
SECRET_REMEDIATIONS: Dict[str, Dict[str, str]] = {
    "SEC001": {
        "id": "Segera nonaktifkan dan rotasi Access Key di AWS IAM Management Console. Pindahkan kunci ke environment variable (AWS_ACCESS_KEY_ID) atau gunakan IAM Roles / AWS Secrets Manager.",
        "en": "Immediately revoke and rotate this Access Key in the AWS IAM Console. Migrate credentials to environment variables (AWS_ACCESS_KEY_ID) or use IAM Roles / AWS Secrets Manager."
    },
    "SEC002": {
        "id": "Batasi otorisasi API key pada Google Cloud Console (HTTP referrers / IP restrictions). Pindahkan kunci ke environment variable atau Google Secret Manager.",
        "en": "Apply API & application restrictions in Google Cloud Console. Store the key in environment variables or Google Cloud Secret Manager instead of hardcoding."
    },
    "SEC003": {
        "id": "Segera cabut (revoke) kunci API di OpenAI API Dashboard (platform.openai.com). Simpan kunci baru di environment variable OPENAI_API_KEY dan akses menggunakan os.getenv('OPENAI_API_KEY').",
        "en": "Immediately revoke this API key in the OpenAI API Dashboard (platform.openai.com). Store the new key in the OPENAI_API_KEY environment variable and load it via os.getenv('OPENAI_API_KEY')."
    },
    "SEC004": {
        "id": "Segera cabut API key di Stripe Dashboard (Developers > API keys) untuk mencegah transaksi tidak sah. Terapkan Restricted Key dan simpan di environment variable.",
        "en": "Immediately revoke this secret key in the Stripe Dashboard (Developers > API keys) to prevent unauthorized transactions. Use Stripe Restricted Keys and store in environment variables."
    },
    "SEC005": {
        "id": "Segera cabut Personal Access Token di GitHub Settings > Developer settings. Gunakan GitHub Actions Secrets untuk alur CI/CD atau credential helper lokal.",
        "en": "Revoke this Personal Access Token immediately via GitHub Settings > Developer settings. Use GitHub Actions Secrets for automation or local credential helpers."
    },
    "SEC006": {
        "id": "Segera cabut Fine-Grained Token di GitHub Settings > Developer settings. Batasi scope repositori dan masa berlaku token ke batas minimum yang diperlukan.",
        "en": "Revoke this Fine-Grained Token in GitHub Developer Settings. Restrict repository permissions and set short expiration lifespans."
    },
    "SEC007": {
        "id": "Segera cabut token di konsol manajemen aplikasi Slack (api.slack.com/apps). Simpan token pada environment variable atau secret manager, bukan dalam kode sumber.",
        "en": "Revoke this token in the Slack App Management console (api.slack.com/apps). Inject tokens at runtime via environment variables rather than source code."
    },
    "SEC008": {
        "id": "Jangan menyimpan token JWT aktif secara statis di repositori. Jika token ini aktif di produksi, segera rotasi kunci penandatangan (signing secret / private key).",
        "en": "Do not hardcode active JWT tokens into repositories. If active in production, rotate the signing secret or private key on your identity provider immediately."
    },
    "SEC009": {
        "id": "Jangan menuliskan kata sandi langsung di kode sumber. Pindahkan kata sandi ke berkas konfigurasi rahasia (.env terdaftar di .gitignore) dan lakukan reset kata sandi sekarang.",
        "en": "Never hardcode passwords in source code. Move passwords to a secured .env file (listed in .gitignore) or vault, and reset the compromised account password immediately."
    },
    "SEC010": {
        "id": "Jangan menyematkan kredensial plaintext dalam URI koneksi di kode. Pisahkan ke environment variable (misal DATABASE_URL) dan lakukan rotasi kata sandi database.",
        "en": "Do not embed plaintext credentials in connection strings. Externalize parameters via environment variables (e.g., DATABASE_URL) and rotate the database user password."
    },
    "SEC011": {
        "id": "Kunci privat ini harus dianggap telah disusupi (compromised). Segera buat pasangan kunci baru, cabut kunci lama dari server tujuan, dan jangan simpan di git.",
        "en": "Treat this private key as compromised. Generate a new keypair immediately, revoke the existing key from authorized_keys/servers, and never commit private keys."
    },
    "SEC012": {
        "id": "Tinjau nilai variabel ini. Jika merupakan kredensial riil, lakukan rotasi segera dan migrasikan nilai rahasia ke environment variable atau secret manager.",
        "en": "Review this candidate string. If it is an authentic credential, rotate it immediately and migrate the secret to environment variables or a secret vault."
    }
}


def t(key: str, lang: Optional[str] = None, **kwargs) -> str:
    """Translates a text key to the desired language (defaults to active language)."""
    target_lang = lang or _current_lang
    if target_lang not in SUPPORTED_LANGUAGES:
        target_lang = DEFAULT_LANGUAGE

    val = TRANSLATIONS.get(key, {}).get(target_lang)
    if val is None:
        # Fallback to default language or key itself
        val = TRANSLATIONS.get(key, {}).get(DEFAULT_LANGUAGE, key)

    if kwargs:
        try:
            return val.format(**kwargs)
        except Exception:
            return val
    return val


def get_secret_remediation(rule_id: str, lang: Optional[str] = None) -> str:
    """Returns localized remediation text for a specific secret detector rule."""
    target_lang = lang or _current_lang
    rule_data = SECRET_REMEDIATIONS.get(rule_id, {})
    return rule_data.get(target_lang, rule_data.get(DEFAULT_LANGUAGE, ""))


def get_dependency_remediation(package_name: str, cve_id: str, fixed_version: Optional[str] = None,
                               manifest_file: Optional[str] = None, lang: Optional[str] = None) -> str:
    """Constructs localized remediation guidance for a vulnerable dependency."""
    target_lang = lang or _current_lang
    manifest_desc = f" ({manifest_file})" if manifest_file else ""

    if target_lang == LANG_EN:
        if fixed_version:
            return (
                f"Upgrade dependency '{package_name}' to version >={fixed_version} in your manifest{manifest_desc}. "
                f"Run `pip install --upgrade {package_name}>={fixed_version}` to resolve {cve_id}."
            )
        return (
            f"Review security advisory {cve_id} for package '{package_name}'. "
            f"Upgrade to the latest secure release or consider applying configuration mitigations."
        )
    else:
        if fixed_version:
            return (
                f"Perbarui dependensi '{package_name}' ke versi >={fixed_version} pada berkas manifest{manifest_desc}. "
                f"Jalankan `pip install --upgrade {package_name}>={fixed_version}` untuk mengatasi {cve_id}."
            )
        return (
            f"Tinjau advisori kerentanan {cve_id} untuk paket '{package_name}'. "
            f"Pertimbangkan untuk memperbarui ke rilis aman terbaru atau terapkan mitigasi konfigurasi."
        )
