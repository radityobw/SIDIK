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
        "id": "📁 Uji Secrets (N=100)",
        "en": "📁 Test Secrets (N=100)"
    },
    "preset_deps": {
        "id": "📦 Uji Dependensi v2",
        "en": "📦 Test Manifests v2"
    },
    "preset_external_sec": {
        "id": "🌐 25 Repo Eksternal (Secret)",
        "en": "🌐 25 External Repos (Secret)"
    },
    "preset_external_full": {
        "id": "🌐 25 Repo Eksternal (Full)",
        "en": "🌐 25 External Repos (Full)"
    },
    "preset_root": {
        "id": "🔍 Kode Sumber SIDIK",
        "en": "🔍 SIDIK Source Code"
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
    "btn_copy_all_remediation": {
        "id": "📋 Salin Semua Remediasi",
        "en": "📋 Copy All Remediations"
    },
    "btn_copy_all_snippet": {
        "id": "📋 Salin Semua Kode",
        "en": "📋 Copy All Snippets"
    },
    "toast_copied": {
        "id": "✅ Tersalin ke clipboard!",
        "en": "✅ Copied to clipboard!"
    },
    "toast_copied_all": {
        "id": "✅ {count} item tersalin ke clipboard!",
        "en": "✅ Copied {count} items to clipboard!"
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
        "id": "✓ Bundel Fig 1-4 tersimpan: {name}",
        "en": "✓ Fig 1-4 bundle saved: {name}"
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
            "📌 1. Deteksi Secret Terkontrol (RQ1, N=100):\n"
            "  • Presisi SIDIK:       1.0000 (100%)\n"
            "  • Recall SIDIK:        0.9000 (45/50 TP)\n"
            "  • F1-Score / MCC:      0.9474 / 0.9045\n"
            "  • Alarm Palsu (FP):    0 kasus (FPR: 0%)\n"
            "  • Baseline Regex FP:   10 kasus (FPR: 20%)\n\n"
            "📌 2. Uji 25 Repo GitHub Nyata (RQ1, 1.193 file):\n"
            "  • Total Kode:          186.876 LOC (109 kandidat)\n"
            "  • SIDIK (Usulan):      14 FP (12.84%) | 3.19 dtk\n"
            "  • Bandit (v1.9.4):     98 FP (89.91%) | 25.26 dtk\n"
            "  • Gitleaks (v8.30.1):  0 FP  (0.00%)  | 10.41 dtk\n\n"
            "📌 3. Analisis Dependensi SCA v2 (RQ2, N=200):\n"
            "  • Skala Uji:           39 manifes (5 format)\n"
            "  • Format: req, toml, setup.py, Pipfile, lock\n"
            "  • SIDIK (Luring):      100/100 TP (F1: 1.0000)\n"
            "  • Trivy (v0.76.1):     35/100 TP  (F1: 0.5185)\n"
            "  • pip-audit (v2.10.1): 0/17 TP    (req.txt saja)\n\n"
            "📌 4. Studi Ablasi Komponen (RQ3, N=100):\n"
            "  • Konfig A (Regex):    10 FP | F1: 0.8572\n"
            "  • Konfig B (+Konteks): 0 FP  | F1: 0.9474\n"
            "  • Konfig C (+Entropi): 10 FP | F1: 0.8572\n"
            "  • Konfig D (Penuh):    0 FP  | F1: 0.9474\n\n"
            "📌 5. Efisiensi Waktu & Memori (RQ4):\n"
            "  • Waktu Secret (N=100):  ~26.9 ms\n"
            "  • Waktu SCA (39 file):   ~0.11 - 0.33 dtk\n"
            "  • Waktu 25 Repo Nyata:   ~2.55 - 3.19 dtk\n"
            "  • RAM Scan per Repo:     ~0.15 - 0.91 MB (rerata 0.39 MB)\n"
            "  • RAM Scan 25 Repo:      ~1.33 - 1.58 MB\n"
            "  • Muat DB OSV Luring:    ~116.47 MB (1x awal)\n"
        ),
        "en": (
            "📌 1. Controlled Secret Benchmark (RQ1, N=100):\n"
            "  • SIDIK Precision:     1.0000 (100%)\n"
            "  • SIDIK Recall:        0.9000 (45/50 TP)\n"
            "  • F1-Score / MCC:      0.9474 / 0.9045\n"
            "  • False Alarms (FP):   0 cases (FPR: 0%)\n"
            "  • Baseline Regex FP:   10 cases (FPR: 20%)\n\n"
            "📌 2. 25 Real GitHub Repos (RQ1, 1,193 files):\n"
            "  • Total Codebase:      186,876 LOC (109 candidates)\n"
            "  • SIDIK (Proposed):    14 FP (12.84%) | 3.19 s\n"
            "  • Bandit (v1.9.4):     98 FP (89.91%) | 25.26 s\n"
            "  • Gitleaks (v8.30.1):  0 FP  (0.00%)  | 10.41 s\n\n"
            "📌 3. Multi-Manifest SCA v2 (RQ2, N=200):\n"
            "  • Test Scale:          39 manifests (5 formats)\n"
            "  • Formats: req, toml, setup.py, Pipfile, lock\n"
            "  • SIDIK (Offline):     100/100 TP (F1: 1.0000)\n"
            "  • Trivy (v0.76.1):     35/100 TP  (F1: 0.5185)\n"
            "  • pip-audit (v2.10.1): 0/17 TP    (req.txt only)\n\n"
            "📌 4. Component Ablation Study (RQ3, N=100):\n"
            "  • Config A (Regex):    10 FP | F1: 0.8572\n"
            "  • Config B (+Context): 0 FP  | F1: 0.9474\n"
            "  • Config C (+Entropy): 10 FP | F1: 0.8572\n"
            "  • Config D (Full):     0 FP  | F1: 0.9474\n\n"
            "📌 5. Runtime & Memory Overhead (RQ4):\n"
            "  • Secret Scan (N=100):   ~26.9 ms\n"
            "  • SCA Scan (39 files):   ~0.11 - 0.33 s\n"
            "  • 25 Real GitHub Repos:  ~2.55 - 3.19 s\n"
            "  • Scan RAM per Repo:     ~0.15 - 0.91 MB (avg 0.39 MB)\n"
            "  • Scan RAM (25 Repos):   ~1.33 - 1.58 MB\n"
            "  • Offline OSV DB Load:   ~116.47 MB (1x init)\n"
        )
    },

    # About Tab (Tab 3)
    "about_features_text": {
        "id": (
            "Fitur & Karakteristik Utama:\n"
            "  1. Deteksi Secret Multi-Lapisan: Regex heuristik (12 aturan) + verifikasi entropi Shannon + filter konteks leksikal.\n"
            "  2. Reduksi Alarm Palsu Teruji: 0 FP pada uji terkontrol (N=100) dan memangkas 85.7% alarm palsu dibanding Bandit pada 25 repo GitHub nyata (14 FP vs 98 FP).\n"
            "  3. SCA Multi-Manifes Luring: Mendukung 5 format Python (requirements.txt, pyproject.toml, setup.py, Pipfile, poetry.lock) termasuk rentang versi (>=, ~=).\n"
            "  4. Basis Data Advisori OSV PyPI Luring: Mencakup 29.208 rekaman advisori kerentanan lintas 8.038 paket PyPI dengan akurasi 100/100 pada uji SCA v2 (vs Trivy 35/100) dalam 0.33 detik.\n"
            "  5. Efisiensi Komputasi Tinggi: Memindai 25 repositori nyata (186.876 baris kode) dalam ~2.5 - 3.2 detik (RAM scan rerata ~0.39 MB/repo; muat DB OSV awal ~116.47 MB).\n"
            "  6. Native Cross-Platform: Mendukung Windows, Linux, dan macOS (CLI, GUI, & Git pre-commit hook) tanpa kebocoran data ke pihak ketiga (zero data leakage).\n\n"
            "Aset Identitas & Desain:\n"
            "  • Logo & Icon: Tersimpan pada folder logo/ (format transparan, solid, multi-resolusi .ico, dan hi-res).\n"
            "  • Lisensi: Hak Cipta Terbuka di bawah Lisensi MIT untuk Riset Akademik & Industri."
        ),
        "en": (
            "Key Features & Architecture:\n"
            "  1. Multi-Layer Secret Detection: Regex heuristics (12 rules) + Shannon entropy verification + lexical context filtering.\n"
            "  2. Validated False Positive Reduction: 0 FP on controlled test (N=100) and 85.7% fewer false positives than Bandit across 25 real GitHub repos (14 FP vs 98 FP).\n"
            "  3. Offline Multi-Manifest SCA: Supports 5 Python manifest formats (requirements.txt, pyproject.toml, setup.py, Pipfile, poetry.lock) including version ranges (>=, ~=).\n"
            "  4. Comprehensive Offline PyPI OSV DB: Covers 29,208 vulnerability advisory records across 8,038 PyPI packages achieving 100/100 detection on SCA v2 benchmark in 0.33s.\n"
            "  5. High Computational Efficiency: Scans 25 real repositories (186,876 LOC) in ~2.5 - 3.2s (avg scan RAM ~0.39 MB/repo; one-time OSV DB load ~116.47 MB).\n"
            "  6. Native Cross-Platform: Runs on Windows, Linux, and macOS (CLI, GUI, & Git pre-commit hook) with zero data leakage.\n\n"
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
