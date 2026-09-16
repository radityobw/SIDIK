"""Formatters for scan reports: JSON, Markdown, CSV, and Modern Rich Terminal Table."""

import json
import io
import csv
import sys
import os
from typing import Dict, Any, Optional
from sidik.models import ScanReport


# Windows ANSI terminal enablement via built-in ctypes
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


class ReportFormatter:
    """Renders ScanReport into various output formats: JSON, Markdown, CSV, and Modern Console."""

    @staticmethod
    def to_json(report: ScanReport, indent: int = 2) -> str:
        """Formats report as standardized JSON string."""
        return json.dumps(report.to_dict(), indent=indent)

    @staticmethod
    def to_csv(report: ScanReport) -> str:
        """Exports all findings into a structured CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")

        # CSV Header
        writer.writerow([
            "Finding_ID",
            "Type",
            "Category",
            "Severity",
            "Confidence",
            "File_Path",
            "Line_Number",
            "Title",
            "Description",
            "Code_Snippet",
            "Remediation",
            "Metadata"
        ])

        for f in report.findings:
            meta_str = json.dumps(f.metadata) if f.metadata else ""
            writer.writerow([
                f.id,
                f.finding_type,
                f.category,
                f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                f.file_path,
                f.line_number or "",
                f.title,
                f.description,
                f.snippet or "",
                f.remediation or "",
                meta_str
            ])

        return output.getvalue()

    @staticmethod
    def to_markdown(report: ScanReport, lang: str = "en") -> str:
        """Formats report as detailed Markdown document in English or Indonesian."""
        from sidik.i18n import get_secret_remediation, get_dependency_remediation
        s = report.summary
        is_id = (lang.lower() == "id")

        title_sub = "### Laporan Otomatis Analisis Keamanan & Audit Kerentanan" if is_id else "### Automated Security Assessment & Vulnerability Audit Report"
        sum_heading = "## Ringkasan Eksekutif" if is_id else "## Summary"
        findings_heading = "## Temuan Keamanan" if is_id else "## Findings"
        detailed_heading = "### Rincian Temuan & Rekomendasi" if is_id else "### Detailed Findings"
        clean_msg = "*Tidak ditemukan kerentanan atau kebocoran kredensial pada target.*" if is_id else "*No security issues detected.*"

        lbl_target = "Path Target" if is_id else "Target Path"
        lbl_time = "Waktu Pemindaian" if is_id else "Scan Timestamp"
        lbl_files = "Berkas Dipindai" if is_id else "Files Scanned"
        lbl_secrets = "Secrets Ditemukan" if is_id else "Secrets Found"
        lbl_deps = "Kerentanan Dependensi" if is_id else "Vulnerabilities Found"
        lbl_duration = "Durasi Pemindaian" if is_id else "Scan Duration"
        lbl_memory = "Konsumsi Memori" if is_id else "Peak Memory"

        table_header = "| # | Tipe | Kategori | Tingkat Bahaya | Confidence | Lokasi | Detail |" if is_id else "| # | Type | Category | Severity | Confidence | Location | Detail |"
        lbl_category = "Kategori" if is_id else "Category"
        lbl_conf = "Confidence" if is_id else "Confidence"
        lbl_file = "Berkas" if is_id else "File"
        lbl_line = "Baris" if is_id else "Line"
        lbl_code = "Kode" if is_id else "Code"
        lbl_desc = "Deskripsi" if is_id else "Description"
        lbl_remed = "Rekomendasi Perbaikan" if is_id else "Remediation"

        md = [
            "# 🛡️ SIDIK: Secret Identification and Dependency Inspection Kit",
            title_sub,
            "",
            sum_heading,
            f"- **{lbl_target}:** `{s.target_path}`",
            f"- **{lbl_time}:** `{s.timestamp}`",
            f"- **{lbl_files}:** {s.total_files_scanned}",
            f"- **{lbl_secrets}:** {s.total_secrets_found}",
            f"- **{lbl_deps}:** {s.total_vulnerabilities_found}",
            f"- **{lbl_duration}:** {s.scan_duration_seconds}s",
            f"- **{lbl_memory}:** {s.peak_memory_mb} MB",
            "",
            "---",
            "",
            findings_heading,
            ""
        ]

        if not report.findings:
            md.append(clean_msg)
            return "\n".join(md)

        md.append(table_header)
        md.append("|---|---|---|---|---|---|---|")

        for idx, f in enumerate(report.findings, start=1):
            loc = f"`{f.file_path}`"
            if f.line_number:
                loc += f":{f.line_number}"
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            md.append(f"| {idx} | {f.finding_type} | {f.category} | **{sev_str}** | {conf_str} | {loc} | {f.title} |")

        md.append("")
        md.append(detailed_heading)
        for idx, f in enumerate(report.findings, start=1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            conf_str = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            md.append(f"#### {idx}. [{sev_str}] {f.title}")
            md.append(f"- **{lbl_category}:** {f.category}")
            md.append(f"- **{lbl_conf}:** {conf_str}")
            md.append(f"- **{lbl_file}:** `{f.file_path}` ({lbl_line}: {f.line_number or 'N/A'})")
            if f.snippet:
                md.append(f"- **{lbl_code}:** `{f.snippet}`")
            md.append(f"- **{lbl_desc}:** {f.description}")

            # Localize remediation if possible
            remediation_text = f.remediation
            if f.finding_type == "secret" and "rule_id" in f.metadata:
                remediation_text = get_secret_remediation(f.metadata["rule_id"], lang=lang) or f.remediation
            elif f.finding_type == "dependency" and "cve" in f.metadata:
                remediation_text = get_dependency_remediation(
                    package_name=f.metadata.get("package", ""),
                    cve_id=f.metadata.get("cve", ""),
                    fixed_version=f.metadata.get("fixed_version"),
                    manifest_file=None,
                    lang=lang
                ) or f.remediation

            if remediation_text:
                md.append(f"- **{lbl_remed}:** {remediation_text}")
            md.append("")

        return "\n".join(md)

    @staticmethod
    def to_console_summary(report: ScanReport, lang: str = "en", use_color: Optional[bool] = None) -> str:
        """Renders modern, information-dense CLI output with ANSI styling and actionable remediation blocks."""
        s = report.summary
        is_id = (lang.lower() == "id")

        # Auto-detect color support
        if use_color is None:
            no_color = bool(os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb")
            use_color = sys.stdout.isatty() and not no_color

        # ANSI Color Palette
        if use_color:
            C_RESET = "\033[0m"
            C_BOLD = "\033[1m"
            C_DIM = "\033[2m"
            C_RED = "\033[91m"
            C_YELLOW = "\033[93m"
            C_BLUE = "\033[94m"
            C_GREEN = "\033[92m"
            C_CYAN = "\033[96m"
            C_WHITE = "\033[97m"
            C_BG_DARK = "\033[48;5;236m"
        else:
            C_RESET = C_BOLD = C_DIM = C_RED = C_YELLOW = C_BLUE = C_GREEN = C_CYAN = C_WHITE = C_BG_DARK = ""

        # Localized strings
        t_target = "Target:         " if not is_id else "Target:         "
        t_files = "Files Scanned:  " if not is_id else "Berkas Dipindai:"
        t_secrets = "Secrets:        " if not is_id else "Secrets:        "
        t_vulns = "Vulnerabilities:" if not is_id else "Kerentanan:     "
        t_dur = "Duration:       " if not is_id else "Durasi:         "
        t_mem = "Peak Memory:    " if not is_id else "Puncak Memori:  "
        t_sec_unit = "seconds" if not is_id else "detik"
        t_overview = "Findings Overview:" if not is_id else "Ikhtisar Temuan:"
        t_clean = "[OK] Clean! No security issues detected." if not is_id else "[OK] Bersih! Tidak ditemukan masalah keamanan."
        t_fix_lbl = "Fix / Remediation:" if not is_id else "Solusi / Rekomendasi:"

        # Severity breakdown tally
        crit_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "CRITICAL")
        high_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "HIGH")
        med_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "MEDIUM")
        low_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "LOW")

        border_w = 78
        lines = [
            f"{C_CYAN}{'=' * border_w}{C_RESET}",
            f"{C_BOLD}{C_WHITE} SIDIK: Secret Identification and Dependency Inspection Kit{C_RESET}",
            f"{C_CYAN}{'=' * border_w}{C_RESET}",
            f" {C_DIM}{t_target}{C_RESET} {C_WHITE}{s.target_path}{C_RESET}",
            f" {C_DIM}{t_files}{C_RESET} {s.total_files_scanned}    {C_DIM}{t_dur}{C_RESET} {s.scan_duration_seconds} {t_sec_unit}",
            f" {C_DIM}{t_secrets}{C_RESET} {s.total_secrets_found}       {C_DIM}{t_mem}{C_RESET} {s.peak_memory_mb} MB",
            f" {C_DIM}{t_vulns}{C_RESET} {s.total_vulnerabilities_found}",
            f"{C_DIM}{'-' * border_w}{C_RESET}",
            f" {C_BOLD}Status Severity:{C_RESET} "
            f"{C_RED}[CRITICAL: {crit_n}]{C_RESET} "
            f"{C_YELLOW}[HIGH: {high_n}]{C_RESET} "
            f"{C_BLUE}[MEDIUM: {med_n}]{C_RESET} "
            f"{C_GREEN}[LOW: {low_n}]{C_RESET}",
            f"{C_DIM}{'-' * border_w}{C_RESET}"
        ]

        if report.findings:
            lines.append(f" {C_BOLD}{t_overview}{C_RESET}")
            for idx, f in enumerate(report.findings, start=1):
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if sev_val == "CRITICAL":
                    c_sev = f"{C_BOLD}{C_RED}[CRITICAL]{C_RESET}"
                elif sev_val == "HIGH":
                    c_sev = f"{C_BOLD}{C_YELLOW}[HIGH    ]{C_RESET}"
                elif sev_val == "MEDIUM":
                    c_sev = f"{C_BOLD}{C_BLUE}[MEDIUM  ]{C_RESET}"
                else:
                    c_sev = f"{C_BOLD}{C_GREEN}[LOW     ]{C_RESET}"

                loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
                lines.append(f" [{idx:02d}] {c_sev} [{f.category:16s}] {f.title} -> {loc}")

                # Optional snippet and remediation block for rich information density
                if f.snippet:
                    clean_snip = f.snippet.strip().replace("\n", " ")
                    if len(clean_snip) > 65:
                        clean_snip = clean_snip[:62] + "..."
                    lines.append(f"      {C_DIM}Code:{C_RESET} `{clean_snip}`")

                if f.remediation:
                    rem_first_line = f.remediation.split(". ")[0] + "."
                    if len(rem_first_line) > 70:
                        rem_first_line = rem_first_line[:67] + "..."
                    lines.append(f"      {C_CYAN}{t_fix_lbl}{C_RESET} {C_DIM}{rem_first_line}{C_RESET}")
        else:
            lines.append(f" {C_GREEN}{t_clean}{C_RESET}")

        lines.append(f"{C_CYAN}{'=' * border_w}{C_RESET}")
        return "\n".join(lines)
