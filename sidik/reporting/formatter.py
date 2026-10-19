"""Formatters for scan reports: JSON, Markdown, CSV, and Modern Rich Terminal Table."""

import json
import io
import csv
import sys
import os
import html
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
    def to_html(report: ScanReport, lang: str = "en") -> str:
        """Formats report as a standalone, zero-dependency interactive HTML assessment report."""
        from sidik.i18n import get_secret_remediation, get_dependency_remediation
        s = report.summary
        is_id = (lang.lower() == "id")

        # Localized strings
        doc_title = "SIDIK - Laporan Audit Keamanan" if is_id else "SIDIK - Security Assessment Report"
        app_sub = "Instrumen Analisis Keamanan Statis & Analisis Komposisi Perangkat Lunak" if is_id else "Static Application Security Testing & Software Composition Analysis"
        lbl_target = "Path Target" if is_id else "Target Path"
        lbl_time = "Waktu Pemindaian" if is_id else "Scan Timestamp"
        lbl_files = "Berkas Dipindai" if is_id else "Files Scanned"
        lbl_secrets = "Secrets" if is_id else "Secrets Found"
        lbl_deps = "Kerentanan SCA" if is_id else "Vulnerabilities"
        lbl_duration = "Durasi" if is_id else "Duration"
        lbl_memory = "Puncak Memori" if is_id else "Peak Memory"
        lbl_total = "Total Temuan" if is_id else "Total Findings"

        lbl_search_ph = "Ketik kata kunci (ID, file, judul, kode)..." if is_id else "Filter findings (ID, file, title, code)..."
        lbl_all_sev = "Semua Tingkat Bahaya" if is_id else "All Severities"
        lbl_all_type = "Semua Tipe Temuan" if is_id else "All Types"
        lbl_type_sec = "Secret / Kredensial" if is_id else "Secrets Only"
        lbl_type_dep = "Kerentanan Dependensi" if is_id else "Dependencies Only"
        lbl_showing = "Menampilkan" if is_id else "Showing"
        lbl_of = "dari" if is_id else "of"
        lbl_findings_unit = "temuan" if is_id else "findings"
        lbl_no_match = "Tidak ada temuan yang cocok dengan kriteria filter." if is_id else "No findings match the current filter criteria."
        lbl_clean = "Bersih! Tidak ditemukan kebocoran kredensial rahasia atau kerentanan dependensi." if is_id else "Clean! No hardcoded secrets or vulnerable dependencies detected."
        lbl_copy_code = "Salin Kode" if is_id else "Copy Code"
        lbl_copy_rem = "Salin Solusi" if is_id else "Copy Fix"
        lbl_rem_title = "Rekomendasi Perbaikan & Mitigasi:" if is_id else "Remediation & Mitigation Guidance:"
        lbl_location = "Lokasi Berkas:" if is_id else "File Location:"

        # Severity tallies
        crit_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper() == "CRITICAL")
        high_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper() == "HIGH")
        med_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper() == "MEDIUM")
        low_n = sum(1 for f in report.findings if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper() == "LOW")
        total_n = len(report.findings)

        # Build cards HTML
        cards_html = []
        for idx, f in enumerate(report.findings, start=1):
            sev_val = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
            conf_val = (f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)).upper()
            ftype = f.finding_type.lower()
            loc_str = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path

            # Localize remediation
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

            snippet_block = ""
            if f.snippet:
                escaped_snip = html.escape(f.snippet)
                raw_snip_js = html.escape(json.dumps(f.snippet))
                snippet_block = f"""
                <div class="code-box">
                    <div class="code-header">
                        <span>Snippet</span>
                        <button class="btn-copy" onclick='copyToClipboard(this, {raw_snip_js})'>{lbl_copy_code}</button>
                    </div>
                    <pre><code>{escaped_snip}</code></pre>
                </div>
                """

            remediation_block = ""
            if remediation_text:
                escaped_rem = html.escape(remediation_text)
                raw_rem_js = html.escape(json.dumps(remediation_text))
                remediation_block = f"""
                <div class="remediation-box">
                    <div class="rem-header">
                        <strong>🛡️ {lbl_rem_title}</strong>
                        <button class="btn-copy" onclick='copyToClipboard(this, {raw_rem_js})'>{lbl_copy_rem}</button>
                    </div>
                    <p>{escaped_rem}</p>
                </div>
                """

            card = f"""
            <div class="finding-card sev-{sev_val.lower()}" data-severity="{sev_val}" data-type="{ftype}">
                <div class="card-top">
                    <div class="badges">
                        <span class="badge badge-sev badge-{sev_val.lower()}">{sev_val}</span>
                        <span class="badge badge-type">{f.finding_type.upper()}</span>
                        <span class="badge badge-cat">{html.escape(f.category)}</span>
                        <span class="badge badge-conf">{conf_val} CONFIDENCE</span>
                    </div>
                    <div class="finding-id">#{idx} | {html.escape(f.id)}</div>
                </div>
                <h3 class="finding-title">{html.escape(f.title)}</h3>
                <div class="finding-loc"><strong>{lbl_location}</strong> <code>{html.escape(loc_str)}</code></div>
                <p class="finding-desc">{html.escape(f.description)}</p>
                {snippet_block}
                {remediation_block}
            </div>
            """
            cards_html.append(card)

        findings_body = "\n".join(cards_html) if cards_html else f'<div class="clean-box">🎉 {lbl_clean}</div>'

        return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(doc_title)}</title>
    <style>
        :root {{
            --bg: #0a0d12;
            --bg-card: #13181f;
            --bg-card-alt: #171d27;
            --border: #21293a;
            --text-main: #e2e8f0;
            --text-muted: #94a3b8;
            --primary: #3b82f6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --high: #f97316;
            --purple: #a78bfa;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #13181f 0%, #171d27 100%);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header-title h1 {{ font-size: 22px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }}
        .header-title p {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
        .header-meta {{ font-size: 12px; color: var(--text-muted); text-align: right; line-height: 1.6; }}
        .header-meta code {{ background: #080b0f; padding: 2px 6px; border-radius: 4px; color: var(--primary); }}

        /* Metrics grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px 16px;
            text-align: center;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        .metric-card:hover {{ transform: translateY(-2px); border-color: #3b82f6; }}
        .metric-val {{ font-size: 24px; font-weight: 700; color: #fff; margin-bottom: 2px; }}
        .metric-lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}
        .val-crit {{ color: var(--danger); }}
        .val-high {{ color: var(--high); }}
        .val-med {{ color: var(--warning); }}
        .val-low {{ color: var(--primary); }}

        /* Controls */
        .controls-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 24px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
        }}
        .filters-group {{ display: flex; gap: 10px; flex-wrap: wrap; flex: 1; }}
        input[type="text"], select {{
            background: #080b0f;
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 13px;
            outline: none;
        }}
        input[type="text"] {{ min-width: 260px; flex: 1; }}
        input[type="text"]:focus, select:focus {{ border-color: var(--primary); }}
        .count-badge {{ font-size: 12px; color: var(--text-muted); font-weight: 500; }}

        /* Finding Card */
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-left: 4px solid var(--primary);
            border-radius: 12px;
            padding: 18px 20px;
            margin-bottom: 16px;
            transition: background 0.15s ease;
        }}
        .finding-card.sev-critical {{ border-left-color: var(--danger); }}
        .finding-card.sev-high {{ border-left-color: var(--high); }}
        .finding-card.sev-medium {{ border-left-color: var(--warning); }}
        .finding-card.sev-low {{ border-left-color: var(--primary); }}
        .finding-card:hover {{ background: var(--bg-card-alt); }}

        .card-top {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }}
        .badges {{ display: flex; gap: 6px; flex-wrap: wrap; }}
        .badge {{ font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 6px; letter-spacing: 0.5px; text-transform: uppercase; }}
        .badge-sev.badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-sev.badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-sev.badge-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-sev.badge-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-type {{ background: #1e293b; color: #94a3b8; border: 1px solid #334155; }}
        .badge-cat {{ background: rgba(167, 139, 250, 0.15); color: #c4b5fd; border: 1px solid rgba(167, 139, 250, 0.3); }}
        .badge-conf {{ background: #0f172a; color: #64748b; border: 1px solid #1e293b; }}
        .finding-id {{ font-size: 11px; font-family: monospace; color: var(--text-muted); }}

        .finding-title {{ font-size: 16px; font-weight: 600; color: #fff; margin-bottom: 6px; }}
        .finding-loc {{ font-size: 12px; color: var(--text-muted); margin-bottom: 8px; }}
        .finding-loc code {{ color: #38bdf8; background: #080b0f; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
        .finding-desc {{ font-size: 13px; color: #cbd5e1; margin-bottom: 12px; }}

        /* Code box */
        .code-box {{ background: #080b0f; border: 1px solid #1e293b; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
        .code-header {{ display: flex; justify-content: space-between; align-items: center; padding: 6px 12px; background: #0d1218; font-size: 11px; color: var(--text-muted); border-bottom: 1px solid #1e293b; }}
        .code-box pre {{ padding: 10px 12px; margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; color: #f87171; overflow-x: auto; }}

        /* Remediation Box */
        .remediation-box {{ background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.25); border-radius: 8px; padding: 12px 14px; font-size: 13px; color: #bfdbfe; }}
        .rem-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 12px; }}
        .remediation-box p {{ font-size: 12px; line-height: 1.5; color: #cbd5e1; margin: 0; }}

        .btn-copy {{
            background: #1e293b;
            color: #94a3b8;
            border: 1px solid #334155;
            padding: 3px 8px;
            border-radius: 5px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .btn-copy:hover {{ background: #334155; color: #fff; }}

        /* States */
        .clean-box {{ background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); color: #86efac; border-radius: 12px; padding: 32px; text-align: center; font-size: 16px; font-weight: 500; }}
        .no-match-box {{ display: none; background: var(--bg-card); border: 1px dashed var(--border); color: var(--text-muted); border-radius: 12px; padding: 24px; text-align: center; font-size: 14px; }}

        footer {{ text-align: center; margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 11px; color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🛡️ SIDIK <span>Security Report</span></h1>
                <p>{html.escape(app_sub)}</p>
            </div>
            <div class="header-meta">
                <div><strong>{lbl_target}:</strong> <code>{html.escape(s.target_path)}</code></div>
                <div><strong>{lbl_time}:</strong> {html.escape(s.timestamp)}</div>
            </div>
        </header>

        <section class="metrics-grid">
            <div class="metric-card">
                <div class="metric-val">{total_n}</div>
                <div class="metric-lbl">{lbl_total}</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-crit">{crit_n}</div>
                <div class="metric-lbl">Critical</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-high">{high_n}</div>
                <div class="metric-lbl">High</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-med">{med_n}</div>
                <div class="metric-lbl">Medium</div>
            </div>
            <div class="metric-card">
                <div class="metric-val val-low">{low_n}</div>
                <div class="metric-lbl">Low</div>
            </div>
            <div class="metric-card">
                <div class="metric-val">{s.total_files_scanned}</div>
                <div class="metric-lbl">{lbl_files}</div>
            </div>
            <div class="metric-card">
                <div class="metric-val">{s.scan_duration_seconds:.2f}s</div>
                <div class="metric-lbl">{lbl_duration}</div>
            </div>
            <div class="metric-card">
                <div class="metric-val">{s.peak_memory_mb:.1f} MB</div>
                <div class="metric-lbl">{lbl_memory}</div>
            </div>
        </section>

        <section class="controls-card">
            <div class="filters-group">
                <input type="text" id="search-input" placeholder="{html.escape(lbl_search_ph)}" oninput="filterFindings()">
                <select id="filter-sev" onchange="filterFindings()">
                    <option value="">{lbl_all_sev}</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                </select>
                <select id="filter-type" onchange="filterFindings()">
                    <option value="">{lbl_all_type}</option>
                    <option value="secret">{lbl_type_sec}</option>
                    <option value="dependency">{lbl_type_dep}</option>
                </select>
            </div>
            <div class="count-badge">
                {lbl_showing} <span id="count-visible">{total_n}</span> {lbl_of} <span id="count-total">{total_n}</span> {lbl_findings_unit}
            </div>
        </section>

        <section id="findings-container">
            {findings_body}
            <div id="no-match" class="no-match-box">{lbl_no_match}</div>
        </section>

        <footer>
            SIDIK (Secret Identification and Dependency Inspection Kit) &bull; Automated Security Audit Report &bull; {html.escape(s.timestamp)}
        </footer>
    </div>

    <script>
        function filterFindings() {{
            const query = (document.getElementById('search-input').value || '').toLowerCase().trim();
            const sev = (document.getElementById('filter-sev').value || '');
            const type = (document.getElementById('filter-type').value || '');
            const cards = document.querySelectorAll('.finding-card');
            let visible = 0;

            cards.forEach(card => {{
                const matchQuery = !query || card.innerText.toLowerCase().includes(query);
                const matchSev = !sev || card.getAttribute('data-severity') === sev;
                const matchType = !type || card.getAttribute('data-type') === type;
                if (matchQuery && matchSev && matchType) {{
                    card.style.display = '';
                    visible++;
                }} else {{
                    card.style.display = 'none';
                }}
            }});

            document.getElementById('count-visible').innerText = visible;
            const noMatch = document.getElementById('no-match');
            if (noMatch) {{
                noMatch.style.display = (visible === 0 && cards.length > 0) ? 'block' : 'none';
            }}
        }}

        function copyToClipboard(btn, text) {{
            if (!navigator.clipboard) {{
                const ta = document.createElement('textarea');
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showCopied(btn);
                return;
            }}
            navigator.clipboard.writeText(text).then(() => {{
                showCopied(btn);
            }}).catch(() => {{
                alert('Copy failed');
            }});
        }}

        function showCopied(btn) {{
            const orig = btn.innerText;
            btn.innerText = '✓ Copied';
            btn.style.borderColor = '#22c55e';
            btn.style.color = '#86efac';
            setTimeout(() => {{
                btn.innerText = orig;
                btn.style.borderColor = '';
                btn.style.color = '';
            }}, 1500);
        }}
    </script>
</body>
</html>
"""

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
