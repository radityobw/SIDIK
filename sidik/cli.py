"""Command-line interface (CLI) for SIDIK: Secret Identification and Dependency Inspection Kit."""

import argparse
import sys
import os
from sidik.core import SecurityScanner
from sidik.reporting.formatter import ReportFormatter


def main():
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if callable(reconfig):
            try:
                reconfig(encoding="utf-8")
            except Exception:
                pass

    parser = argparse.ArgumentParser(
        prog="sidik",
        description="SIDIK: Secret Identification and Dependency Inspection Kit (Lightweight Python Static Security Analyzer)"
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Path to file or directory to scan (required unless --update-db or --db-info is used)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write the report file"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["console", "json", "markdown", "csv", "html"],
        default="console",
        help="Output report format: console, json, markdown, csv, or html (default: console)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output"
    )
    parser.add_argument(
        "--secret-only",
        action="store_true",
        help="Perform secret detection scan only"
    )
    parser.add_argument(
        "--dep-only",
        action="store_true",
        help="Perform dependency vulnerability scan only"
    )
    parser.add_argument(
        "--no-context",
        action="store_true",
        help="Disable context-aware filtering (for ablation testing)"
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable Shannon entropy evaluation (for ablation testing)"
    )
    parser.add_argument(
        "--lang",
        choices=["id", "en"],
        default="id",
        help="Output language for console, markdown, and html reports (default: id)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["any", "low", "medium", "high", "critical"],
        default="any",
        help="Exit code 1 threshold: any, low, medium, high, or critical (default: any)"
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Optional path to custom vulnerability database JSON file"
    )

    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Download the latest Google OSV PyPI advisories into the bundled offline database, then exit"
    )
    parser.add_argument(
        "--db-info",
        action="store_true",
        help="Show advisory database statistics (size, source, snapshot date), then exit"
    )

    args = parser.parse_args()

    if args.update_db:
        from sidik.dependency_analyzer import osv_import
        sys.exit(osv_import.main([]))

    if args.db_info:
        from sidik.dependency_analyzer.database import VulnerabilityDatabase
        db = VulnerabilityDatabase(args.db)
        print(f"Advisories : {db.advisory_count}")
        print(f"Packages   : {db.package_count}")
        print(f"Source     : {db.metadata.get('source', 'built-in only')}")
        print(f"Snapshot   : {db.metadata.get('generated_utc', 'N/A')}")
        sys.exit(0)

    if not args.target:
        parser.error("--target is required unless --update-db or --db-info is used")

    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    scanner = SecurityScanner(
        enable_secret_scan=not args.dep_only,
        enable_dependency_scan=not args.secret_only,
        enable_context=not args.no_context,
        enable_entropy=not args.no_entropy,
        custom_vulnerability_db=args.db
    )

    def cli_progress(current: int, total: int, filename: str):
        if args.format != "console":
            return
        if not sys.stdout.isatty():
            return
        bar_len = 24
        frac = (current / total) if total > 0 else 0.0
        filled = int(bar_len * frac)
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = frac * 100
        fname = filename if len(filename) <= 35 else "..." + filename[-32:]
        label = "Memindai" if args.lang == "id" else "Scanning"
        sys.stdout.write(f"\r\033[K[*] {label} [{bar}] {pct:5.1f}% ({current}/{total}) {fname}")
        sys.stdout.flush()

    report = scanner.scan_path(args.target, progress_callback=cli_progress)

    if args.format == "console" and sys.stdout.isatty():
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    # Format output
    if args.format == "json":
        output_text = ReportFormatter.to_json(report)
    elif args.format == "markdown":
        output_text = ReportFormatter.to_markdown(report, lang=args.lang)
    elif args.format == "csv":
        output_text = ReportFormatter.to_csv(report)
    elif args.format == "html":
        output_text = ReportFormatter.to_html(report, lang=args.lang)
    else:
        output_text = ReportFormatter.to_console_summary(report, lang=args.lang, use_color=not args.no_color)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"Scan complete. Report saved to: {args.output}")
    else:
        print(output_text)

    # Determine exit code based on --fail-on threshold
    SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    fail_on = args.fail_on.lower()
    has_failure = False

    if fail_on == "any":
        has_failure = bool(report.findings)
    else:
        threshold_rank = SEVERITY_ORDER.get(fail_on, 1)
        for f in report.findings:
            sev_str = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
            if SEVERITY_ORDER.get(sev_str, 0) >= threshold_rank:
                has_failure = True
                break

    sys.exit(1 if has_failure else 0)


if __name__ == "__main__":
    main()
