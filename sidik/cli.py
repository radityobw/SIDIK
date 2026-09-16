"""Command-line interface (CLI) for SIDIK: Secret Identification and Dependency Inspection Kit."""

import argparse
import sys
import os
from sidik.core import SecurityScanner
from sidik.reporting.formatter import ReportFormatter


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="sidik",
        description="SIDIK: Secret Identification and Dependency Inspection Kit (Lightweight Python Static Security Analyzer)"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Path to file or directory to scan"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write the report file"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["console", "json", "markdown", "csv"],
        default="console",
        help="Output report format: console, json, markdown, or csv (default: console)"
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
        help="Output language for console and markdown reports (default: id)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: Target path '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    scanner = SecurityScanner(
        enable_secret_scan=not args.dep_only,
        enable_dependency_scan=not args.secret_only,
        enable_context=not args.no_context,
        enable_entropy=not args.no_entropy
    )

    report = scanner.scan_path(args.target)

    # Format output
    if args.format == "json":
        output_text = ReportFormatter.to_json(report)
    elif args.format == "markdown":
        output_text = ReportFormatter.to_markdown(report, lang=args.lang)
    elif args.format == "csv":
        output_text = ReportFormatter.to_csv(report)
    else:
        output_text = ReportFormatter.to_console_summary(report, lang=args.lang, use_color=not args.no_color)

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"Scan complete. Report saved to: {args.output}")
    else:
        print(output_text)

    # Exit code: 1 if any findings discovered, else 0
    sys.exit(1 if report.findings else 0)


if __name__ == "__main__":
    main()
