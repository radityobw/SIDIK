"""Command-line interface (CLI) for SIDIK: Secret Identification and Dependency Inspection Kit."""

import argparse
import sys
import os
import stat
from sidik.core import SecurityScanner
from sidik.reporting.formatter import ReportFormatter

VERSION = "1.0.0"

PRE_COMMIT_HOOK_SCRIPT = """#!/bin/sh
# SIDIK Automated Git Pre-Commit Security Hook
echo "[SIDIK] Running pre-commit shift-left security scan..."
python -m sidik.cli --target . --fail-on high --quiet
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "[SIDIK] Commit blocked: High/Critical security findings detected. Fix findings or use --no-verify to bypass."
    exit 1
fi
exit 0
"""


def install_git_hook(target_dir: str = ".") -> int:
    """Installs SIDIK as a native .git/hooks/pre-commit hook."""
    git_dir = os.path.join(os.path.abspath(target_dir), ".git")
    if not os.path.isdir(git_dir):
        print(f"Error: No .git directory found in '{os.path.abspath(target_dir)}'.", file=sys.stderr)
        return 2
    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-commit")
    with open(hook_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(PRE_COMMIT_HOOK_SCRIPT)
    try:
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC)
    except Exception:
        pass
    print(f"[OK] SIDIK pre-commit hook installed at: {hook_path}")
    return 0


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
        description="SIDIK: Secret Identification and Dependency Inspection Kit (Lightweight Offline Python SAST & SCA)",
        epilog=(
            "Examples:\n"
            "  sidik .                                         # Scan current directory (secrets + dependencies)\n"
            "  sidik dataset/external --mode secret            # Scan target in secret-only mode\n"
            "  sidik --target . --format sarif -o sidik.sarif  # Export SARIF v2.1.0 for GitHub Code Scanning\n"
            "  sidik --target . --format github --fail-on high # Emit inline GitHub Actions PR annotations\n"
            "  sidik --install-hook                            # Install native .git/hooks/pre-commit blocker"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "positional_target",
        nargs="*",
        help="Optional positional target path (e.g., 'sidik .' or 'sidik scan .')"
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Path to file or directory to scan"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path to write the report file"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["console", "json", "markdown", "csv", "html", "sarif", "github"],
        default="console",
        help="Output report format: console, json, markdown, csv, html, sarif, or github (default: console)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["all", "secret", "secrets", "dep", "deps", "dependency", "dependencies"],
        default="all",
        help="Scan mode: all (default), secret (secret scan only), or dep/dependency (dependency scan only)"
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
        "--severity", "-s",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Filter reported findings by minimum severity level (low, medium, high, critical)"
    )
    parser.add_argument(
        "--lang",
        choices=["id", "en"],
        default="id",
        help="Output language for console, markdown, and html reports (default: id)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "any", "low", "medium", "high", "critical"],
        default="any",
        help="Exit code 1 threshold: none, any, low, medium, high, or critical (default: any)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress interactive progress bar during scan"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"SIDIK v{VERSION} (Lightweight Offline SAST & SCA Security Scanner)"
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install SIDIK as a native Git pre-commit hook (.git/hooks/pre-commit)"
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

    # Resolve positional target (supports `sidik .` or `sidik scan .`)
    target_path = args.target
    if not target_path and args.positional_target:
        pos = list(args.positional_target)
        if pos[0].lower() == "scan":
            pos = pos[1:]
        target_path = pos[0] if pos else "."

    if args.install_hook:
        sys.exit(install_git_hook(target_path or "."))

    if not target_path:
        parser.error("Target path is required (e.g., 'sidik .' or 'sidik --target <path>')")

    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    mode_val = (args.mode or "all").lower()
    is_secret_only = args.secret_only or mode_val in ("secret", "secrets")
    is_dep_only = args.dep_only or mode_val in ("dep", "deps", "dependency", "dependencies")

    scanner = SecurityScanner(
        enable_secret_scan=not is_dep_only,
        enable_dependency_scan=not is_secret_only,
        enable_context=not args.no_context,
        enable_entropy=not args.no_entropy,
        custom_vulnerability_db=args.db
    )

    def cli_progress(current: int, total: int, filename: str):
        if args.quiet or args.format != "console":
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

    report = scanner.scan_path(target_path, progress_callback=cli_progress)

    if not args.quiet and args.format == "console" and sys.stdout.isatty():
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    # Optional minimum severity filtering (--severity)
    if args.severity:
        min_rank = SEVERITY_ORDER.get(args.severity.lower(), 1)
        filtered = [
            f for f in report.findings
            if SEVERITY_ORDER.get((f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower(), 0) >= min_rank
        ]
        report.findings = filtered
        report.summary.total_secrets_found = sum(1 for f in filtered if f.finding_type == "secret")
        report.summary.total_vulnerabilities_found = sum(1 for f in filtered if f.finding_type == "dependency")

    # Format output
    if args.format == "json":
        output_text = ReportFormatter.to_json(report)
    elif args.format == "markdown":
        output_text = ReportFormatter.to_markdown(report, lang=args.lang)
    elif args.format == "csv":
        output_text = ReportFormatter.to_csv(report)
    elif args.format == "html":
        output_text = ReportFormatter.to_html(report, lang=args.lang)
    elif args.format == "sarif":
        output_text = ReportFormatter.to_sarif(report)
    elif args.format == "github":
        output_text = ReportFormatter.to_github_annotations(report, lang=args.lang)
    else:
        output_text = ReportFormatter.to_console_summary(report, lang=args.lang, use_color=not args.no_color)

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        if not args.quiet:
            print(f"Scan complete. Report saved to: {args.output}")
    else:
        print(output_text)

    # Automatic GitHub Actions Job Summary ($GITHUB_STEP_SUMMARY)
    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as sf:
                sf.write(ReportFormatter.to_markdown(report, lang=args.lang) + "\n")
        except Exception:
            pass

    # Determine exit code based on --fail-on threshold
    fail_on = args.fail_on.lower()
    has_failure = False

    if fail_on == "none":
        has_failure = False
    elif fail_on == "any":
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
