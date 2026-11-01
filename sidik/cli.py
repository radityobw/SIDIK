"""Command-line interface (CLI) and Interactive Terminal Console (TUI) for SIDIK."""

import argparse
import shlex
import stat
import subprocess
import sys
import os
from typing import Optional, List
from sidik.core import SecurityScanner
from sidik.models import ScanReport, Finding
from sidik.reporting.formatter import ReportFormatter
from sidik.i18n import get_secret_remediation, get_dependency_remediation

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


def _enable_windows_ansi() -> None:
    """Enables UTF-8 and ANSI Virtual Terminal sequences on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfig = getattr(stream, "reconfigure", None)
        if callable(reconfig):
            try:
                reconfig(encoding="utf-8")
            except Exception:
                pass
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def _copy_to_system_clipboard(text: str) -> bool:
    """Copies text to the OS clipboard from the CLI without requiring a GUI window."""
    if sys.platform == "win32":
        try:
            proc = subprocess.Popen(["clip"], stdin=subprocess.PIPE, close_fds=True)
            proc.communicate(input=text.encode("utf-16-le"))
            return proc.returncode == 0
        except Exception:
            pass
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
        return True
    except Exception:
        return False


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


def run_interactive_cli(initial_lang: str = "id") -> int:
    """Runs the interactive SIDIK CLI Window / Terminal User Interface (TUI)."""
    _enable_windows_ansi()
    if sys.platform == "win32":
        os.system("title SIDIK CLI v1.0 - Interactive Static Security Console")

    C_RESET = "\033[0m"
    C_BOLD = "\033[1m"
    C_DIM = "\033[2m"
    C_CYAN = "\033[96m"
    C_GREEN = "\033[92m"
    C_YELLOW = "\033[93m"
    C_RED = "\033[91m"
    C_PURPLE = "\033[95m"
    C_WHITE = "\033[97m"

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lang = initial_lang
    enable_context = True
    enable_entropy = True
    last_report: Optional[ScanReport] = None

    def print_banner():
        ctx_str = f"{C_GREEN}ON{C_RESET}" if enable_context else f"{C_RED}OFF{C_RESET}"
        ent_str = f"{C_GREEN}ON{C_RESET}" if enable_entropy else f"{C_RED}OFF{C_RESET}"
        last_str = (
            f"{len(last_report.findings)} temuan ({last_report.summary.scan_duration_seconds}s)"
            if last_report else ("Belum ada" if lang == "id" else "None")
        )
        print(f"\n{C_CYAN}╔════════════════════════════════════════════════════════════════════════════════╗{C_RESET}")
        print(f"{C_CYAN}║{C_RESET}  {C_BOLD}{C_WHITE}🛡️  SIDIK CLI v{VERSION} - Secret Identification & Dependency Inspection Kit{C_RESET}      {C_CYAN}║{C_RESET}")
        print(f"{C_CYAN}║{C_RESET}  {C_DIM}Lightweight Offline Python SAST & SCA | 29,208 OSV PyPI Advisories{C_RESET}           {C_CYAN}║{C_RESET}")
        print(f"{C_CYAN}╠════════════════════════════════════════════════════════════════════════════════╣{C_RESET}")
        print(f"{C_CYAN}║{C_RESET}  Bahasa: {C_BOLD}{lang.upper()}{C_RESET}  |  Filter Konteks: {ctx_str}  |  Entropi: {ent_str}  |  Scan Terakhir: {C_YELLOW}{last_str}{C_RESET}")
        print(f"{C_CYAN}╚════════════════════════════════════════════════════════════════════════════════╝{C_RESET}")
        if lang == "id":
            print(f"  {C_BOLD}[1]{C_RESET} 🔍 Pindai Folder / Berkas Kustom (Input Path)")
            print(f"  {C_BOLD}[2]{C_RESET} 📁 Preset: Uji Secrets Terkontrol (N=100 berkas | dataset/secrets/test)")
            print(f"  {C_BOLD}[3]{C_RESET} 📦 Preset: Uji Dependensi PyPI v2 (N=200 entri  | dataset/dependencies_v2/test)")
            print(f"  {C_BOLD}[4]{C_RESET} 🌐 Preset: 25 Repo GitHub Eksternal - Secret Only (1.193 berkas .py)")
            print(f"  {C_BOLD}[5]{C_RESET} 🌐 Preset: 25 Repo GitHub Eksternal - Full Scan (Secret + 45 Manifes)")
            print(f"  {C_BOLD}[6]{C_RESET} 🛡️  Preset: Audit Kode Sumber Internal SIDIK (sidik/)")
            print(f"  {C_BOLD}[7]{C_RESET} 📋 Aksi Hasil Scan: Salin Semua Kode / Salin Semua Remediasi / Ekspor Laporan")
            print(f"  {C_BOLD}[8]{C_RESET} ⚙️  Pengaturan: Toggle Konteks/Entropi, Bahasa (ID/EN), Info DB, Pre-Commit Hook")
            print(f"  {C_BOLD}[9]{C_RESET} 🖥️  Buka Antarmuka Desktop GUI (Windowed Mode)")
            print(f"  {C_BOLD}[0]{C_RESET} 🚪 Keluar  {C_DIM}(atau ketik perintah CLI langsung, misal: --target . --mode secret){C_RESET}")
        else:
            print(f"  {C_BOLD}[1]{C_RESET} 🔍 Scan Custom Folder / File Path")
            print(f"  {C_BOLD}[2]{C_RESET} 📁 Preset: Controlled Secret Test Set (N=100 files | dataset/secrets/test)")
            print(f"  {C_BOLD}[3]{C_RESET} 📦 Preset: PyPI Dependency Benchmark v2 (N=200     | dataset/dependencies_v2/test)")
            print(f"  {C_BOLD}[4]{C_RESET} 🌐 Preset: 25 External GitHub Repos - Secret Only (1,193 .py files)")
            print(f"  {C_BOLD}[5]{C_RESET} 🌐 Preset: 25 External GitHub Repos - Full Scan (Secrets + 45 Manifests)")
            print(f"  {C_BOLD}[6]{C_RESET} 🛡️  Preset: Self-Audit SIDIK Source Code (sidik/)")
            print(f"  {C_BOLD}[7]{C_RESET} 📋 Post-Scan Actions: Copy All Snippets / Copy All Remediations / Export Report")
            print(f"  {C_BOLD}[8]{C_RESET} ⚙️  Settings: Toggle Context/Entropy, Language (ID/EN), OSV DB Info, Git Hook")
            print(f"  {C_BOLD}[9]{C_RESET} 🖥️  Launch Desktop GUI Window")
            print(f"  {C_BOLD}[0]{C_RESET} 🚪 Exit    {C_DIM}(or type any CLI flags directly, e.g.: --target . --mode secret){C_RESET}")
        print(f"{C_DIM}{'─' * 82}{C_RESET}")

    def execute_scan(target: str, sec: bool = True, dep: bool = True):
        nonlocal last_report
        if not os.path.exists(target):
            print(f"{C_RED}[!] Path tidak ditemukan: {target}{C_RESET}")
            return
        scanner = SecurityScanner(
            enable_secret_scan=sec,
            enable_dependency_scan=dep,
            enable_context=enable_context,
            enable_entropy=enable_entropy
        )

        def progress(cur: int, tot: int, fname: str):
            bar_len = 24
            frac = (cur / tot) if tot > 0 else 0.0
            filled = int(bar_len * frac)
            bar = "█" * filled + "░" * (bar_len - filled)
            short_f = fname if len(fname) <= 35 else "..." + fname[-32:]
            sys.stdout.write(f"\r\033[K[*] [{bar}] {frac * 100:5.1f}% ({cur}/{tot}) {short_f}")
            sys.stdout.flush()

        report = scanner.scan_path(target, progress_callback=progress)
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        last_report = report
        print(ReportFormatter.to_console_summary(report, lang=lang, use_color=True))
        if report.findings:
            print(f" {C_PURPLE}💡 Tip:{C_RESET} Ketik {C_BOLD}7{C_RESET}, {C_BOLD}copy code{C_RESET}, {C_BOLD}copy rem{C_RESET}, atau {C_BOLD}export hasil.html{C_RESET} untuk menyalin/mengekspor seluruh temuan.")

    def copy_all_items(mode: str):
        if not last_report or not last_report.findings:
            print(f"{C_YELLOW}[!] Belum ada temuan untuk disalin. Jalankan pemindaian terlebih dahulu.{C_RESET}")
            return
        blocks = []
        for idx, f in enumerate(last_report.findings, 1):
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            if mode == "code":
                if f.snippet:
                    blocks.append(f"# [{idx}] {f.id} | {f.title} ({loc})\n{f.snippet}")
            else:
                rem = f.remediation or ""
                if f.finding_type == "secret" and "rule_id" in f.metadata:
                    rem = get_secret_remediation(f.metadata["rule_id"], lang=lang) or rem
                elif f.finding_type == "dependency" and "cve" in f.metadata:
                    rem = get_dependency_remediation(
                        package_name=f.metadata.get("package", ""),
                        cve_id=f.metadata.get("cve", ""),
                        fixed_version=f.metadata.get("fixed_version"),
                        manifest_file=os.path.basename(f.file_path) if f.file_path else None,
                        lang=lang
                    ) or rem
                if rem:
                    blocks.append(f"[{idx}] {f.id} | {f.title} ({loc})\n{rem}")
        if not blocks:
            print(f"{C_YELLOW}[!] Tidak ada konten yang tersedia untuk disalin.{C_RESET}")
            return
        ok = _copy_to_system_clipboard("\n\n".join(blocks))
        if ok:
            print(f"{C_GREEN}[OK] Berhasil menyalin {len(blocks)} item ke clipboard sistem!{C_RESET}")
        else:
            print(f"{C_RED}[!] Gagal mengakses clipboard sistem.{C_RESET}")

    def export_interactive(out_path: str):
        if not last_report:
            print(f"{C_YELLOW}[!] Belum ada hasil pemindaian untuk diekspor.{C_RESET}")
            return
        ext = os.path.splitext(out_path)[1].lower()
        if ext in (".html", ".htm"):
            content = ReportFormatter.to_html(last_report, lang=lang)
        elif ext == ".sarif":
            content = ReportFormatter.to_sarif(last_report)
        elif ext == ".json":
            content = ReportFormatter.to_json(last_report)
        elif ext == ".csv":
            content = ReportFormatter.to_csv(last_report)
        elif ext == ".md":
            content = ReportFormatter.to_markdown(last_report, lang=lang)
        else:
            content = ReportFormatter.to_console_summary(last_report, lang=lang, use_color=False)
        out_abs = os.path.abspath(out_path)
        os.makedirs(os.path.dirname(out_abs), exist_ok=True)
        with open(out_abs, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"{C_GREEN}[OK] Laporan berhasil disimpan ke: {out_abs}{C_RESET}")

    print_banner()

    while True:
        try:
            cmd_raw = input(f"\n{C_BOLD}{C_CYAN}sidik>{C_RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C_CYAN}[*] Menutup konsol SIDIK. Sampai jumpa!{C_RESET}")
            return 0

        if not cmd_raw:
            continue

        low = cmd_raw.lower()
        if low in ("0", "exit", "quit", "q"):
            print(f"{C_CYAN}[*] Menutup konsol SIDIK. Sampai jumpa!{C_RESET}")
            return 0
        elif low in ("menu", "help", "?", "cls", "clear"):
            if low in ("cls", "clear"):
                os.system("cls" if sys.platform == "win32" else "clear")
            print_banner()
        elif low == "1":
            t_in = input("  Masukkan path folder/berkas target [default: .]: ").strip() or "."
            m_in = input("  Pilih mode (all / secret / dep) [default: all]: ").strip().lower() or "all"
            execute_scan(t_in, sec=(m_in != "dep"), dep=(m_in != "secret"))
        elif low == "2":
            execute_scan(os.path.join(base_dir, "dataset", "secrets", "test"), sec=True, dep=False)
        elif low == "3":
            execute_scan(os.path.join(base_dir, "dataset", "dependencies_v2", "test"), sec=False, dep=True)
        elif low == "4":
            execute_scan(os.path.join(base_dir, "dataset", "external", "_repos"), sec=True, dep=False)
        elif low == "5":
            execute_scan(os.path.join(base_dir, "dataset", "external", "_repos"), sec=True, dep=True)
        elif low == "6":
            execute_scan(os.path.join(base_dir, "sidik"), sec=True, dep=True)
        elif low == "7":
            print(f"  {C_BOLD}[a]{C_RESET} Salin Semua Potongan Kode ({len(last_report.findings) if last_report else 0} flag) ke Clipboard")
            print(f"  {C_BOLD}[b]{C_RESET} Salin Semua Panduan Remediasi ({len(last_report.findings) if last_report else 0} flag) ke Clipboard")
            print(f"  {C_BOLD}[c]{C_RESET} Ekspor Laporan ke Berkas (.html, .sarif, .md, .json, .csv)")
            sub = input("  Pilih aksi [a/b/c]: ").strip().lower()
            if sub == "a":
                copy_all_items("code")
            elif sub == "b":
                copy_all_items("rem")
            elif sub == "c":
                f_out = input("  Nama berkas output [default: results/laporan_sidik.html]: ").strip() or os.path.join(base_dir, "results", "laporan_sidik.html")
                export_interactive(f_out)
        elif low == "8":
            print(f"  {C_BOLD}[a]{C_RESET} Toggle Filter Konteks Leksikal (Saat ini: {'ON' if enable_context else 'OFF'})")
            print(f"  {C_BOLD}[b]{C_RESET} Toggle Filter Entropi Shannon  (Saat ini: {'ON' if enable_entropy else 'OFF'})")
            print(f"  {C_BOLD}[c]{C_RESET} Ganti Bahasa Antarmuka         (Saat ini: {lang.upper()})")
            print(f"  {C_BOLD}[d]{C_RESET} Tampilkan Statistik Basis Data OSV Luring")
            print(f"  {C_BOLD}[e]{C_RESET} Pasang Git Pre-Commit Hook (.git/hooks/pre-commit)")
            sub = input("  Pilih pengaturan [a/b/c/d/e]: ").strip().lower()
            if sub == "a":
                enable_context = not enable_context
                print(f"{C_GREEN}[OK] Filter Konteks Leksikal: {'ON' if enable_context else 'OFF'}{C_RESET}")
            elif sub == "b":
                enable_entropy = not enable_entropy
                print(f"{C_GREEN}[OK] Filter Entropi Shannon: {'ON' if enable_entropy else 'OFF'}{C_RESET}")
            elif sub == "c":
                lang = "en" if lang == "id" else "id"
                print_banner()
            elif sub == "d":
                from sidik.dependency_analyzer.database import VulnerabilityDatabase
                db = VulnerabilityDatabase()
                print(f"  • Total Advisori OSV : {db.advisory_count}")
                print(f"  • Total Paket PyPI   : {db.package_count}")
                print(f"  • Sumber Basis Data  : {db.metadata.get('source', 'OSV PyPI')}")
            elif sub == "e":
                install_git_hook(".")
        elif low == "9":
            print(f"{C_CYAN}[*] Membuka jendela Desktop GUI SIDIK...{C_RESET}")
            from sidik.gui import main as gui_main
            gui_main()
        elif low == "copy code":
            copy_all_items("code")
        elif low == "copy rem":
            copy_all_items("rem")
        elif low.startswith("export "):
            export_interactive(cmd_raw[7:].strip())
        else:
            # Parse direct CLI command inside the interactive shell
            try:
                tokens = shlex.split(cmd_raw, posix=(sys.platform != "win32"))
                if tokens and tokens[0].lower() in ("sidik", "python"):
                    tokens = tokens[1:]
                run_cli_with_args(tokens, exit_on_finish=False)
            except SystemExit:
                pass
            except Exception as e:
                print(f"{C_RED}[!] Perintah tidak dikenali ({e}). Ketik 'menu' untuk melihat daftar opsi.{C_RESET}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sidik",
        description="SIDIK: Secret Identification and Dependency Inspection Kit (Lightweight Offline Python SAST & SCA)",
        epilog=(
            "Examples:\n"
            "  sidik -i                                        # Launch Interactive CLI Console Window (TUI)\n"
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
        "--interactive", "-i", "--cli",
        action="store_true",
        help="Launch interactive CLI console window (TUI menu & command shell)"
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
    return parser


def run_cli_with_args(argv: Optional[List[str]] = None, exit_on_finish: bool = True) -> int:
    _enable_windows_ansi()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.interactive:
        code = run_interactive_cli(initial_lang=args.lang)
        if exit_on_finish:
            sys.exit(code)
        return code

    if args.update_db:
        from sidik.dependency_analyzer import osv_import
        code = osv_import.main([])
        if exit_on_finish:
            sys.exit(code)
        return code

    if args.db_info:
        from sidik.dependency_analyzer.database import VulnerabilityDatabase
        db = VulnerabilityDatabase(args.db)
        print(f"Advisories : {db.advisory_count}")
        print(f"Packages   : {db.package_count}")
        print(f"Source     : {db.metadata.get('source', 'built-in only')}")
        print(f"Snapshot   : {db.metadata.get('generated_utc', 'N/A')}")
        if exit_on_finish:
            sys.exit(0)
        return 0

    # Resolve positional target (supports `sidik .` or `sidik scan .`)
    target_path = args.target
    if not target_path and args.positional_target:
        pos = list(args.positional_target)
        if pos[0].lower() == "scan":
            pos = pos[1:]
        target_path = pos[0] if pos else "."

    if args.install_hook:
        code = install_git_hook(target_path or ".")
        if exit_on_finish:
            sys.exit(code)
        return code

    # If invoked with zero arguments in an interactive terminal, launch the Interactive CLI Console!
    if not target_path:
        if sys.stdin.isatty() and sys.stdout.isatty() and exit_on_finish:
            code = run_interactive_cli(initial_lang=args.lang)
            sys.exit(code)
        parser.error("Target path is required (e.g., 'sidik .' or 'sidik --target <path>' or 'sidik -i')")

    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        if exit_on_finish:
            sys.exit(2)
        return 2

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

    code = 1 if has_failure else 0
    if exit_on_finish:
        sys.exit(code)
    return code


def main():
    run_cli_with_args()


if __name__ == "__main__":
    main()
