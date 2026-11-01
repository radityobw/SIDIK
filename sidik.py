"""SIDIK: Secret Identification and Dependency Inspection Kit
Universal Root Launcher (Desktop GUI, Interactive CLI Window, & One-Shot CLI)
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def run():
    """Launch Desktop GUI if no args (or --gui), Interactive CLI Console if --cli/-i, or One-Shot CLI."""
    if len(sys.argv) == 1 or "--gui" in sys.argv:
        if "--gui" in sys.argv:
            sys.argv.remove("--gui")
        try:
            print("[*] Starting SIDIK Desktop GUI (Glassmorphic & Lightweight mode)...")
            print("[*] Tip: Use 'python sidik.py --cli' for Interactive CLI Window, or 'python sidik.py .' for direct scan.\n")
            from sidik.gui import main as gui_main
            gui_main()
        except Exception as e:
            print(f"[!] GUI initialization notice ({e}). Falling back to Interactive CLI Console:\n")
            from sidik.cli import run_interactive_cli
            run_interactive_cli()
    else:
        from sidik.cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    run()
