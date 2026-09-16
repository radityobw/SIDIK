"""SIDIK: Secret Identification and Dependency Inspection Kit
Universal Root Launcher (CLI & Desktop GUI)
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def run():
    """Run CLI scanner if arguments provided, or launch Desktop GUI."""
    if len(sys.argv) == 1 or "--gui" in sys.argv:
        if "--gui" in sys.argv:
            sys.argv.remove("--gui")
        try:
            print("[*] Starting SIDIK Desktop GUI (Glassmorphic & Lightweight mode)...")
            print("[*] Tip: To run the CLI scanner directly, use: python sidik.py --target <path>\n")
            from sidik.gui import main as gui_main
            gui_main()
        except Exception as e:
            print(f"[!] GUI initialization notice ({e}). Falling back to CLI scanner:\n")
            from sidik.cli import main as cli_main
            cli_main()
    else:
        from sidik.cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    run()
