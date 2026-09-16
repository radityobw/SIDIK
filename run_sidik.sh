#!/usr/bin/env bash
# ======================================================================
# SIDIK: Secret Identification and Dependency Inspection Kit
# Cross-Platform Launcher for Linux and macOS
# ======================================================================

set -e

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

# Detect Python 3 executable
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "Error: Python 3 is required but was not found in PATH."
    exit 1
fi

# Run GUI if no arguments, or pass arguments to sidik.py
if [ $# -eq 0 ]; then
    exec "$PY_CMD" sidik_gui.py
else
    exec "$PY_CMD" sidik.py "$@"
fi
