"""Thin wrapper: download Google OSV PyPI advisories and write sidik/data/pypi_advisories.json.

Usage:
    python scripts/import_osv.py                  # download and convert
    python scripts/import_osv.py --input all.zip  # convert a local archive (offline)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sidik.dependency_analyzer.osv_import import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
