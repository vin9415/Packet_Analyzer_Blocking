#!/usr/bin/env python3
"""Start the DPI Engine web application.

Author: Vinit Kumar Pandey
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from web.app import app
from dpi.report import AUTHOR

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"DPI Web App by {AUTHOR}")
    print(f"Open http://127.0.0.1:{port} in your browser")
    app.run(host="0.0.0.0", port=port, debug=True)
