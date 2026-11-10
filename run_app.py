#!/usr/bin/env python3
"""SafeContain AI — Unified Full-Stack Application Launcher.

Launches the unified FastAPI backend and React single-page frontend
together on a single port (default: 8000). Automatically opens your default
web browser to the dashboard.
"""

import os
import sys
import time
import webbrowser
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def launch():
    port = int(os.environ.get("PORT", 8000))
    host = "127.0.0.1"
    url = f"http://{host}:{port}/"

    print("=" * 79)
    print("           SAFECONTAIN AI — UNIFIED ENTERPRISE LAUNCHER")
    print(f"             Live Full-Stack Dashboard: {url}")
    print(f"             Swagger OpenAPI Docs:      {url}docs")
    print(f"             Health Endpoint:           {url}api/v1/health")
    print("=" * 79)

    # Open browser automatically in background
    def _open_browser():
        time.sleep(2.0)
        print(f"\n[INFO] Opening {url} in your default browser...")
        webbrowser.open(url)

    import threading
    browser_thread = threading.Thread(target=_open_browser, daemon=True)
    browser_thread.start()

    try:
        import uvicorn
        uvicorn.run("backend.app.main:app", host=host, port=port, reload=False)
    except KeyboardInterrupt:
        print("\n[INFO] SafeContain AI stopped safely.")


if __name__ == "__main__":
    launch()
