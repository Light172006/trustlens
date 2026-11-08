"""TrustLens Local Backend Server Launcher.

Ensures all parent modules ('shared' and 'intelligence') are present on sys.path
and starts Uvicorn cleanly without manual environment variable configuration.
"""

import os
import sys
from pathlib import Path

# Add backend directory and parent directory (for shared & intelligence modules) to sys.path
backend_dir = Path(__file__).resolve().parent
parent_dir = backend_dir.parent

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

if __name__ == "__main__":
    import uvicorn

    print(f"Starting TrustLens API Server from {backend_dir}...")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

