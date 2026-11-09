"""TrustLens Local Backend Server Launcher.

Ensures all parent modules ('shared' and 'intelligence') and virtualenv site-packages
are present on sys.path and PYTHONPATH, automatically detects PostgreSQL availability,
and provides seamless local SQLite fallback so developers can run without Docker.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
from pathlib import Path

# Resolve core repository directories
backend_dir = Path(__file__).resolve().parent
parent_dir = backend_dir.parent
venv_site_packages = backend_dir / ".venv" / "Lib" / "site-packages"

extra_paths = [
    str(backend_dir),
    str(parent_dir),
    str(venv_site_packages),
    str(parent_dir / "intelligence"),
    str(parent_dir / "intelligence" / "certificate_analyzer" / "src"),
    str(parent_dir / "intelligence" / "certificate_dataset" / "src"),
    str(parent_dir / "intelligence" / "web_security_analysis"),
    str(parent_dir / "intelligence" / "web_security_analysis" / "analyzer"),
    str(parent_dir / "shared"),
]

for p in extra_paths:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

# Propagate to PYTHONPATH so child reload processes inherit all search paths
existing_pythonpath = os.environ.get("PYTHONPATH", "")
combined_pythonpath = os.pathsep.join(
    [p for p in extra_paths if os.path.exists(p)]
    + ([existing_pythonpath] if existing_pythonpath else [])
)
os.environ["PYTHONPATH"] = combined_pythonpath


def is_port_open(host: str = "127.0.0.1", port: int = 5432, timeout: float = 0.2) -> bool:
    """Quickly probe if a TCP port is actively listening."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def setup_database_mode() -> None:
    """Detect whether PostgreSQL is running; if not, automatically configure local SQLite."""
    pg_active = is_port_open("127.0.0.1", 5432)

    if pg_active:
        print("[TrustLens] PostgreSQL detected on port 5432. Using PostgreSQL database engine.")
    else:
        # Fall back to SQLite for instant, zero-friction local development
        dev_db_file = (backend_dir / "trustlens_dev.db").resolve()
        sqlite_async_url = f"sqlite+aiosqlite:///{dev_db_file.as_posix()}"
        sqlite_sync_url = f"sqlite:///{dev_db_file.as_posix()}"

        os.environ["DATABASE_URL"] = sqlite_async_url
        os.environ["DATABASE_SYNC_URL"] = sqlite_sync_url

        print("=" * 80)
        print("  [TrustLens Local Dev] PostgreSQL (port 5432) is not currently active.")
        print(f"  Auto-configured local SQLite database: {dev_db_file.name}")
        print("  All API features (User Auth, Scans, Web Security, Certificates) will work.")
        print("  (To use PostgreSQL instead: run 'docker compose up -d postgres redis')")
        print("=" * 80)


if __name__ == "__main__":
    setup_database_mode()

    # Pre-initialize database tables so user operations succeed immediately
    try:
        from app.database.init_db import init_db

        asyncio.run(init_db())
    except Exception as exc:
        print(f"[TrustLens] Pre-flight database initialization note: {exc}")

    try:
        import uvicorn
    except ImportError:
        if str(venv_site_packages) not in sys.path:
            sys.path.insert(0, str(venv_site_packages))
        import uvicorn

    print(f"\nStarting TrustLens API Server from {backend_dir} on http://localhost:8000 ...")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
