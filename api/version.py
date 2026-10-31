"""
version.py - Which build this server runs, e.g. "dev+9151441 (2026-10-29)" or "0.1.0 (2026-11-02)".

The deploy writes BUILD_VERSION next to this file (scripts/version.sh). The API returns it in
/server-info and /health, so a client and the web UI can tell which code a server runs.
"""
import os

_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "BUILD_VERSION")


def _read() -> str:
    try:
        with open(_FILE, encoding="utf-8") as f:
            v = f.read().strip()
    except OSError:
        return "dev"
    return v[:80] or "dev"


VERSION = _read()
