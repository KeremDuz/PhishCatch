"""Command-line compatibility entry point for the container feed updater."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.feed_update import decode_feed, download_feed, main, write_snapshot

__all__ = ["decode_feed", "download_feed", "main", "write_snapshot"]

if __name__ == "__main__":
    raise SystemExit(main())
