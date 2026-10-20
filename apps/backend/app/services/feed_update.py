"""Bounded PhishTank download/import; atomically replace private hash snapshot."""

from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.local_phishing_feed import MAX_FEED_ENTRIES, url_digest

MAX_COMPRESSED = 16 * 1024**2
MAX_DECODED = 64 * 1024**2


def decode_feed(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_COMPRESSED:
        raise ValueError("compressed_limit")
    decoder = bz2.BZ2Decompressor()
    decoded = bytearray()
    chunk = raw
    while True:
        decoded.extend(decoder.decompress(chunk, max_length=64 * 1024))
        if len(decoded) > MAX_DECODED:
            raise ValueError("decoded_limit")
        if decoder.eof:
            if decoder.unused_data:
                raise ValueError("trailing_data")
            break
        if decoder.needs_input:
            raise ValueError("truncated_feed")
        chunk = b""
    rows = json.loads(decoded)
    if not isinstance(rows, list) or len(rows) > MAX_FEED_ENTRIES:
        raise ValueError("entry_limit")
    hashes: set[str] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or row.get("verified") not in ("yes", True)
            or row.get("online") not in ("yes", True)
        ):
            continue
        try:
            hashes.add(url_digest(row.get("url")))
        except (ValueError, TypeError):
            continue
    if not hashes:
        raise ValueError("empty_verified_feed")
    return {
        "schema": "phishcatch-feed-1",
        "source": "phishtank",
        "fetched_at": datetime.now(UTC).isoformat(),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "url_sha256": sorted(hashes),
    }


def write_snapshot(snapshot: dict[str, object], target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    pending: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent, delete=False
        ) as stream:
            pending = Path(stream.name)
            os.chmod(pending, 0o600)
            json.dump(snapshot, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, target)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)


def download_feed(key_file: Path | None) -> bytes:
    key = key_file.read_text(encoding="utf-8").strip() if key_file else ""
    if key and not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", key):
        raise ValueError("invalid_key")
    source = f"https://data.phishtank.com/data/{key + '/' if key else ''}online-valid.json.bz2"
    request = Request(
        source,
        headers={
            "User-Agent": "PhishCatch/0.2 (+https://github.com/KeremDuz/PhishCatch)",
            "Accept-Encoding": "identity",
        },
    )
    with build_opener(ProxyHandler({})).open(request, timeout=15) as response:
        if response.geturl() != source:
            raise ValueError("unexpected_redirect")
        return response.read(MAX_COMPRESSED + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--download", action="store_true")
    source.add_argument("--input", type=Path)
    parser.add_argument("--app-key-file", type=Path)
    parser.add_argument(
        "--output", type=Path, default=PROJECT_ROOT / "data" / "phishing-feed.json"
    )
    args = parser.parse_args()
    try:
        if args.input:
            with args.input.open("rb") as stream:
                raw = stream.read(MAX_COMPRESSED + 1)
        else:
            raw = download_feed(args.app_key_file)
        snapshot = decode_feed(raw)
        write_snapshot(snapshot, args.output)
    except HTTPError as exc:
        print(
            f"Feed provider returned HTTP {exc.code}; previous snapshot preserved.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # noqa: BLE001 - never print URLs or application keys.
        print(
            f"Feed update failed ({type(exc).__name__}); previous snapshot preserved.",
            file=sys.stderr,
        )
        return 1
    print(f"Verified phishing snapshot updated: {len(snapshot['url_sha256'])} hashes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
