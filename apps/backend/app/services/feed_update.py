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
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.local_phishing_feed import (
    MAX_FEED_ENTRIES,
    LocalPhishingFeed,
    url_digest,
)

MAX_COMPRESSED = 16 * 1024**2
MAX_DECODED = 64 * 1024**2
CDN_SOURCE = "https://cdn.phishtank.com/datadumps/verified_online.json.bz2"
CERTPL_SOURCE = "https://hole.cert.pl/domains/v2/domains.txt"


def is_feed_cdn_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "cdn.phishtank.com"
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
            and parsed.path == "/datadumps/verified_online.json.bz2"
            and not parsed.fragment
            and len(parsed.query) <= 1024
        )
    except ValueError:
        return False


class FeedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The official data endpoint redirects to this observed HTTPS CDN file.
        # Reject every downgrade, arbitrary redirect and credential destination.
        if not is_feed_cdn_url(newurl):
            raise ValueError("unexpected_feed_redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("unexpected_feed_redirect")


def decode_certpl(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_COMPRESSED:
        raise ValueError("feed_limit")
    hashes: set[str] = set()
    for value in raw.decode("utf-8-sig").splitlines():
        domain = value.strip().lower().rstrip(".")
        if not domain or domain.startswith("#"):
            continue
        domain = domain.encode("idna").decode("ascii")
        if (
            len(domain) > 253
            or "." not in domain
            or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in domain.split(".")
            )
        ):
            raise ValueError("invalid_feed_domain")
        hashes.add(hashlib.sha256(domain.encode()).hexdigest())
        if len(hashes) > MAX_FEED_ENTRIES:
            raise ValueError("entry_limit")
    if not hashes:
        raise ValueError("empty_feed")
    return {
        "schema": "phishcatch-feed-1",
        "source": "certpl",
        "fetched_at": datetime.now(UTC).isoformat(),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "domain_sha256": sorted(hashes),
    }


def download_certpl(etag: str | None = None) -> tuple[bytes | None, str | None]:
    request = Request(
        CERTPL_SOURCE,
        headers={
            "User-Agent": "PhishCatch/0.2 (+https://github.com/KeremDuz/PhishCatch)",
            "Accept-Encoding": "identity",
        },
    )
    if (
        isinstance(etag, str)
        and len(etag) <= 256
        and not any(c in etag for c in "\r\n")
    ):
        request.add_header("If-None-Match", etag)
    try:
        with build_opener(ProxyHandler({}), NoRedirectHandler()).open(
            request, timeout=15
        ) as response:
            return response.read(MAX_COMPRESSED + 1), response.headers.get("ETag")
    except HTTPError as exc:
        if exc.code == 304 and etag:
            return None, etag
        raise


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
    with build_opener(ProxyHandler({}), FeedRedirectHandler()).open(
        request, timeout=15
    ) as response:
        if response.geturl() != source and not is_feed_cdn_url(response.geturl()):
            raise ValueError("unexpected_redirect")
        return response.read(MAX_COMPRESSED + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--download", action="store_true")
    source.add_argument("--input", type=Path)
    parser.add_argument("--app-key-file", type=Path)
    parser.add_argument(
        "--provider", choices=("phishtank", "certpl"), default="phishtank"
    )
    parser.add_argument(
        "--output", type=Path, default=PROJECT_ROOT / "data" / "phishing-feed.json"
    )
    args = parser.parse_args()
    try:
        previous = None
        etag = None
        if args.input:
            with args.input.open("rb") as stream:
                raw = stream.read(MAX_COMPRESSED + 1)
        elif args.provider == "certpl":
            info = LocalPhishingFeed(args.output).health()
            if info.get("source") == "certpl" and info.get("entries"):
                previous = json.loads(args.output.read_text(encoding="utf-8"))
            raw, etag = download_certpl(
                previous.get("source_etag") if previous else None
            )
        else:
            raw = download_feed(args.app_key_file)
        if raw is None:
            if previous is None:
                raise ValueError("missing_previous_feed")
            snapshot = {**previous, "fetched_at": datetime.now(UTC).isoformat()}
        else:
            snapshot = (
                decode_certpl(raw) if args.provider == "certpl" else decode_feed(raw)
            )
        if etag is not None:
            snapshot["source_etag"] = etag
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
    print(
        f"Warning snapshot updated ({snapshot['source']}): {len(snapshot.get('url_sha256', snapshot.get('domain_sha256', [])))} hashes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
