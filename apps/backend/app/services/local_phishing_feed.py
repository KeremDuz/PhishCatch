"""Private fresh hashes from a declared phishing/warning-list provider."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from urllib.parse import urlsplit, urlunsplit

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.utils.url_utils import canonicalize_url

MAX_FEED_BYTES = 24 * 1024**2
MAX_FEED_ENTRIES = 250_000


def url_digest(url: str) -> str:
    if not isinstance(url, str) or not 1 <= len(url) <= 2048:
        raise ValueError("invalid_url")
    parts = urlsplit(canonicalize_url(url))
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        raise ValueError("invalid_url")
    # Preserve path/query semantics; fragments are not sent to the HTTP server.
    value = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    return hashlib.sha256(value.encode()).hexdigest()


class LocalPhishingFeed(BaseScanner):
    def __init__(self, path: str | Path, max_age_hours: int = 26) -> None:
        super().__init__(name="LocalPhishingFeed")
        self.path = Path(path)
        self.max_age_hours = max(1, min(max_age_hours, 48))
        self._lock = RLock()
        self._signature: tuple[int, int] | None = None
        self._hashes: frozenset[str] = frozenset()
        self._fetched_at: datetime | None = None
        self._source = "unconfigured"

    def health(self) -> dict[str, object]:
        with self._lock:
            try:
                stat = self.path.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
                if signature != self._signature:
                    if stat.st_size > MAX_FEED_BYTES:
                        raise ValueError("feed_size")
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    source = data.get("source")
                    values = data[
                        "domain_sha256" if source == "certpl" else "url_sha256"
                    ]
                    fetched = datetime.fromisoformat(data["fetched_at"])
                    if (
                        data.get("schema") != "phishcatch-feed-1"
                        or source not in {"phishtank", "certpl"}
                        or fetched.tzinfo is None
                        or not isinstance(values, list)
                        or not 1 <= len(values) <= MAX_FEED_ENTRIES
                        or any(
                            not isinstance(v, str)
                            or len(v) != 64
                            or any(c not in "0123456789abcdef" for c in v)
                            for v in values
                        )
                    ):
                        raise ValueError("feed_schema")
                    self._hashes = frozenset(values)
                    self._fetched_at = fetched
                    self._signature = signature
                    self._source = source
                age = (datetime.now(UTC) - self._fetched_at).total_seconds()
                maximum_age = (
                    min(self.max_age_hours * 3600, 900)
                    if self._source == "certpl"
                    else self.max_age_hours * 3600
                )
                return {
                    "available": -300 <= age <= maximum_age,
                    "source": self._source,
                    "fetched_at": self._fetched_at.isoformat(),
                    "entries": len(self._hashes),
                    "age_seconds": round(age),
                }
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                self._signature = None
                self._hashes = frozenset()
                self._fetched_at = None
                return {"available": False, "source": self._source}

    def scan(self, url: str) -> StageResult:
        with self._lock:
            info = self.health()
            if info["available"] is not True:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    status="unavailable",
                    reason="Fresh warning feed unavailable",
                    details=info,
                )
            try:
                if self._source == "certpl":
                    host = urlsplit(canonicalize_url(url)).hostname or ""
                    labels = host.lower().rstrip(".").split(".")
                    matched = any(
                        hashlib.sha256(".".join(labels[index:]).encode()).hexdigest()
                        in self._hashes
                        for index in range(max(0, len(labels) - 1))
                    )
                else:
                    matched = url_digest(url) in self._hashes
            except ValueError:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    status="failed",
                    reason="Invalid feed lookup URL",
                )
            return StageResult(
                scanner=self.name,
                verdict="malicious" if matched else "unknown",
                risk_score=0.97 if matched else 0.0,
                reason="Known phishing/warning-list match"
                if matched
                else "No match in declared warning list",
                details={
                    **info,
                    "match_scope": "domain_and_subdomains"
                    if self._source == "certpl"
                    else "exact_url",
                    "matched": matched,
                },
            )
