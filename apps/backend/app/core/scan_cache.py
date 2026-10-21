from __future__ import annotations

import hashlib
import time
from urllib.parse import urlsplit
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock

from app.models.schemas import StageResult


@dataclass
class _CacheEntry:
    expires_at: float
    ttl_seconds: int
    result: StageResult


class ScannerResultCache:
    def __init__(
        self,
        ttl_seconds: int = 300,
        max_entries: int = 2048,
        version: str = "phishcatch-risk-v2",
    ) -> None:
        self.ttl_seconds = max(0, ttl_seconds)
        self.max_entries = max(1, max_entries)
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = RLock()
        self.version = version

    def purge_expired(self) -> None:
        with self._lock:
            now = time.monotonic()
            for key in [
                key for key, entry in self._entries.items() if entry.expires_at <= now
            ]:
                self._entries.pop(key, None)

    def get(self, scanner_name: str, url: str) -> StageResult | None:
        if self.ttl_seconds <= 0:
            return None

        key = self._key(scanner_name, url)
        self.purge_expired()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None

            self._entries.move_to_end(key)
            result = entry.result.model_copy(deep=True)
        result.details["cache"] = {
            "hit": True,
            "ttl_seconds": entry.ttl_seconds,
            "version": self.version,
        }
        return result

    def set(self, scanner_name: str, url: str, result: StageResult) -> None:
        if self.ttl_seconds <= 0:
            return

        # Missing evidence must recover promptly; raw page assessments must
        # correspond to the current GET artifact rather than a stale URL entry.
        self.purge_expired()
        if result.status != "completed" or scanner_name in {
            "UrlResolver",
            "HtmlScraper",
            "LocalPhishingFeed",
        }:
            return
        ttl = min(self.ttl_seconds, 300)
        if scanner_name == "CloudflareDnsSecurity":
            provider_ttl = result.details.get("provider_cache_ttl_seconds", 0)
            if type(provider_ttl) is not int or provider_ttl <= 0:
                return
            ttl = min(ttl, provider_ttl)
        # The provider's match expiry is an upper bound, even if our normal
        # cache lifetime is longer. Never turn an expired match into a hit.
        if scanner_name == "GoogleWebRisk" and result.verdict == "malicious":
            try:
                expires = datetime.fromisoformat(str(result.details["expire_time"]))
                if expires.tzinfo is None:
                    return
                ttl = min(ttl, max(0, int((expires - datetime.now(UTC)).total_seconds())))
            except (KeyError, ValueError, TypeError):
                return
            if ttl <= 0:
                return
        if (
            scanner_name
            in {
                "GoogleSafeBrowsing",
                "GoogleWebRisk",
                "VirusTotalScanner",
                "URLhausScanner",
                "LocalPhishingFeed",
                "CloudflareDnsSecurity",
            }
            and result.verdict != "malicious"
        ):
            ttl = min(ttl, 60)

        key = self._key(scanner_name, url)
        stored = result.model_copy(deep=True)
        stored.details["cache"] = {
            "hit": False,
            "ttl_seconds": ttl,
            "version": self.version,
        }
        with self._lock:
            self._entries[key] = _CacheEntry(
                expires_at=time.monotonic() + ttl,
                ttl_seconds=ttl,
                result=stored,
            )
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def _key(self, scanner_name: str, url: str) -> str:
        if scanner_name == "CloudflareDnsSecurity":
            # Domain context does not vary by URL path or query. This also
            # deduplicates same-host redirect hops without retaining raw URLs.
            try:
                url = (urlsplit(url).hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
            except (ValueError, UnicodeError):
                # Cache lookup must not bypass the scanner's unavailable result.
                url = "invalid-host\0" + url
        digest = hashlib.sha256(
            f"{self.version}\0{scanner_name}\0{url}".encode("utf-8")
        ).hexdigest()
        return digest
