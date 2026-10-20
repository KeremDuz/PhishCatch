from __future__ import annotations

from dataclasses import dataclass
import hashlib
from threading import RLock
import time
from collections import OrderedDict

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
        if (
            scanner_name
            in {
                "GoogleSafeBrowsing",
                "GoogleWebRisk",
                "VirusTotalScanner",
                "URLhausScanner",
                "LocalPhishingFeed",
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
        digest = hashlib.sha256(
            f"{self.version}\0{scanner_name}\0{url}".encode("utf-8")
        ).hexdigest()
        return digest
