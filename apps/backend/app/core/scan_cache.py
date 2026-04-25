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
    result: StageResult


class ScannerResultCache:
    def __init__(self, ttl_seconds: int = 900, max_entries: int = 2048) -> None:
        self.ttl_seconds = max(0, ttl_seconds)
        self.max_entries = max(1, max_entries)
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = RLock()

    def get(self, scanner_name: str, url: str) -> StageResult | None:
        if self.ttl_seconds <= 0:
            return None

        key = self._key(scanner_name, url)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None

            if entry.expires_at <= time.time():
                self._entries.pop(key, None)
                return None

            self._entries.move_to_end(key)
            result = entry.result.model_copy(deep=True)
        result.details["cache"] = {"hit": True, "ttl_seconds": self.ttl_seconds}
        return result

    def set(self, scanner_name: str, url: str, result: StageResult) -> None:
        if self.ttl_seconds <= 0:
            return

        key = self._key(scanner_name, url)
        stored = result.model_copy(deep=True)
        stored.details["cache"] = {"hit": False, "ttl_seconds": self.ttl_seconds}
        with self._lock:
            self._entries[key] = _CacheEntry(
                expires_at=time.time() + self.ttl_seconds,
                result=stored,
            )
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    @staticmethod
    def _key(scanner_name: str, url: str) -> str:
        digest = hashlib.sha256(f"{scanner_name}\0{url}".encode("utf-8")).hexdigest()
        return digest
