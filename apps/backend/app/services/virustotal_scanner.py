import base64
import threading

import requests

from app.core.config import Settings
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class VirusTotalScanner(BaseScanner):
    def __init__(self, settings: Settings) -> None:
        super().__init__(name="VirusTotalScanner")
        self.settings = settings
        self._api_key_index = 0
        self._api_key_lock = threading.Lock()

    def scan(self, url: str) -> StageResult:
        api_keys = self._api_keys()
        if not api_keys:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="VIRUSTOTAL_API_KEYS/VIRUSTOTAL_API_KEY not configured",
            )

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        ordered_key_indexes = self._ordered_key_indexes(len(api_keys))
        rate_limited_key_indexes: list[int] = []

        try:
            for attempted_keys, key_index in enumerate(ordered_key_indexes, start=1):
                headers = {"x-apikey": api_keys[key_index]}
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=self.settings.virustotal_timeout_seconds,
                )

                if response.status_code == 429:
                    rate_limited_key_indexes.append(key_index + 1)
                    self._advance_api_key_index(key_index, len(api_keys))
                    if attempted_keys < len(api_keys):
                        continue

                    return StageResult(
                        scanner=self.name,
                        verdict="unknown",
                        risk_score=0.0,
                        reason="VirusTotal rate limit reached for all configured API keys, fallback to ML",
                        details={
                            "status_code": 429,
                            "api_key_count": len(api_keys),
                            "attempted_keys": attempted_keys,
                            "rate_limited_key_indexes": rate_limited_key_indexes,
                        },
                    )

                self._remember_api_key_index(key_index, len(api_keys))
                request_details = self._request_details(
                    key_index=key_index,
                    api_key_count=len(api_keys),
                    attempted_keys=attempted_keys,
                    rate_limited_key_indexes=rate_limited_key_indexes,
                )
                break
            else:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="VirusTotal API keys not available",
                )

            if response.status_code == 404:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="URL not found in VirusTotal",
                    details={**request_details, "status_code": 404},
                )

            if response.status_code != 200:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="VirusTotal request failed, fallback to ML",
                    details={**request_details, "status_code": response.status_code},
                )

            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_hits = int(stats.get("malicious", 0))
            suspicious_hits = int(stats.get("suspicious", 0))

            if malicious_hits > 0 or suspicious_hits > 0:
                confidence = min(1.0, (malicious_hits + suspicious_hits) / 10)
                risk_score = min(0.95, max(0.65, ((malicious_hits * 2) + suspicious_hits) / 8))
                return StageResult(
                    scanner=self.name,
                    verdict="malicious",
                    confidence=round(confidence, 4),
                    risk_score=round(risk_score, 4),
                    reason="VirusTotal flagged URL",
                    details={**request_details, "analysis_stats": stats},
                )

            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="VirusTotal clean/unrated result, fallback to ML",
                details={**request_details, "analysis_stats": stats},
            )
        except requests.RequestException as exc:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="VirusTotal network error, fallback to ML",
                details={"error": str(exc), "api_key_count": len(api_keys)},
            )

    def _api_keys(self) -> list[str]:
        configured_keys = getattr(self.settings, "virustotal_api_keys", None) or []
        fallback_key = getattr(self.settings, "virustotal_api_key", None)
        keys = [fallback_key, *configured_keys]
        deduped_keys: list[str] = []
        seen: set[str] = set()

        for key in keys:
            clean_key = (key or "").strip()
            if clean_key and clean_key not in seen:
                deduped_keys.append(clean_key)
                seen.add(clean_key)

        return deduped_keys

    def _ordered_key_indexes(self, api_key_count: int) -> list[int]:
        with self._api_key_lock:
            start_index = self._api_key_index % api_key_count
        return [(start_index + offset) % api_key_count for offset in range(api_key_count)]

    def _advance_api_key_index(self, rate_limited_index: int, api_key_count: int) -> None:
        with self._api_key_lock:
            if self._api_key_index % api_key_count == rate_limited_index:
                self._api_key_index = (rate_limited_index + 1) % api_key_count

    def _remember_api_key_index(self, key_index: int, api_key_count: int) -> None:
        with self._api_key_lock:
            self._api_key_index = key_index % api_key_count

    @staticmethod
    def _request_details(
        *,
        key_index: int,
        api_key_count: int,
        attempted_keys: int,
        rate_limited_key_indexes: list[int],
    ) -> dict[str, object]:
        details: dict[str, object] = {
            "api_key_index": key_index + 1,
            "api_key_count": api_key_count,
            "attempted_keys": attempted_keys,
        }
        if rate_limited_key_indexes:
            details["rate_limited_key_indexes"] = list(rate_limited_key_indexes)
        return details
