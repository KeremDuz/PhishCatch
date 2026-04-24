import base64

import requests

from app.core.config import Settings
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class VirusTotalScanner(BaseScanner):
    def __init__(self, settings: Settings) -> None:
        super().__init__(name="VirusTotalScanner")
        self.settings = settings

    def scan(self, url: str) -> StageResult:
        if not self.settings.virustotal_api_key:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="VIRUSTOTAL_API_KEY not configured",
            )

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.settings.virustotal_api_key}

        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=self.settings.virustotal_timeout_seconds,
            )

            if response.status_code == 404:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="URL not found in VirusTotal",
                    details={"status_code": 404},
                )

            if response.status_code == 429:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="VirusTotal rate limit reached, fallback to ML",
                    details={"status_code": 429},
                )

            if response.status_code != 200:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="VirusTotal request failed, fallback to ML",
                    details={"status_code": response.status_code},
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
                    details={"analysis_stats": stats},
                )

            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="VirusTotal clean/unrated result, fallback to ML",
                details={"analysis_stats": stats},
            )
        except requests.RequestException as exc:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="VirusTotal network error, fallback to ML",
                details={"error": str(exc)},
            )
