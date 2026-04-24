import requests

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class UrlhausScanner(BaseScanner):
    """abuse.ch URLhaus — query endpoint can be used without an API key.
    
    Malware URL veritabanı. Bilinen kötücül URL'leri kontrol eder.
    https://urlhaus-api.abuse.ch/
    """

    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, auth_key: str | None = None) -> None:
        super().__init__(name="URLhausScanner")
        self.auth_key = auth_key

    def scan(self, url: str) -> StageResult:
        try:
            headers = {"Auth-Key": self.auth_key} if self.auth_key else {}
            response = requests.post(
                self.API_URL,
                data={"url": url},
                headers=headers,
                timeout=5,
            )

            if response.status_code != 200:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason=f"URLhaus API error (status: {response.status_code})",
                    details={"status_code": response.status_code},
                )

            data = response.json()
            query_status = data.get("query_status", "")

            if query_status == "no_results":
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="URL not found in URLhaus database",
                    details={"query_status": query_status},
                )

            if query_status == "ok":
                threat = data.get("threat", "unknown")
                url_status = data.get("url_status", "unknown")
                tags = data.get("tags", [])

                return StageResult(
                    scanner=self.name,
                    verdict="malicious",
                    confidence=0.95,
                    risk_score=0.97,
                    reason=f"URLhaus: known malicious URL (threat: {threat}, status: {url_status})",
                    details={
                        "threat": threat,
                        "url_status": url_status,
                        "tags": tags,
                        "date_added": data.get("date_added"),
                    },
                )

            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason=f"URLhaus unexpected response: {query_status}",
                details={"query_status": query_status},
            )

        except requests.RequestException as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="URLhaus network error",
                details={"error": str(e)},
            )


class GoogleSafeBrowsingScanner(BaseScanner):
    """Google Safe Browsing API v4 — 10.000 sorgu/gün, ücretsiz.
    
    Google'ın kara listesini kontrol eder. VirusTotal'dan ~2x fazla limit.
    API key gerektirir (Google Cloud Console'dan alınır).
    https://developers.google.com/safe-browsing/v4
    """

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(name="GoogleSafeBrowsing")
        self.api_key = api_key

    def scan(self, url: str) -> StageResult:
        if not self.api_key:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="GOOGLE_SAFE_BROWSING_API_KEY not configured",
            )

        try:
            payload = {
                "client": {
                    "clientId": "phishcatch",
                    "clientVersion": "1.0.0",
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }

            response = requests.post(
                f"{self.API_URL}?key={self.api_key}",
                json=payload,
                timeout=5,
            )

            if response.status_code != 200:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason=f"Google Safe Browsing API error (status: {response.status_code})",
                    details={"status_code": response.status_code},
                )

            data = response.json()
            matches = data.get("matches", [])

            if not matches:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="URL not flagged by Google Safe Browsing",
                    details={"matches": 0},
                )

            # Tehdit bulundu
            threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
            return StageResult(
                scanner=self.name,
                verdict="malicious",
                confidence=0.95,
                risk_score=0.97,
                reason=f"Google Safe Browsing: flagged as {', '.join(threat_types)}",
                details={
                    "threat_types": threat_types,
                    "match_count": len(matches),
                },
            )

        except requests.RequestException as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="Google Safe Browsing network error",
                details={"error": str(e)},
            )
