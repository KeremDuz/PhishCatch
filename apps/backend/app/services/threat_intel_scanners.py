import requests

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.web_risk_scanner import GoogleWebRiskScanner as GoogleWebRiskScanner


class UrlhausScanner(BaseScanner):
    """abuse.ch URLhaus queries require an Auth-Key.
    
    Malware URL veritabanı. Bilinen kötücül URL'leri kontrol eder.
    Authentication: https://urlhaus.abuse.ch/api/
    """

    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, auth_key: str | None = None) -> None:
        super().__init__(name="URLhausScanner")
        self.auth_key = (auth_key or "").strip() or None

    def scan(self, url: str) -> StageResult:
        if not self.auth_key:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                status="unavailable",
                risk_score=None,
                reason="URLHAUS_AUTH_KEY is required but not configured",
                details={"auth_key_required": True, "auth_key_configured": False},
            )
        try:
            headers = {"Auth-Key": self.auth_key}
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

        except requests.RequestException:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="URLhaus network error",
                details={"error": "provider_request_failed"},
            )


class GoogleSafeBrowsingScanner(BaseScanner):
    """Legacy v4 adapter; not a promise of a current free quota or license.

    New deployments should select one licensed provider and use the bounded
    Web Risk adapter, or implement the v5 hash protocol for noncommercial use.
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
                self.API_URL,
                json=payload,
                headers={"x-goog-api-key": self.api_key},
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

        except requests.RequestException:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="Google Safe Browsing network error",
                details={"error": "provider_request_failed"},
            )
