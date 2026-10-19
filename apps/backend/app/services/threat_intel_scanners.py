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


class GoogleWebRiskScanner(BaseScanner):
    """Google Cloud Web Risk Lookup API.

    Checks one URL against Google's Web Risk lists using the uris.search
    endpoint. Web Risk can be used as a stronger production reputation signal
    alongside Safe Browsing.
    """

    API_URL = "https://webrisk.googleapis.com/v1/uris:search"
    THREAT_TYPES = (
        "SOCIAL_ENGINEERING",
        "MALWARE",
        "UNWANTED_SOFTWARE",
    )

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(name="GoogleWebRisk")
        self.api_key = api_key

    def scan(self, url: str) -> StageResult:
        if not self.api_key:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="GOOGLE_WEB_RISK_API_KEY not configured",
            )

        try:
            params = [("threatTypes", threat_type) for threat_type in self.THREAT_TYPES]
            params.extend((("uri", url), ("key", self.api_key)))
            response = requests.get(self.API_URL, params=params, timeout=5)

            if response.status_code != 200:
                error_details = self._error_details(response)
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason=f"Google Web Risk API error (status: {response.status_code})",
                    details=error_details,
                )

            data = response.json()
            threat = data.get("threat") or {}
            threat_types = threat.get("threatTypes") or []

            if not threat_types:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="URL not flagged by Google Web Risk",
                    details={"matches": 0},
                )

            return StageResult(
                scanner=self.name,
                verdict="malicious",
                confidence=0.95,
                risk_score=0.97,
                reason=f"Google Web Risk: flagged as {', '.join(threat_types)}",
                details={
                    "threat_types": threat_types,
                    "expire_time": threat.get("expireTime"),
                },
            )

        except requests.RequestException as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0.0,
                reason="Google Web Risk network error",
                details={"error": str(e)},
            )

    @staticmethod
    def _error_details(response: requests.Response) -> dict[str, object]:
        details: dict[str, object] = {"status_code": response.status_code}
        try:
            error = response.json().get("error") or {}
        except ValueError:
            details["response"] = response.text[:200]
            return details

        if error.get("status"):
            details["status"] = error["status"]
        if error.get("message"):
            details["message"] = error["message"]

        for item in error.get("details") or []:
            if isinstance(item, dict) and item.get("reason"):
                details["reason"] = item["reason"]
                break
        return details
