from __future__ import annotations

import base64

import httpx

from app.models.scan_schemas import FastScanResponse


class VirusTotalFastScanner:
    def __init__(self, api_key: str | None, timeout_seconds: float = 4.0) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def scan(self, url: str) -> FastScanResponse:
        if not self.api_key:
            return self._mock_response(url)

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                )

            if response.status_code == 404:
                return FastScanResponse(
                    url=url,
                    normalized_url=url,
                    status="unknown",
                    risk_score=None,
                    reason="VirusTotal has no record for this URL.",
                )

            if response.status_code != 200:
                return FastScanResponse(
                    url=url,
                    normalized_url=url,
                    status="unknown",
                    risk_score=None,
                    reason=f"VirusTotal request failed with status {response.status_code}.",
                )

            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))

            if malicious > 0 or suspicious > 0:
                risk = min(100.0, float((malicious + suspicious) * 10))
                return FastScanResponse(
                    url=url,
                    normalized_url=url,
                    status="malicious",
                    risk_score=round(risk, 2),
                    reason="VirusTotal detected malicious/suspicious engines.",
                )

            return FastScanResponse(
                url=url,
                normalized_url=url,
                status="safe",
                risk_score=0.0,
                reason="VirusTotal shows clean/unrated result.",
            )
        except Exception as exc:
            return FastScanResponse(
                url=url,
                normalized_url=url,
                status="unknown",
                risk_score=None,
                reason=f"Fast scan failed: {exc}",
            )

    @staticmethod
    def _mock_response(url: str) -> FastScanResponse:
        suspicious_tokens = ["login", "verify", "secure", "account-update", "bank"]
        flagged = any(token in url.lower() for token in suspicious_tokens)
        if flagged:
            return FastScanResponse(
                url=url,
                normalized_url=url,
                status="malicious",
                risk_score=70.0,
                reason="Mock VT fast check flagged suspicious token pattern.",
            )
        return FastScanResponse(
            url=url,
            normalized_url=url,
            status="safe",
            risk_score=10.0,
            reason="Mock VT fast check found no suspicious indicators.",
        )
