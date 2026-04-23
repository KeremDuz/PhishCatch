import requests
from urllib.parse import urlparse

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class UrlResolverScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="UrlResolver")

    def scan(self, url: str) -> StageResult:
        try:
            # Sadece başlıkları al, gövdeyi indirme (hız için)
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"}
            response = requests.head(url, allow_redirects=True, timeout=5, headers=headers)
            final_url = response.url

            if final_url != url:
                return StageResult(
                    scanner=self.name,
                    verdict="clean",
                    reason="URL redirected to a new destination",
                    details={
                        "original_url": url,
                        "resolved_url": final_url,
                        "status_code": response.status_code,
                    },
                )
            
            return StageResult(
                scanner=self.name,
                verdict="clean",
                reason="No redirects detected",
                details={
                    "original_url": url,
                    "resolved_url": final_url,
                },
            )

        except requests.RequestException as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                reason="Failed to resolve URL (network error or timeout)",
                details={"error": str(e), "resolved_url": url},
            )
