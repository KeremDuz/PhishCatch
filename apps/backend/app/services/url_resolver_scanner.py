import requests
from urllib.parse import urljoin

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.url_safety import validate_public_http_url


class UrlResolverScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="UrlResolver")
        self.max_redirects = 5

    def scan(self, url: str) -> StageResult:
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/114.0.0.0 Safari/537.36"
                )
            }
            current_url = url
            redirect_chain = []
            status_code = None

            for _ in range(self.max_redirects + 1):
                safety = validate_public_http_url(current_url)
                if not safety.is_safe:
                    return StageResult(
                        scanner=self.name,
                        verdict="unknown",
                        reason=f"URL fetch blocked: {safety.reason}",
                        details={
                            "original_url": url,
                            "resolved_url": current_url,
                            "safety": safety.details or {},
                        },
                    )

                response = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=5,
                    headers=headers,
                )
                status_code = response.status_code

                if not response.is_redirect:
                    break

                location = response.headers.get("Location")
                if not location:
                    break

                next_url = urljoin(current_url, location)
                redirect_chain.append(
                    {
                        "from": current_url,
                        "to": next_url,
                        "status_code": status_code,
                    }
                )
                current_url = next_url
            else:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    reason="Maximum redirect depth exceeded",
                    details={
                        "original_url": url,
                        "resolved_url": current_url,
                        "redirect_chain": redirect_chain,
                    },
                )

            if current_url != url:
                return StageResult(
                    scanner=self.name,
                    verdict="clean",
                    reason="URL redirected to a new destination",
                    details={
                        "original_url": url,
                        "resolved_url": current_url,
                        "status_code": status_code,
                        "redirect_chain": redirect_chain,
                    },
                )

            return StageResult(
                scanner=self.name,
                verdict="clean",
                reason="No redirects detected",
                details={
                    "original_url": url,
                    "resolved_url": current_url,
                    "status_code": status_code,
                },
            )

        except requests.RequestException as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                reason="Failed to resolve URL (network error or timeout)",
                details={"error": str(e), "resolved_url": url},
            )
