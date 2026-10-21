from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.page_fetch import FetchFailure, fetch_page


class UrlResolverScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="UrlResolver")

    def scan(self, url: str) -> StageResult:
        try:
            page = fetch_page(url)
            return StageResult(
                scanner=self.name,
                verdict="clean" if page.status_code < 400 else "unknown",
                status="completed" if page.status_code < 400 else "failed",
                risk_score=0.0,
                reason="GET target and redirect chain resolved"
                if page.status_code < 400
                else "Target returned an unsuccessful HTTP status",
                details=page.metadata(),
            )
        except FetchFailure as exc:
            details: dict[str, object] = {
                "error": exc.code,
                "resolved_url": exc.resolved_url or url,
                "redirect_chain": list(exc.redirect_chain),
            }
            if exc.safety is not None:
                details["safety"] = exc.safety
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                status="failed",
                reason="Page could not be retrieved safely",
                details=details,
            )
