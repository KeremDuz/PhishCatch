from app.core.risk_aggregator import RiskAggregator
from app.core.scan_cache import ScannerResultCache
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.services.base_scanner import BaseScanner


EXTERNAL_REPUTATION_SCANNERS = {
    "URLhausScanner",
    "GoogleSafeBrowsing",
    "VirusTotalScanner",
}


class ScanningPipeline:
    def __init__(
        self,
        scanners: list[BaseScanner],
        risk_aggregator: RiskAggregator | None = None,
        scan_cache: ScannerResultCache | None = None,
        skip_html_on_confident_clean: bool = False,
        html_skip_max_prior_risk: float = 0.08,
    ) -> None:
        if not scanners:
            raise ValueError("ScanningPipeline requires at least one scanner")
        self.scanners = scanners
        self.risk_aggregator = risk_aggregator or RiskAggregator()
        self.scan_cache = scan_cache
        self.skip_html_on_confident_clean = skip_html_on_confident_clean
        self.html_skip_max_prior_risk = html_skip_max_prior_risk

    def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
        stages: list[StageResult] = []
        current_url = url
        fetch_safety_blocked = False

        for scanner in self.scanners:
            if fetch_safety_blocked and scanner.name in EXTERNAL_REPUTATION_SCANNERS:
                stages.append(
                    StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
                        risk_score=0.0,
                        reason="Skipped external reputation lookup because URL is not public-fetch safe",
                        details={"skipped": True, "skip_reason": "unsafe_url"},
                    )
                )
                continue

            if scanner.name == "HtmlScraper" and self._should_skip_html_scan(stages):
                stages.append(
                    StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
                        risk_score=0.0,
                        reason="Skipped HTML scan because earlier signals were confidently clean",
                        details={
                            "skipped": True,
                            "skip_reason": "confident_clean_prior_signals",
                            "prior_risk_score": self.risk_aggregator.aggregate(stages).risk_score,
                        },
                    )
                )
                continue

            stage_result = self._scan_with_cache(scanner, current_url)
            stages.append(stage_result)

            if stage_result.details.get("safety"):
                fetch_safety_blocked = True

            # Check if this scanner resolved to a new URL
            resolved_url = stage_result.details.get("resolved_url")
            if resolved_url and resolved_url != current_url:
                current_url = resolved_url

        decision = self.risk_aggregator.aggregate(stages)
        return AnalyzeUrlResponse(
            url=current_url,
            original_input=original_input,
            normalized_url=current_url,
            final_verdict=decision.final_verdict,
            confidence=decision.confidence,
            risk_score=decision.risk_score,
            malicious_probability=decision.malicious_probability,
            clean_probability=decision.clean_probability,
            decided_by="RiskAggregator",
            summary=decision.summary,
            signals=decision.signals,
            stages=stages,
        )

    def _scan_with_cache(self, scanner: BaseScanner, url: str) -> StageResult:
        if self.scan_cache is not None:
            cached = self.scan_cache.get(scanner.name, url)
            if cached is not None:
                return cached

        result = scanner.scan(url)
        if self.scan_cache is not None:
            self.scan_cache.set(scanner.name, url, result)
        return result

    def _should_skip_html_scan(self, stages: list[StageResult]) -> bool:
        if not self.skip_html_on_confident_clean:
            return False

        if not stages:
            return False

        prior_decision = self.risk_aggregator.aggregate(stages)
        if (prior_decision.risk_score or 0.0) > self.html_skip_max_prior_risk:
            return False

        has_clean_url_heuristic = any(
            stage.scanner == "URLHeuristicScanner" and stage.verdict == "clean"
            for stage in stages
        )
        has_confident_clean_ml = any(
            stage.scanner == "MLModelScanner"
            and stage.verdict == "clean"
            and stage.details.get("decision") == "confident_clean"
            for stage in stages
        )
        has_blocking_or_suspicious_signal = any(
            stage.verdict == "malicious"
            or (stage.risk_score is not None and stage.risk_score > self.html_skip_max_prior_risk)
            or bool(stage.details.get("safety"))
            for stage in stages
        )

        return has_clean_url_heuristic and has_confident_clean_ml and not has_blocking_or_suspicious_signal
