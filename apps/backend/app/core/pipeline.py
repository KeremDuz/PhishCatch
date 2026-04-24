from app.core.risk_aggregator import RiskAggregator
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.services.base_scanner import BaseScanner


EXTERNAL_REPUTATION_SCANNERS = {
    "URLhausScanner",
    "GoogleSafeBrowsing",
    "VirusTotalScanner",
}


class ScanningPipeline:
    def __init__(self, scanners: list[BaseScanner], risk_aggregator: RiskAggregator | None = None) -> None:
        if not scanners:
            raise ValueError("ScanningPipeline requires at least one scanner")
        self.scanners = scanners
        self.risk_aggregator = risk_aggregator or RiskAggregator()

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

            stage_result = scanner.scan(current_url)
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
