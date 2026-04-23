from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.services.base_scanner import BaseScanner


class ScanningPipeline:
    def __init__(self, scanners: list[BaseScanner]) -> None:
        if not scanners:
            raise ValueError("ScanningPipeline requires at least one scanner")
        self.scanners = scanners

    def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
        stages: list[StageResult] = []
        current_url = url

        for scanner in self.scanners:
            stage_result = scanner.scan(current_url)
            stages.append(stage_result)

            # Check if this scanner resolved to a new URL
            resolved_url = stage_result.details.get("resolved_url")
            if resolved_url and resolved_url != current_url:
                current_url = resolved_url

            if scanner.should_halt(stage_result):
                return AnalyzeUrlResponse(
                    url=current_url,
                    original_input=original_input,
                    normalized_url=current_url,
                    final_verdict=stage_result.verdict,
                    confidence=stage_result.confidence,
                    malicious_probability=stage_result.malicious_probability,
                    clean_probability=stage_result.clean_probability,
                    decided_by=scanner.name,
                    stages=stages,
                )

        final_stage = stages[-1]
        return AnalyzeUrlResponse(
            url=current_url,
            original_input=original_input,
            normalized_url=current_url,
            final_verdict=final_stage.verdict,
            confidence=final_stage.confidence,
            malicious_probability=final_stage.malicious_probability,
            clean_probability=final_stage.clean_probability,
            decided_by=final_stage.scanner,
            stages=stages,
        )
