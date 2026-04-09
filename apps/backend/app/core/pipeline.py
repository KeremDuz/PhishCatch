from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.services.base_scanner import BaseScanner


class ScanningPipeline:
    def __init__(self, scanners: list[BaseScanner]) -> None:
        if not scanners:
            raise ValueError("ScanningPipeline requires at least one scanner")
        self.scanners = scanners

    def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
        stages: list[StageResult] = []

        for scanner in self.scanners:
            stage_result = scanner.scan(url)
            stages.append(stage_result)

            if scanner.should_halt(stage_result):
                return AnalyzeUrlResponse(
                    url=url,
                    original_input=original_input,
                    normalized_url=url,
                    final_verdict=stage_result.verdict,
                    confidence=stage_result.confidence,
                    malicious_probability=stage_result.malicious_probability,
                    clean_probability=stage_result.clean_probability,
                    decided_by=scanner.name,
                    stages=stages,
                )

        final_stage = stages[-1]
        return AnalyzeUrlResponse(
            url=url,
            original_input=original_input,
            normalized_url=url,
            final_verdict=final_stage.verdict,
            confidence=final_stage.confidence,
            malicious_probability=final_stage.malicious_probability,
            clean_probability=final_stage.clean_probability,
            decided_by=final_stage.scanner,
            stages=stages,
        )
