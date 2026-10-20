from threading import BoundedSemaphore
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline
from app.models.public_analysis import PublicAnalysisRequest, PublicAnalysisResponse
from app.models.schemas import AnalyzeUrlResponse, StageResult, Verdict
from app.services.url_safety import validate_public_http_url

router = APIRouter(prefix="/api/v1/public", tags=["Public URL Analysis"])
_PUBLIC_SCAN_SLOT = BoundedSemaphore(1)


@router.post("/analyze", response_model=PublicAnalysisResponse)
def analyze_public_url(
    payload: PublicAnalysisRequest,
    pipeline: Annotated[ScanningPipeline, Depends(get_scanning_pipeline)],
) -> PublicAnalysisResponse:
    if not _PUBLIC_SCAN_SLOT.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Analysis is busy. Please try again shortly.",
            headers={"Retry-After": "10"},
        )

    try:
        try:
            safety = validate_public_http_url(payload.url)
        except Exception:  # noqa: BLE001 - redact diagnostics at the public boundary.
            raise HTTPException(
                status_code=400, detail="This URL cannot be analyzed."
            ) from None
        if not safety.is_safe:
            raise HTTPException(status_code=400, detail="This URL cannot be analyzed.")

        try:
            analysis = pipeline.run(payload.url, original_input=payload.url)
            return _public_result(analysis, payload.url)
        except Exception:  # noqa: BLE001 - redact diagnostics at the public boundary.
            raise HTTPException(
                status_code=503,
                detail="Analysis is temporarily unavailable. Please try again later.",
            ) from None
    finally:
        _PUBLIC_SCAN_SLOT.release()


def _public_result(
    analysis: AnalyzeUrlResponse, normalized_url: str
) -> PublicAnalysisResponse:
    status = analysis.scan_status
    verdict: Verdict = "unknown"
    if (
        analysis.contract_version != "2"
        or status not in {"complete", "partial", "failed"}
        or not analysis.stages
    ):
        status = "failed"
    else:
        completed = [stage for stage in analysis.stages if stage.status == "completed"]
        all_completed = len(completed) == len(analysis.stages)
        if status == "complete" and not all_completed:
            status = "partial" if completed else "failed"
        if analysis.final_verdict == "malicious" and any(
            _has_positive_evidence(stage) for stage in completed
        ):
            verdict = "malicious"
        elif (
            status == "complete" and all_completed and analysis.final_verdict == "clean"
        ):
            verdict = "clean"

    return PublicAnalysisResponse(
        url=normalized_url, final_verdict=verdict, scan_status=status
    )


def _has_positive_evidence(stage: StageResult) -> bool:
    return stage.scanner != "UrlResolver" and (
        stage.verdict == "malicious"
        or (stage.risk_score is not None and stage.risk_score > 0)
        or (
            stage.malicious_probability is not None
            and stage.malicious_probability >= 0.5
        )
    )
