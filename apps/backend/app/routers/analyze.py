from fastapi import APIRouter, Depends

from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline
from app.models.schemas import AnalyzeUrlRequest, AnalyzeUrlResponse

router = APIRouter(prefix="/api/v1", tags=["URL Analysis"])


@router.post("/analyze", response_model=AnalyzeUrlResponse)
def analyze_url(
    payload: AnalyzeUrlRequest,
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
) -> AnalyzeUrlResponse:
    return pipeline.run(payload.url, original_input=payload.original_input)
