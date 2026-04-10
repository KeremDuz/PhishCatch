from __future__ import annotations

from functools import lru_cache

from fastapi import APIRouter

from app.core.config import settings
from app.models.scan_schemas import DeepScanResponse, FastScanResponse, ScanRequest
from app.services.fast_scanner import VirusTotalFastScanner
from app.services.ml_model_scanner import MLModelScanner


router = APIRouter(prefix="/api/v1/scan", tags=["Scan"])


@lru_cache(maxsize=1)
def get_fast_scanner() -> VirusTotalFastScanner:
    return VirusTotalFastScanner(
        api_key=settings.virustotal_api_key,
        timeout_seconds=float(settings.virustotal_timeout_seconds),
    )


@lru_cache(maxsize=1)
def get_deep_scanner() -> MLModelScanner:
    verify = settings.html_fetch_ca_bundle_path or settings.html_fetch_verify_ssl
    return MLModelScanner(
        model_path=settings.ml_champion_model_path,
        scaler_path=settings.ml_scaler_path,
        timeout_seconds=float(settings.html_fetch_timeout_seconds),
        malicious_threshold=float(settings.ml_malicious_threshold),
        verify_ssl=verify,
    )


@router.post("/fast", response_model=FastScanResponse)
async def scan_fast(payload: ScanRequest) -> FastScanResponse:
    result = await get_fast_scanner().scan(payload.url)
    result.original_input = payload.original_input
    result.normalized_url = payload.url
    result.url = payload.url
    return result


@router.post("/deep", response_model=DeepScanResponse)
async def scan_deep(payload: ScanRequest) -> DeepScanResponse:
    deep_result = await get_deep_scanner().scan(payload.url)
    return DeepScanResponse(
        url=payload.url,
        original_input=payload.original_input,
        normalized_url=payload.url,
        status=deep_result.status,
        risk_score=deep_result.risk_score,
        malicious_probability=deep_result.malicious_probability,
        confidence=deep_result.confidence,
        model_name=deep_result.model_name,
        html_fetched=deep_result.html_fetched,
        error=deep_result.error,
    )
