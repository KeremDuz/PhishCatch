from __future__ import annotations

import asyncio
from functools import lru_cache

from fastapi import APIRouter

from app.core.config import settings
from app.models.scan_schemas import (
    BatchScanItem,
    BatchScanRequest,
    BatchScanResponse,
    DeepScanResponse,
    FastScanResponse,
    ScanRequest,
)
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
        feature_signals=deep_result.feature_signals,
        matched_brands=deep_result.matched_brands,
        brand_signal_score=deep_result.brand_signal_score,
        campaign_fingerprint=deep_result.campaign_fingerprint,
    )


@router.post("/batch", response_model=BatchScanResponse)
async def scan_batch(payload: BatchScanRequest) -> BatchScanResponse:
    normalized_requests = [ScanRequest(url=url) for url in payload.urls]

    if payload.mode == "fast":
        fast_scanner = get_fast_scanner()
        fast_results = await asyncio.gather(*(fast_scanner.scan(item.url) for item in normalized_requests))
        items = [
            BatchScanItem(
                url=item.url,
                original_input=item.original_input or item.url,
                normalized_url=item.url,
                tier="tier1_virustotal",
                status=result.status,
                risk_score=result.risk_score,
                reason=result.reason,
            )
            for item, result in zip(normalized_requests, fast_results, strict=False)
        ]
        return BatchScanResponse(mode="fast", total=len(items), results=items)

    deep_scanner = get_deep_scanner()
    deep_results = await asyncio.gather(*(deep_scanner.scan(item.url) for item in normalized_requests))
    items = [
        BatchScanItem(
            url=item.url,
            original_input=item.original_input or item.url,
            normalized_url=item.url,
            tier="tier2_ml_deep",
            status=result.status,
            risk_score=result.risk_score,
            malicious_probability=result.malicious_probability,
            confidence=result.confidence,
            model_name=result.model_name,
            html_fetched=result.html_fetched,
            error=result.error,
            feature_signals=result.feature_signals if payload.include_feature_signals else None,
            matched_brands=result.matched_brands,
            brand_signal_score=result.brand_signal_score,
            campaign_fingerprint=result.campaign_fingerprint,
        )
        for item, result in zip(normalized_requests, deep_results, strict=False)
    ]
    return BatchScanResponse(mode="deep", total=len(items), results=items)
