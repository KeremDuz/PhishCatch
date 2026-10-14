import hmac
import logging
import math
import re
from numbers import Real
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from pydantic import ValidationError

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline, get_training_store
from app.ml.feature_extractor import URL_FEATURE_COLUMNS, extract_features_dict
from app.ml.html_feature_extractor import HTML_MODEL_FEATURE_COLUMNS
from app.models.schemas import (
    AllsafeAnalysisResponse,
    AnalyzeUrlRequest,
    AnalyzeUrlResponse,
    BatchAnalyzeItem,
    BatchAnalyzeResponse,
    BatchAnalyzeSummary,
    StageResult,
)
from app.storage import TrainingStore

router = APIRouter(prefix="/api/v1", tags=["URL Analysis"])
MAX_BATCH_FILE_BYTES = 512 * 1024
LOGGER = logging.getLogger(__name__)


@router.post("/analyze", response_model=AnalyzeUrlResponse)
def analyze_url(
    payload: AnalyzeUrlRequest,
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
    training_store: TrainingStore = Depends(get_training_store),
) -> AnalyzeUrlResponse:
    response = pipeline.run(payload.url, original_input=payload.original_input)
    response.observation_id = _record_observation_safely(
        response, training_store, source="user_scan"
    )
    return response


def require_allsafe_integration(
    x_integration_key: str | None = Header(default=None),
) -> None:
    configured = settings.allsafe_integration_key
    if configured is None:
        raise HTTPException(
            status_code=503, detail="ALLSAFE integration is not configured"
        )
    supplied = (x_integration_key or "").encode("utf-8")
    if not hmac.compare_digest(supplied, configured.get_secret_value().encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid integration credentials")


@router.get("/integrations/allsafe/health")
def allsafe_health(
    _: None = Depends(require_allsafe_integration),
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
) -> dict[str, str | bool]:
    def model_available(scanner_name: str) -> bool:
        scanner = next(
            (item for item in pipeline.scanners if item.name == scanner_name), None
        )
        model = getattr(scanner, "model", None)
        classes = list(getattr(model, "classes_", []))
        return (
            callable(getattr(model, "predict_proba", None))
            and len(classes) == 2
            and set(classes) == {0, 1}
        )

    return {
        "contract_version": "2",
        "status": "ok",
        "url_model_available": model_available("MLModelScanner"),
        "html_model_available": model_available("HtmlScraper"),
    }


@router.post("/integrations/allsafe/analyze", response_model=AllsafeAnalysisResponse)
def analyze_for_allsafe(
    payload: AnalyzeUrlRequest,
    _: None = Depends(require_allsafe_integration),
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
    training_store: TrainingStore = Depends(get_training_store),
) -> AllsafeAnalysisResponse:
    response = pipeline.run(payload.url, original_input=payload.original_input)
    response.observation_id = _record_observation_safely(
        response, training_store, source="allsafe_scan"
    )
    feature_url = _extract_final_url(response)
    features = _allowed_numeric_features(
        "url", extract_features_dict(feature_url), URL_FEATURE_COLUMNS
    )
    html_features = _extract_html_features(response.stages)
    if html_features:
        features.update(
            _allowed_numeric_features("html", html_features, HTML_MODEL_FEATURE_COLUMNS)
        )
    return AllsafeAnalysisResponse(analysis=response, features=features)


def _allowed_numeric_features(
    prefix: str, values: dict[str, object], columns: list[str]
) -> dict[str, float]:
    return {
        f"{prefix}.{name}": float(value)
        for name in columns
        if isinstance((value := values.get(name)), Real)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    }


@router.post("/analyze-file", response_model=BatchAnalyzeResponse)
async def analyze_url_file(
    file: UploadFile = File(...),
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
    training_store: TrainingStore = Depends(get_training_store),
) -> BatchAnalyzeResponse:
    raw_content = await file.read(MAX_BATCH_FILE_BYTES + 1)
    if len(raw_content) > MAX_BATCH_FILE_BYTES:
        raise HTTPException(
            status_code=413, detail="File is too large. Maximum size is 512 KB."
        )

    text = raw_content.decode("utf-8", errors="replace")
    candidates = _extract_url_candidates(text)
    if not candidates:
        raise HTTPException(status_code=400, detail="No URL found in uploaded file.")

    results: list[BatchAnalyzeItem] = []
    counts = {"malicious": 0, "clean": 0, "unknown": 0, "invalid": 0}

    for index, candidate in enumerate(candidates, start=1):
        try:
            payload = AnalyzeUrlRequest.model_validate({"url": candidate})
            response = pipeline.run(payload.url, original_input=payload.original_input)
            response.observation_id = _record_observation_safely(
                response, training_store, source="user_scan_file"
            )
        except ValidationError as exc:
            counts["invalid"] += 1
            results.append(
                BatchAnalyzeItem(
                    index=index,
                    input=candidate,
                    final_verdict="invalid",
                    error=_validation_error_message(exc),
                )
            )
            continue

        counts[response.final_verdict] += 1
        results.append(
            BatchAnalyzeItem(
                index=index,
                input=response.original_input or candidate,
                normalized_url=response.normalized_url,
                final_verdict=response.final_verdict,
                confidence=response.confidence,
                risk_score=response.risk_score,
                malicious_probability=response.malicious_probability,
                clean_probability=response.clean_probability,
                summary=response.summary,
            )
        )

    analyzed = len(candidates) - counts["invalid"]
    return BatchAnalyzeResponse(
        filename=file.filename or "uploaded_urls.txt",
        summary=BatchAnalyzeSummary(
            submitted=len(candidates),
            analyzed=analyzed,
            malicious=counts["malicious"],
            clean=counts["clean"],
            unknown=counts["unknown"],
            invalid=counts["invalid"],
        ),
        results=results,
    )


def _extract_url_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue

        for token in re.split(r"[\s,;]+", line):
            candidate = token.strip().strip("\"'<>[]()")
            if not candidate:
                continue
            if candidate.lower() in {"url", "urls", "link", "links"}:
                continue
            if not _looks_like_url_candidate(candidate):
                continue
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

    return candidates


def _looks_like_url_candidate(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("http://", "https://")) or "." in value


def _validation_error_message(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "Invalid URL"
    return str(errors[0].get("msg") or "Invalid URL")


def _record_observation_safely(
    response: AnalyzeUrlResponse,
    training_store: TrainingStore,
    source: str,
) -> int | None:
    try:
        final_url = _extract_final_url(response)
        feature_url = final_url or response.normalized_url
        domain = _domain_from_url(feature_url)
        url_features = extract_features_dict(feature_url)
        html_features = _extract_html_features(response.stages)
        return training_store.add_observation(
            url=response.original_input or response.url,
            normalized_url=response.normalized_url,
            final_url=final_url,
            domain=domain,
            source=source,
            final_verdict=response.final_verdict,
            risk_score=response.risk_score,
            confidence=response.confidence,
            malicious_probability=response.malicious_probability,
            clean_probability=response.clean_probability,
            url_features=url_features,
            html_features=html_features,
            scanner_results=[
                stage.model_dump(mode="json") for stage in response.stages
            ],
        )
    except Exception:
        LOGGER.warning("Failed to persist URL observation")
        return None


def _extract_html_features(stages: list[StageResult]) -> dict[str, object] | None:
    for stage in stages:
        features = stage.training_features.get("html_features")
        if isinstance(features, dict):
            return features
    return None


def _extract_final_url(response: AnalyzeUrlResponse) -> str:
    for stage in reversed(response.stages):
        if stage.scanner == "HtmlScraper":
            final_url = stage.details.get("final_url")
            if isinstance(final_url, str) and final_url:
                return final_url

    for stage in reversed(response.stages):
        resolved_url = stage.details.get("resolved_url")
        if isinstance(resolved_url, str) and resolved_url:
            return resolved_url

    return response.normalized_url


def _domain_from_url(url: str) -> str | None:
    hostname = urlsplit(url).hostname
    return hostname.lower().strip(".") if hostname else None
