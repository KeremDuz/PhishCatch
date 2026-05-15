import logging
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import ValidationError

from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline, get_training_store
from app.ml.feature_extractor import extract_features_dict
from app.models.schemas import (
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
TRUSTED_MALICIOUS_LABELERS = {
    "URLhausScanner": ("urlhaus", 0.98),
    "GoogleSafeBrowsing": ("google_safe_browsing", 0.98),
    "GoogleWebRisk": ("google_web_risk", 0.98),
}


@router.post("/analyze", response_model=AnalyzeUrlResponse)
def analyze_url(
    payload: AnalyzeUrlRequest,
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
    training_store: TrainingStore = Depends(get_training_store),
) -> AnalyzeUrlResponse:
    response = pipeline.run(payload.url, original_input=payload.original_input)
    _record_observation_safely(response, training_store, source="user_scan")
    return response


@router.post("/analyze-file", response_model=BatchAnalyzeResponse)
async def analyze_url_file(
    file: UploadFile = File(...),
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
    training_store: TrainingStore = Depends(get_training_store),
) -> BatchAnalyzeResponse:
    raw_content = await file.read(MAX_BATCH_FILE_BYTES + 1)
    if len(raw_content) > MAX_BATCH_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File is too large. Maximum size is 512 KB.")

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
            _record_observation_safely(response, training_store, source="user_scan_file")
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
) -> None:
    try:
        final_url = _extract_final_url(response)
        feature_url = final_url or response.normalized_url
        domain = _domain_from_url(feature_url)
        url_features = extract_features_dict(feature_url)
        html_features = _extract_html_features(response.stages)
        observation_id = training_store.add_observation(
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
            scanner_results=[stage.model_dump(mode="json") for stage in response.stages],
        )
        _record_trusted_malicious_sample(
            response=response,
            training_store=training_store,
            observation_id=observation_id,
            training_url=feature_url,
            final_url=final_url,
            domain=domain,
            url_features=url_features,
            html_features=html_features,
        )
    except Exception:
        LOGGER.warning("Failed to persist URL observation", exc_info=True)


def _record_trusted_malicious_sample(
    *,
    response: AnalyzeUrlResponse,
    training_store: TrainingStore,
    observation_id: int,
    training_url: str,
    final_url: str,
    domain: str | None,
    url_features: dict[str, object],
    html_features: dict[str, object] | None,
) -> None:
    label = _trusted_malicious_label(response.stages)
    if label is None:
        return

    training_store.add_training_sample(
        observation_id=observation_id,
        url=training_url,
        final_url=final_url,
        domain=domain,
        label=1,
        label_source=label["source"],
        label_confidence=float(label["confidence"]),
        approved_for_training=True,
        url_features=url_features,
        html_features=html_features,
        notes=str(label["notes"]),
        dedupe=True,
    )


def _trusted_malicious_label(stages: list[StageResult]) -> dict[str, object] | None:
    labels = [
        label
        for stage in stages
        if (label := _trusted_malicious_stage_label(stage)) is not None
    ]
    if not labels:
        return None

    best = max(labels, key=lambda item: float(item["confidence"]))
    sources = ", ".join(str(item["source"]) for item in labels)
    return {
        "source": str(best["source"]),
        "confidence": float(best["confidence"]),
        "notes": f"Auto-approved malicious label from trusted reputation source(s): {sources}",
    }


def _trusted_malicious_stage_label(stage: StageResult) -> dict[str, object] | None:
    if stage.verdict != "malicious":
        return None

    if stage.scanner in TRUSTED_MALICIOUS_LABELERS:
        source, default_confidence = TRUSTED_MALICIOUS_LABELERS[stage.scanner]
        confidence = max(default_confidence, float(stage.confidence or 0.0), float(stage.risk_score or 0.0))
        return {"source": source, "confidence": min(confidence, 1.0)}

    if stage.scanner != "VirusTotalScanner":
        return None

    stats = stage.details.get("analysis_stats") or {}
    malicious_hits = _int_value(stats.get("malicious"))
    suspicious_hits = _int_value(stats.get("suspicious"))
    if malicious_hits < 1 and (malicious_hits + suspicious_hits) < 2:
        return None

    confidence = min(0.98, max(0.82, ((malicious_hits * 2) + suspicious_hits) / 10))
    return {"source": "virustotal", "confidence": confidence}


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


def _int_value(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
