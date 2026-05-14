import re

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import ValidationError

from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline
from app.models.schemas import (
    AnalyzeUrlRequest,
    AnalyzeUrlResponse,
    BatchAnalyzeItem,
    BatchAnalyzeResponse,
    BatchAnalyzeSummary,
)

router = APIRouter(prefix="/api/v1", tags=["URL Analysis"])
MAX_BATCH_FILE_BYTES = 512 * 1024


@router.post("/analyze", response_model=AnalyzeUrlResponse)
def analyze_url(
    payload: AnalyzeUrlRequest,
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
) -> AnalyzeUrlResponse:
    return pipeline.run(payload.url, original_input=payload.original_input)


@router.post("/analyze-file", response_model=BatchAnalyzeResponse)
async def analyze_url_file(
    file: UploadFile = File(...),
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
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
