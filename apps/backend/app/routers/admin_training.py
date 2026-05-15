import csv
import io
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile

from app.core.config import settings
from app.dependencies import get_training_store
from app.ml.feature_extractor import extract_features_dict
from app.models.schemas import (
    AdminBulkObservationTrainingSampleRequest,
    AdminBulkObservationTrainingSampleResponse,
    AdminBulkObservationTrainingSampleResult,
    AdminObservationDetail,
    AdminObservationListItem,
    AdminObservationListResponse,
    AdminObservationTrainingSampleRequest,
    AdminTrainingSampleImportResponse,
    AdminTrainingSampleImportResult,
    AdminTrainingSampleListItem,
    AdminTrainingSampleListResponse,
    AdminTrainingSampleRequest,
    AdminTrainingSampleResponse,
    AnalyzeUrlRequest,
)
from app.storage import TrainingStore


router = APIRouter(prefix="/api/v1/admin", tags=["Training Admin"])
MAX_IMPORT_FILE_BYTES = 512 * 1024


def require_training_admin(x_admin_token: str | None = Header(default=None)) -> None:
    if not settings.training_admin_token:
        raise HTTPException(
            status_code=503,
            detail="Training admin API is disabled. Set TRAINING_ADMIN_TOKEN to enable it.",
        )
    if x_admin_token != settings.training_admin_token:
        raise HTTPException(status_code=403, detail="Invalid admin token.")


@router.post("/training-samples", response_model=AdminTrainingSampleResponse)
def add_training_sample(
    payload: AdminTrainingSampleRequest,
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
) -> AdminTrainingSampleResponse:
    return _create_training_sample(payload, training_store)


@router.get("/training-samples", response_model=AdminTrainingSampleListResponse)
def list_training_samples(
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    approved_only: bool = False,
) -> AdminTrainingSampleListResponse:
    samples, total = training_store.training_samples_page(
        limit=limit,
        offset=offset,
        approved_only=approved_only,
    )
    return AdminTrainingSampleListResponse(
        total=total,
        limit=limit,
        offset=offset,
        results=[_training_sample_list_item(sample) for sample in samples],
    )


@router.get("/observations", response_model=AdminObservationListResponse)
def list_observations(
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    final_verdict: str | None = Query(default=None, pattern="^(malicious|clean|unknown)$"),
    q: str | None = Query(default=None, max_length=300),
) -> AdminObservationListResponse:
    observations, total = training_store.observations(
        limit=limit,
        offset=offset,
        final_verdict=final_verdict,
        query=q,
    )
    return AdminObservationListResponse(
        total=total,
        limit=limit,
        offset=offset,
        results=[_observation_list_item(observation) for observation in observations],
    )


@router.post("/observations/bulk-training-samples", response_model=AdminBulkObservationTrainingSampleResponse)
def bulk_observations_to_training_samples(
    payload: AdminBulkObservationTrainingSampleRequest,
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
) -> AdminBulkObservationTrainingSampleResponse:
    results: list[AdminBulkObservationTrainingSampleResult] = []
    created = 0
    invalid = 0

    for observation_id in payload.observation_ids:
        observation = training_store.observation_by_id(observation_id)
        if observation is None:
            invalid += 1
            results.append(
                AdminBulkObservationTrainingSampleResult(
                    observation_id=observation_id,
                    status="invalid",
                    error="Observation not found",
                )
            )
            continue

        sample_id = _create_training_sample_from_observation(
            observation=observation,
            payload=payload,
            training_store=training_store,
        )
        created += 1
        results.append(
            AdminBulkObservationTrainingSampleResult(
                observation_id=observation_id,
                sample_id=sample_id,
                status="created",
            )
        )

    return AdminBulkObservationTrainingSampleResponse(
        submitted=len(payload.observation_ids),
        created=created,
        invalid=invalid,
        results=results,
    )


@router.get("/observations/{observation_id}", response_model=AdminObservationDetail)
def get_observation(
    observation_id: int,
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
) -> AdminObservationDetail:
    observation = training_store.observation_by_id(observation_id)
    if observation is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    item = _observation_list_item(observation).model_dump()
    return AdminObservationDetail(
        **item,
        url_features=_dict_or_none(observation.get("url_features")),
        html_features=_dict_or_none(observation.get("html_features")),
        scanner_results=_list_of_dicts(observation.get("scanner_results")),
    )


@router.post("/observations/{observation_id}/training-sample", response_model=AdminTrainingSampleResponse)
def observation_to_training_sample(
    observation_id: int,
    payload: AdminObservationTrainingSampleRequest,
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
) -> AdminTrainingSampleResponse:
    observation = training_store.observation_by_id(observation_id)
    if observation is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    sample_id = _create_training_sample_from_observation(
        observation=observation,
        payload=payload,
        training_store=training_store,
    )
    return _training_sample_response_from_observation(sample_id, observation, payload)


@router.post("/training-samples/import", response_model=AdminTrainingSampleImportResponse)
async def import_training_samples(
    file: UploadFile = File(...),
    _: None = Depends(require_training_admin),
    training_store: TrainingStore = Depends(get_training_store),
) -> AdminTrainingSampleImportResponse:
    raw_content = await file.read(MAX_IMPORT_FILE_BYTES + 1)
    if len(raw_content) > MAX_IMPORT_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File is too large. Maximum size is 512 KB.")

    text = raw_content.decode("utf-8", errors="replace")
    rows = csv.DictReader(io.StringIO(text))
    if not rows.fieldnames:
        raise HTTPException(status_code=400, detail="CSV must include a header row.")

    results: list[AdminTrainingSampleImportResult] = []
    imported = 0
    invalid = 0

    for index, row in enumerate(rows, start=2):
        try:
            payload = _payload_from_csv_row(row)
            response = _create_training_sample(payload, training_store)
        except Exception as exc:
            invalid += 1
            results.append(
                AdminTrainingSampleImportResult(
                    row=index,
                    url=row.get("url") or None,
                    status="invalid",
                    error=str(exc),
                )
            )
            continue

        imported += 1
        results.append(
            AdminTrainingSampleImportResult(
                row=index,
                url=response.normalized_url,
                sample_id=response.id,
                status="imported",
            )
        )

    return AdminTrainingSampleImportResponse(
        filename=file.filename or "training_samples.csv",
        submitted=imported + invalid,
        imported=imported,
        invalid=invalid,
        results=results,
    )


def _payload_from_csv_row(row: dict[str, str | None]) -> AdminTrainingSampleRequest:
    url = (row.get("url") or "").strip()
    if not url:
        raise ValueError("Missing url")

    label_raw = (row.get("label") or "").strip()
    if label_raw not in {"0", "1"}:
        raise ValueError("label must be 0 or 1")

    confidence_raw = (row.get("label_confidence") or "").strip()
    confidence = float(confidence_raw) if confidence_raw else 1.0

    approved_raw = (row.get("approved_for_training") or "").strip().lower()
    approved = approved_raw not in {"0", "false", "no", "off"}

    return AdminTrainingSampleRequest(
        url=url,
        label=int(label_raw),
        source=(row.get("source") or "admin").strip() or "admin",
        label_confidence=confidence,
        approved_for_training=approved,
        notes=(row.get("notes") or "").strip() or None,
    )


def _create_training_sample(
    payload: AdminTrainingSampleRequest,
    training_store: TrainingStore,
) -> AdminTrainingSampleResponse:
    normalized = AnalyzeUrlRequest.model_validate({"url": payload.url})
    observation = training_store.latest_observation_for_url(normalized.url)

    final_url = _value_from_observation(observation, "final_url") or normalized.url
    domain = _value_from_observation(observation, "domain") or _domain_from_url(final_url)
    url_features = _dict_from_observation(observation, "url_features") or extract_features_dict(final_url)
    html_features = _dict_from_observation(observation, "html_features")
    observation_id = int(observation["id"]) if observation else None

    sample_id = training_store.add_training_sample(
        observation_id=observation_id,
        url=normalized.url,
        final_url=final_url,
        domain=domain,
        label=payload.label,
        label_source=payload.source,
        label_confidence=payload.label_confidence,
        approved_for_training=payload.approved_for_training,
        url_features=url_features,
        html_features=html_features,
        notes=payload.notes,
        dedupe=True,
    )

    return AdminTrainingSampleResponse(
        id=sample_id,
        url=payload.url,
        normalized_url=normalized.url,
        final_url=final_url,
        domain=domain,
        label=payload.label,
        label_source=payload.source,
        label_confidence=payload.label_confidence,
        approved_for_training=payload.approved_for_training,
        reused_observation_id=observation_id,
        html_features_available=bool(html_features),
    )


def _create_training_sample_from_observation(
    *,
    observation: dict[str, object],
    payload: AdminObservationTrainingSampleRequest,
    training_store: TrainingStore,
) -> int:
    training_url = _observation_training_url(observation)
    url_features = _dict_from_observation(observation, "url_features") or extract_features_dict(training_url)
    html_features = _dict_from_observation(observation, "html_features")

    return training_store.add_training_sample(
        observation_id=int(observation["id"]),
        url=training_url,
        final_url=_value_from_observation(observation, "final_url") or training_url,
        domain=_value_from_observation(observation, "domain") or _domain_from_url(training_url),
        label=payload.label,
        label_source=payload.source,
        label_confidence=payload.label_confidence,
        approved_for_training=payload.approved_for_training,
        url_features=url_features,
        html_features=html_features,
        notes=payload.notes,
        dedupe=True,
    )


def _training_sample_response_from_observation(
    sample_id: int,
    observation: dict[str, object],
    payload: AdminObservationTrainingSampleRequest,
) -> AdminTrainingSampleResponse:
    training_url = _observation_training_url(observation)
    return AdminTrainingSampleResponse(
        id=sample_id,
        url=str(observation.get("url") or training_url),
        normalized_url=training_url,
        final_url=_value_from_observation(observation, "final_url") or training_url,
        domain=_value_from_observation(observation, "domain") or _domain_from_url(training_url),
        label=payload.label,
        label_source=payload.source,
        label_confidence=payload.label_confidence,
        approved_for_training=payload.approved_for_training,
        reused_observation_id=int(observation["id"]),
        html_features_available=bool(_dict_from_observation(observation, "html_features")),
    )


def _observation_list_item(observation: dict[str, object]) -> AdminObservationListItem:
    scanner_results = _list_of_dicts(observation.get("scanner_results"))
    return AdminObservationListItem(
        id=int(observation["id"]),
        url=str(observation.get("url") or ""),
        normalized_url=_value_from_observation(observation, "normalized_url"),
        final_url=_value_from_observation(observation, "final_url"),
        domain=_value_from_observation(observation, "domain"),
        source=str(observation.get("source") or "unknown"),
        scanned_at=str(observation.get("scanned_at") or observation.get("created_at") or ""),
        final_verdict=observation.get("final_verdict"),  # type: ignore[arg-type]
        risk_score=_float_or_none(observation.get("risk_score")),
        confidence=_float_or_none(observation.get("confidence")),
        malicious_probability=_float_or_none(observation.get("malicious_probability")),
        clean_probability=_float_or_none(observation.get("clean_probability")),
        has_url_features=isinstance(observation.get("url_features"), dict),
        has_html_features=isinstance(observation.get("html_features"), dict),
        stage_count=len(scanner_results),
    )


def _training_sample_list_item(sample: dict[str, object]) -> AdminTrainingSampleListItem:
    return AdminTrainingSampleListItem(
        id=int(sample["id"]),
        observation_id=int(sample["observation_id"]) if sample.get("observation_id") is not None else None,
        url=str(sample.get("url") or ""),
        final_url=_value_from_observation(sample, "final_url"),
        domain=_value_from_observation(sample, "domain"),
        label=int(sample["label"]),  # type: ignore[arg-type]
        label_source=str(sample.get("label_source") or "unknown"),
        label_confidence=float(sample.get("label_confidence") or 0.0),
        approved_for_training=bool(sample.get("approved_for_training")),
        created_at=str(sample.get("created_at") or ""),
        updated_at=str(sample.get("updated_at") or ""),
        has_url_features=isinstance(sample.get("url_features"), dict),
        has_html_features=isinstance(sample.get("html_features"), dict),
        notes=_value_from_observation(sample, "notes"),
    )


def _value_from_observation(observation: dict[str, object] | None, key: str) -> str | None:
    if not observation:
        return None
    value = observation.get(key)
    return value if isinstance(value, str) and value else None


def _dict_from_observation(observation: dict[str, object] | None, key: str) -> dict[str, object] | None:
    if not observation:
        return None
    value = observation.get(key)
    return value if isinstance(value, dict) else None


def _dict_or_none(value: object) -> dict[str, object] | None:
    return value if isinstance(value, dict) else None


def _list_of_dicts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _observation_training_url(observation: dict[str, object]) -> str:
    return (
        _value_from_observation(observation, "final_url")
        or _value_from_observation(observation, "normalized_url")
        or str(observation.get("url") or "")
    )


def _domain_from_url(url: str) -> str | None:
    hostname = urlsplit(url).hostname
    return hostname.lower().strip(".") if hostname else None


def _float_or_none(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
