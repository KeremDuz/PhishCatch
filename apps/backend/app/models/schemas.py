from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator

from app.utils.url_utils import canonicalize_url, ensure_http_url


Verdict = Literal["malicious", "clean", "unknown"]
BatchVerdict = Literal["malicious", "clean", "unknown", "invalid"]


class AnalyzeUrlRequest(BaseModel):
    url: str
    original_input: str | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_url(cls, value):
        if not isinstance(value, dict) or "url" not in value:
            return value

        candidate = str(value["url"]).strip()
        if not candidate:
            raise ValueError("URL cannot be empty")

        original_input = candidate

        candidate = ensure_http_url(candidate)
        candidate = canonicalize_url(candidate)

        parsed = urlsplit(candidate)
        if not parsed.netloc:
            raise ValueError("Input should be a valid URL")

        value["original_input"] = original_input
        value["url"] = candidate
        return value


class StageResult(BaseModel):
    scanner: str
    verdict: Verdict
    confidence: float | None = None
    risk_score: float | None = None
    malicious_probability: float | None = None
    clean_probability: float | None = None
    reason: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    training_features: dict[str, Any] = Field(default_factory=dict, exclude=True)


class AnalyzeUrlResponse(BaseModel):
    url: str
    original_input: str | None = None
    normalized_url: str
    final_verdict: Verdict
    confidence: float | None = None
    risk_score: float | None = None
    malicious_probability: float | None = None
    clean_probability: float | None = None
    decided_by: str
    summary: str | None = None
    signals: dict[str, Any] = Field(default_factory=dict)
    stages: list[StageResult]


class BatchAnalyzeItem(BaseModel):
    index: int
    input: str
    normalized_url: str | None = None
    final_verdict: BatchVerdict
    confidence: float | None = None
    risk_score: float | None = None
    malicious_probability: float | None = None
    clean_probability: float | None = None
    summary: str | None = None
    error: str | None = None


class BatchAnalyzeSummary(BaseModel):
    submitted: int
    analyzed: int
    malicious: int
    clean: int
    unknown: int
    invalid: int


class BatchAnalyzeResponse(BaseModel):
    filename: str
    summary: BatchAnalyzeSummary
    results: list[BatchAnalyzeItem]


class AdminTrainingSampleRequest(BaseModel):
    url: str
    label: Literal[0, 1]
    source: str = "admin"
    label_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    approved_for_training: bool = True
    notes: str | None = None


class AdminTrainingSampleResponse(BaseModel):
    id: int
    url: str
    normalized_url: str
    final_url: str | None = None
    domain: str | None = None
    label: Literal[0, 1]
    label_source: str
    label_confidence: float
    approved_for_training: bool
    reused_observation_id: int | None = None
    html_features_available: bool = False


class AdminObservationListItem(BaseModel):
    id: int
    url: str
    normalized_url: str | None = None
    final_url: str | None = None
    domain: str | None = None
    source: str
    scanned_at: str
    final_verdict: Verdict | None = None
    risk_score: float | None = None
    confidence: float | None = None
    malicious_probability: float | None = None
    clean_probability: float | None = None
    has_url_features: bool = False
    has_html_features: bool = False
    stage_count: int = 0


class AdminObservationListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    results: list[AdminObservationListItem]


class AdminObservationDetail(AdminObservationListItem):
    url_features: dict[str, Any] | None = None
    html_features: dict[str, Any] | None = None
    scanner_results: list[dict[str, Any]] = Field(default_factory=list)


class AdminObservationTrainingSampleRequest(BaseModel):
    label: Literal[0, 1]
    source: str = "admin_observation"
    label_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    approved_for_training: bool = True
    notes: str | None = None


class AdminBulkObservationTrainingSampleRequest(AdminObservationTrainingSampleRequest):
    observation_ids: list[int] = Field(min_length=1, max_length=500)


class AdminBulkObservationTrainingSampleResult(BaseModel):
    observation_id: int
    sample_id: int | None = None
    status: Literal["created", "invalid"]
    error: str | None = None


class AdminBulkObservationTrainingSampleResponse(BaseModel):
    submitted: int
    created: int
    invalid: int
    results: list[AdminBulkObservationTrainingSampleResult]


class AdminTrainingSampleListItem(BaseModel):
    id: int
    observation_id: int | None = None
    url: str
    final_url: str | None = None
    domain: str | None = None
    label: Literal[0, 1]
    label_source: str
    label_confidence: float
    approved_for_training: bool
    created_at: str
    updated_at: str
    has_url_features: bool = False
    has_html_features: bool = False
    notes: str | None = None


class AdminTrainingSampleListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    results: list[AdminTrainingSampleListItem]


class AdminTrainingSampleImportResult(BaseModel):
    row: int
    url: str | None = None
    sample_id: int | None = None
    status: Literal["imported", "invalid"]
    error: str | None = None


class AdminTrainingSampleImportResponse(BaseModel):
    filename: str
    submitted: int
    imported: int
    invalid: int
    results: list[AdminTrainingSampleImportResult]
