from __future__ import annotations

from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator


ScanStatus = Literal["safe", "malicious", "unknown"]
ScanMode = Literal["fast", "deep"]


class ScanRequest(BaseModel):
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
        if not candidate.startswith(("http://", "https://")):
            candidate = f"https://{candidate}"

        parsed = urlparse(candidate)
        if not parsed.netloc:
            raise ValueError("Input should be a valid URL")

        value["original_input"] = original_input
        value["url"] = candidate
        return value


class FastScanResponse(BaseModel):
    url: str
    original_input: str | None = None
    normalized_url: str
    tier: str = "tier1_virustotal"
    status: ScanStatus
    risk_score: float | None = None
    reason: str


class DeepScanResponse(BaseModel):
    url: str
    original_input: str | None = None
    normalized_url: str
    tier: str = "tier2_ml_deep"
    status: ScanStatus
    risk_score: float
    malicious_probability: float
    confidence: float
    model_name: str
    html_fetched: bool
    error: str | None = None
    feature_signals: dict[str, float] | None = None
    matched_brands: list[str] | None = None
    brand_signal_score: float | None = None
    campaign_fingerprint: str | None = None


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=100)
    mode: ScanMode = "fast"
    include_feature_signals: bool = False


class BatchScanItem(BaseModel):
    url: str
    original_input: str
    normalized_url: str
    tier: str
    status: ScanStatus
    risk_score: float | None = None
    reason: str | None = None
    malicious_probability: float | None = None
    confidence: float | None = None
    model_name: str | None = None
    html_fetched: bool | None = None
    error: str | None = None
    feature_signals: dict[str, float] | None = None
    matched_brands: list[str] | None = None
    brand_signal_score: float | None = None
    campaign_fingerprint: str | None = None


class BatchScanResponse(BaseModel):
    mode: ScanMode
    total: int
    results: list[BatchScanItem]
