from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator


Verdict = Literal["malicious", "clean", "unknown"]


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

        if not candidate.startswith(("http://", "https://")):
            candidate = f"https://{candidate}"

        parsed = urlparse(candidate)
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
