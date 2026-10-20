from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.schemas import AnalyzeUrlRequest


class PublicAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(strict=True, min_length=1, max_length=2048)
    source: Literal["qr", "url"] = "url"
    client_request_id: UUID | None = None

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        candidate = value.strip()
        if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
            raise ValueError("URL contains unsupported characters")

        parsed = urlsplit(candidate)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs with embedded credentials are not supported")
        if parsed.scheme:
            scheme = parsed.scheme.lower()
            if scheme in {"http", "https"}:
                if not candidate.lower().startswith(f"{scheme}://"):
                    raise ValueError("Only http and https URLs are supported")
                candidate = scheme + candidate[len(parsed.scheme) :]
            elif "://" in candidate or "." not in scheme:
                # A scheme-less domain with a port remains supported.
                raise ValueError("Only http and https URLs are supported")

        normalized = AnalyzeUrlRequest.model_validate({"url": candidate}).url
        if len(normalized) > 2048:
            raise ValueError("Normalized URL is too long")
        return normalized


class PublicAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["consumer-1"] = "consumer-1"
    url: str
    final_verdict: Literal["malicious", "clean", "unknown"]
    scan_status: Literal["complete", "partial", "failed"]
