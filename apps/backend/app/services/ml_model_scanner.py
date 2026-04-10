from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from app.ml.feature_extractor import FeatureExtractor


@dataclass
class DeepScanResult:
    url: str
    status: str
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


class MLModelScanner:
    def __init__(
        self,
        model_path: str = "phishcatch_champion_model.pkl",
        scaler_path: str = "phishcatch_scaler.pkl",
        timeout_seconds: float = 4.0,
        malicious_threshold: float = 0.5,
        verify_ssl: bool | str = True,
    ) -> None:
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.malicious_threshold = malicious_threshold
        self.feature_extractor = FeatureExtractor(timeout_seconds=timeout_seconds, verify_ssl=verify_ssl)
        self.model = self._load_artifact(model_path)
        self.scaler = self._load_artifact(scaler_path)

    async def scan(self, url: str) -> DeepScanResult:
        default_fingerprint = self._build_campaign_fingerprint(url, [], 0.0)
        if self.model is None or self.scaler is None:
            return DeepScanResult(
                url=url,
                status="unknown",
                risk_score=0.0,
                malicious_probability=0.0,
                confidence=0.0,
                model_name="xgboost",
                html_fetched=False,
                error="Model or scaler artifact is unavailable.",
                feature_signals=None,
                matched_brands=None,
                brand_signal_score=None,
                campaign_fingerprint=default_fingerprint,
            )

        extracted = await self.feature_extractor.extract(url)
        fingerprint = self._build_campaign_fingerprint(
            url=url,
            matched_brands=extracted.matched_brands,
            brand_signal_score=extracted.brand_signal_score,
        )
        if not extracted.html_fetched:
            return DeepScanResult(
                url=url,
                status="unknown",
                risk_score=0.0,
                malicious_probability=0.0,
                confidence=0.0,
                model_name="xgboost",
                html_fetched=False,
                error=extracted.fetch_error or "HTML could not be fetched.",
                feature_signals=None,
                matched_brands=extracted.matched_brands,
                brand_signal_score=extracted.brand_signal_score,
                campaign_fingerprint=fingerprint,
            )

        if extracted.vector.shape != (1, 48):
            return DeepScanResult(
                url=url,
                status="unknown",
                risk_score=0.0,
                malicious_probability=0.0,
                confidence=0.0,
                model_name="xgboost",
                html_fetched=extracted.html_fetched,
                error="Feature vector shape mismatch. Expected (1, 48).",
                feature_signals=extracted.feature_map,
                matched_brands=extracted.matched_brands,
                brand_signal_score=extracted.brand_signal_score,
                campaign_fingerprint=fingerprint,
            )

        try:
            feature_names = getattr(self.scaler, "feature_names_in_", None)
            scaler_feature_names = list(feature_names) if feature_names is not None else []
            if scaler_feature_names:
                row = {name: float(extracted.feature_map.get(name, 0.0)) for name in scaler_feature_names}
                feature_frame = pd.DataFrame([row], columns=scaler_feature_names)
                scaled = self.scaler.transform(feature_frame)
            else:
                scaled = self.scaler.transform(extracted.vector)
            probabilities = self.model.predict_proba(scaled)
            malicious_probability = float(probabilities[0][1])
            risk_score = round(malicious_probability * 100.0, 2)
            status = "malicious" if malicious_probability >= self.malicious_threshold else "safe"
            confidence = round(max(malicious_probability, 1.0 - malicious_probability), 4)

            return DeepScanResult(
                url=url,
                status=status,
                risk_score=risk_score,
                malicious_probability=round(malicious_probability, 4),
                confidence=confidence,
                model_name="xgboost",
                html_fetched=extracted.html_fetched,
                error=extracted.fetch_error,
                feature_signals=extracted.feature_map,
                matched_brands=extracted.matched_brands,
                brand_signal_score=extracted.brand_signal_score,
                campaign_fingerprint=fingerprint,
            )
        except Exception as exc:
            return DeepScanResult(
                url=url,
                status="unknown",
                risk_score=0.0,
                malicious_probability=0.0,
                confidence=0.0,
                model_name="xgboost",
                html_fetched=extracted.html_fetched,
                error=str(exc),
                feature_signals=extracted.feature_map,
                matched_brands=extracted.matched_brands,
                brand_signal_score=extracted.brand_signal_score,
                campaign_fingerprint=fingerprint,
            )

    @staticmethod
    def _build_campaign_fingerprint(url: str, matched_brands: list[str], brand_signal_score: float) -> str:
        domain = urlparse(url).netloc.lower() or "unknown-domain"
        brands = ",".join(sorted(set(matched_brands))) if matched_brands else "no-brand"
        source = f"{domain}|{brands}|{round(brand_signal_score, 2)}"
        digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:12]
        return f"cmp_{digest}"

    @staticmethod
    def _load_artifact(path_str: str):
        path = Path(path_str)
        if not path.is_absolute():
            backend_root = Path(__file__).resolve().parents[2]
            path = backend_root / path
        if not path.exists():
            return None
        try:
            return joblib.load(path)
        except Exception:
            return None
