from pathlib import Path
from typing import Iterable

import joblib
import pandas as pd

from app.core.config import Settings
from app.ml.feature_extractor import (
    FEATURE_COLUMNS,
    LEGACY_FEATURE_COLUMNS,
    MENDELEY_48_FEATURE_COLUMNS,
    extract_features_dataframe,
    extract_48_features_dataframe,
    extract_legacy_features_dataframe,
)
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class MLModelScanner(BaseScanner):
    def __init__(self, settings: Settings) -> None:
        super().__init__(name="MLModelScanner")
        self.settings = settings
        self.model = self._load_artifact(settings.ml_model_path)
        loaded_scaler = self._load_artifact(settings.ml_scaler_path) if settings.ml_scaler_path else None
        self.scaler = loaded_scaler if self._is_compatible_scaler(self.model, loaded_scaler) else None

    def scan(self, url: str) -> StageResult:
        if self.model is None:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=None,
                reason="ML model unavailable (not found or failed to load)",
                details={"model_path": self.settings.ml_model_path},
            )

        try:
            feature_frame = self._build_feature_frame(url)
            model_input = self._prepare_model_input(feature_frame)
            confidence = self._predict_confidence(model_input)
        except Exception as exc:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=None,
                reason="ML model prediction failed",
                details={
                    "error": str(exc),
                    "model_path": self.settings.ml_model_path,
                    "scaler_path": self.settings.ml_scaler_path,
                },
            )

        malicious_probability = round(confidence, 4)
        clean_probability = round(1 - confidence, 4)
        details = {
            "threshold": self.settings.ml_malicious_threshold,
            "confident_malicious_threshold": self.settings.ml_confident_malicious_threshold,
            "confident_clean_threshold": self.settings.ml_confident_clean_threshold,
            "model_path": self.settings.ml_model_path,
            "scaler_path": self.settings.ml_scaler_path,
            "feature_count": int(feature_frame.shape[1]),
            "feature_schema": self._feature_schema_name(feature_frame),
        }

        if confidence >= self.settings.ml_confident_malicious_threshold:
            details["decision"] = "confident_malicious"
            return StageResult(
                scanner=self.name,
                verdict="malicious",
                confidence=malicious_probability,
                risk_score=malicious_probability,
                malicious_probability=malicious_probability,
                clean_probability=clean_probability,
                reason="ML model: high confidence phishing",
                details=details,
            )

        if confidence <= self.settings.ml_confident_clean_threshold:
            details["decision"] = "confident_clean"
            return StageResult(
                scanner=self.name,
                verdict="clean",
                confidence=clean_probability,
                risk_score=malicious_probability,
                malicious_probability=malicious_probability,
                clean_probability=clean_probability,
                reason="ML model: high confidence clean",
                details=details,
            )

        details["decision"] = "uncertain"
        return StageResult(
            scanner=self.name,
            verdict="unknown",
            confidence=malicious_probability,
            risk_score=malicious_probability,
            malicious_probability=malicious_probability,
            clean_probability=clean_probability,
            reason=f"ML model uncertain (confidence: {malicious_probability}), needs deeper analysis",
            details=details,
        )

    def should_halt(self, result: StageResult) -> bool:
        decision = result.details.get("decision", "")
        return decision in ("confident_malicious", "confident_clean")

    @staticmethod
    def _load_artifact(artifact_path: str | None):
        if not artifact_path:
            return None

        path = Path(artifact_path)
        if not path.exists():
            return None

        try:
            return joblib.load(path)
        except Exception:
            return None

    def _build_feature_frame(self, url: str) -> pd.DataFrame:
        feature_names = self._expected_feature_names()
        if feature_names:
            return self._feature_frame_for_names(url, feature_names)

        expected_count = self._expected_feature_count()
        if expected_count == len(LEGACY_FEATURE_COLUMNS):
            return extract_legacy_features_dataframe(url)
        if expected_count == len(MENDELEY_48_FEATURE_COLUMNS):
            return extract_48_features_dataframe(url)

        return extract_features_dataframe(url)

    def _feature_frame_for_names(self, url: str, feature_names: list[str]) -> pd.DataFrame:
        feature_set = set(feature_names)
        modern_frame = extract_features_dataframe(url)
        if feature_set.issubset(modern_frame.columns):
            return modern_frame.reindex(columns=feature_names)

        mendeley_frame = extract_48_features_dataframe(url)
        if feature_set.issubset(mendeley_frame.columns):
            return mendeley_frame.reindex(columns=feature_names)

        legacy_frame = extract_legacy_features_dataframe(url)
        if feature_set.issubset(legacy_frame.columns):
            return legacy_frame.reindex(columns=feature_names)

        missing = sorted(feature_set - set(FEATURE_COLUMNS) - set(MENDELEY_48_FEATURE_COLUMNS) - set(LEGACY_FEATURE_COLUMNS))
        raise ValueError(f"Model expects unknown feature columns: {missing}")

    @staticmethod
    def _feature_schema_name(feature_frame: pd.DataFrame) -> str:
        columns = list(feature_frame.columns)
        if columns == FEATURE_COLUMNS:
            return "url_lexical_v1"
        if columns == MENDELEY_48_FEATURE_COLUMNS:
            return "mendeley_48_approx"
        if columns == LEGACY_FEATURE_COLUMNS:
            return "legacy_16"
        return "custom"

    def _prepare_model_input(self, feature_frame: pd.DataFrame):
        if self.scaler is None or self._is_pipeline(self.model):
            return feature_frame

        return self.scaler.transform(feature_frame)

    def _expected_feature_count(self) -> int | None:
        for artifact in (self.scaler, self.model):
            count = getattr(artifact, "n_features_in_", None)
            if count:
                return int(count)
        return None

    def _expected_feature_names(self) -> list[str] | None:
        for artifact in (self.scaler, self.model):
            names = getattr(artifact, "feature_names_in_", None)
            if names is not None:
                return [str(name) for name in names]
        return None

    @staticmethod
    def _is_pipeline(model) -> bool:
        return hasattr(model, "steps") and hasattr(model, "predict")

    @staticmethod
    def _is_compatible_scaler(model, scaler) -> bool:
        if scaler is None or model is None:
            return False
        if MLModelScanner._is_pipeline(model):
            return False

        model_feature_count = getattr(model, "n_features_in_", None)
        scaler_feature_count = getattr(scaler, "n_features_in_", None)
        if model_feature_count and scaler_feature_count:
            return int(model_feature_count) == int(scaler_feature_count)

        return True

    def _predict_confidence(self, model_input: pd.DataFrame | Iterable[Iterable[float]]) -> float:
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(model_input)
            return float(probabilities[0][1])

        prediction = int(self.model.predict(model_input)[0])
        return float(prediction)
