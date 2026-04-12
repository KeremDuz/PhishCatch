from pathlib import Path

import joblib

from app.core.config import Settings
from app.ml.feature_extractor import extract_features_dataframe
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class MLModelScanner(BaseScanner):
    def __init__(self, settings: Settings) -> None:
        super().__init__(name="MLModelScanner")
        self.settings = settings
        self.model = self._load_model(settings.ml_model_path)

    def scan(self, url: str) -> StageResult:
        feature_frame = extract_features_dataframe(url)

        if self.model is None:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                reason="ML model unavailable (not found or failed to load)",
                details={"model_path": self.settings.ml_model_path},
            )

        confidence = self._predict_confidence(feature_frame)
        is_malicious = confidence >= self.settings.ml_malicious_threshold
        malicious_probability = round(confidence, 4)
        clean_probability = round(1 - confidence, 4)

        return StageResult(
            scanner=self.name,
            verdict="malicious" if is_malicious else "clean",
            confidence=malicious_probability,
            malicious_probability=malicious_probability,
            clean_probability=clean_probability,
            reason="ML model decision",
            details={
                "threshold": self.settings.ml_malicious_threshold,
                "model_path": self.settings.ml_model_path,
            },
        )

    @staticmethod
    def _load_model(model_path: str):
        path = Path(model_path)
        if not path.exists():
            return None

        try:
            return joblib.load(path)
        except Exception:
            return None

    def _predict_confidence(self, feature_frame) -> float:
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(feature_frame)
            return float(probabilities[0][1])

        prediction = int(self.model.predict(feature_frame)[0])
        return float(prediction)
