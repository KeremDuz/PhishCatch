from pathlib import Path

import joblib

from app.core.config import Settings
from app.ml.feature_extractor import extract_features_dataframe
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class MLModelScanner(BaseScanner):
    # Kesin karar eşikleri
    CONFIDENT_MALICIOUS = 0.95   # Bu üstü → kesin phishing, pipeline dur
    CONFIDENT_CLEAN = 0.15       # Bu altı → kesin temiz, pipeline dur
    # Arada kalan (0.15 - 0.95) → kararsız, HtmlScraper'a devret

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
        malicious_probability = round(confidence, 4)
        clean_probability = round(1 - confidence, 4)

        # Kesin karar verebildiği durumlar
        if confidence >= self.CONFIDENT_MALICIOUS:
            return StageResult(
                scanner=self.name,
                verdict="malicious",
                confidence=malicious_probability,
                malicious_probability=malicious_probability,
                clean_probability=clean_probability,
                reason="ML model: HIGH confidence phishing",
                details={
                    "threshold": self.settings.ml_malicious_threshold,
                    "model_path": self.settings.ml_model_path,
                    "decision": "confident_malicious",
                },
            )

        if confidence <= self.CONFIDENT_CLEAN:
            return StageResult(
                scanner=self.name,
                verdict="clean",
                confidence=malicious_probability,
                malicious_probability=malicious_probability,
                clean_probability=clean_probability,
                reason="ML model: HIGH confidence clean",
                details={
                    "threshold": self.settings.ml_malicious_threshold,
                    "model_path": self.settings.ml_model_path,
                    "decision": "confident_clean",
                },
            )

        # Kararsız bölge → pipeline devam etsin (HtmlScraper'a düşsün)
        return StageResult(
            scanner=self.name,
            verdict="unknown",
            confidence=malicious_probability,
            malicious_probability=malicious_probability,
            clean_probability=clean_probability,
            reason=f"ML model uncertain (confidence: {malicious_probability}), needs deeper analysis",
            details={
                "threshold": self.settings.ml_malicious_threshold,
                "model_path": self.settings.ml_model_path,
                "decision": "uncertain",
            },
        )

    def should_halt(self, result: StageResult) -> bool:
        """ML kesin karar verdiyse dur. Kararsızsa devam et."""
        decision = result.details.get("decision", "")
        return decision in ("confident_malicious", "confident_clean")

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
