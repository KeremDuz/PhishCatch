import unittest

from app.core.config import Settings
from app.services.ml_model_scanner import MLModelScanner


class DummyModel:
    def __init__(self, feature_count: int, probability: float):
        self.n_features_in_ = feature_count
        self.probability = probability

    def predict_proba(self, model_input):
        self.last_shape = model_input.shape
        return [[1 - self.probability, self.probability]]


class MLModelScannerTests(unittest.TestCase):
    def _scanner_with_model(self, feature_count: int, probability: float) -> MLModelScanner:
        scanner = MLModelScanner(Settings(ml_model_path="missing.pkl", ml_scaler_path=None))
        scanner.model = DummyModel(feature_count=feature_count, probability=probability)
        scanner.scaler = None
        return scanner

    def test_uses_url_only_feature_frame_for_new_models(self):
        scanner = self._scanner_with_model(feature_count=30, probability=0.8)

        result = scanner.scan("https://example.com/login")

        self.assertEqual(scanner.model.last_shape, (1, 30))
        self.assertEqual(result.details["feature_schema"], "url_lexical_v1")
        self.assertEqual(result.details["feature_count"], 30)

    def test_uses_mendeley_48_feature_frame_for_compatibility(self):
        scanner = self._scanner_with_model(feature_count=48, probability=0.8)

        result = scanner.scan("https://example.com/login")

        self.assertEqual(scanner.model.last_shape, (1, 48))
        self.assertEqual(result.details["feature_schema"], "mendeley_48_approx")
        self.assertEqual(result.details["feature_count"], 48)

    def test_uses_legacy_16_feature_frame_for_old_models(self):
        scanner = self._scanner_with_model(feature_count=16, probability=0.8)

        result = scanner.scan("https://example.com/login")

        self.assertEqual(scanner.model.last_shape, (1, 16))
        self.assertEqual(result.details["feature_schema"], "legacy_16")
        self.assertEqual(result.details["feature_count"], 16)

    def test_confident_malicious_halts_pipeline(self):
        scanner = self._scanner_with_model(feature_count=48, probability=0.99)

        result = scanner.scan("https://example.com/login")

        self.assertEqual(result.verdict, "malicious")
        self.assertTrue(scanner.should_halt(result))
        self.assertEqual(result.details["decision"], "confident_malicious")

    def test_confident_clean_halts_pipeline(self):
        scanner = self._scanner_with_model(feature_count=48, probability=0.01)

        result = scanner.scan("https://example.com")

        self.assertEqual(result.verdict, "clean")
        self.assertTrue(scanner.should_halt(result))
        self.assertEqual(result.details["decision"], "confident_clean")

    def test_uncertain_result_continues_pipeline(self):
        scanner = self._scanner_with_model(feature_count=48, probability=0.5)

        result = scanner.scan("https://example.com")

        self.assertEqual(result.verdict, "unknown")
        self.assertFalse(scanner.should_halt(result))
        self.assertEqual(result.details["decision"], "uncertain")


if __name__ == "__main__":
    unittest.main()
