import unittest

from app.ml.feature_extractor import (
    FEATURE_COLUMNS,
    LEGACY_FEATURE_COLUMNS,
    MENDELEY_48_FEATURE_COLUMNS,
    URL_FEATURE_COLUMNS,
    extract_48_features_dataframe,
    extract_features_dataframe,
    extract_legacy_features_dataframe,
)


class FeatureExtractorTests(unittest.TestCase):
    def test_default_extractor_returns_url_only_ordered_features(self):
        frame = extract_features_dataframe("https://secure-login.example.com/verify?token=123")

        self.assertEqual(frame.shape, (1, 30))
        self.assertEqual(list(frame.columns), URL_FEATURE_COLUMNS)
        self.assertEqual(list(frame.columns), FEATURE_COLUMNS)
        self.assertEqual(frame.loc[0, "NoHttps"], 0.0)
        self.assertGreater(frame.loc[0, "NumSensitiveWords"], 0.0)

    def test_mendeley_48_extractor_stays_available_for_old_models(self):
        frame = extract_48_features_dataframe("https://secure-login.example.com/verify?token=123")

        self.assertEqual(frame.shape, (1, 48))
        self.assertEqual(list(frame.columns), MENDELEY_48_FEATURE_COLUMNS)
        self.assertIn("PctExtHyperlinks", frame.columns)

    def test_legacy_extractor_stays_available_for_old_models(self):
        frame = extract_legacy_features_dataframe("https://example.com/login")

        self.assertEqual(frame.shape, (1, 16))
        self.assertEqual(list(frame.columns), LEGACY_FEATURE_COLUMNS)
        self.assertGreater(frame.loc[0, "has_suspicious_word"], 0.0)


if __name__ == "__main__":
    unittest.main()
