import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.models.scan_schemas import FastScanResponse
from app.routers import scan as scan_router
from app.services.ml_model_scanner import DeepScanResult


class ScanEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        scan_router.get_fast_scanner.cache_clear()
        scan_router.get_deep_scanner.cache_clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        scan_router.get_fast_scanner.cache_clear()
        scan_router.get_deep_scanner.cache_clear()

    def test_scan_fast_returns_safe(self) -> None:
        mocked_response = FastScanResponse(
            url="https://example.com",
            normalized_url="https://example.com",
            status="safe",
            risk_score=0.0,
            reason="mock safe",
        )

        with patch(
            "app.services.fast_scanner.VirusTotalFastScanner.scan",
            new=AsyncMock(return_value=mocked_response),
        ):
            response = self.client.post("/api/v1/scan/fast", json={"url": "example.com"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "safe")
        self.assertEqual(body["normalized_url"], "https://example.com")
        self.assertEqual(body["original_input"], "example.com")

    def test_scan_deep_returns_malicious(self) -> None:
        mocked_deep = DeepScanResult(
            url="https://example.com",
            status="malicious",
            risk_score=87.5,
            malicious_probability=0.875,
            confidence=0.875,
            model_name="xgboost",
            html_fetched=True,
            error=None,
        )

        with patch(
            "app.services.ml_model_scanner.MLModelScanner.scan",
            new=AsyncMock(return_value=mocked_deep),
        ):
            response = self.client.post("/api/v1/scan/deep", json={"url": "https://example.com"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["tier"], "tier2_ml_deep")
        self.assertEqual(body["status"], "malicious")
        self.assertEqual(body["risk_score"], 87.5)
        self.assertTrue(body["html_fetched"])

    def test_scan_deep_returns_unknown_when_fetch_fails(self) -> None:
        mocked_deep = DeepScanResult(
            url="https://example.com",
            status="unknown",
            risk_score=0.0,
            malicious_probability=0.0,
            confidence=0.0,
            model_name="xgboost",
            html_fetched=False,
            error="SSL verify failed",
        )

        with patch(
            "app.services.ml_model_scanner.MLModelScanner.scan",
            new=AsyncMock(return_value=mocked_deep),
        ):
            response = self.client.post("/api/v1/scan/deep", json={"url": "https://example.com"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "unknown")
        self.assertEqual(body["risk_score"], 0.0)
        self.assertFalse(body["html_fetched"])
        self.assertIsNotNone(body["error"])


if __name__ == "__main__":
    unittest.main()
