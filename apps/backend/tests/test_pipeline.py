import unittest

from app.core.pipeline import ScanningPipeline
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner


class StubScanner(BaseScanner):
    def __init__(self, name, result, halt=False):
        super().__init__(name=name)
        self.result = result
        self.halt = halt
        self.seen_urls = []

    def scan(self, url: str) -> StageResult:
        self.seen_urls.append(url)
        return self.result

    def should_halt(self, result: StageResult) -> bool:
        return self.halt


class ScanningPipelineTests(unittest.TestCase):
    def test_requires_at_least_one_scanner(self):
        with self.assertRaises(ValueError):
            ScanningPipeline([])

    def test_passes_resolved_url_to_next_scanner(self):
        resolver = StubScanner(
            "resolver",
            StageResult(
                scanner="resolver",
                verdict="clean",
                details={"resolved_url": "https://resolved.example"},
            ),
        )
        ml = StubScanner(
            "ml",
            StageResult(scanner="ml", verdict="clean", confidence=0.1),
            halt=True,
        )

        response = ScanningPipeline([resolver, ml]).run("https://short.example")

        self.assertEqual(ml.seen_urls, ["https://resolved.example"])
        self.assertEqual(response.normalized_url, "https://resolved.example")
        self.assertEqual(response.decided_by, "RiskAggregator")
        self.assertEqual(response.final_verdict, "clean")

    def test_collects_all_scanner_results_before_final_decision(self):
        first = StubScanner(
            "first",
            StageResult(scanner="first", verdict="malicious", confidence=0.9),
            halt=True,
        )
        second = StubScanner(
            "second",
            StageResult(scanner="second", verdict="clean", confidence=0.1),
        )

        response = ScanningPipeline([first, second]).run("https://example.com")

        self.assertEqual(second.seen_urls, ["https://example.com"])
        self.assertEqual(response.decided_by, "RiskAggregator")
        self.assertEqual(response.final_verdict, "malicious")
        self.assertEqual(len(response.stages), 2)

    def test_skips_external_reputation_when_url_is_not_public_fetch_safe(self):
        resolver = StubScanner(
            "UrlResolver",
            StageResult(
                scanner="UrlResolver",
                verdict="unknown",
                risk_score=0.7,
                reason="URL fetch blocked",
                details={
                    "resolved_url": "http://127.0.0.1/login",
                    "safety": {"hostname": "127.0.0.1", "blocked_ips": ["127.0.0.1"]},
                },
            ),
        )
        external = StubScanner(
            "URLhausScanner",
            StageResult(scanner="URLhausScanner", verdict="malicious", confidence=0.95),
        )
        ml = StubScanner(
            "MLModelScanner",
            StageResult(scanner="MLModelScanner", verdict="unknown", malicious_probability=0.2),
        )

        response = ScanningPipeline([resolver, external, ml]).run("http://127.0.0.1/login")

        self.assertEqual(external.seen_urls, [])
        self.assertTrue(response.stages[1].details["skipped"])
        self.assertEqual(response.final_verdict, "malicious")


if __name__ == "__main__":
    unittest.main()
