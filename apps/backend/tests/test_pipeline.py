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
        self.assertEqual(response.decided_by, "ml")
        self.assertEqual(response.final_verdict, "clean")

    def test_halts_on_scanner_decision(self):
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

        self.assertEqual(second.seen_urls, [])
        self.assertEqual(response.decided_by, "first")
        self.assertEqual(response.final_verdict, "malicious")


if __name__ == "__main__":
    unittest.main()
