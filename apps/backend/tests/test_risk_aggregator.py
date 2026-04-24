import unittest

from app.core.risk_aggregator import RiskAggregator
from app.models.schemas import StageResult


class RiskAggregatorTests(unittest.TestCase):
    def test_threat_intel_hit_returns_malicious(self):
        decision = RiskAggregator().aggregate(
            [
                StageResult(
                    scanner="URLhausScanner",
                    verdict="malicious",
                    confidence=0.95,
                    risk_score=0.97,
                    reason="Known malicious URL",
                )
            ]
        )

        self.assertEqual(decision.final_verdict, "malicious")
        self.assertGreaterEqual(decision.risk_score, 0.95)

    def test_weak_whois_signal_alone_stays_clean(self):
        decision = RiskAggregator().aggregate(
            [
                StageResult(
                    scanner="WhoisScanner",
                    verdict="unknown",
                    risk_score=0.45,
                    reason="Domain is very new",
                    details={"signal": "new_domain"},
                )
            ]
        )

        self.assertEqual(decision.final_verdict, "clean")
        self.assertLess(decision.risk_score, RiskAggregator.MALICIOUS_THRESHOLD)

    def test_combined_medium_signals_return_malicious(self):
        decision = RiskAggregator().aggregate(
            [
                StageResult(
                    scanner="WhoisScanner",
                    verdict="unknown",
                    risk_score=0.45,
                    reason="Domain is very new",
                    details={"signal": "new_domain"},
                ),
                StageResult(
                    scanner="HtmlScraper",
                    verdict="unknown",
                    risk_score=0.4,
                    reason="Sensitive form behavior detected",
                ),
            ]
        )

        self.assertEqual(decision.final_verdict, "malicious")
        self.assertGreaterEqual(decision.risk_score, RiskAggregator.MALICIOUS_THRESHOLD)

    def test_clean_ml_and_html_reduce_risk(self):
        decision = RiskAggregator().aggregate(
            [
                StageResult(
                    scanner="MLModelScanner",
                    verdict="clean",
                    malicious_probability=0.05,
                    clean_probability=0.95,
                    reason="ML model: high confidence clean",
                ),
                StageResult(
                    scanner="HtmlScraper",
                    verdict="clean",
                    risk_score=0.0,
                    reason="DOM structure appears normal",
                    details={"threat_score": 0.0},
                ),
            ]
        )

        self.assertEqual(decision.final_verdict, "clean")
        self.assertLess(decision.risk_score, 0.1)


if __name__ == "__main__":
    unittest.main()
