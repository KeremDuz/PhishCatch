import unittest

from app.services.campaign_context import build_campaign_context, evaluate_campaign_url


class CampaignContextTests(unittest.TestCase):
    def test_repeated_high_risk_host_returns_campaign_signal(self):
        urls = [
            "https://kopinyakopikopi.run.place/mpps/aaa111/websrc",
            "https://kopinyakopikopi.run.place/mpps/bbb222/websrc",
            "https://kopinyakopikopi.run.place/mpps/ccc333/websrc",
            "https://kopinyakopikopi.run.place/mpps/ddd444/websrc",
            "https://kopinyakopikopi.run.place/mpps/eee555/websrc",
        ]

        context = build_campaign_context(urls)
        signal = evaluate_campaign_url(urls[0], context)

        self.assertIsNotNone(signal)
        self.assertGreaterEqual(signal.score, 0.6)
        self.assertIn("Repeated high-risk campaign host", signal.reason)

    def test_repeated_legitimate_host_without_suspicious_context_stays_quiet(self):
        urls = [
            "https://example.com/about",
            "https://example.com/pricing",
            "https://example.com/blog",
            "https://example.com/contact",
            "https://example.com/docs",
        ]

        context = build_campaign_context(urls)
        signal = evaluate_campaign_url(urls[0], context)

        self.assertIsNone(signal)


if __name__ == "__main__":
    unittest.main()
