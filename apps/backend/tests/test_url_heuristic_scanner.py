import unittest

from app.services.url_heuristic_scanner import URLHeuristicScanner


class URLHeuristicScannerTests(unittest.TestCase):
    def test_brand_impersonation_on_free_hosting_is_malicious(self):
        result = URLHeuristicScanner().scan("https://auth-login-office-com.saxeco7653.workers.dev/")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.65)
        self.assertGreaterEqual(len(result.details["matched_rules"]), 2)

    def test_legitimate_brand_host_stays_clean(self):
        result = URLHeuristicScanner().scan("https://login.microsoft.com/common/oauth2/v2.0/authorize")

        self.assertEqual(result.verdict, "clean")
        self.assertEqual(result.risk_score, 0.0)

    def test_plain_free_hosting_without_brand_or_auth_stays_clean(self):
        result = URLHeuristicScanner().scan("https://my-portfolio.vercel.app/")

        self.assertEqual(result.verdict, "clean")
        self.assertEqual(result.risk_score, 0.0)

    def test_brand_plus_auth_context_crosses_malicious_threshold(self):
        result = URLHeuristicScanner().scan("https://www.usps-service.info/contact")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.6)

    def test_brand_lookalike_crosses_malicious_threshold(self):
        result = URLHeuristicScanner().scan("http://koquinlogin.webflow.io/")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.65)

    def test_shortener_is_positive_but_not_final_malicious_alone(self):
        result = URLHeuristicScanner().scan("http://did.li/r39CN")

        self.assertEqual(result.verdict, "unknown")
        self.assertGreater(result.risk_score, 0.0)
        self.assertLess(result.risk_score, 0.65)

    def test_repeated_campaign_path_on_run_place_is_malicious(self):
        result = URLHeuristicScanner().scan("https://kopinyakopikopi.run.place/mpps/abcdef123456/websrc")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.65)

    def test_tiktok_shop_impersonation_is_malicious(self):
        result = URLHeuristicScanner().scan("https://wap.tiktokshopwholesale.com")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.65)

    def test_trezor_lookalike_on_weebly_is_malicious(self):
        result = URLHeuristicScanner().scan("https://trezzuresuite-net.weebly.com/help")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.65)

    def test_idn_homoglyph_brand_is_malicious(self):
        result = URLHeuristicScanner().scan("https://\u0440\u0430ypal-login.example.com")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 0.65)
        self.assertEqual(result.details["matched_rules"][0]["rule"], "idn_homoglyph_brand")


if __name__ == "__main__":
    unittest.main()
