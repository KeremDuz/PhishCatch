import unittest
from unittest.mock import Mock, patch

from app.services.browser_renderer import BrowserRenderResult
from app.services.html_scraper_scanner import HtmlScraperScanner


class FakeHtmlModel:
    def predict_proba(self, features):
        self.feature_count = features.shape[1]
        return [[0.02, 0.98]]


class HtmlScraperScannerTests(unittest.TestCase):
    def test_blocks_localhost_fetches(self):
        result = HtmlScraperScanner().scan("http://127.0.0.1/login")

        self.assertEqual(result.verdict, "unknown")
        self.assertIn("URL fetch blocked", result.details["error"])

    def test_medium_dom_threat_score_is_unknown_not_malicious(self):
        html = """
        <html>
          <head><title>Checkout</title></head>
          <body>
            <form action="/pay">
              <input name="card_number" />
            </form>
          </body>
        </html>
        """
        response = Mock()
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.iter_content.return_value = [html.encode("utf-8")]

        scanner = HtmlScraperScanner()
        with patch.object(scanner, "_safe_get", return_value=(response, "https://shop.example/pay", [])):
            result = scanner.scan("https://shop.example/pay")

        self.assertEqual(result.verdict, "unknown")
        self.assertGreaterEqual(result.details["threat_score"], 0.3)
        self.assertLess(result.details["threat_score"], 0.6)

    def test_html_model_score_is_combined_with_rule_score(self):
        html = """
        <html>
          <head><title>Document viewer</title></head>
          <body>
            <form action="/next">
              <input name="email" />
              <input name="password" type="password" />
            </form>
          </body>
        </html>
        """
        response = Mock()
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.iter_content.return_value = [html.encode("utf-8")]

        scanner = HtmlScraperScanner()
        scanner.model = FakeHtmlModel()
        with patch.object(scanner, "_safe_get", return_value=(response, "https://docs.example/login", [])):
            result = scanner.scan("https://docs.example/login")

        self.assertEqual(result.verdict, "malicious")
        self.assertTrue(result.details["html_model"]["available"])
        self.assertEqual(result.details["html_model"]["malicious_probability"], 0.98)
        self.assertGreater(result.details["threat_score"], result.details["rule_threat_score"])

    def test_high_html_model_probability_crosses_threshold(self):
        self.assertGreaterEqual(HtmlScraperScanner._model_probability_to_risk(0.82), 0.75)

    def test_visual_brand_mismatch_can_cross_malicious_threshold(self):
        html = """
        <html>
          <head><title>Microsoft sign in</title></head>
          <body>
            <h1>Microsoft account security verification</h1>
            <form action="/next">
              <input name="email" />
              <input name="password" type="password" />
            </form>
          </body>
        </html>
        """
        response = Mock()
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.iter_content.return_value = [html.encode("utf-8")]

        scanner = HtmlScraperScanner()
        with patch.object(scanner, "_safe_get", return_value=(response, "https://ms-login.pages.dev", [])):
            result = scanner.scan("https://ms-login.pages.dev")

        self.assertEqual(result.verdict, "malicious")
        self.assertGreaterEqual(result.details["threat_score"], 0.6)
        self.assertEqual(result.details["visual_brand_signals"][0]["rule"], "visual_brand_mismatch")

    def test_browser_rendered_html_is_analyzed_when_static_shell_is_sparse(self):
        static_html = """
        <html>
          <head><title></title></head>
          <body><div id="root"></div><script src="/app.js"></script></body>
        </html>
        """
        rendered_html = """
        <html>
          <head><title>Wallet verification</title></head>
          <body>
            <h1>MetaMask wallet verification</h1>
            <form><input name="seed_phrase" /><input name="password" type="password" /></form>
          </body>
        </html>
        """
        response = Mock()
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.iter_content.return_value = [static_html.encode("utf-8")]

        scanner = HtmlScraperScanner(browser_render_enabled=True)
        rendered = BrowserRenderResult(
            available=True,
            html=rendered_html,
            final_url="https://wallet-check.pages.dev",
            title="Wallet verification",
            visible_text="MetaMask wallet verification",
            reason="Rendered with test browser",
        )
        with patch.object(scanner, "_safe_get", return_value=(response, "https://wallet-check.pages.dev", [])):
            with patch("app.services.html_scraper_scanner.render_page", return_value=rendered):
                result = scanner.scan("https://wallet-check.pages.dev")

        self.assertEqual(result.verdict, "malicious")
        self.assertTrue(result.details["browser_render"]["available"])
        self.assertIn("crypto", result.details["input_summary"])


if __name__ == "__main__":
    unittest.main()
