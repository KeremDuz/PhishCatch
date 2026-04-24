import unittest
from unittest.mock import Mock, patch

from app.services.html_scraper_scanner import HtmlScraperScanner


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


if __name__ == "__main__":
    unittest.main()
