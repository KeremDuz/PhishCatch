import unittest

from pydantic import ValidationError

from app.models.schemas import AnalyzeUrlRequest


class AnalyzeUrlRequestTests(unittest.TestCase):
    def test_adds_https_scheme_to_bare_domain(self):
        payload = AnalyzeUrlRequest.model_validate({"url": "example.com/login"})

        self.assertEqual(payload.url, "https://example.com/login")
        self.assertEqual(payload.original_input, "example.com/login")

    def test_keeps_existing_http_scheme(self):
        payload = AnalyzeUrlRequest.model_validate({"url": "http://example.com"})

        self.assertEqual(payload.url, "http://example.com")
        self.assertEqual(payload.original_input, "http://example.com")

    def test_canonicalizes_unicode_hostname(self):
        payload = AnalyzeUrlRequest.model_validate({"url": "https://\u0440\u0430ypal-login.example.com"})

        self.assertTrue(payload.url.startswith("https://xn--"))
        self.assertEqual(payload.original_input, "https://\u0440\u0430ypal-login.example.com")

    def test_rejects_empty_url(self):
        with self.assertRaises(ValidationError):
            AnalyzeUrlRequest.model_validate({"url": "   "})

    def test_rejects_missing_hostname(self):
        with self.assertRaises(ValidationError):
            AnalyzeUrlRequest.model_validate({"url": "https:///missing-host"})


if __name__ == "__main__":
    unittest.main()
