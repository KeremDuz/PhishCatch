import unittest

from app.utils.url_utils import canonicalize_url, parse_url_parts


class UrlUtilsTests(unittest.TestCase):
    def test_canonicalizes_unicode_hostname_to_idna(self):
        url = "https://\u0440\u0430ypal-login.example.com"

        canonical = canonicalize_url(url)
        parts = parse_url_parts(url)

        self.assertTrue(canonical.startswith("https://xn--"))
        self.assertEqual(parts.skeleton_hostname, "paypal-login.example.com")
        self.assertTrue(parts.is_idn)
        self.assertTrue(parts.has_punycode_label)
        self.assertTrue(parts.has_mixed_script)

    def test_extracts_known_public_suffix_fallbacks(self):
        parts = parse_url_parts("https://login.example.github.io/path")

        self.assertEqual(parts.registrable_domain, "example.github.io")
        self.assertEqual(parts.suffix, "github.io")
        self.assertEqual(parts.subdomain, "login")


if __name__ == "__main__":
    unittest.main()
