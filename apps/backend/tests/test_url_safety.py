import unittest

from app.services.url_safety import validate_public_http_url


class UrlSafetyTests(unittest.TestCase):
    def test_blocks_non_http_schemes(self):
        result = validate_public_http_url("ftp://example.com/file")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.reason, "Only http and https URLs can be fetched")

    def test_blocks_localhost(self):
        result = validate_public_http_url("http://localhost:8001/health")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.reason, "Localhost URLs are not fetched")

    def test_blocks_private_ip(self):
        result = validate_public_http_url("http://192.168.1.10/admin")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.reason, "Hostname resolves to a non-public IP address")

    def test_blocks_cloud_metadata_ip(self):
        result = validate_public_http_url("http://169.254.169.254/latest/meta-data")

        self.assertFalse(result.is_safe)
        self.assertEqual(result.reason, "Hostname resolves to a non-public IP address")

    def test_allows_public_ip_without_dns_lookup(self):
        result = validate_public_http_url("https://8.8.8.8/dns-query")

        self.assertTrue(result.is_safe)


if __name__ == "__main__":
    unittest.main()
