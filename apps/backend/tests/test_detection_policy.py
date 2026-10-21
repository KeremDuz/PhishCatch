"""Behavioral regressions from the offline audit; not trained-model accuracy tests."""

from __future__ import annotations

from typing import ClassVar

import pytest
from app.core.config import Settings
from app.core.pipeline import ScanningPipeline
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.routers.public_analysis import _public_result
from app.services.base_scanner import BaseScanner
from app.services.html_policy import external_form_targets
from app.services.html_scraper_scanner import HtmlScraperScanner, _scan_inputs
from app.services.ml_model_scanner import MLModelScanner
from bs4 import BeautifulSoup


class FixedScanner(BaseScanner):
    def __init__(self, result: StageResult) -> None:
        super().__init__(result.scanner)
        self.result = result

    def scan(self, url: str) -> StageResult:
        return self.result.model_copy(deep=True)


class ProbabilityModel:
    classes_: ClassVar[list[int]] = [0, 1]

    def __init__(self, probability: float) -> None:
        self.probability = probability

    def predict_proba(self, features):
        return [[1 - self.probability, self.probability]]


class MemoryResponse:
    headers: ClassVar[dict[str, str]] = {"Content-Type": "text/html; charset=utf-8"}

    def __init__(self, html: str) -> None:
        self.body = html.encode()

    def raise_for_status(self) -> None:
        pass

    def iter_content(self, chunk_size: int):
        yield self.body

    def close(self) -> None:
        pass


def analyze(
    monkeypatch,
    html: str,
    *,
    html_probability: float = 0.01,
    url_probability: float = 0.1,
):
    target = "https://shop.example/checkout"
    lexical = MLModelScanner(Settings(ml_model_path="", ml_scaler_path=None))
    lexical.model = ProbabilityModel(url_probability)
    dom = HtmlScraperScanner(model_path=None)
    dom.model = ProbabilityModel(html_probability)
    monkeypatch.setattr(
        dom, "_safe_get", lambda url, headers: (MemoryResponse(html), target, [])
    )
    resolver = FixedScanner(
        StageResult(
            scanner="UrlResolver", verdict="clean", details={"resolved_url": target}
        )
    )
    reputation = FixedScanner(
        StageResult(
            scanner="URLhausScanner",
            verdict="unknown",
            details={"query_status": "no_results"},
        )
    )
    whois = FixedScanner(
        StageResult(
            scanner="WhoisScanner",
            verdict="clean",
            details={"signal": "established_domain", "age_days": 3650},
        )
    )
    result = ScanningPipeline(
        [whois, lexical, dom],
        redirect_resolver=resolver,
        threat_intel_scanners=[reputation],
    ).run(target)
    return result, next(
        stage for stage in result.stages if stage.scanner == "HtmlScraper"
    )


def test_strong_html_model_conflict_never_becomes_public_clean(monkeypatch):
    result, dom = analyze(
        monkeypatch,
        "<html><title>Example</title><p>Ordinary static content</p></html>",
        html_probability=0.99,
    )
    assert dom.verdict == "malicious"
    assert result.scan_status == "complete"
    assert result.final_verdict == "unknown"
    assert _public_result(result, result.url).final_verdict == "unknown"
    assert result.signals["unresolved_local_alerts"] == ["HtmlScraper"]
    assert result.confidence is None


def test_standard_checkout_is_not_phishing_evidence(monkeypatch):
    result, dom = analyze(
        monkeypatch,
        """<html><title>Checkout</title><body>
      <form action='/pay'><input name='card_number' autocomplete='cc-number'>
      <input name='cvv' autocomplete='cc-csc' inputmode='numeric' maxlength='3'>
      <input name='shipping_address'><input name='postcode'>
      <input type='hidden' name='csrf_token' value='private-token-do-not-store'>
      <button formaction='/pay'>Pay</button></form>
      <iframe src='https://payments.example/three-d-secure'></iframe>
      <script>document.addEventListener('keydown', validate); navigator.clipboard.writeText('receipt');</script>
    </body></html>""",
    )
    assert dom.details["rule_threat_score"] == 0
    assert dom.details["input_summary"].get("pin_otp", 0) == 0
    assert dom.details["input_summary"].get("identity", 0) == 0
    assert "private-token-do-not-store" not in result.model_dump_json()
    # Ordinary payment controls are not threat evidence, but the embedded page
    # and script's data flow have not been inspected by the static scanner.
    assert result.scan_status == "partial"
    assert _public_result(result, result.url).final_verdict == "unknown"


@pytest.mark.parametrize(
    "name",
    [
        "shipping_address",
        "account_name",
        "watchlist_filter",
        "postcode",
        "spinning",
        "passenger",
    ],
)
def test_normal_field_substrings_are_not_sensitive_categories(name):
    findings = _scan_inputs(BeautifulSoup(f'<input name="{name}">', "lxml"))
    assert not any(
        findings[key] for key in ("pin_otp", "banking", "identity", "credentials")
    )


@pytest.mark.parametrize(
    "name,category",
    [
        ("verificationCode", "pin_otp"),
        ("şifre", "credentials"),
        ("bank_account", "banking"),
        ("tc_kimlik", "identity"),
    ],
)
def test_explicit_sensitive_field_tokens_remain_observable(name, category):
    assert _scan_inputs(BeautifulSoup(f'<input name="{name}">', "lxml"))[category]


@pytest.mark.parametrize(
    "action",
    [
        "https://collector.example/receive",
        "//collector.example/receive",
        "HTTPS://collector.example/receive",
    ],
)
def test_equivalent_external_form_targets_have_identical_policy(monkeypatch, action):
    result, dom = analyze(
        monkeypatch,
        f'<html><title>Sign in</title><form action="{action}"><input type="password"></form></html>',
    )
    assert dom.details["external_form_actions"] == 1
    assert dom.details["rule_threat_score"] == 0.35
    assert _public_result(result, result.url).final_verdict == "unknown"


def test_base_and_button_formaction_are_resolved_without_fetching():
    soup = BeautifulSoup(
        '<base href="https://collector.example/path/"><form action="receive"><button formaction="//other.example/pay">Pay</button></form>',
        "lxml",
    )
    assert external_form_targets(soup, "https://shop.example/") == (2, 0)


@pytest.mark.parametrize(
    "first,second,count",
    [
        ("https://a.github.io/", "https://b.github.io/submit", 1),
        ("https://shop.company.co.uk/", "https://pay.company.co.uk/submit", 0),
        ("https://shop.example/", "https://user:secret@shop.example/submit", 0),
    ],
)
def test_site_identity_and_unsupported_credentials(first, second, count):
    soup = BeautifulSoup(f'<form action="{second}"></form>', "lxml")
    external, unsupported = external_form_targets(soup, first)
    assert external == count
    assert unsupported == int("secret@" in second)


@pytest.mark.parametrize("padding", ["", "<!--" + "x" * 5000 + "-->"])
def test_padding_does_not_make_unrendered_shell_complete(monkeypatch, padding):
    result, dom = analyze(
        monkeypatch,
        '<html><title>Application</title><div id="root"></div><script src="/app.js"></script>'
        + padding
        + "</html>",
    )
    assert dom.status == "completed"  # Static assessment is retained.
    assert result.scan_status == "partial"
    assert any(
        s.scanner == "BrowserRenderer" and s.status == "unavailable"
        for s in result.stages
    )
    assert _public_result(result, result.url).final_verdict == "unknown"


def test_login_keyboard_validation_is_missing_coverage_not_threat_evidence(monkeypatch):
    result, dom = analyze(
        monkeypatch,
        '<html><title>Sign in</title><form method="post"><input type="password"><button>Continue</button></form><script>document.onkeydown=validate;</script></html>',
    )
    assert dom.details["rule_threat_score"] == 0
    assert result.scan_status == "partial"
    assert result.final_verdict == "unknown"


def test_repeated_title_and_logo_brand_claim_are_one_signal(monkeypatch):
    result, dom = analyze(
        monkeypatch,
        '<html><title>Microsoft Login</title><h1>Microsoft</h1><img src="microsoft-logo.png"><form action="//collector.example/login"><input type="password"></form></html>',
    )
    assert len(dom.details["visual_brand_signals"]) == 1
    assert dom.details["rule_context"]["strong_signal"]
    assert result.final_verdict == "malicious"


def test_public_projection_rejects_inconsistent_custom_clean_decision():
    result = AnalyzeUrlResponse(
        url="https://example.com/",
        normalized_url="https://example.com/",
        final_verdict="clean",
        decided_by="custom",
        stages=[
            StageResult(scanner="HtmlScraper", verdict="malicious", risk_score=0.9)
        ],
    )
    assert _public_result(result, result.url).final_verdict == "unknown"


def test_html_model_score_mapping_is_monotone_and_continuous_at_point_eight():
    mapping = HtmlScraperScanner._model_probability_to_risk
    assert 0 <= mapping(0.7999) <= mapping(0.8) <= mapping(0.8001) <= 1
    assert mapping(0.8) - mapping(0.7999) < 0.001
