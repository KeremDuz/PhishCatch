from __future__ import annotations

import pytest
from app.core.pipeline import ScanningPipeline
from app.models.schemas import StageResult
from app.services import page_fetch
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.url_resolver_scanner import UrlResolverScanner
from app.services.url_safety import UrlSafetyResult
from test_detection_policy import FixedScanner, ProbabilityModel


class Response:
    def __init__(
        self,
        *,
        status=200,
        body=b"<html><title>Example</title><p>Static content</p></html>",
        location=None,
    ):
        self.status_code = status
        self.headers = {"Content-Type": "text/html"}
        self.is_redirect = location is not None
        if location:
            self.headers["Location"] = location
        self.body = body
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def iter_content(self, chunk_size):
        yield self.body


def prepare(monkeypatch, responses):
    calls = []
    monkeypatch.setattr(
        page_fetch, "validate_public_http_url", lambda url: UrlSafetyResult(True)
    )

    def request(method, url, **kwargs):
        calls.append((method, url))
        return responses[len(calls) - 1]

    monkeypatch.setattr(page_fetch, "public_http_request", request)
    return calls


def test_redirect_and_html_share_the_same_get_artifact(monkeypatch):
    responses = [
        Response(status=302, location="https://destination.example/"),
        Response(),
    ]
    calls = prepare(monkeypatch, responses)
    html = HtmlScraperScanner()
    html.model = ProbabilityModel(0.01)
    checked = []

    class Reputation(FixedScanner):
        def scan(self, url):
            checked.append(url)
            return super().scan(url)

    reputation = Reputation(StageResult(scanner="URLhausScanner", verdict="unknown"))
    result = ScanningPipeline(
        [html],
        redirect_resolver=UrlResolverScanner(),
        threat_intel_scanners=[reputation],
    ).run("https://initial.example/")
    assert calls == [
        ("GET", "https://initial.example/"),
        ("GET", "https://destination.example/"),
    ]
    assert checked == ["https://initial.example/", "https://destination.example/"]
    assert result.url == "https://destination.example/"
    dom = next(stage for stage in result.stages if stage.scanner == "HtmlScraper")
    assert dom.details["final_url"] == result.url
    assert all(response.closed for response in responses)
    assert "<html>" not in result.model_dump_json()


def test_meta_refresh_is_followed_and_counted_in_the_same_bounded_chain(monkeypatch):
    calls = prepare(
        monkeypatch,
        [
            Response(body=b'<meta http-equiv="REFRESH" content="0; URL=\'/next\'">'),
            Response(),
        ],
    )
    with page_fetch.page_fetch_session():
        page = page_fetch.fetch_page("https://initial.example/")
    assert [url for _, url in calls] == [
        "https://initial.example/",
        "https://initial.example/next",
    ]
    assert page.redirect_chain[0]["kind"] == "meta_refresh"


def test_redirect_to_private_destination_stops_before_second_connection(monkeypatch):
    calls = prepare(monkeypatch, [Response(status=302, location="http://127.0.0.1/")])
    monkeypatch.setattr(
        page_fetch,
        "validate_public_http_url",
        lambda url: (
            UrlSafetyResult(False, "private", {"blocked_ips": ["127.0.0.1"]})
            if "127.0.0.1" in url
            else UrlSafetyResult(True)
        ),
    )
    with pytest.raises(page_fetch.FetchFailure):
        page_fetch.fetch_page("https://initial.example/")
    assert len(calls) == 1


def test_fetch_failure_is_not_retried_by_html_in_same_analysis(monkeypatch):
    calls = prepare(
        monkeypatch, [Response(status=302, location="https://initial.example/")]
    )
    with page_fetch.page_fetch_session():
        for _ in range(2):
            with pytest.raises(page_fetch.FetchFailure):
                page_fetch.fetch_page("https://initial.example/")
    assert len(calls) == 1


def test_divergent_custom_content_target_cannot_be_public_clean():
    resolver = FixedScanner(
        StageResult(
            scanner="UrlResolver",
            verdict="clean",
            details={"resolved_url": "https://head.example/"},
        )
    )
    dom = FixedScanner(
        StageResult(
            scanner="HtmlScraper",
            verdict="clean",
            details={"final_url": "https://get.example/"},
        )
    )
    result = ScanningPipeline([dom], redirect_resolver=resolver).run(
        "https://initial.example/"
    )
    assert result.final_verdict == "unknown"
    assert any(
        stage.scanner == "TargetConsistency" and stage.status == "failed"
        for stage in result.stages
    )


def test_original_redirector_url_model_evidence_is_preserved(monkeypatch):
    class Lexical(FixedScanner):
        def scan(self, url):
            return StageResult(
                scanner="MLModelScanner",
                verdict="malicious" if "initial" in url else "clean",
                malicious_probability=0.99 if "initial" in url else 0.01,
                clean_probability=0.01 if "initial" in url else 0.99,
                training_features={"feature_url": url},
            )

    resolver = FixedScanner(
        StageResult(
            scanner="UrlResolver",
            verdict="clean",
            details={"resolved_url": "https://destination.example/"},
        )
    )
    result = ScanningPipeline(
        [Lexical(StageResult(scanner="MLModelScanner", verdict="unknown"))],
        redirect_resolver=resolver,
    ).run("https://initial.example/")
    assert result.final_verdict == "malicious"
    assert next(
        stage for stage in result.stages if stage.scanner == "MLModelScanner"
    ).training_features == {"feature_url": "https://destination.example/"}
    assert (
        next(
            stage for stage in result.stages if stage.scanner == "RedirectUrlModel"
        ).training_features
        == {}
    )
