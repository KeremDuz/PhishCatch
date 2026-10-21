from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from app.services import cloudflare_dns_scanner as module
from app.core import scan_cache as cache_module
from app.core.scan_cache import ScannerResultCache
from app.models.schemas import StageResult
from app.services.cloudflare_dns_scanner import CloudflareDnsSecurityScanner
from app.services.web_risk_scanner import lookup_session
from app.services.worker_process import WorkerFailure
from app.core.config import Settings
from app.core.pipeline import ScanningPipeline
from app.services.base_scanner import BaseScanner


def answer(address="1.1.1.1", *, ttl=60, name="example.com.", record_type=1):
    return {"name": name, "type": record_type, "TTL": ttl, "data": address}


def dns_response(*, answers=None, status=0):
    return {
        "Status": status,
        "TC": False,
        "Question": [{"name": "example.com.", "type": 1}],
        "Answer": [answer()] if answers is None else answers,
    }


def transport(monkeypatch, payload):
    response = Mock(status_code=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    response.iter_content.return_value = [json.dumps(payload).encode()]
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=None)
    session.get.return_value = response
    monkeypatch.setattr(module.requests, "Session", Mock(return_value=session))
    return session, response


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://192.168.1.1/",
        "https://machine.internal/",
        "https://machine.local/",
        "https://intranet/",
        "https://host.home.arpa/",
        "https://user:secret@example.com/",
    ],
)
def test_private_or_ineligible_targets_do_not_query_provider(monkeypatch, url):
    worker = Mock()
    monkeypatch.setattr(module, "bounded_process", worker)
    result = CloudflareDnsSecurityScanner().scan(url)
    assert result.verdict == "unknown"
    worker.assert_not_called()


def test_only_hostname_reaches_child_no_path_query_fragment_or_api_key(monkeypatch):
    worker = Mock(
        return_value=json.dumps(
            {
                "filtered": False,
                "ambiguous_sinkhole": False,
                "provider_cache_ttl_seconds": 60,
            }
        ).encode()
    )
    monkeypatch.setattr(module, "bounded_process", worker)
    result = CloudflareDnsSecurityScanner().scan(
        "https://Example.COM/private/reset?token=secret#hidden"
    )
    assert result.verdict == "unknown" and result.status == "completed"
    assert result.details["scope"] == "hostname_only"
    assert json.loads(worker.call_args.args[1]) == {"hostname": "example.com"}
    assert worker.call_args.args[2] <= 5
    assert "token" not in result.model_dump_json()


def test_transport_fixed_resolver_no_redirect_and_bounded_response(monkeypatch):
    session, response = transport(monkeypatch, dns_response())
    result = module._dns_query(module.SECURITY_ENDPOINT, "example.com")
    assert result["addresses"] == ["1.1.1.1"]
    assert session.trust_env is False
    assert session.get.call_args.args == (module.SECURITY_ENDPOINT,)
    options = session.get.call_args.kwargs
    assert options["params"] == {"name": "example.com", "type": "A"}
    assert options["allow_redirects"] is False
    assert options["headers"] == {"Accept": "application/dns-json"}
    response.iter_content.return_value = [b"x" * (module.MAX_DNS_RESPONSE + 1)]
    with pytest.raises(ValueError):
        module._dns_query(module.SECURITY_ENDPOINT, "example.com")
    with pytest.raises(ValueError):
        module._dns_query("https://untrusted.example/dns-query", "example.com")


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_question",
        "boolean_question_type",
        "boolean_record_type",
        "integer_address",
        "nxdomain_with_address",
        "truncated",
        "bad_status",
        "nonobject_question",
    ],
)
def test_malformed_dns_responses_fail_closed(monkeypatch, mutation):
    data = dns_response()
    if mutation == "wrong_question":
        data["Question"][0]["name"] = "other.com."
    elif mutation == "boolean_question_type":
        data["Question"][0]["type"] = True
    elif mutation == "boolean_record_type":
        data["Answer"][0]["type"] = True
    elif mutation == "integer_address":
        data["Answer"][0]["data"] = 0
    elif mutation == "nxdomain_with_address":
        data["Status"] = 3
    elif mutation == "truncated":
        data["TC"] = True
    elif mutation == "bad_status":
        data["Status"] = 2
    else:
        data["Question"] = [None]
    transport(monkeypatch, data)
    assert (
        module.query_security_dns("example.com").get("error")
        == "dns_security_lookup_failed"
    )


def test_cname_chain_and_only_relevant_records_contribute_addresses_and_ttl(
    monkeypatch,
):
    data = dns_response(
        answers=[
            answer("alias.example.net.", ttl=7, record_type=5),
            answer("1.1.1.1", ttl=40, name="alias.example.net."),
            answer("0.0.0.0", ttl=0, name="unrelated.example.org."),
        ]
    )
    transport(monkeypatch, data)
    result = module._dns_query(module.SECURITY_ENDPOINT, "example.com")
    assert result["addresses"] == ["1.1.1.1"]
    assert result["ttl"] == 7


@pytest.mark.parametrize(
    "control_addresses,filtered,ambiguous",
    [
        (["1.1.1.1"], True, False),
        (["0.0.0.0"], False, True),
        ([], False, True),
    ],
)
def test_security_sinkhole_needs_control_comparison_and_shortest_ttl(
    monkeypatch, control_addresses, filtered, ambiguous
):
    def query(endpoint, hostname):
        if endpoint == module.SECURITY_ENDPOINT:
            return {
                "addresses": ["0.0.0.0"],
                "ttl": 300,
                "ede_codes": [16],
                "nxdomain": False,
            }
        return {
            "addresses": control_addresses,
            "ttl": 2,
            "ede_codes": [],
            "nxdomain": False,
        }

    monkeypatch.setattr(module, "_dns_query", query)
    result = module.query_security_dns("example.com")
    assert result["filtered"] is filtered
    assert result["ambiguous_sinkhole"] is ambiguous
    assert result["provider_cache_ttl_seconds"] <= 2


@pytest.mark.parametrize(
    "filtered,ambiguous", [(True, False), (False, True), (False, False)]
)
def test_dns_context_never_invents_phishing_or_clean_verdict(
    monkeypatch, filtered, ambiguous
):
    monkeypatch.setattr(
        module,
        "bounded_process",
        Mock(
            return_value=json.dumps(
                {
                    "filtered": filtered,
                    "ambiguous_sinkhole": ambiguous,
                    "provider_cache_ttl_seconds": 0,
                }
            ).encode()
        ),
    )
    result = CloudflareDnsSecurityScanner().scan("https://example.com/")
    assert result.verdict == "unknown"
    assert result.malicious_probability is None
    assert result.details["requires_review"] is (filtered or ambiguous)
    assert result.details["provider_cache_ttl_seconds"] == 0


@pytest.mark.parametrize("ede,review", [(15, True), (16, True), (17, True), (3, False)])
def test_policy_filter_without_sinkhole_is_review_not_phishing(
    monkeypatch, ede, review
):
    monkeypatch.setattr(
        module,
        "_dns_query",
        lambda *args: {
            "addresses": ["1.1.1.1"],
            "ttl": 60,
            "ede_codes": [ede],
            "nxdomain": False,
        },
    )
    captured = module.query_security_dns("example.com")
    assert captured["policy_filter"] is review
    monkeypatch.setattr(
        module, "bounded_process", Mock(return_value=json.dumps(captured).encode())
    )
    result = CloudflareDnsSecurityScanner().scan("https://example.com/")
    assert result.verdict == "unknown"
    assert result.details["requires_review"] is review
    assert result.malicious_probability is None


def test_failed_hostname_is_retried_next_scan_not_for_each_redirect_path(monkeypatch):
    child = Mock(side_effect=WorkerFailure("worker_timeout"))
    monkeypatch.setattr(module, "bounded_process", child)
    service = CloudflareDnsSecurityScanner()
    with lookup_session():
        assert service.scan("https://example.com/a").status == "unavailable"
        assert service.scan("https://example.com/b").status == "unavailable"
    assert child.call_count == 1
    with lookup_session():
        assert service.scan("https://example.com/a").status == "unavailable"
    assert child.call_count == 2


def test_child_timeout_is_redacted_and_unavailable(monkeypatch):
    monkeypatch.setattr(
        module, "bounded_process", Mock(side_effect=WorkerFailure("worker_timeout"))
    )
    result = CloudflareDnsSecurityScanner().scan(
        "https://example.com/private?secret=token"
    )
    assert result.verdict == "unknown" and result.status == "unavailable"
    assert "secret" not in result.model_dump_json()


def test_shared_scan_budget_is_not_reset_by_dns_lookup(monkeypatch):
    worker = Mock(
        return_value=b'{"filtered":false,"ambiguous_sinkhole":false,"provider_cache_ttl_seconds":60}'
    )
    monkeypatch.setattr(module, "bounded_process", worker)
    service = CloudflareDnsSecurityScanner()
    with lookup_session():
        for index in range(6):
            assert (
                service.scan(f"https://host{index}.example.com/").status == "completed"
            )
        result = service.scan("https://seventh.example.com/")
    assert result.status == "unavailable"
    assert worker.call_count == 6


def test_same_hostname_reuses_dns_context_without_spending_more_calls(monkeypatch):
    worker = Mock(
        return_value=b'{"filtered":false,"ambiguous_sinkhole":false,"provider_cache_ttl_seconds":60}'
    )
    monkeypatch.setattr(module, "bounded_process", worker)
    service = CloudflareDnsSecurityScanner()
    with lookup_session():
        for index in range(8):
            assert (
                service.scan(f"https://example.com/{index}?token=private").status
                == "completed"
            )
    assert worker.call_count == 1


def test_dns_cache_uses_hostname_and_never_exceeds_provider_ttl(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(cache_module.time, "monotonic", lambda: clock[0])
    cache = ScannerResultCache(ttl_seconds=300)
    result = StageResult(
        scanner="CloudflareDnsSecurity",
        verdict="unknown",
        details={
            "requires_review": True,
            "provider_cache_ttl_seconds": 1,
        },
    )
    cache.set(result.scanner, "https://Example.COM/one?token=private", result)
    assert cache.get(result.scanner, "http://example.com/two") is not None
    assert all("example.com" not in value for value in cache._entries)
    clock[0] += 2
    assert cache.get(result.scanner, "https://example.com/three") is None
    result.details["provider_cache_ttl_seconds"] = 0
    cache.set(result.scanner, "https://example.com/", result)
    assert cache.get(result.scanner, "https://example.com/") is None


def test_malformed_idna_target_cannot_raise_from_dns_cache():
    cache = ScannerResultCache()
    assert cache.get("CloudflareDnsSecurity", f"https://{'a' * 64}.com/") is None


@pytest.mark.parametrize("kind", ["cycle", "too_deep"])
def test_cname_cycles_and_truncated_chains_are_unavailable(monkeypatch, kind):
    if kind == "cycle":
        records = [
            answer("alias.example.net.", record_type=5),
            answer("example.com.", name="alias.example.net.", record_type=5),
        ]
    else:
        records = []
        name = "example.com."
        for number in range(17):
            target = f"alias{number}.example.net."
            records.append(answer(target, name=name, record_type=5))
            name = target
        records.append(answer("0.0.0.0", name=name))
    transport(monkeypatch, dns_response(answers=records))
    assert (
        module.query_security_dns("example.com").get("error")
        == "dns_security_lookup_failed"
    )


class ForbiddenScanner(BaseScanner):
    def __init__(self, name):
        super().__init__(name)
        self.calls = 0

    def scan(self, url):
        self.calls += 1
        pytest.fail("DNS review must stop before target fetch and local analysis")


@pytest.mark.parametrize("filtered,ambiguous", [(True, False), (False, True)])
def test_dns_review_precheck_stops_before_fetch_without_inventing_phishing(
    monkeypatch, filtered, ambiguous
):
    worker = Mock(
        return_value=json.dumps(
            {
                "filtered": filtered,
                "ambiguous_sinkhole": ambiguous,
                "provider_cache_ttl_seconds": 60,
            }
        ).encode()
    )
    monkeypatch.setattr(module, "bounded_process", worker)
    resolver = ForbiddenScanner("UrlResolver")
    html = ForbiddenScanner("HtmlScraper")
    pipeline = ScanningPipeline(
        scanners=[html],
        redirect_resolver=resolver,
        threat_intel_scanners=[CloudflareDnsSecurityScanner()],
    )
    result = pipeline.run("https://example.com/")
    assert result.final_verdict == "unknown"
    assert result.scan_status == "partial"
    assert result.decided_by == "DnsSecurityReview"
    assert result.malicious_probability is None
    assert resolver.calls == 0 and html.calls == 0
    assert all(stage.verdict != "malicious" for stage in result.stages)
    assert worker.call_count == 1


def test_free_profile_cannot_activate_credentialed_providers_even_with_old_keys(
    monkeypatch, tmp_path
):
    from app import dependencies

    configured = Settings(
        reputation_free_only=True,
        cloudflare_dns_security_enabled=True,
        phishing_feed_path=str(tmp_path / "missing-test-feed.json"),
        urlhaus_auth_key="test-only-urlhaus",
        google_safe_browsing_api_key="test-only-gsb",
        google_web_risk_api_key="test-only-webrisk",
        google_web_risk_allow_url_sharing=True,
        virustotal_api_key="test-only-vt",
        virustotal_api_keys=["test-only-vt"],
        ml_model_path=str(tmp_path / "missing-model.pkl"),
        html_model_path=None,
    )
    monkeypatch.setattr(dependencies, "settings", configured)

    def forbidden_provider(*args, **kwargs):
        pytest.fail("The free profile must never instantiate a credentialed provider")

    for provider in (
        "UrlhausScanner",
        "GoogleSafeBrowsingScanner",
        "GoogleWebRiskScanner",
        "VirusTotalScanner",
    ):
        monkeypatch.setattr(dependencies, provider, forbidden_provider)
    monkeypatch.setattr(
        dependencies,
        "MLModelScanner",
        lambda **kwargs: ForbiddenScanner("MLModelScanner"),
    )
    monkeypatch.setattr(
        dependencies,
        "HtmlScraperScanner",
        lambda **kwargs: ForbiddenScanner("HtmlScraper"),
    )
    monkeypatch.setattr(
        dependencies, "RdapScanner", lambda: ForbiddenScanner("RdapScanner")
    )
    dependencies.get_scanning_pipeline.cache_clear()
    try:
        pipeline = dependencies.get_scanning_pipeline()
        assert [item.name for item in pipeline.threat_intel_scanners] == [
            "LocalPhishingFeed",
            "CloudflareDnsSecurity",
        ]
    finally:
        dependencies.get_scanning_pipeline.cache_clear()


@pytest.mark.parametrize("missing_last", [False, True])
def test_redirect_review_is_retained_even_when_other_targets_have_no_warning(
    missing_last,
):
    class Fixed(BaseScanner):
        def __init__(self, result):
            super().__init__(result.scanner)
            self.result = result

        def scan(self, url):
            return self.result.model_copy(deep=True)

    class DomainContext(BaseScanner):
        def __init__(self):
            super().__init__("CloudflareDnsSecurity")

        def scan(self, url):
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                status="unavailable" if missing_last and "last" in url else "completed",
                details={"requires_review": "middle" in url},
            )

    first, middle, last = (
        f"https://{name}.com/" for name in ("first", "middle", "last")
    )
    resolver = Fixed(
        StageResult(
            scanner="UrlResolver",
            verdict="clean",
            details={
                "resolved_url": last,
                "redirect_chain": [
                    {"from": first, "to": middle},
                    {"from": middle, "to": last},
                ],
            },
        )
    )
    clean = Fixed(StageResult(scanner="HtmlScraper", verdict="clean"))
    result = ScanningPipeline(
        [clean], redirect_resolver=resolver, threat_intel_scanners=[DomainContext()]
    ).run(first)
    assert result.final_verdict == "unknown"
    stage = next(
        item for item in result.stages if item.scanner == "CloudflareDnsSecurity"
    )
    assert stage.details["requires_review"] is True
    assert result.scan_status == ("partial" if missing_last else "complete")
