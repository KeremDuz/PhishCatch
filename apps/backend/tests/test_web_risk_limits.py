from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from app.core.pipeline import ScanningPipeline
from app.core.scan_cache import ScannerResultCache
from app.models.schemas import StageResult
from app.services import web_risk_scanner as module
from app.services.base_scanner import BaseScanner
from app.services.web_risk_scanner import (
    GoogleWebRiskScanner,
    LookupQuota,
    lookup_session,
)
from app.services.worker_process import WorkerFailure


def scanner(tmp_path, **options):
    return GoogleWebRiskScanner(
        "test-only-key",
        allow_url_sharing=True,
        quota_path=tmp_path / "quota.sqlite3",
        **options,
    )


def worker(monkeypatch, value):
    call = Mock(return_value=json.dumps(value).encode())
    monkeypatch.setattr(module, "bounded_process", call)
    return call


@pytest.mark.parametrize(
    "options,code",
    [
        ({"api_key": None, "allow_url_sharing": True}, "provider_key_missing"),
        ({"api_key": "test-key"}, "url_sharing_not_enabled"),
    ],
)
def test_key_or_sharing_policy_missing_never_calls_provider(monkeypatch, options, code):
    call = worker(monkeypatch, {})
    result = GoogleWebRiskScanner(**options).scan("https://example.com/")
    assert result.status == "unavailable"
    assert result.details["error"] == code
    call.assert_not_called()


def test_query_tokens_stay_local_by_default_and_fragment_is_not_sent(
    tmp_path, monkeypatch
):
    call = worker(monkeypatch, {"threat_types": []})
    service = scanner(tmp_path)
    assert (
        service.scan("https://example.com/reset?token=private").status == "unavailable"
    )
    call.assert_not_called()
    assert service.scan("https://example.com/#private").verdict == "unknown"
    payload = json.loads(call.call_args.args[1])
    assert payload == {"url": "https://example.com/", "key": "test-only-key"}
    assert "test-only-key" not in " ".join(call.call_args.args[0])
    assert call.call_args.args[2] <= 6


def test_no_match_is_completed_unknown_not_clean(tmp_path, monkeypatch):
    worker(monkeypatch, {"threat_types": []})
    result = scanner(tmp_path).scan("https://example.com/")
    assert result.verdict == "unknown" and result.status == "completed"
    assert result.confidence is None and result.malicious_probability is None


@pytest.mark.parametrize(
    "value",
    [
        {"error": "private-url-and-key", "status_code": 429},
        {"threat_types": ["UNRECOGNIZED"]},
        {
            "threat_types": ["SOCIAL_ENGINEERING"],
            "expire_time": "2000-01-01T00:00:00+00:00",
        },
        [],
    ],
)
def test_errors_and_invalid_results_are_redacted_failed_unknown(
    tmp_path, monkeypatch, value
):
    worker(monkeypatch, value)
    result = scanner(tmp_path).scan("https://example.com/")
    assert result.status == "failed" and result.verdict == "unknown"
    assert "private-url-and-key" not in result.model_dump_json()
    assert "test-only-key" not in result.model_dump_json()


def test_worker_timeout_is_failed_and_never_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module, "bounded_process", Mock(side_effect=WorkerFailure("worker_timeout"))
    )
    service = scanner(tmp_path)
    result = service.scan("https://example.com/")
    cache = ScannerResultCache()
    cache.set(service.name, "https://example.com/", result)
    assert result.status == "failed"
    assert cache.get(service.name, "https://example.com/") is None


def test_daily_quota_is_persistent_and_atomic(tmp_path):
    path = tmp_path / "quota.sqlite3"
    quota = LookupQuota(path, daily=3, monthly=5)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: quota.reserve(), range(12)))
    assert sum(results) == 3
    assert LookupQuota(path, daily=3, monthly=5).reserve() is False
    assert b"http" not in path.read_bytes()


def test_monthly_quota_survives_day_change_and_all_failures_consume_calls(
    tmp_path, monkeypatch
):
    quota = LookupQuota(tmp_path / "months.sqlite3", daily=2, monthly=3)
    now = datetime(2026, 10, 1, tzinfo=UTC)
    assert quota.reserve(now) and quota.reserve(now)
    assert not quota.reserve(now)
    assert quota.reserve(now + timedelta(days=1))
    assert not quota.reserve(now + timedelta(days=2))
    assert quota.reserve(datetime(2026, 11, 1, tzinfo=UTC))
    call = worker(monkeypatch, {"error": "redacted"})
    service = scanner(tmp_path, daily_limit=1)
    assert service.scan("https://example.com/").status == "failed"
    result = service.scan("https://example.com/")
    assert result.details["error"] == "provider_local_quota_exhausted"
    assert call.call_count == 1


def test_lookup_session_has_finite_call_allowance(tmp_path, monkeypatch):
    call = worker(monkeypatch, {"threat_types": []})
    service = scanner(tmp_path)
    with lookup_session():
        for number in range(6):
            assert service.scan(f"https://example.com/{number}").status == "completed"
        assert service.scan("https://example.com/seven").status == "unavailable"
    assert call.call_count == 6
    # Each new analysis gets a fresh bounded allowance, not a global lockout.
    with lookup_session():
        assert service.scan("https://example.com/new").status == "completed"


def test_redirect_lookup_calls_share_budget_across_pipeline_threads(
    tmp_path, monkeypatch
):
    call = worker(monkeypatch, {"threat_types": []})
    real_budget = module.LookupBudget
    monkeypatch.setattr(
        "app.services.reputation_budget.LookupBudget",
        lambda: real_budget(remaining_calls=2),
    )

    class Fixed(BaseScanner):
        def __init__(self, result):
            super().__init__(result.scanner)
            self.result = result

        def scan(self, url):
            return self.result.model_copy(deep=True)

    resolver = Fixed(
        StageResult(
            scanner="UrlResolver",
            verdict="unknown",
            details={
                "resolved_url": "https://example.com/last",
                "redirect_chain": [
                    {
                        "from": "https://example.com/first",
                        "to": "https://example.com/middle",
                    },
                    {
                        "from": "https://example.com/middle",
                        "to": "https://example.com/last",
                    },
                ],
            },
        )
    )
    model = Fixed(
        StageResult(
            scanner="MLModelScanner",
            verdict="clean",
            malicious_probability=0.1,
            clean_probability=0.9,
        )
    )
    local = Fixed(StageResult(scanner="LocalPhishingFeed", verdict="unknown"))
    pipeline = ScanningPipeline(
        [model],
        redirect_resolver=resolver,
        threat_intel_scanners=[local, scanner(tmp_path)],
    )
    result = pipeline.run("https://example.com/first")
    assert call.call_count == 2
    assert result.final_verdict == "unknown" and result.scan_status == "partial"
    assert (
        next(
            stage for stage in result.stages if stage.scanner == "GoogleWebRisk"
        ).status
        == "unavailable"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://192.168.1.4/",
        "http://100.87.174.61/",
        "http://[::1]/",
        "http://localhost/",
        "https://printer.local/",
        "https://intranet/",
        "https://user:password@example.com/",
    ],
)
def test_ineligible_internal_urls_never_reach_provider_or_quota(
    tmp_path, monkeypatch, url
):
    call = worker(monkeypatch, {"threat_types": []})
    service = scanner(tmp_path)
    assert service.scan(url).status == "unavailable"
    call.assert_not_called()
    assert not service.quota.path.exists()


def test_provider_expiry_bounds_match_cache(tmp_path, monkeypatch):
    expiry = (datetime.now(UTC) + timedelta(seconds=20)).isoformat()
    worker(monkeypatch, {"threat_types": ["SOCIAL_ENGINEERING"], "expire_time": expiry})
    result = scanner(tmp_path).scan("https://example.com/")
    assert result.verdict == "malicious"
    cache = ScannerResultCache(ttl_seconds=300)
    cache.set("GoogleWebRisk", "https://example.com/", result)
    assert (
        cache.get("GoogleWebRisk", "https://example.com/").details["cache"][
            "ttl_seconds"
        ]
        <= 20
    )
    result.details["expire_time"] = "2000-01-01T00:00:00+00:00"
    cache.set("GoogleWebRisk", "https://example.com/expired", result)
    assert cache.get("GoogleWebRisk", "https://example.com/expired") is None


def test_transport_uses_fixed_host_header_key_no_redirect_and_bounded_body(monkeypatch):
    response = Mock(status_code=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)
    response.iter_content.return_value = [b"{}"]
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=None)
    session.get.return_value = response
    monkeypatch.setattr(module.requests, "Session", Mock(return_value=session))
    assert module._lookup("https://example.com/", "test-only-key") == {
        "threat_types": []
    }
    assert session.trust_env is False
    assert session.get.call_args.args == (module.API_URL,)
    options = session.get.call_args.kwargs
    assert options["headers"] == {"x-goog-api-key": "test-only-key"}
    assert options["allow_redirects"] is False
    assert "key" not in dict(options["params"])
    response.iter_content.return_value = [b"x" * (module.MAX_RESPONSE_BYTES + 1)]
    assert (
        module._lookup("https://example.com/", "test-only-key")["error"]
        == "provider_response_limit"
    )


def test_transport_exception_never_exposes_request_details(monkeypatch):
    session = Mock()
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=None)
    session.get.side_effect = module.requests.RequestException("private-url secret-key")
    monkeypatch.setattr(module.requests, "Session", Mock(return_value=session))
    assert module._lookup("https://example.com/", "secret-key") == {
        "error": "provider_request_failed"
    }


def test_missing_sharing_policy_is_visible_in_health(tmp_path):
    service = GoogleWebRiskScanner("test-key", quota_path=tmp_path / "quota.sqlite3")
    health = ScanningPipeline._scanner_health(service)
    assert health["status"] == "degraded"
    assert health["url_sharing_enabled"] is False
