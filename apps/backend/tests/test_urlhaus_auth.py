from unittest.mock import Mock

import pytest
from app.core.pipeline import ScanningPipeline
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.threat_intel_scanners import UrlhausScanner


class UnavailableLocalScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="UnavailableLocalScanner")

    def scan(self, url: str) -> StageResult:
        return StageResult(scanner=self.name, verdict="unknown", status="unavailable")


@pytest.mark.parametrize("auth_key", [None, "", "   "])
def test_missing_urlhaus_key_is_unavailable_without_any_network_request(
    monkeypatch: pytest.MonkeyPatch, auth_key: str | None
) -> None:
    post = Mock(side_effect=AssertionError("No HTTP request is allowed without a key"))
    monkeypatch.setattr("app.services.threat_intel_scanners.requests.post", post)
    scanner = UrlhausScanner(auth_key=auth_key)

    result = scanner.scan("https://example.test/")

    post.assert_not_called()
    assert result.status == "unavailable"
    assert result.verdict == "unknown"
    assert result.risk_score is None
    assert result.malicious_probability is None
    assert result.clean_probability is None
    assert "URLHAUS_AUTH_KEY" in result.reason
    health = ScanningPipeline(
        [UnavailableLocalScanner()], threat_intel_scanners=[scanner]
    ).health_report()
    assert health["status"] == "degraded"
    provider = next(
        scanner
        for layer in health["layers"]
        for scanner in layer.get("scanners", [])
        if scanner["name"] == "URLhausScanner"
    )
    assert provider["status"] == "degraded"
    assert provider["auth_key_required"] is True
    assert provider["auth_key_configured"] is False


def test_configured_urlhaus_key_stays_in_header_and_no_match_is_not_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = "test-only-urlhaus-key"
    response = Mock(status_code=200)
    response.json.return_value = {"query_status": "no_results"}
    post = Mock(return_value=response)
    monkeypatch.setattr("app.services.threat_intel_scanners.requests.post", post)
    scanner = UrlhausScanner(auth_key=key)

    result = scanner.scan("https://example.test/")

    post.assert_called_once_with(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": "https://example.test/"},
        headers={"Auth-Key": key},
        timeout=5,
    )
    assert result.status == "completed"
    assert result.verdict == "unknown"
    assert key not in result.model_dump_json()
    provider = ScanningPipeline._scanner_health(scanner)
    assert provider["status"] == "ok"
    assert provider["auth_key_required"] is True
    assert provider["auth_key_configured"] is True


def test_rejected_urlhaus_credentials_are_a_failed_unknown_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = "test-only-rejected-urlhaus-key"
    response = Mock(status_code=401)
    post = Mock(return_value=response)
    monkeypatch.setattr("app.services.threat_intel_scanners.requests.post", post)
    pipeline = ScanningPipeline(
        [UnavailableLocalScanner()],
        threat_intel_scanners=[UrlhausScanner(auth_key=key)],
    )

    result = pipeline.run("https://example.test/")

    assert post.call_count == 1
    response.json.assert_not_called()
    assert result.final_verdict == "unknown"
    assert result.scan_status == "failed"
    assert result.stages[0].status == "failed"
    assert result.stages[0].details["status_code"] == 401
    assert result.clean_probability is None
    assert key not in result.model_dump_json()
