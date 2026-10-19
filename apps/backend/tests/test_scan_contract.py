import math

import pytest
from app.core.config import Settings, settings
from app.core.pipeline import ScanningPipeline
from app.core.risk_aggregator import RiskAggregator
from app.dependencies import get_scanning_pipeline, get_training_store
from app.main import app
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.ml_model_scanner import MLModelScanner
from app.storage import TrainingStore
from fastapi.testclient import TestClient
from pydantic import SecretStr


class StubScanner(BaseScanner):
    def __init__(
        self, result: StageResult | None = None, name: str = "FailingScanner"
    ) -> None:
        super().__init__(name=result.scanner if result else name)
        self.result = result
        self.calls = 0

    def scan(self, url: str) -> StageResult:
        self.calls += 1
        if self.result is None:
            raise RuntimeError("scanner diagnostic containing a private URL")
        return self.result.model_copy(deep=True)


@pytest.fixture
def client(tmp_path):
    store = TrainingStore(tmp_path / "observations.sqlite3")
    store.init_db()
    app.dependency_overrides[get_training_store] = lambda: store
    with TestClient(app) as http:
        yield http, store
    app.dependency_overrides.clear()


def configure_pipeline(*scanners: StubScanner, **options) -> ScanningPipeline:
    pipeline = ScanningPipeline(list(scanners), **options)
    app.dependency_overrides[get_scanning_pipeline] = lambda: pipeline
    return pipeline


def test_empty_or_inconclusive_evidence_is_never_clean():
    for stages in ([], [StageResult(scanner="MLModelScanner", verdict="unknown")]):
        decision = RiskAggregator().aggregate(stages)
        assert decision.final_verdict == "unknown"
        assert decision.confidence is None
        assert decision.malicious_probability is None
        assert decision.clean_probability is None


def test_missing_model_and_failed_html_cannot_be_offset_by_clean_whois():
    pipeline = ScanningPipeline(
        [
            StubScanner(StageResult(scanner="WhoisScanner", verdict="clean")),
            StubScanner(
                StageResult(
                    scanner="MLModelScanner",
                    verdict="unknown",
                    reason="ML model unavailable",
                )
            ),
            StubScanner(
                StageResult(
                    scanner="HtmlScraper",
                    verdict="unknown",
                    details={"error": "timeout"},
                )
            ),
        ]
    )
    result = pipeline.run("https://example.com/")
    assert result.final_verdict == "unknown"
    assert result.scan_status == "partial"
    assert [stage.status for stage in result.stages] == [
        "completed",
        "unavailable",
        "failed",
    ]
    assert result.confidence is None
    assert result.clean_probability is None


def test_only_actual_model_probability_is_returned_not_rule_score():
    result = RiskAggregator().aggregate(
        [
            StageResult(
                scanner="MLModelScanner",
                verdict="malicious",
                malicious_probability=0.91,
                clean_probability=0.09,
            ),
        ]
    )
    assert result.final_verdict == "malicious"
    assert result.risk_score != 0.91
    assert result.malicious_probability == 0.91
    assert result.clean_probability == 0.09
    assert result.confidence is None
    assert result.signals["probability_source"] == "MLModelScanner"


def test_blocked_resolver_is_visible_and_does_not_prove_phishing():
    resolver = StubScanner(
        StageResult(
            scanner="UrlResolver",
            verdict="unknown",
            risk_score=0.9,
            reason="URL fetch blocked",
            details={"safety": {"hostname": "localhost", "blocked_ips": ["127.0.0.1"]}},
        )
    )
    reputation = StubScanner(StageResult(scanner="URLhausScanner", verdict="malicious"))
    pipeline = ScanningPipeline(
        [
            StubScanner(
                StageResult(scanner="HtmlScraper", verdict="clean", risk_score=0)
            )
        ],
        redirect_resolver=resolver,
        threat_intel_scanners=[reputation],
    )
    response = pipeline.run("http://localhost/")
    assert response.final_verdict == "unknown"
    assert response.scan_status == "partial"
    assert response.stages[0].scanner == "UrlResolver"
    assert response.stages[0].status == "failed"
    assert reputation.calls == 0
    assert response.stages[1].status == "skipped"


def test_scanner_exception_is_a_failed_record_not_an_unhandled_error():
    result = ScanningPipeline([StubScanner()]).run("https://example.com/")
    assert result.final_verdict == "unknown"
    assert result.scan_status == "failed"
    assert result.stages[0].status == "failed"
    assert "private URL" not in result.model_dump_json()


def test_failure_details_do_not_add_phishing_risk():
    result = RiskAggregator().aggregate(
        [
            StageResult(
                scanner="HtmlScraper",
                verdict="unknown",
                status="failed",
                risk_score=0.9,
                details={"error": "Hostname could not be resolved"},
            ),
        ]
    )
    assert result.final_verdict == "unknown"
    assert result.risk_score == 0


def test_successful_no_reputation_match_is_not_an_unavailable_api():
    pipeline = ScanningPipeline(
        [
            StubScanner(
                StageResult(scanner="HtmlScraper", verdict="clean", risk_score=0)
            )
        ],
        threat_intel_scanners=[
            StubScanner(
                StageResult(
                    scanner="URLhausScanner",
                    verdict="unknown",
                    reason="URL not found in URLhaus database",
                    details={"query_status": "no_results"},
                )
            )
        ],
    )
    assert pipeline.run("https://example.com/").scan_status == "complete"


def test_reputation_hit_persists_an_observation_without_approving_training(client):
    http, store = client
    reputation = StubScanner(
        StageResult(scanner="URLhausScanner", verdict="malicious", risk_score=0.97)
    )
    local = StubScanner()
    configure_pipeline(local, threat_intel_scanners=[reputation])
    result = http.post("/api/v1/analyze", json={"url": "https://example.com/"})
    assert result.status_code == 200
    data = result.json()
    assert data["contract_version"] == "2"
    assert data["final_verdict"] == "malicious"
    assert data["malicious_probability"] is None
    assert data["observation_id"] is not None
    assert (
        store.observation_by_id(data["observation_id"])["final_verdict"] == "malicious"
    )
    assert store.training_samples() == []
    assert local.calls == 0


def test_integration_authentication_rejects_missing_configuration_and_wrong_keys(
    client, monkeypatch
):
    http, _ = client
    endpoint = "/api/v1/integrations/allsafe/analyze"
    monkeypatch.setattr(settings, "allsafe_integration_key", None)
    assert http.post(endpoint, json={"url": "https://example.com/"}).status_code == 503
    monkeypatch.setattr(
        settings,
        "allsafe_integration_key",
        SecretStr("integration-secret-aaaaaaaaaaaaaaaa"),
    )
    for header in ({}, {"X-Integration-Key": "wrong-key"}):
        response = http.post(
            endpoint, json={"url": "https://example.com/"}, headers=header
        )
        assert response.status_code == 401
        assert "integration-secret" not in response.text


def test_integration_returns_only_versioned_allowlisted_finite_numeric_features(
    client, monkeypatch
):
    http, store = client
    monkeypatch.setattr(
        settings,
        "allsafe_integration_key",
        SecretStr("integration-secret-aaaaaaaaaaaaaaaa"),
    )
    configure_pipeline(
        StubScanner(
            StageResult(
                scanner="HtmlScraper",
                verdict="clean",
                risk_score=0,
                training_features={
                    "html_features": {
                        "HtmlLength": 30,
                        "FormCount": float("nan"),
                        "InputCount": True,
                        "url": "private",
                        "employee_email": "private@example.com",
                    }
                },
            )
        )
    )
    response = http.post(
        "/api/v1/integrations/allsafe/analyze",
        json={"url": "https://example.com/?token=private-value"},
        headers={"X-Integration-Key": "integration-secret-aaaaaaaaaaaaaaaa"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["feature_version"] == "phishcatch-v1"
    assert data["analysis"]["observation_id"] is not None
    assert "training_features" not in response.text
    assert data["features"]["html.HtmlLength"] == 30
    assert "html.FormCount" not in data["features"]
    assert "html.InputCount" not in data["features"]
    assert "url.UrlLength" in data["features"]
    assert all(
        isinstance(value, (float, int)) and math.isfinite(value)
        for value in data["features"].values()
    )
    assert "private-value" not in str(data["features"])
    assert "employee_email" not in str(data["features"])
    assert store.training_samples() == []


def test_model_health_is_degraded_without_local_artifacts(tmp_path):
    scanner = MLModelScanner(
        Settings(ml_model_path=str(tmp_path / "missing-model.pkl"))
    )
    result = scanner.scan("https://example.com/")
    assert result.status == "unavailable"
    assert result.malicious_probability is None
    health = ScanningPipeline([scanner]).health_report()
    assert health["status"] == "degraded"
    model = health["layers"][1]["scanners"][0]
    assert model["model_loaded"] is False
    assert model["probabilities_available"] is False


def test_authenticated_health_has_no_paths_and_reports_missing_models(
    client, monkeypatch
):
    http, _ = client
    monkeypatch.setattr(
        settings,
        "allsafe_integration_key",
        SecretStr("integration-secret-aaaaaaaaaaaaaaaa"),
    )
    configure_pipeline(
        StubScanner(StageResult(scanner="MLModelScanner", verdict="unknown"))
    )
    endpoint = "/api/v1/integrations/allsafe/health"
    assert http.get(endpoint).status_code == 401
    response = http.get(
        endpoint, headers={"X-Integration-Key": "integration-secret-aaaaaaaaaaaaaaaa"}
    )
    assert response.json() == {
        "contract_version": "2",
        "status": "ok",
        "url_model_available": False,
        "html_model_available": False,
    }


def test_model_probabilities_use_explicit_class_order_and_reject_predictions_only(
    tmp_path,
):
    scanner = MLModelScanner(
        Settings(ml_model_path=str(tmp_path / "missing-model.pkl"))
    )

    class ReverseClasses:
        classes_ = [1, 0]

        def predict_proba(self, values):
            return [[0.8, 0.2]]

    scanner.model = ReverseClasses()
    assert scanner._predict_confidence([[0]]) == 0.8
    scanner.model = object()
    with pytest.raises(ValueError, match="does not provide probabilities"):
        scanner._predict_confidence([[0]])
