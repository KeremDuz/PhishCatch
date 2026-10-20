from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.dependencies import get_scanning_pipeline, get_training_store
from app.main import app
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.routers import public_analysis
from app.services.url_safety import UrlSafetyResult, validate_public_http_url

ENDPOINT = "/api/v1/public/analyze"


def analysis_result(
    verdict: str = "clean",
    status: str = "complete",
    stages: list[StageResult] | None = None,
) -> AnalyzeUrlResponse:
    return AnalyzeUrlResponse(
        url="https://redirect.example.com/",
        normalized_url="https://redirect.example.com/",
        final_verdict=verdict,
        scan_status=status,
        decided_by="RiskAggregator",
        observation_id=1234,
        malicious_probability=0.1,
        clean_probability=0.9,
        summary="private diagnostic /app/models/model.pkl integration-secret",
        signals={"private": "server-key"},
        stages=stages
        if stages is not None
        else [StageResult(scanner="MLModelScanner", verdict="clean")],
    )


class FakePipeline:
    def __init__(self) -> None:
        self.response = analysis_result()
        self.calls: list[tuple[str, str | None]] = []
        self.error: Exception | None = None
        self.started: Event | None = None
        self.finish: Event | None = None

    def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
        self.calls.append((url, original_input))
        if self.started is not None:
            self.started.set()
        if self.finish is not None and not self.finish.wait(timeout=5):
            raise RuntimeError("Test analysis was not released")
        if self.error is not None:
            raise self.error
        return self.response.model_copy(deep=True)


def test_validation_worker_timeout_is_unavailable_and_releases_slot(public_client, monkeypatch):
    from app.services.worker_process import WorkerFailure
    client, pipeline = public_client
    pipeline.fetch_worker = True
    def timeout(*args, **kwargs):
        raise WorkerFailure("worker_timeout")
    monkeypatch.setattr(public_analysis, "run_worker", timeout)
    first = client.post(ENDPOINT, json={"url": "https://example.com/"})
    assert first.status_code == 503 and not pipeline.calls
    monkeypatch.setattr(public_analysis, "run_worker", lambda *a, **k: {"is_safe": True})
    second = client.post(ENDPOINT, json={"url": "https://example.com/"})
    assert second.status_code == 200


@pytest.fixture
def public_client(monkeypatch):
    pipeline = FakePipeline()

    def forbidden_training_store():
        raise AssertionError("Anonymous analysis must not access the training store")

    app.dependency_overrides[get_scanning_pipeline] = lambda: pipeline
    app.dependency_overrides[get_training_store] = forbidden_training_store
    monkeypatch.setattr(
        public_analysis,
        "validate_public_http_url",
        lambda url: UrlSafetyResult(is_safe=True),
    )
    try:
        with TestClient(app) as client:
            yield client, pipeline
    finally:
        app.dependency_overrides.clear()


def test_anonymous_analysis_returns_only_consumer_contract(public_client):
    client, pipeline = public_client
    pipeline.response.stages[0].details = {
        "model_path": "/app/models/model.pkl",
        "api_key": "server-key",
    }
    pipeline.response.stages[0].training_features = {"url.UrlLength": 30}
    response = client.post(
        ENDPOINT,
        json={
            "url": "HTTPS://Example.COM:443/check",
            "source": "qr",
            "client_request_id": str(uuid4()),
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "contract_version": "consumer-1",
        "url": "https://example.com/check",
        "final_verdict": "clean",
        "scan_status": "complete",
    }
    assert pipeline.calls == [
        ("https://example.com/check", "https://example.com/check")
    ]
    for private in (
        "model_path",
        "model.pkl",
        "server-key",
        "observation_id",
        "features",
        "stages",
        "probability",
        "risk_score",
    ):
        assert private not in response.text


@pytest.mark.parametrize(
    ("upstream_status", "stages", "expected_status"),
    [
        (
            "partial",
            [StageResult(scanner="MLModelScanner", verdict="clean")],
            "partial",
        ),
        ("failed", [StageResult(scanner="MLModelScanner", verdict="clean")], "failed"),
        ("complete", [], "failed"),
        (
            "complete",
            [
                StageResult(scanner="MLModelScanner", verdict="clean"),
                StageResult(scanner="HtmlScraper", verdict="unknown", status="failed"),
            ],
            "partial",
        ),
        (
            "complete",
            [StageResult(scanner="HtmlScraper", verdict="unknown", status="failed")],
            "failed",
        ),
    ],
)
def test_incomplete_or_empty_analysis_cannot_claim_clean(
    public_client, upstream_status, stages, expected_status
):
    client, pipeline = public_client
    pipeline.response = analysis_result("clean", upstream_status, stages)
    response = client.post(ENDPOINT, json={"url": "example.com"})
    assert response.status_code == 200
    assert response.json()["final_verdict"] == "unknown"
    assert response.json()["scan_status"] == expected_status


@pytest.mark.parametrize(
    "stage",
    [
        StageResult(scanner="URLhausScanner", verdict="malicious"),
        StageResult(
            scanner="MLModelScanner",
            verdict="unknown",
            malicious_probability=0.85,
            risk_score=0.72,
        ),
    ],
)
def test_completed_malicious_evidence_survives_other_layer_failure(
    public_client, stage
):
    client, pipeline = public_client
    pipeline.response = analysis_result(
        "malicious",
        "partial",
        [
            stage,
            StageResult(scanner="HtmlScraper", verdict="unknown", status="unavailable"),
        ],
    )
    response = client.post(ENDPOINT, json={"url": "https://example.com"})
    assert response.json()["final_verdict"] == "malicious"
    assert response.json()["scan_status"] == "partial"


def test_failed_malicious_stage_is_not_evidence(public_client):
    client, pipeline = public_client
    pipeline.response = analysis_result(
        "malicious",
        "failed",
        [StageResult(scanner="MLModelScanner", verdict="malicious", status="failed")],
    )
    response = client.post(ENDPOINT, json={"url": "https://example.com"})
    assert response.json()["final_verdict"] == "unknown"


@pytest.mark.parametrize(
    "invalid_fields", [{"scan_status": "unexpected"}, {"contract_version": "3"}]
)
def test_unrecognized_upstream_contract_is_failed_unknown(
    public_client, invalid_fields
):
    client, pipeline = public_client
    pipeline.response = pipeline.response.model_copy(update=invalid_fields)
    response = client.post(ENDPOINT, json={"url": "https://example.com"})
    assert response.json()["scan_status"] == "failed"
    assert response.json()["final_verdict"] == "unknown"


@pytest.mark.parametrize(
    "payload",
    [
        {"url": ""},
        {"url": "https://example.com/" + "a" * 2048},
        {"url": "ftp://example.com/file"},
        {"url": "file:///etc/passwd"},
        {"url": "javascript:alert(1)"},
        {"url": "http:example.com"},
        {"url": "https://example.com/\nheader"},
        {"url": "https://user:password@example.com"},
        {"url": "https://@example.com"},
        {"url": "https://:password@example.com"},
        {"url": 123},
        {"url": "https://example.com", "source": "employee"},
        {"url": "https://example.com", "client_request_id": "not-a-uuid"},
        {"url": "https://example.com", "original_input": "override"},
        {"url": "https://example.com", "approved_for_training": True},
    ],
)
def test_invalid_public_input_does_not_run_pipeline(public_client, payload):
    client, pipeline = public_client
    assert client.post(ENDPOINT, json=payload).status_code == 422
    assert pipeline.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
    ],
)
def test_private_and_credential_urls_are_rejected_before_pipeline(
    public_client, monkeypatch, url
):
    client, pipeline = public_client
    monkeypatch.setattr(
        public_analysis, "validate_public_http_url", validate_public_http_url
    )
    response = client.post(ENDPOINT, json={"url": url})
    assert response.status_code == 400
    assert response.json() == {"detail": "This URL cannot be analyzed."}
    assert pipeline.calls == []


def test_only_one_public_analysis_can_run_at_a_time(public_client):
    client, pipeline = public_client
    pipeline.started = Event()
    pipeline.finish = Event()
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            client.post, ENDPOINT, json={"url": "https://example.com"}
        )
        try:
            assert pipeline.started.wait(timeout=5)
            second = client.post(ENDPOINT, json={"url": "https://example.org"})
            assert second.status_code == 429
            assert second.headers["Retry-After"] == "10"
            assert len(pipeline.calls) == 1
        finally:
            pipeline.finish.set()
        assert first.result(timeout=5).status_code == 200


def test_pipeline_exception_is_sanitized_and_releases_public_slot(public_client):
    client, pipeline = public_client
    pipeline.error = RuntimeError("/app/models/private.pkl secret integration-key")
    response = client.post(ENDPOINT, json={"url": "https://example.com"})
    assert response.status_code == 503
    assert response.json() == {
        "detail": "Analysis is temporarily unavailable. Please try again later."
    }
    pipeline.error = None
    assert client.post(ENDPOINT, json={"url": "https://example.com"}).status_code == 200


def test_safety_exception_is_sanitized_and_releases_public_slot(
    public_client, monkeypatch
):
    client, pipeline = public_client

    def fail_safety(url):
        raise RuntimeError("private DNS diagnostic 100.64.0.1")

    monkeypatch.setattr(public_analysis, "validate_public_http_url", fail_safety)
    response = client.post(ENDPOINT, json={"url": "https://example.com"})
    assert response.status_code == 400
    assert "100.64" not in response.text
    assert pipeline.calls == []
    monkeypatch.setattr(
        public_analysis,
        "validate_public_http_url",
        lambda url: UrlSafetyResult(is_safe=True),
    )
    assert client.post(ENDPOINT, json={"url": "https://example.com"}).status_code == 200
