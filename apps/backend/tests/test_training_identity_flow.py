from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline, get_training_store
from app.main import app
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.routers.analyze import _record_observation_safely
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.browser_renderer import BrowserRenderResult
from app.services.page_fetch import BufferedPageResponse, PageArtifact
from app.storage import TrainingStore
from scripts.export_training_datasets import build_html_rows

URL = "https://fixture.example/guide"
HTML = '<html><head><meta charset="windows-1252"><title>Caf\u00e9 guide</title></head><body><p>A static guide.</p></body></html>'
DIGEST = hashlib.sha256(HTML.encode("utf-8")).hexdigest()


def analyzed_stage(monkeypatch) -> StageResult:
    page = PageArtifact(
        URL, URL, 200, "text/html", HTML.encode("windows-1252"), (),
        datetime.now(UTC).isoformat(),
    )
    assert page.body_sha256 != DIGEST
    scanner = HtmlScraperScanner(model_path=None)
    monkeypatch.setattr(
        scanner, "_safe_get", lambda url, headers: (BufferedPageResponse(page), URL, [])
    )
    stage = scanner.scan(URL)
    assert stage.status == "completed"
    return stage


def response_with(stage: StageResult) -> AnalyzeUrlResponse:
    return AnalyzeUrlResponse(
        url=URL, normalized_url=URL, final_verdict="unknown", scan_status="partial",
        decided_by="RiskAggregator", summary="Controlled fixture", stages=[stage],
    )


@pytest.fixture
def identity_client(tmp_path, monkeypatch):
    store = TrainingStore(tmp_path / "identity.sqlite3")
    store.init_db()
    response = response_with(analyzed_stage(monkeypatch))

    class FixturePipeline:
        def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
            return response.model_copy(deep=True)

    monkeypatch.setattr(settings, "training_admin_token", "test-admin-identity-token")
    monkeypatch.setattr(settings, "training_admin_username", None)
    monkeypatch.setattr(settings, "training_admin_password", None)
    app.dependency_overrides[get_scanning_pipeline] = FixturePipeline
    app.dependency_overrides[get_training_store] = lambda: store
    try:
        with TestClient(app) as client:
            yield client, store, response
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("sample_route", ["latest", "observation", "bulk"])
def test_analyzed_identity_survives_authenticated_label_and_export(
    identity_client, sample_route
):
    client, store, _ = identity_client
    result = client.post("/api/v1/analyze", json={"url": URL})
    assert result.status_code == 200
    assert "training_features" not in result.text
    assert DIGEST not in result.text
    observation_id = result.json()["observation_id"]
    observation = store.observation_by_id(observation_id)
    assert observation["html_hash"] == DIGEST
    assert observation["html_path"] is None
    assert HTML not in json.dumps(observation, ensure_ascii=False)
    assert store.training_samples() == []

    payload = {"label": 1, "source": "manual_review", "approved_for_training": True}
    if sample_route == "latest":
        endpoint = "/api/v1/admin/training-samples"
        payload["url"] = URL
    elif sample_route == "observation":
        endpoint = f"/api/v1/admin/observations/{observation_id}/training-sample"
    else:
        endpoint = "/api/v1/admin/observations/bulk-training-samples"
        payload["observation_ids"] = [observation_id]

    assert client.post(endpoint, json=payload).status_code == 401
    assert store.training_samples() == []
    approved = client.post(
        endpoint, json=payload, headers={"X-Admin-Token": "test-admin-identity-token"}
    )
    assert approved.status_code == 200
    samples = store.training_samples(approved_only=True)
    assert len(samples) == 1
    assert samples[0]["html_hash"] == DIGEST
    assert samples[0]["html_path"] is None
    assert samples[0]["label"] == 1
    assert samples[0]["label_source"] == "manual_review"
    assert build_html_rows(samples)[0]["template_group"] == DIGEST


@pytest.mark.parametrize(
    "change",
    ["wrong_scanner", "failed", "wrong_feature_url", "wrong_final_url", "wrong_scheme",
     "invalid_hash", "no_features", "resolver_only"],
)
def test_unbound_or_unvalidated_scanner_metadata_cannot_supply_identity(
    tmp_path, monkeypatch, change
):
    stage = analyzed_stage(monkeypatch)
    if change == "wrong_scanner":
        stage.scanner = "OtherScanner"
    elif change == "failed":
        stage.status = "failed"
    elif change == "wrong_feature_url":
        stage.training_features["feature_url"] = "https://other.example/"
    elif change == "wrong_final_url":
        stage.details["final_url"] = "https://other.example/"
    elif change == "wrong_scheme":
        stage.training_features["html_hash_scheme"] = "unverified-body"
    elif change == "invalid_hash":
        stage.training_features["html_hash"] = "not-a-sha256"
    elif change == "no_features":
        stage.training_features.pop("html_features")
    else:
        stage.training_features.pop("html_hash")
        stage.details["body_sha256"] = DIGEST

    response = response_with(stage)
    response.stages.insert(0, StageResult(
        scanner="UrlResolver", verdict="clean", details={"body_sha256": DIGEST}
    ))
    store = TrainingStore(tmp_path / "unbound.sqlite3")
    store.init_db()
    observation_id = _record_observation_safely(response, store, "test")
    assert observation_id is not None
    observation = store.observation_by_id(observation_id)
    assert observation["html_hash"] is None
    if change in {"wrong_feature_url", "wrong_final_url"}:
        assert observation["html_features"] is None


def test_legacy_missing_identity_is_not_fabricated_during_manual_review(identity_client):
    client, store, response = identity_client
    response.stages[0].training_features.pop("html_hash")
    result = client.post("/api/v1/analyze", json={"url": URL})
    observation_id = result.json()["observation_id"]
    assert store.observation_by_id(observation_id)["html_hash"] is None
    result = client.post(
        f"/api/v1/admin/observations/{observation_id}/training-sample",
        json={"label": 0}, headers={"X-Admin-Token": "test-admin-identity-token"},
    )
    assert result.status_code == 200
    sample = store.training_samples()[0]
    assert sample["html_hash"] is None
    assert sample["label"] == 0


def test_retained_original_html_alert_cannot_train_under_changed_rendered_url(
    tmp_path, monkeypatch
):
    source = "<html><body><form><input type='password' name='password'></form></body></html>"
    destination = "https://destination.example/guide"
    rendered = "<html><body><p>A different rendered destination.</p></body></html>"
    page = PageArtifact(URL, URL, 200, "text/html", source.encode(), (), datetime.now(UTC).isoformat())
    scanner = HtmlScraperScanner(model_path=None)

    class ControlledModel:
        classes_ = [0, 1]

        def predict_proba(self, features):
            probability = 0.99 if features.iloc[0]["PasswordInputCount"] else 0.01
            return [[1 - probability, probability]]

    scanner.model = ControlledModel()
    monkeypatch.setattr(scanner, "_safe_get", lambda url, headers: (BufferedPageResponse(page), URL, []))
    monkeypatch.setattr(scanner, "_maybe_render_html", lambda *args: BrowserRenderResult(
        available=True, html=rendered, final_url=destination, coverage_complete=False,
    ))
    response = ScanningPipeline([scanner]).run(URL)
    stage = next(item for item in response.stages if item.scanner == "HtmlScraper")
    assert stage.verdict == "malicious"
    assert stage.malicious_probability == 0.99
    assert stage.training_features["feature_url"] == URL
    assert stage.details["final_url"] == destination

    store = TrainingStore(tmp_path / "different-destination.sqlite3")
    store.init_db()
    observation_id = _record_observation_safely(response, store, "test")
    observation = store.observation_by_id(observation_id)
    assert observation["final_url"] == destination
    assert observation["url_features"] is not None
    assert observation["html_features"] is None
    assert observation["html_hash"] is None
    saved_alert = next(item for item in observation["scanner_results"] if item["scanner"] == "HtmlScraper")
    assert saved_alert["verdict"] == "malicious"
