from __future__ import annotations

import bz2
import gzip
import io
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.request import Request

import joblib
import pandas as pd
import pytest
import requests
from app.core.config import Settings
from app.core.pipeline import ScanningPipeline
from app.core.risk_aggregator import RiskAggregator
from app.ml.evaluation import grouped_temporal_indices, wilson_upper
from app.models.schemas import StageResult
from app.services import rdap_scanner, safe_http
from app.services.feed_update import CDN_SOURCE, FeedRedirectHandler
from app.services.local_phishing_feed import LocalPhishingFeed, url_digest
from app.services.page_fetch import PageArtifact
from app.services.virustotal_scanner import VirusTotalScanner
from scripts.export_training_datasets import provenance
from scripts.promote_candidate_models import evaluate_and_promote, gate_failures
from scripts.retrain_models import train_candidate
from scripts.update_phishing_feed import decode_feed, write_snapshot
from sklearn.tree import DecisionTreeClassifier
from test_detection_policy import FixedScanner
from urllib3.response import HTTPResponse


def snapshot(tmp_path, url="https://fixture.example/login", hours=0):
    target = tmp_path / "feed.json"
    write_snapshot(
        {
            "schema": "phishcatch-feed-1",
            "source": "phishtank",
            "url_sha256": [url_digest(url)],
            "fetched_at": (datetime.now(UTC) - timedelta(hours=hours)).isoformat(),
        },
        target,
    )
    return target


def test_fresh_feed_hit_stops_before_fetch_and_miss_is_not_clean_evidence(tmp_path):
    feed = LocalPhishingFeed(snapshot(tmp_path))

    class ForbiddenResolver(FixedScanner):
        def scan(self, url):
            pytest.fail("Known phishing URLs must not be fetched")

    result = ScanningPipeline(
        [FixedScanner(StageResult(scanner="MLModelScanner", verdict="clean"))],
        redirect_resolver=ForbiddenResolver(
            StageResult(scanner="UrlResolver", verdict="unknown")
        ),
        threat_intel_scanners=[feed],
    ).run("https://fixture.example/login#fragment")
    assert result.final_verdict == "malicious"
    assert len(result.stages) == 1
    assert feed.scan("https://other.example/").verdict == "unknown"


@pytest.mark.parametrize("hours", [27, -1])
def test_stale_or_future_feed_is_unavailable(tmp_path, hours):
    feed = LocalPhishingFeed(snapshot(tmp_path, hours=hours))
    assert feed.scan("https://fixture.example/login").status == "unavailable"


def test_missing_corrupt_or_deleted_feed_cannot_reuse_previous_match(tmp_path):
    target = snapshot(tmp_path)
    feed = LocalPhishingFeed(target)
    assert feed.health()["available"]
    target.write_text("broken")
    assert feed.scan("https://fixture.example/login").status == "unavailable"
    target.unlink()
    assert feed.scan("https://fixture.example/login").status == "unavailable"


def test_import_only_verified_online_rows_and_keep_query_semantics():
    rows = [
        {
            "url": "https://fixture.example/login?a=1",
            "verified": "yes",
            "online": "yes",
        },
        {"url": "https://unverified.example/", "verified": "no", "online": "yes"},
        {"url": "https://offline.example/", "verified": "yes", "online": "no"},
    ]
    result = decode_feed(bz2.compress(json.dumps(rows).encode()))
    assert result["url_sha256"] == [url_digest(rows[0]["url"])]
    assert url_digest(rows[0]["url"]) != url_digest("https://fixture.example/login?a=2")
    assert "https://" not in json.dumps(result)


@pytest.mark.parametrize(
    "raw",
    [
        b"not bz2",
        bz2.compress(b"[]"),
        bz2.compress(b"[]") + b"junk",
        bz2.compress(b"[]")[:-1],
    ],
)
def test_invalid_feed_cannot_be_imported(raw):
    with pytest.raises((ValueError, OSError, EOFError)):
        decode_feed(raw)


def test_official_feed_cdn_redirect_is_allowed_but_downgrades_and_other_hosts_are_not():
    handler = FeedRedirectHandler()
    request = Request("https://data.phishtank.com/data/online-valid.json.bz2")
    assert (
        handler.redirect_request(request, None, 302, "", {}, CDN_SOURCE).full_url
        == CDN_SOURCE
    )
    for url in (
        "http://cdn.phishtank.com/datadumps/verified_online.json.bz2",
        "https://other.example/feed",
        "http://127.0.0.1/",
    ):
        with pytest.raises(ValueError):
            handler.redirect_request(request, None, 302, "", {}, url)


def cohort():
    return pd.DataFrame(
        {
            "x": range(50),
            "result": [i % 2 for i in range(50)],
            "sample_id": [f"url-{i}" for i in range(50)],
            "domain_group": [f"site-{i}" for i in range(50)],
            "template_group": ["" for _ in range(50)],
            "observed_at": pd.date_range("2026-01-01", periods=50, tz="UTC").astype(
                str
            ),
            "label_source": "human_review",
            "verified_label": True,
        }
    )


def test_temporal_split_removes_shared_domains_templates_and_feature_vectors():
    data = cohort()
    data.loc[0, "domain_group"] = data.loc[40, "domain_group"]
    data.loc[1, "template_group"] = data.loc[41, "template_group"] = "shared-template"
    data.loc[2, "x"] = data.loc[42, "x"]
    train, test = grouped_temporal_indices(data, ["x"], 0.2)
    assert len(test) == 10 and not {0, 1, 2}.intersection(train)
    assert max(train) < min(test)


@pytest.mark.parametrize(
    "column,value",
    [
        ("observed_at", ""),
        ("verified_label", False),
        ("label_source", "model_prediction"),
        ("domain_group", ""),
    ],
)
def test_missing_or_prediction_derived_provenance_cannot_evaluate(column, value):
    data = cohort()
    data[column] = value
    with pytest.raises(ValueError):
        grouped_temporal_indices(data, ["x"], 0.2)


def test_export_uses_observation_time_not_label_creation_time():
    result = provenance(
        {
            "url": "https://a.example.co.uk/",
            "created_at": "2026-01-01",
            "approved_for_training": True,
        }
    )
    assert result["observed_at"] == ""
    assert "example.co.uk" not in result["domain_group"]


def test_saved_candidate_has_not_been_refitted_on_its_holdout(tmp_path):
    data = cohort()
    path = tmp_path / "dataset.csv"
    data.to_csv(path, index=False)
    result = train_candidate(
        name="url",
        dataset_path=path,
        feature_columns=["x"],
        build_model=lambda: DecisionTreeClassifier(random_state=42),
        model_path=tmp_path / "candidate.pkl",
        min_samples=20,
        test_size=0.2,
        threshold=0.5,
        seed=42,
    )
    assert result["status"] == "trained"
    model = joblib.load(result["model_path"])
    assert model.tree_.n_node_samples[0] == 40
    proof = result["validation"]["evaluation"]
    assert proof["test_rows"] == 10 and proof["refit_on_holdout"] is False


def test_repeated_samples_do_not_inflate_test_rows():
    data = cohort()
    data.loc[41, "sample_id"] = data.loc[40, "sample_id"]
    data.loc[41, "result"] = data.loc[40, "result"]
    train, test = grouped_temporal_indices(data, ["x"], 0.2)
    assert len(train) + len(test) == 49


@pytest.mark.parametrize(
    "malicious,suspicious,expected",
    [(0, 1, "unknown"), (1, 0, "unknown"), (2, 0, "malicious")],
)
def test_virustotal_single_alert_requires_corroboration(
    monkeypatch, malicious, suspicious, expected
):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: SimpleNamespace(
            status_code=200,
            json=lambda: {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": suspicious,
                        }
                    }
                }
            },
        ),
    )
    result = VirusTotalScanner(Settings(virustotal_api_key="test-only-key")).scan(
        "https://fixture.example/"
    )
    assert result.verdict == expected
    combined = RiskAggregator().aggregate(
        [
            result,
            StageResult(
                scanner="MLModelScanner", verdict="clean", malicious_probability=0.01
            ),
        ]
    )
    assert combined.final_verdict == expected


def test_legacy_perfect_metrics_cannot_pass_promotion_even_with_force(tmp_path):
    candidate = tmp_path / "candidate.pkl"
    candidate.write_bytes(b"not loaded by promotion")
    result = evaluate_and_promote(
        model_name="url",
        model_result={
            "status": "trained",
            "model_path": str(candidate),
            "row_count": 100000,
            "validation": {"precision": 1, "recall": 1, "f1": 1},
        },
        active_path=tmp_path / "active.pkl",
        backup_dir=tmp_path / "backups",
        timestamp="test",
        dry_run=False,
        force=True,
        no_backup=False,
        min_rows=20,
        min_precision=0.8,
        min_recall=0.6,
        min_f1=0.7,
    )
    assert result["status"] == "rejected"
    assert not (tmp_path / "active.pkl").exists()


def test_nan_metrics_are_rejected_and_uncertainty_matters():
    failures = gate_failures(
        {"validation": {"precision": float("nan"), "recall": 1, "f1": 1}},
        min_rows=500,
        min_precision=0.98,
        min_recall=0.9,
        min_f1=0.94,
    )
    assert "Invalid evaluation metrics" in failures
    assert wilson_upper(0, 4) > 0.4
    assert wilson_upper(0, 1000) < 0.01


def test_rdap_uses_registrable_domain_and_never_turns_age_into_clean(monkeypatch):
    calls = []

    def fetch(url, headers):
        calls.append(url)
        record = (
            {"services": [[["uk"], ["https://registry.example/rdap/"]]]}
            if len(calls) == 1
            else {
                "ldhName": "example.co.uk",
                "events": [
                    {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}
                ],
            }
        )
        return PageArtifact(
            url, url, 200, "application/json", json.dumps(record).encode(), (), "now"
        )

    monkeypatch.setattr(rdap_scanner, "_fetch_page", fetch)
    info = rdap_scanner.registration_context("https://sub.example.co.uk/login")
    assert calls[-1] == "https://registry.example/rdap/domain/example.co.uk"
    monkeypatch.setattr(rdap_scanner, "run_worker", lambda *a, **k: info)
    result = rdap_scanner.RdapScanner().scan("https://sub.example.co.uk/")
    assert result.verdict == "unknown" and result.risk_score == 0
    assert result.details["available"] is True


@pytest.mark.parametrize(
    "body,success",
    [(b"<html>normal</html>", True), (b"x" * (1024**2 + 1), False)],
    ids=["normal", "expansion_limit"],
)
def test_gzip_reader_bounds_decompressed_output_and_closes(body, success):
    response = requests.Response()
    response.headers["Content-Encoding"] = "gzip"
    response.raw = HTTPResponse(
        body=io.BytesIO(gzip.compress(body)), preload_content=False
    )
    closed = []
    wrapped = safe_http.PublicHttpResponse(
        response, SimpleNamespace(close=lambda: closed.append(True))
    )
    if success:
        assert b"".join(wrapped.iter_content(8192)) == body
    else:
        with pytest.raises(requests.RequestException):
            b"".join(wrapped.iter_content(8192))
    assert closed
