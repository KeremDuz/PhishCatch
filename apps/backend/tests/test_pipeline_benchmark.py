"""Synthetic fixtures verify the harness, never report classifier accuracy."""

from __future__ import annotations

import copy
import json
import os
import socket
from pathlib import Path
from typing import ClassVar

import pytest
from app.core.config import Settings
from app.ml.benchmark import (
    BenchmarkManifest,
    build_replay_pipeline,
    compare_reports,
    digest_bytes,
    evaluate_replay,
    load_manifest,
    network_denied,
    snapshot_path,
    summarize,
    wilson_interval,
)
from pydantic import ValidationError


class LowProbabilityModel:
    classes_: ClassVar[list[int]] = [0, 1]

    def predict_proba(self, features):
        return [[0.99, 0.01]]


def example_sample(
    tmp_path: Path, key: str, label: str, *, split: str = "evaluation"
) -> dict:
    body = f"<html><title>Static {key}</title><p>Ordinary archived content {key}</p></html>".encode()
    filename = f"{key}.html"
    (tmp_path / filename).write_bytes(body)
    return {
        "sample_id": key,
        "url": f"https://{key}.example/",
        "final_url": f"https://{key}.example/",
        "template_group": f"template-{key}",
        "campaign_group": f"campaign-{key}",
        "observed_at": "2026-10-20T10:00:00Z"
        if split == "evaluation"
        else "2026-09-20T10:00:00Z",
        "labelled_at": "2026-10-20T11:00:00Z",
        "split": split,
        "label": label,
        "label_method": "human_double_review",
        "reviewers": ["fixture-reviewer-a", "fixture-reviewer-b"],
        "label_evidence": [
            "Synthetic test fixture; never a real independently verified label"
        ],
        "html_path": filename,
        "html_sha256": digest_bytes(body),
        "context": [
            {
                "target": f"https://{key}.example/",
                "captured_at": "2026-10-20T10:00:00Z"
                if split == "evaluation"
                else "2026-09-20T10:00:00Z",
                "evidence_reference": "Synthetic fixture no-match, not real feed evidence",
                "adapter_sha256": "f" * 64,
                "stage": {
                    "scanner": "LocalPhishingFeed",
                    "verdict": "unknown",
                    "status": "completed",
                    "risk_score": 0,
                },
            }
        ],
    }


@pytest.fixture
def manifest_data(tmp_path):
    return {
        "cohort_id": "synthetic-harness-regression",
        "cohort_kind": "synthetic_regression",
        "training_provenance": "unavailable",
        "training_cutoff_at": "2026-09-01T00:00:00Z",
        "tuning_cutoff_at": "2026-10-01T00:00:00Z",
        "samples": [
            example_sample(tmp_path, "clean", "clean"),
            example_sample(tmp_path, "phishing", "phishing"),
        ],
    }


def freeze(data: dict) -> BenchmarkManifest:
    manifest = BenchmarkManifest.model_validate(data)
    return BenchmarkManifest.model_validate(
        {**manifest.model_dump(mode="json"), "frozen_sha256": manifest.content_digest()}
    )


def pipeline(providers: list[str] | None = None):
    result = build_replay_pipeline(
        Settings(
            ml_model_path="",
            html_model_path=None,
            html_skip_on_confident_clean=False,
            cloudflare_dns_security_enabled=False,
        ),
        providers or [],
    )
    result.scanners[1].model = LowProbabilityModel()
    result.scanners[2].model = LowProbabilityModel()
    return result


def test_actual_pipeline_and_public_projection_are_replayed_without_live_network(
    manifest_data, tmp_path
):
    report = evaluate_replay(
        freeze(manifest_data),
        tmp_path,
        pipeline(),
        run_name="fixture",
        fingerprints={"models": "fake-test-models"},
    )
    # A low fixture model misses the labelled phishing example. The harness must
    # expose that mistake, not call every completed analysis a success.
    assert report["metrics"]["confusion_matrix"] == {
        "clean": {"clean": 1, "malicious": 0, "unknown": 0},
        "phishing": {"clean": 1, "malicious": 0, "unknown": 0},
    }
    assert report["metrics"]["phishing_to_clean"]["rate"] == 1
    assert report["validity"]["quality_claim_eligible"] is False
    assert any(
        "training provenance" in reason for reason in report["validity"]["limitations"]
    )
    assert "https://" not in json.dumps(report["results"])


def test_unknown_is_abstention_and_never_counted_as_detection(manifest_data, tmp_path):
    item = manifest_data["samples"][1]
    item.update(
        fetch_error="fetch_deadline",
        html_path=None,
        html_sha256=None,
        capture_elapsed_seconds=30,
    )
    report = evaluate_replay(
        freeze(manifest_data), tmp_path, pipeline(), run_name="timeout", fingerprints={}
    )
    assert report["metrics"]["confusion_matrix"]["phishing"]["unknown"] == 1
    assert report["metrics"]["by_class"]["phishing"]["correct_decision"]["rate"] == 0
    assert report["metrics"]["by_class"]["phishing"]["decision_coverage"]["rate"] == 0
    assert report["metrics"]["archived_fetch_timeout_count"] == 1


def test_missing_reputation_cannot_disappear_from_the_production_profile(
    manifest_data, tmp_path
):
    manifest_data["samples"][0]["context"] = []
    report = evaluate_replay(
        freeze(manifest_data),
        tmp_path,
        pipeline(),
        run_name="missing-context",
        fingerprints={},
    )
    assert "LocalPhishingFeed" in report["providers"]
    assert report["results"][0]["final_verdict"] == "unknown"
    assert report["results"][0]["scan_status"] == "partial"
    assert any(
        "local reputation context" in reason
        for reason in report["validity"]["limitations"]
    )


def test_known_feed_hit_does_not_require_collecting_a_hostile_html_page(
    manifest_data, tmp_path
):
    sample = manifest_data["samples"][1]
    sample.update(
        fetch_error="not_fetched_known_reputation", html_path=None, html_sha256=None
    )
    sample["context"][0]["stage"].update(verdict="malicious", risk_score=1)
    report = evaluate_replay(
        freeze(manifest_data),
        tmp_path,
        pipeline(),
        run_name="known-no-fetch",
        fingerprints={},
    )
    assert report["results"][1]["final_verdict"] == "malicious"
    assert report["reputation_cohorts"]["known_local"]["count"] == 1
    assert report["metrics"]["archived_fetch_timeout_count"] == 0


def test_cloudflare_filter_replay_is_unknown_and_skips_target_content(
    manifest_data, tmp_path, monkeypatch
):
    sample = manifest_data["samples"][1]
    sample.update(
        fetch_error="not_fetched_dns_review", html_path=None, html_sha256=None
    )
    sample["context"].append(
        {
            "target": sample["url"],
            "captured_at": sample["observed_at"],
            "evidence_reference": "Synthetic hostname filter fixture",
            "adapter_sha256": "d" * 64,
            "stage": {
                "scanner": "CloudflareDnsSecurity",
                "verdict": "unknown",
                "risk_score": 0,
                "details": {
                    "scope": "hostname_only",
                    "requires_review": True,
                    "filtered": True,
                },
            },
        }
    )
    replay = pipeline(["CloudflareDnsSecurity"])
    from app.services.url_resolver_scanner import UrlResolverScanner

    original_scan = UrlResolverScanner.scan

    def deny_filtered_target(self, url):
        if url == sample["url"]:
            pytest.fail("DNS-filtered target content must not be fetched")
        return original_scan(self, url)

    monkeypatch.setattr(UrlResolverScanner, "scan", deny_filtered_target)
    report = evaluate_replay(
        freeze(manifest_data),
        tmp_path,
        replay,
        run_name="free-dns-review",
        fingerprints={},
        external_reputation=True,
    )
    assert report["results"][1]["final_verdict"] == "unknown"
    assert report["results"][1]["scan_status"] == "partial"
    assert report["reputation_cohorts"]["dns_filter_review"]["count"] == 1
    assert report["reputation_cohorts"]["known_api"]["count"] == 0
    assert report["metrics"]["by_class"]["phishing"]["correct_decision"]["rate"] == 0


def test_enabled_cloudflare_profile_cannot_silently_drop_missing_captures(
    manifest_data, tmp_path
):
    settings = Settings(
        ml_model_path="",
        html_model_path=None,
        html_skip_on_confident_clean=False,
        cloudflare_dns_security_enabled=True,
    )
    replay = build_replay_pipeline(settings, [])
    replay.scanners[1].model = LowProbabilityModel()
    replay.scanners[2].model = LowProbabilityModel()
    report = evaluate_replay(
        freeze(manifest_data),
        tmp_path,
        replay,
        run_name="missing-dns-captures",
        fingerprints={},
        external_reputation=True,
    )
    assert "CloudflareDnsSecurity" in report["providers"]
    assert all(
        row["final_verdict"] == "unknown" and row["scan_status"] == "partial"
        for row in report["results"]
    )
    assert any(
        "external reputation context" in reason
        for reason in report["validity"]["limitations"]
    )


def test_cloudflare_capture_cannot_claim_a_phishing_category(manifest_data):
    sample = manifest_data["samples"][0]
    sample["context"].append(
        {
            "target": sample["url"],
            "captured_at": sample["observed_at"],
            "evidence_reference": "Synthetic invalid fixture",
            "adapter_sha256": "d" * 64,
            "stage": {
                "scanner": "CloudflareDnsSecurity",
                "verdict": "malicious",
                "risk_score": 1,
            },
        }
    )
    with pytest.raises(ValidationError, match="hostname context"):
        BenchmarkManifest.model_validate(manifest_data)


def test_large_snapshot_is_rejected_before_parsing(manifest_data, tmp_path):
    sample = manifest_data["samples"][0]
    body = b"x" * (1024 * 1024 + 1)
    (tmp_path / sample["html_path"]).write_bytes(body)
    sample["html_sha256"] = digest_bytes(body)
    with pytest.raises(ValueError, match="HTML size limit"):
        evaluate_replay(
            freeze(manifest_data),
            tmp_path,
            pipeline(),
            run_name="large",
            fingerprints={},
        )


def test_reputation_api_on_off_share_frozen_corpus_and_preserve_capture_identity(
    manifest_data, tmp_path
):
    for sample in manifest_data["samples"]:
        sample["context"].append(
            {
                "target": sample["url"],
                "captured_at": sample["observed_at"],
                "evidence_reference": "Private captured response checksum",
                "adapter_sha256": "a" * 64,
                "stage": {
                    "scanner": "GoogleWebRisk",
                    "verdict": "malicious"
                    if sample["label"] == "phishing"
                    else "unknown",
                    "status": "completed",
                    "risk_score": 1 if sample["label"] == "phishing" else 0,
                },
            }
        )
    cohort = freeze(manifest_data)
    off = evaluate_replay(
        cohort, tmp_path, pipeline(), run_name="off", fingerprints={"models": "same"}
    )
    on = evaluate_replay(
        cohort,
        tmp_path,
        pipeline(["GoogleWebRisk"]),
        run_name="on",
        fingerprints={"models": "same"},
        external_reputation=True,
    )
    assert on["metrics"]["confusion_matrix"]["phishing"]["malicious"] == 1
    assert off["manifest_sha256"] == on["manifest_sha256"]
    assert on["reputation_cohorts"]["known_api"]["count"] == 1
    assert off["reputation_cohorts"]["known_api"]["count"] == 1
    comparison = compare_reports(off, on)
    assert comparison["no_count_regression_on_this_cohort"] is True
    assert comparison["promotion_authorized"] is False


def test_stale_or_future_context_rejected(manifest_data):
    sample = manifest_data["samples"][0]
    for captured_at in ("2026-10-20T10:01:00Z", "2026-10-20T09:00:00Z"):
        sample["context"] = [
            {
                "target": sample["url"],
                "captured_at": captured_at,
                "evidence_reference": "Captured source",
                "adapter_sha256": "a" * 64,
                "stage": {"scanner": "GoogleWebRisk", "verdict": "unknown"},
            }
        ]
        with pytest.raises(ValidationError, match="Future|contemporaneous"):
            BenchmarkManifest.model_validate(manifest_data)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("label_evidence", ["model prediction"], "ground-truth"),
        ("reviewers", ["only-one"], "two independent"),
        ("reviewers", ["same", "same"], "distinct"),
        ("observed_at", "2026-10-20T10:00:00", "timezone"),
        ("observed_at", "2026-09-20T10:00:00Z", "newer"),
        ("html_sha256", "x", "pattern"),
    ],
)
def test_unverified_or_invalid_inputs_rejected(manifest_data, field, value, error):
    manifest_data["samples"][0][field] = value
    if field == "observed_at":
        manifest_data["samples"][0]["context"][0]["captured_at"] = value
    with pytest.raises(ValidationError, match=error):
        BenchmarkManifest.model_validate(manifest_data)


@pytest.mark.parametrize(
    "attribute", ["template_group", "campaign_group", "url", "html_sha256"]
)
def test_training_overlap_cannot_pass_as_independent_evaluation(
    manifest_data, attribute
):
    row = manifest_data["samples"][0]
    exclusion = {
        "sample_id": "old-training",
        "url": "https://training.example/",
        "template_group": "training-template",
        "campaign_group": "training-campaign",
        "observed_at": "2026-08-01T00:00:00Z",
        "html_sha256": "a" * 64,
    }
    exclusion[attribute] = row[attribute]
    manifest_data["training_exclusions"] = [exclusion]
    with pytest.raises(ValidationError, match="overlap|Duplicate"):
        BenchmarkManifest.model_validate(manifest_data)


def test_domain_group_derived_from_url_not_caller_supplied(manifest_data):
    row = manifest_data["samples"][0]
    row["url"] = row["final_url"] = "https://clean-example.com/"
    row["context"][0]["target"] = row["url"]
    manifest_data["training_exclusions"] = [
        {
            "sample_id": "old-training",
            "url": row["url"].replace("https://", "https://sub."),
            "template_group": "other",
            "campaign_group": "other",
            "observed_at": "2026-08-01T00:00:00Z",
        }
    ]
    with pytest.raises(ValidationError, match="domain_group overlap"):
        BenchmarkManifest.model_validate(manifest_data)


def test_tuning_and_evaluation_html_overlap_rejected_even_with_different_family_ids(
    manifest_data, tmp_path
):
    tuning = example_sample(tmp_path, "tuning", "clean", split="tuning")
    tuning["html_sha256"] = manifest_data["samples"][0]["html_sha256"]
    manifest_data["samples"].append(tuning)
    with pytest.raises(ValidationError, match="html_sha256 overlap"):
        BenchmarkManifest.model_validate(manifest_data)


def test_training_provenance_cannot_be_declared_complete_without_ledger(manifest_data):
    manifest_data["training_provenance"] = "declared_complete"
    with pytest.raises(ValidationError, match="exclusion ledger"):
        BenchmarkManifest.model_validate(manifest_data)


def test_original_and_landing_domains_cannot_cross_split(manifest_data, tmp_path):
    tuning = example_sample(tmp_path, "tuning", "clean", split="tuning")
    original = manifest_data["samples"][0]
    tuning["final_url"] = original["url"] + "landing"
    tuning["redirect_chain"] = [
        {
            "from": tuning["url"],
            "to": tuning["final_url"],
            "kind": "http",
            "status": 302,
        }
    ]
    manifest_data["samples"].append(tuning)
    with pytest.raises(ValidationError, match="domain_group overlap"):
        BenchmarkManifest.model_validate(manifest_data)


def test_frozen_digest_detects_edits_and_evaluation_refuses_unfrozen(
    manifest_data, tmp_path
):
    cohort = freeze(manifest_data)
    edited = cohort.model_dump(mode="json")
    edited["samples"][0]["label"] = "phishing"
    with pytest.raises(ValidationError, match="digest mismatch"):
        BenchmarkManifest.model_validate(edited)
    with pytest.raises(ValueError, match="Freeze"):
        evaluate_replay(
            BenchmarkManifest.model_validate(manifest_data),
            tmp_path,
            pipeline(),
            run_name="unfrozen",
            fingerprints={},
        )


def test_snapshot_hash_corruption_fails_instead_of_becoming_unknown(
    manifest_data, tmp_path
):
    (tmp_path / manifest_data["samples"][0]["html_path"]).write_text("modified")
    with pytest.raises(ValueError, match="Snapshot hash mismatch"):
        evaluate_replay(
            freeze(manifest_data),
            tmp_path,
            pipeline(),
            run_name="tampered",
            fingerprints={},
        )


def test_traversal_and_symlink_escape_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="traverse"):
        snapshot_path(tmp_path, "../outside.html")
    outer = tmp_path.parent / f"{tmp_path.name}-outside.html"
    outer.write_text("private outside content")
    link = tmp_path / "escape.html"
    try:
        link.symlink_to(outer)
    except OSError:
        pytest.skip("Creating symlinks is unavailable on this Windows test account")
    with pytest.raises(ValueError, match="escapes"):
        snapshot_path(tmp_path, "escape.html")


def test_network_guard_blocks_dns_http_and_worker_paths():
    import requests
    from app.services import worker_process

    with network_denied():
        with pytest.raises(RuntimeError, match="disabled"):
            socket.getaddrinfo("must-not-resolve.example", 443)
        with pytest.raises(RuntimeError, match="disabled"):
            requests.get("https://must-not-fetch.example/")
        with pytest.raises(RuntimeError, match="disabled"):
            worker_process.run_worker(
                "rdap", {"url": "https://must-not-fetch.example/"}, timeout=1
            )


def test_comparison_rejects_different_corpus_and_exposes_regressions(
    manifest_data, tmp_path
):
    report = evaluate_replay(
        freeze(manifest_data), tmp_path, pipeline(), run_name="active", fingerprints={}
    )
    changed = copy.deepcopy(report)
    changed["comparison_context_sha256"] = "other"
    with pytest.raises(ValueError, match="same frozen cohort"):
        compare_reports(report, changed)
    changed = copy.deepcopy(report)
    changed["results"][0]["final_verdict"] = "unknown"
    comparison = compare_reports(report, changed)
    assert comparison["no_count_regression_on_this_cohort"] is False
    assert "clean: fewer correct definitive decisions" in comparison["regressions"]
    assert comparison["promotion_authorized"] is False


def test_metrics_do_not_manufacture_rates_for_empty_groups():
    assert summarize([])["unknown"]["rate"] is None
    interval = wilson_interval(0, 300)
    assert interval["rate"] == 0
    assert 0 < interval["upper_95"] < 0.02


def test_manifest_loader_is_bounded(manifest_data, tmp_path, monkeypatch):
    from app.ml import benchmark

    target = tmp_path / "manifest.json"
    target.write_text(json.dumps(manifest_data), encoding="utf-8")
    assert load_manifest(target).cohort_id == "synthetic-harness-regression"
    monkeypatch.setattr(benchmark, "MAX_MANIFEST_BYTES", 2)
    with pytest.raises(ValueError, match="size limit"):
        load_manifest(target)


def test_cli_outputs_are_exclusive_and_private_from_creation(tmp_path, monkeypatch):
    from scripts.benchmark_pipeline import _write

    real_open = os.open
    observed_modes: list[int] = []

    def capture_open(path, flags, mode=0o777):
        observed_modes.append(mode)
        assert flags & os.O_EXCL
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", capture_open)
    target = tmp_path / "private-report.json"
    _write(target, {"private": "fixture"})
    assert observed_modes == [0o600]
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exists"):
        _write(target, {"overwritten": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {"private": "fixture"}
