"""Private, network-denied replay of independently labelled archived pages.

This measures consumer decisions, not only model scores. It never collects pages,
creates labels, retrains, or promotes a model. A provenance declaration cannot
prove that an old model's unavailable training corpus was disjoint.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import socket
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any, Literal
from unittest.mock import patch
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.config import Settings
from app.core.pipeline import ScanningPipeline
from app.models.schemas import StageResult
from app.routers.public_analysis import _public_result
from app.services.base_scanner import BaseScanner
from app.services.html_policy import site_key
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.ml_model_scanner import MLModelScanner
from app.services.page_fetch import MAX_HTML_BYTES, FetchFailure, PageArtifact
from app.services.url_resolver_scanner import UrlResolverScanner
from app.utils.url_utils import canonicalize_url

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SAMPLES = 20_000
VERDICTS = ("clean", "malicious", "unknown")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: object) -> str:
    return digest_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )


def digest_file(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return value.astimezone(UTC)


def _url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Only credential-free absolute HTTP(S) URLs are allowed")
    return canonicalize_url(value)


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class SampleIdentity(StrictRecord):
    sample_id: str = Field(min_length=1, max_length=128)
    url: str = Field(max_length=2048)
    # A non-empty reviewed family identifier is mandatory, even for unique pages.
    template_group: str = Field(min_length=1, max_length=128)
    campaign_group: str = Field(min_length=1, max_length=128)
    observed_at: datetime
    html_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    _normalize_url = field_validator("url")(_url)
    _normalize_time = field_validator("observed_at")(_aware)

    @field_validator("sample_id", "template_group", "campaign_group")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Identity cannot be blank")
        return value.strip()

    @property
    def domain_group(self) -> str:
        return site_key(self.url)


class CapturedStage(StrictRecord):
    """A response recorded before a decision, never reconstructed from its label."""

    target: str = Field(max_length=2048)
    captured_at: datetime
    evidence_reference: str = Field(min_length=1, max_length=500)
    adapter_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stage: StageResult

    _normalize_url = field_validator("target")(_url)
    _normalize_time = field_validator("captured_at")(_aware)


class BenchmarkSample(SampleIdentity):
    split: Literal["tuning", "evaluation"]
    label: Literal["clean", "phishing"]
    label_method: Literal["human_double_review", "independent_feed_and_review"]
    reviewers: list[str] = Field(min_length=1, max_length=5)
    label_evidence: list[str] = Field(min_length=1, max_length=10)
    labelled_at: datetime
    # Relative to the private manifest directory; raw HTML must remain outside Git.
    html_path: str | None = Field(default=None, max_length=512)
    final_url: str = Field(max_length=2048)
    status_code: int = Field(default=200, ge=100, le=599)
    content_type: str = Field(default="text/html", max_length=120)
    redirect_chain: list[dict[str, str | int]] = Field(
        default_factory=list, max_length=5
    )
    fetch_error: (
        Literal[
            "fetch_deadline",
            "fetch_failed",
            "unsafe_destination",
            "html_too_large",
            "not_fetched_known_reputation",
            "not_fetched_dns_review",
        ]
        | None
    ) = None
    capture_elapsed_seconds: float | None = Field(
        default=None, ge=0, le=3600, allow_inf_nan=False
    )
    # Lookups and optional RDAP context are contemporaneous archived snapshots.
    context: list[CapturedStage] = Field(default_factory=list, max_length=48)

    _normalize_final_url = field_validator("final_url")(_url)
    _normalize_label_time = field_validator("labelled_at")(_aware)

    @model_validator(mode="after")
    def verify_capture(self) -> BenchmarkSample:
        if self.labelled_at < self.observed_at:
            raise ValueError("Labels must be verified at or after capture")
        if not all(item.strip() for item in self.reviewers + self.label_evidence):
            raise ValueError(
                "Reviewed ground truth requires non-empty evidence and reviewers"
            )
        if len(set(self.reviewers)) != len(self.reviewers):
            raise ValueError("Reviewer identifiers must be distinct")
        if self.label_method == "human_double_review" and len(self.reviewers) < 2:
            raise ValueError("Double review requires two independent reviewers")
        if any(
            re.search(
                r"\b(?:model|prediction|predicted|self[- ]?label)\b",
                item,
                re.IGNORECASE,
            )
            for item in self.label_evidence
        ):
            raise ValueError("Model predictions cannot be ground-truth evidence")
        if self.fetch_error is None:
            if (
                not self.html_path
                or not self.html_sha256
                or not SHA256.fullmatch(self.html_sha256)
            ):
                raise ValueError("Successful captures require a local body and SHA-256")
        elif self.html_path is not None or self.html_sha256 is not None:
            raise ValueError("Failed captures cannot supply a successful page body")
        targets = {self.url, self.final_url}
        previous = self.url
        for hop in self.redirect_chain:
            if not {"from", "to"}.issubset(hop):
                raise ValueError("Redirect captures require from and to")
            origin, destination = _url(str(hop["from"])), _url(str(hop["to"]))
            if origin != previous:
                raise ValueError("Redirect chain is not contiguous")
            targets.update((origin, destination))
            previous = destination
        if previous != self.final_url:
            raise ValueError("Final URL must match the captured redirect chain")
        identities: set[tuple[str, str]] = set()
        for capture in self.context:
            key = (capture.stage.scanner, capture.target)
            if key in identities or capture.target not in targets:
                raise ValueError("Duplicate or unrelated context capture")
            identities.add(key)
            if capture.captured_at > self.observed_at:
                raise ValueError("Future reputation information would leak the label")
            if (self.observed_at - capture.captured_at).total_seconds() > 900:
                raise ValueError(
                    "Context captures must be contemporaneous (within 15 minutes)"
                )
            if capture.stage.scanner not in {
                "RdapScanner",
                "LocalPhishingFeed",
                "GoogleSafeBrowsing",
                "GoogleWebRisk",
                "URLhausScanner",
                "VirusTotalScanner",
                "CloudflareDnsSecurity",
            }:
                raise ValueError(
                    "Only declared registration/reputation context is replayable"
                )
            if capture.stage.scanner == "CloudflareDnsSecurity" and (
                capture.stage.verdict != "unknown"
                or capture.stage.risk_score not in {None, 0}
                or capture.stage.malicious_probability not in {None, 0}
                or capture.stage.clean_probability not in {None, 0}
            ):
                raise ValueError(
                    "Security DNS captures are hostname context, not phishing/clean predictions"
                )
        if self.fetch_error == "not_fetched_known_reputation" and not any(
            capture.stage.scanner != "RdapScanner"
            and capture.stage.status == "completed"
            and capture.stage.verdict == "malicious"
            for capture in self.context
        ):
            raise ValueError(
                "An unfetched known threat needs contemporaneous positive reputation evidence"
            )
        if self.fetch_error == "not_fetched_dns_review" and not any(
            capture.stage.scanner == "CloudflareDnsSecurity"
            and capture.stage.status == "completed"
            and capture.stage.details.get("requires_review") is True
            for capture in self.context
        ):
            raise ValueError(
                "An unfetched DNS review requires contemporaneous filter evidence"
            )
        return self


class BenchmarkManifest(StrictRecord):
    schema_version: Literal["pipeline-benchmark-1"] = "pipeline-benchmark-1"
    cohort_id: str = Field(min_length=1, max_length=128)
    cohort_kind: Literal["archived_reviewed", "synthetic_regression"]
    training_provenance: Literal["unavailable", "declared_complete"]
    training_cutoff_at: datetime
    tuning_cutoff_at: datetime
    training_exclusions: list[SampleIdentity] = Field(
        default_factory=list, max_length=MAX_SAMPLES
    )
    samples: list[BenchmarkSample] = Field(min_length=1, max_length=MAX_SAMPLES)
    frozen_sha256: str | None = None

    _normalize_train_time = field_validator("training_cutoff_at")(_aware)
    _normalize_tune_time = field_validator("tuning_cutoff_at")(_aware)

    def content_digest(self) -> str:
        return digest_json(self.model_dump(mode="json", exclude={"frozen_sha256"}))

    @model_validator(mode="after")
    def validate_separation(self) -> BenchmarkManifest:
        if self.training_cutoff_at >= self.tuning_cutoff_at:
            raise ValueError("Training must precede tuning and frozen evaluation")
        if (
            self.training_provenance == "declared_complete"
            and not self.training_exclusions
        ):
            raise ValueError(
                "Complete training provenance requires an exclusion ledger"
            )
        if self.training_provenance == "declared_complete" and any(
            not row.html_sha256 for row in self.training_exclusions
        ):
            raise ValueError(
                "Complete exclusion ledgers require HTML identities as well as URL identities"
            )
        if (
            self.frozen_sha256 is not None
            and self.frozen_sha256 != self.content_digest()
        ):
            raise ValueError("Frozen manifest digest mismatch")
        partitions: dict[str, list[SampleIdentity]] = {
            "training": list(self.training_exclusions),
            "tuning": [],
            "evaluation": [],
        }
        for sample in self.samples:
            if (
                sample.split == "tuning"
                and not self.training_cutoff_at
                < sample.observed_at
                <= self.tuning_cutoff_at
            ):
                raise ValueError(
                    "Tuning observations must lie between the temporal cutoffs"
                )
            if (
                sample.split == "evaluation"
                and sample.observed_at <= self.tuning_cutoff_at
            ):
                raise ValueError("Evaluation must be newer than tuning")
            partitions[sample.split].append(sample)
        if any(
            row.observed_at > self.training_cutoff_at
            for row in self.training_exclusions
        ):
            raise ValueError("Training exclusion dates exceed the training cutoff")
        seen_ids: set[str] = set()
        seen_urls: set[str] = set()
        for rows in partitions.values():
            for row in rows:
                if row.sample_id in seen_ids or row.url in seen_urls:
                    raise ValueError("Duplicate sample identity or canonical URL")
                seen_ids.add(row.sample_id)
                seen_urls.add(row.url)
        for attribute in (
            "domain_group",
            "template_group",
            "campaign_group",
            "html_sha256",
        ):
            groups = {
                name: {
                    getattr(row, attribute) for row in rows if getattr(row, attribute)
                }
                for name, rows in partitions.items()
            }
            if attribute == "domain_group":
                # The final landing domain matters even when the original is a shortener.
                for name, rows in partitions.items():
                    for row in rows:
                        if isinstance(row, BenchmarkSample):
                            groups[name].add(site_key(row.final_url))
                            for hop in row.redirect_chain:
                                groups[name].update(
                                    (
                                        site_key(str(hop["from"])),
                                        site_key(str(hop["to"])),
                                    )
                                )
            for left, right in (
                ("training", "tuning"),
                ("training", "evaluation"),
                ("tuning", "evaluation"),
            ):
                if groups[left] & groups[right]:
                    raise ValueError(f"{attribute} overlap between {left} and {right}")
        return self


def load_manifest(path: Path) -> BenchmarkManifest:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("Benchmark manifest exceeds the size limit")
    return BenchmarkManifest.model_validate_json(path.read_bytes())


def snapshot_path(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(
            "Snapshot path must be relative and cannot traverse directories"
        )
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / candidate).resolve(strict=True)
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError("Snapshot escapes the manifest directory")
    if resolved.stat().st_size > MAX_HTML_BYTES:
        raise ValueError("Snapshot exceeds the production HTML size limit")
    return resolved


def load_page(sample: BenchmarkSample, root: Path) -> PageArtifact:
    if sample.fetch_error:
        raise FetchFailure(sample.fetch_error)
    if sample.html_path is None:
        raise ValueError("Missing snapshot")
    body = snapshot_path(root, sample.html_path).read_bytes()
    if len(body) > MAX_HTML_BYTES or digest_bytes(body) != sample.html_sha256:
        raise ValueError("Snapshot hash mismatch")
    return PageArtifact(
        sample.url,
        sample.final_url,
        sample.status_code,
        sample.content_type,
        body,
        tuple(sample.redirect_chain),
        sample.observed_at.isoformat(),
    )


@contextmanager
def network_denied() -> Iterator[None]:
    """Fail closed on accidental live I/O, including provider worker processes.

    This is a single-process benchmark guard, not an OS sandbox for untrusted code.
    Only load trusted local model pickles; do not run in a live API server process.
    """

    def reject(*args: object, **kwargs: object) -> Any:
        raise RuntimeError(
            "Network and external worker execution are disabled during replay"
        )

    with ExitStack() as stack:
        for target in (
            "socket.create_connection",
            "socket.getaddrinfo",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.gethostbyaddr",
            "requests.sessions.Session.request",
            "app.services.worker_process.run_worker",
        ):
            stack.enter_context(patch(target, side_effect=reject))
        stack.enter_context(patch.object(socket.socket, "connect", reject))
        stack.enter_context(patch.object(socket.socket, "connect_ex", reject))
        stack.enter_context(patch.object(socket.socket, "sendto", reject))
        yield


class ReplayScanner(BaseScanner):
    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.captures: dict[str, StageResult] = {}

    def scan(self, url: str) -> StageResult:
        if url in self.captures:
            return self.captures[url].model_copy(deep=True)
        if self.name == "RdapScanner":
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=0,
                details={"available": False, "optional_context": True},
            )
        return StageResult(
            scanner=self.name,
            verdict="unknown",
            status="unavailable",
            reason="No contemporaneous archived reputation response",
        )


def build_replay_pipeline(
    settings: Settings, provider_names: list[str]
) -> ScanningPipeline:
    """Production scanner/policy classes, replacing only external input transport."""
    providers = {"LocalPhishingFeed", *provider_names}
    if settings.cloudflare_dns_security_enabled:
        providers.add("CloudflareDnsSecurity")
    return ScanningPipeline(
        [
            ReplayScanner("RdapScanner"),
            MLModelScanner(settings),
            HtmlScraperScanner(model_path=settings.html_model_path, isolated=False),
        ],
        redirect_resolver=UrlResolverScanner(),
        threat_intel_scanners=[ReplayScanner(name) for name in sorted(providers)],
        scan_cache=None,
        skip_html_on_confident_clean=settings.html_skip_on_confident_clean,
        html_skip_max_prior_risk=settings.html_skip_max_prior_risk,
        fetch_worker=False,
    )


def wilson_interval(events: int, count: int) -> dict[str, float | int | None]:
    if not 0 <= events <= count:
        raise ValueError("Invalid event counts")
    if count == 0:
        return {
            "events": events,
            "count": count,
            "rate": None,
            "lower_95": None,
            "upper_95": None,
        }
    z, p = 1.959963984540054, events / count
    denominator = 1 + z * z / count
    center = (p + z * z / (2 * count)) / denominator
    radius = (
        z * math.sqrt(p * (1 - p) / count + z * z / (4 * count * count)) / denominator
    )
    return {
        "events": events,
        "count": count,
        "rate": p,
        "lower_95": max(0.0, center - radius),
        "upper_95": min(1.0, center + radius),
    }


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    return ordered[lower] + (
        ordered[min(lower + 1, len(ordered) - 1)] - ordered[lower]
    ) * (position - lower)


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    matrix = {
        label: {verdict: 0 for verdict in VERDICTS} for label in ("clean", "phishing")
    }
    for row in rows:
        matrix[row["label"]][row["final_verdict"]] += 1
    by_class: dict[str, Any] = {}
    for label, counts in matrix.items():
        count = sum(counts.values())
        correct = counts["clean" if label == "clean" else "malicious"]
        by_class[label] = {
            "count": count,
            "correct_decision": wilson_interval(correct, count),
            "unknown": wilson_interval(counts["unknown"], count),
            "decision_coverage": wilson_interval(count - counts["unknown"], count),
        }
    elapsed = [float(row["replay_elapsed_seconds"]) for row in rows]
    captured = [
        float(row["capture_elapsed_seconds"])
        for row in rows
        if row["capture_elapsed_seconds"] is not None
    ]
    return {
        "count": len(rows),
        "confusion_matrix": matrix,
        "by_class": by_class,
        "phishing_to_clean": wilson_interval(
            matrix["phishing"]["clean"], sum(matrix["phishing"].values())
        ),
        "benign_false_positive": wilson_interval(
            matrix["clean"]["malicious"], sum(matrix["clean"].values())
        ),
        "unknown": wilson_interval(
            sum(counts["unknown"] for counts in matrix.values()), len(rows)
        ),
        "scan_status_counts": {
            state: sum(row["scan_status"] == state for row in rows)
            for state in ("complete", "partial", "failed")
        },
        "archived_fetch_timeout_count": sum(
            row["archived_fetch_timeout"] for row in rows
        ),
        "replay_processing_seconds": {
            "p50": _percentile(elapsed, 0.5),
            "p95": _percentile(elapsed, 0.95),
        },
        "archived_capture_seconds": {
            "count": len(captured),
            "p50": _percentile(captured, 0.5),
            "p95": _percentile(captured, 0.95),
        },
    }


def code_fingerprint() -> str:
    app_root = Path(__file__).resolve().parents[1]
    return digest_json(
        {
            str(path.relative_to(app_root)).replace("\\", "/"): digest_file(path)
            for path in sorted(app_root.rglob("*.py"))
        }
    )


def evaluate_replay(
    manifest: BenchmarkManifest,
    snapshot_root: Path,
    pipeline: ScanningPipeline,
    *,
    run_name: str,
    fingerprints: dict[str, str],
    split: Literal["tuning", "evaluation"] = "evaluation",
    external_reputation: bool = False,
) -> dict[str, Any]:
    """Replay only; timing excludes network, production workers and model loading."""
    if split == "evaluation" and manifest.frozen_sha256 is None:
        raise ValueError("Freeze the evaluation manifest before running it")
    samples = [sample for sample in manifest.samples if sample.split == split]
    if not samples:
        raise ValueError("Selected split has no samples")
    if pipeline.fetch_worker or pipeline.scan_cache is not None:
        raise ValueError(
            "Replay requires disabled fetch workers and cross-sample caches"
        )
    if any(
        not isinstance(scanner, ReplayScanner)
        for scanner in pipeline.threat_intel_scanners
    ):
        raise ValueError("Only archived reputation scanners may run during replay")
    if any(
        scanner.name == "HtmlScraper" and getattr(scanner, "isolated", True)
        for scanner in pipeline.scanners
    ):
        raise ValueError("Replay must use the in-process production HTML scanner")
    rows: list[dict[str, Any]] = []
    provider_names = sorted(scanner.name for scanner in pipeline.threat_intel_scanners)
    external_names = [name for name in provider_names if name != "LocalPhishingFeed"]
    if bool(external_names) != external_reputation:
        raise ValueError("Declared API profile must match replay providers")
    with network_denied():
        for sample in samples:
            # Verify before running, including known-list short circuits.
            page = None if sample.fetch_error else load_page(sample, snapshot_root)
            for scanner in [*pipeline.scanners, *pipeline.threat_intel_scanners]:
                if isinstance(scanner, ReplayScanner):
                    scanner.captures = {
                        capture.target: capture.stage
                        for capture in sample.context
                        if capture.stage.scanner == scanner.name
                    }

            def fetch(
                url: str,
                headers: object = None,
                *,
                captured_sample: BenchmarkSample = sample,
                captured_page: PageArtifact | None = page,
            ) -> PageArtifact:
                del headers
                if url not in {captured_sample.url, captured_sample.final_url}:
                    raise FetchFailure("unrecorded_target")
                if captured_sample.fetch_error:
                    raise FetchFailure(captured_sample.fetch_error)
                if captured_page is None:
                    raise ValueError("Missing page")
                return captured_page

            started = time.perf_counter()
            with (
                patch("app.services.url_resolver_scanner.fetch_page", fetch),
                patch("app.services.html_scraper_scanner.fetch_page", fetch),
            ):
                analysis = pipeline.run(sample.url, original_input=sample.url)
                public = _public_result(analysis, sample.url)
            local_hit = any(
                capture.stage.scanner == "LocalPhishingFeed"
                and capture.stage.status == "completed"
                and capture.stage.verdict == "malicious"
                for capture in sample.context
            )
            api_hit = any(
                capture.stage.scanner
                not in {"LocalPhishingFeed", "RdapScanner", "CloudflareDnsSecurity"}
                and capture.stage.status == "completed"
                and capture.stage.verdict == "malicious"
                for capture in sample.context
            )
            dns_review = any(
                capture.stage.scanner == "CloudflareDnsSecurity"
                and capture.stage.status == "completed"
                and capture.stage.details.get("requires_review") is True
                for capture in sample.context
            )
            rows.append(
                {
                    "sample_id": sample.sample_id,
                    "label": sample.label,
                    "domain_group_sha256": digest_bytes(sample.domain_group.encode()),
                    "final_verdict": public.final_verdict,
                    "scan_status": public.scan_status,
                    "replay_elapsed_seconds": time.perf_counter() - started,
                    "capture_elapsed_seconds": sample.capture_elapsed_seconds,
                    "archived_fetch_timeout": sample.fetch_error == "fetch_deadline",
                    "reputation_cohort": "known_local"
                    if local_hit
                    else (
                        "known_api"
                        if api_hit
                        else (
                            "dns_filter_review"
                            if dns_review
                            else "not_known_in_captured_sources"
                        )
                    ),
                }
            )
    reasons = []
    if manifest.cohort_kind != "archived_reviewed":
        reasons.append("Synthetic regressions do not measure real-world accuracy")
    if manifest.training_provenance != "declared_complete":
        reasons.append(
            "Original training provenance is unavailable; training overlap cannot be excluded"
        )
    if split != "evaluation":
        reasons.append("Tuning results cannot be used as frozen evaluation results")
    counts = {
        label: sum(row["label"] == label for row in rows)
        for label in ("clean", "phishing")
    }
    if counts["clean"] < 3000 or counts["phishing"] < 1000:
        reasons.append(
            "Initial target of 3000 benign and 1000 phishing examples is not met"
        )
    if not all(
        SHA256.fullmatch(fingerprints.get(key, ""))
        for key in ("production_code_sha256", "url_model_sha256", "html_model_sha256")
    ):
        reasons.append(
            "Trusted production code and both model fingerprints are required"
        )
    if any(
        not any(
            capture.stage.scanner == "LocalPhishingFeed" for capture in sample.context
        )
        for sample in samples
    ):
        reasons.append("Some samples lack contemporaneous local reputation context")
    if external_reputation and any(
        not any(capture.stage.scanner in external_names for capture in sample.context)
        for sample in samples
    ):
        reasons.append("Some samples lack contemporaneous external reputation context")
    return {
        "schema_version": "pipeline-benchmark-report-1",
        "run_name": run_name,
        "created_at": datetime.now(UTC).isoformat(),
        "manifest_sha256": manifest.content_digest(),
        "split": split,
        "mode": "offline_archived_replay",
        "external_reputation": external_reputation,
        "providers": provider_names,
        "fingerprints": fingerprints,
        "comparison_context_sha256": digest_json(
            {"manifest": manifest.content_digest(), "split": split}
        ),
        "validity": {
            "quality_claim_eligible": not reasons,
            "limitations": reasons,
            "training_provenance": manifest.training_provenance,
            "labels_are_reviewers_declarations": True,
        },
        "timing_note": "Replay timing excludes capture networking, model loading and production worker overhead; archived timeouts are not live timeouts.",
        "transport_note": "URL/HTML extraction, decision pipeline and consumer projection are live code; registration/reputation stages replay archived normalized responses, not live provider HTTP adapters.",
        "metrics": summarize(rows),
        "group_counts": {
            "domains": len({sample.domain_group for sample in samples}),
            "templates": len({sample.template_group for sample in samples}),
            "campaigns": len({sample.campaign_group for sample in samples}),
        },
        "interval_note": "Wilson intervals are sample-level descriptive intervals; correlated campaigns require separate cluster-aware uncertainty analysis.",
        "reputation_cohorts": {
            name: summarize([row for row in rows if row["reputation_cohort"] == name])
            for name in (
                "known_local",
                "known_api",
                "dns_filter_review",
                "not_known_in_captured_sources",
            )
        },
        "results": rows,
    }


def compare_reports(
    active: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    """Strict descriptive non-regression report, never a promotion authorization."""
    if (
        active.get("mode") != "offline_archived_replay"
        or candidate.get("mode") != active["mode"]
    ):
        raise ValueError("Only comparable offline replay reports may be compared")
    if active.get("split") != "evaluation" or candidate.get("split") != "evaluation":
        raise ValueError("Candidate comparisons require frozen evaluation reports")
    if active.get("comparison_context_sha256") != candidate.get(
        "comparison_context_sha256"
    ):
        raise ValueError("Active and candidate must use the same frozen cohort")
    baseline = {row["sample_id"]: row for row in active["results"]}
    proposed = {row["sample_id"]: row for row in candidate["results"]}
    if baseline.keys() != proposed.keys() or any(
        baseline[key]["label"] != proposed[key]["label"] for key in baseline
    ):
        raise ValueError("Comparison sample identities or labels differ")
    before, after = (
        summarize(list(baseline.values())),
        summarize(list(proposed.values())),
    )
    regressions = []
    for label in ("clean", "phishing"):
        correct = "clean" if label == "clean" else "malicious"
        wrong = "malicious" if label == "clean" else "clean"
        old, new = before["confusion_matrix"][label], after["confusion_matrix"][label]
        if new[wrong] > old[wrong]:
            regressions.append(f"{label}: more incorrect definitive decisions")
        if new[correct] < old[correct]:
            regressions.append(f"{label}: fewer correct definitive decisions")
        if new["unknown"] > old["unknown"]:
            regressions.append(f"{label}: more unknown results")
    transitions: dict[str, int] = {}
    for key, row in baseline.items():
        transition = (
            f"{row['label']}:{row['final_verdict']}->{proposed[key]['final_verdict']}"
        )
        transitions[transition] = transitions.get(transition, 0) + 1
    return {
        "schema_version": "pipeline-benchmark-comparison-1",
        "manifest_sha256": active["manifest_sha256"],
        "active_fingerprints": active["fingerprints"],
        "candidate_fingerprints": candidate["fingerprints"],
        "external_api_profiles": {
            "active": active["external_reputation"],
            "candidate": candidate["external_reputation"],
        },
        "no_count_regression_on_this_cohort": not regressions,
        "regressions": regressions,
        "paired_transitions": transitions,
        "quality_claim_eligible": active["validity"]["quality_claim_eligible"]
        and candidate["validity"]["quality_claim_eligible"],
        "promotion_authorized": False,
        "note": "Descriptive paired comparison only; this is not statistical proof of superiority or an automatic promotion gate.",
    }


def runtime_fingerprints(settings: Settings) -> dict[str, str]:
    result = {
        "production_code_sha256": code_fingerprint(),
        "url_model_sha256": digest_file(Path(settings.ml_model_path)),
        "html_model_sha256": digest_file(Path(str(settings.html_model_path))),
        "settings_sha256": digest_json(
            {
                "url_confident_malicious": settings.ml_confident_malicious_threshold,
                "url_confident_clean": settings.ml_confident_clean_threshold,
                "html_skip": settings.html_skip_on_confident_clean,
                "html_skip_max_prior_risk": settings.html_skip_max_prior_risk,
            }
        ),
    }
    if settings.ml_scaler_path:
        result["url_scaler_sha256"] = digest_file(Path(settings.ml_scaler_path))
    for package in ("scikit-learn", "numpy", "pandas", "beautifulsoup4", "lxml"):
        result[package] = version(package)
    return result
