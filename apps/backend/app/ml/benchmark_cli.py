"""Özel arşivden ağ erişimi olmadan tüketici kararlarını değerlendirin.

Ham HTML, URL manifestleri, modeller ve raporlar Git dışında tutulmalıdır.
Bu araç sayfa indirmez, etiket oluşturmaz veya model yayımlamaz.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from app.core.config import Settings
from app.ml.benchmark import (
    BenchmarkManifest,
    build_replay_pipeline,
    compare_reports,
    evaluate_replay,
    load_manifest,
    load_page,
    network_denied,
    runtime_fingerprints,
)


def _write(path: Path, value: object) -> None:
    if path.exists():
        raise ValueError("Output already exists; preserve frozen manifests and reports")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Set POSIX confidentiality in the creation syscall, before any bytes exist.
    # Windows uses the private workspace ACL; chmod is not an ACL replacement.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate consumer decisions using private reviewed snapshots; no live network requests, training or model promotion."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    schema = commands.add_parser(
        "schema", help="Export the strict private manifest JSON schema"
    )
    schema.add_argument("--output", type=Path, required=True)
    freeze = commands.add_parser(
        "freeze", help="Validate and hash a reviewed private manifest"
    )
    freeze.add_argument("manifest", type=Path)
    freeze.add_argument("--output", type=Path, required=True)
    run = commands.add_parser(
        "run", help="Replay archived snapshots; no live network requests"
    )
    run.add_argument("manifest", type=Path)
    run.add_argument("--url-model", type=Path, required=True)
    run.add_argument("--html-model", type=Path, required=True)
    run.add_argument("--url-scaler", type=Path)
    run.add_argument(
        "--trust-local-models",
        action="store_true",
        help="Acknowledge that pickle/joblib artifacts must be trusted",
    )
    run.add_argument("--split", choices=["tuning", "evaluation"], default="evaluation")
    run.add_argument(
        "--external-reputation",
        action="store_true",
        help="Replay captured external API/domain-security DNS stages as well as the local feed; never submit URLs to a scanner",
    )
    run.add_argument("--name", required=True)
    run.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser(
        "compare", help="Compare two reports from the same frozen cohort"
    )
    compare.add_argument("active", type=Path)
    compare.add_argument("candidate", type=Path)
    compare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "schema":
            _write(args.output, BenchmarkManifest.model_json_schema())
        elif args.command == "freeze":
            manifest = load_manifest(args.manifest)
            if manifest.frozen_sha256 is not None:
                raise ValueError("Manifest is already frozen")
            if args.output.parent.resolve() != args.manifest.parent.resolve():
                raise ValueError("Keep the frozen manifest beside its snapshots")
            for sample in manifest.samples:
                if sample.fetch_error is None:
                    load_page(sample, args.manifest.parent)
            frozen = manifest.model_dump(mode="json")
            frozen["frozen_sha256"] = manifest.content_digest()
            checked = BenchmarkManifest.model_validate(frozen)
            _write(args.output, checked.model_dump(mode="json"))
            print(f"Frozen manifest SHA-256: {checked.frozen_sha256}")
        elif args.command == "run":
            if not args.trust_local_models:
                raise ValueError(
                    "Only load trusted local artifacts; --trust-local-models is required"
                )
            manifest = load_manifest(args.manifest)
            settings = Settings(
                ml_model_path=str(args.url_model.resolve(strict=True)),
                ml_scaler_path=str(args.url_scaler.resolve(strict=True))
                if args.url_scaler
                else None,
                html_model_path=str(args.html_model.resolve(strict=True)),
                # Match the declared complete static production profile.
                html_skip_on_confident_clean=False,
                html_browser_render_enabled=False,
                scanner_cache_enabled=False,
                # CLI defaults to an explicit local-only replay, independent of env.
                cloudflare_dns_security_enabled=False,
                google_safe_browsing_api_key=None,
                google_web_risk_api_key=None,
                urlhaus_auth_key=None,
                virustotal_api_key=None,
                virustotal_api_keys=[],
            )
            captured_providers = {
                capture.stage.scanner
                for sample in manifest.samples
                if sample.split == args.split
                for capture in sample.context
                if capture.stage.scanner != "RdapScanner"
            }
            providers = [
                name
                for name in captured_providers
                if name == "LocalPhishingFeed" or args.external_reputation
            ]
            with network_denied():
                pipeline = build_replay_pipeline(settings, providers)
                lexical, html = pipeline.scanners[1:]
                if (
                    getattr(lexical, "model", None) is None
                    or getattr(html, "model", None) is None
                ):
                    raise ValueError(
                        "Both model artifacts must load successfully; no fallback accuracy evaluation"
                    )
                report = evaluate_replay(
                    manifest,
                    args.manifest.parent,
                    pipeline,
                    run_name=args.name,
                    fingerprints=runtime_fingerprints(settings),
                    split=args.split,
                    external_reputation=args.external_reputation,
                )
            _write(args.output, report)
            print(
                json.dumps(
                    {
                        "count": report["metrics"]["count"],
                        "quality_claim_eligible": report["validity"][
                            "quality_claim_eligible"
                        ],
                        "limitations": report["validity"]["limitations"],
                    },
                    ensure_ascii=False,
                )
            )
        else:
            reports = []
            for path in (args.active, args.candidate):
                if path.stat().st_size > 64 * 1024 * 1024:
                    raise ValueError("Comparison report exceeds the size limit")
                reports.append(json.loads(path.read_text(encoding="utf-8")))
            comparison = compare_reports(*reports)
            _write(args.output, comparison)
            print(
                json.dumps(
                    {
                        "no_count_regression_on_this_cohort": comparison[
                            "no_count_regression_on_this_cohort"
                        ],
                        "promotion_authorized": False,
                    }
                )
            )
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Do not print URLs, model-loading errors, or raw label evidence to logs.
        print(
            f"Benchmark failed ({type(exc).__name__}); validate the private manifest, snapshots and options.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
