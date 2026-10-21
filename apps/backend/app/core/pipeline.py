import importlib.util
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import copy_context

from app.core.risk_aggregator import RiskAggregator
from app.core.scan_cache import ScannerResultCache
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.services.base_scanner import BaseScanner
from app.services.page_fetch import page_fetch_session
from app.services.reputation_budget import lookup_session

EXTERNAL_REPUTATION_SCANNERS = {
    "URLhausScanner",
    "GoogleSafeBrowsing",
    "GoogleWebRisk",
    "VirusTotalScanner",
    "CloudflareDnsSecurity",
}


class ScanningPipeline:
    def __init__(
        self,
        scanners: list[BaseScanner],
        redirect_resolver: BaseScanner | None = None,
        threat_intel_scanners: list[BaseScanner] | None = None,
        risk_aggregator: RiskAggregator | None = None,
        scan_cache: ScannerResultCache | None = None,
        skip_html_on_confident_clean: bool = False,
        html_skip_max_prior_risk: float = 0.08,
        fetch_worker: bool = False,
    ) -> None:
        if not scanners:
            raise ValueError("ScanningPipeline requires at least one scanner")
        self.scanners = scanners
        self.redirect_resolver = redirect_resolver
        self.threat_intel_scanners = threat_intel_scanners or []
        self.risk_aggregator = risk_aggregator or RiskAggregator()
        self.scan_cache = scan_cache
        self.skip_html_on_confident_clean = skip_html_on_confident_clean
        self.html_skip_max_prior_risk = html_skip_max_prior_risk
        self.fetch_worker = fetch_worker

    def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
        with page_fetch_session(use_worker=self.fetch_worker), lookup_session():
            return self._run(url, original_input)

    def _run(self, url: str, original_input: str | None) -> AnalyzeUrlResponse:
        stages: list[StageResult] = []
        current_url = url
        external_reputation_blocked = False
        preprocessing_details: dict[str, object] = {}
        targets = [url]

        # A verified local match needs no request to the potentially hostile site.
        for scanner in self.threat_intel_scanners:
            if scanner.name == "LocalPhishingFeed":
                local = self._scan_with_cache(scanner, url)
                if local.status == "completed" and local.verdict == "malicious":
                    return self._build_response(
                        url,
                        original_input,
                        [local],
                        {},
                        decided_by="ThreatIntelShortCircuit",
                    )

        # DNS filtering is domain context, not proof of phishing. A filtered
        # target remains unknown, and no hostile content is fetched for it.
        for scanner in self.threat_intel_scanners:
            if scanner.name == "CloudflareDnsSecurity":
                dns = self._scan_with_cache(scanner, url)
                if dns.status == "completed" and dns.details.get("requires_review") is True:
                    return self._build_response(
                        url, original_input,
                        [dns, StageResult(scanner="TargetContentCoverage", verdict="unknown",
                                          status="skipped", reason="Content was not fetched after a security DNS filter warning")],
                        {}, decided_by="DnsSecurityReview",
                    )

        if self.redirect_resolver is not None:
            resolver_result = self._scan_with_cache(self.redirect_resolver, current_url)
            stages.append(resolver_result)
            preprocessing_details = {
                "redirect_resolver": {
                    "scanner": resolver_result.scanner,
                    "verdict": resolver_result.verdict,
                    "reason": resolver_result.reason,
                    "details": resolver_result.details,
                }
            }

            if resolver_result.details.get("safety"):
                external_reputation_blocked = self._should_skip_external_reputation(
                    resolver_result
                )

            resolved_url = resolver_result.details.get("resolved_url")
            if resolved_url and resolved_url != current_url:
                current_url = resolved_url
            for hop in resolver_result.details.get("redirect_chain", []):
                for key in ("from", "to"):
                    candidate = hop.get(key)
                    if (
                        isinstance(candidate, str)
                        and candidate not in targets
                        and len(targets) < 8
                    ):
                        targets.append(candidate)
            if current_url not in targets:
                targets.append(current_url)

        threat_intel_stages = self._scan_threat_intelligence_targets(
            targets, external_reputation_blocked
        )
        stages.extend(threat_intel_stages)
        malicious_reputation_stages = [
            stage for stage in threat_intel_stages if stage.verdict == "malicious"
        ]
        if malicious_reputation_stages:
            return self._build_response(
                current_url,
                original_input,
                stages,
                preprocessing_details,
                decided_by="ThreatIntelShortCircuit",
                extra_signals={
                    "short_circuit": {
                        "layer": "threat_intelligence",
                        "reason": "At least one trusted reputation API returned malicious.",
                        "matched_scanners": [
                            stage.scanner for stage in malicious_reputation_stages
                        ],
                    }
                },
            )

        for scanner in self.scanners:
            if (
                external_reputation_blocked
                and scanner.name in EXTERNAL_REPUTATION_SCANNERS
            ):
                stages.append(
                    StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
                        status="skipped",
                        risk_score=0.0,
                        reason="Skipped external reputation lookup because URL is not public-fetch safe",
                        details={"skipped": True, "skip_reason": "unsafe_url"},
                    )
                )
                continue

            if scanner.name == "HtmlScraper" and self._should_skip_html_scan(stages):
                stages.append(
                    StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
                        status="skipped",
                        risk_score=0.0,
                        reason="Skipped HTML scan because earlier signals were confidently clean",
                        details={
                            "skipped": True,
                            "skip_reason": "confident_clean_prior_signals",
                            "prior_risk_score": self.risk_aggregator.aggregate(
                                stages
                            ).risk_score,
                        },
                    )
                )
                continue

            stage_result = self._scan_with_cache(scanner, current_url)
            stages.append(stage_result)
            if scanner.name == "MLModelScanner" and len(targets) > 1:
                redirect_results = [
                    self._scan_with_cache(scanner, target)
                    for target in targets
                    if target != current_url
                ]
                selected = max(
                    redirect_results, key=lambda item: item.malicious_probability or 0
                )
                stages.append(
                    selected.model_copy(
                        deep=True,
                        update={
                            "scanner": "RedirectUrlModel",
                            "training_features": {},
                            "details": {
                                "checked_targets": [
                                    target
                                    for target in targets
                                    if target != current_url
                                ],
                                "component_of": "redirect_chain",
                            },
                        },
                    )
                )
                if (
                    any(item.status != "completed" for item in redirect_results)
                    and selected.status == "completed"
                ):
                    stages.append(
                        StageResult(
                            scanner="RedirectModelCoverage",
                            verdict="unknown",
                            status="unavailable",
                            reason="Some redirect URL features could not be assessed",
                        )
                    )
            if (
                scanner.name == "HtmlScraper"
                and stage_result.details.get("final_url", current_url) != current_url
            ):
                stages.append(
                    StageResult(
                        scanner="TargetConsistency",
                        verdict="unknown",
                        status="failed",
                        reason="Content and URL evidence refer to different destinations",
                    )
                )
            dynamic = stage_result.details.get("dynamic_analysis")
            if (
                stage_result.scanner == "HtmlScraper"
                and isinstance(dynamic, dict)
                and dynamic.get("required") is True
                and dynamic.get("available") is not True
            ):
                stages.append(
                    StageResult(
                        scanner="BrowserRenderer",
                        verdict="unknown",
                        status="unavailable",
                        reason="Dynamic content requires an isolated browser worker",
                        details={"component_of": "HtmlScraper"},
                    )
                )
            html_model = stage_result.details.get("html_model")
            if (
                stage_result.scanner == "HtmlScraper"
                and isinstance(html_model, dict)
                and html_model.get("available") is False
            ):
                # Keep completed DOM rule evidence, while exposing the missing
                # model component without duplicating its score or probabilities.
                failed = bool(html_model.get("error"))
                stages.append(
                    StageResult(
                        scanner="HtmlModelScanner",
                        verdict="unknown",
                        status="failed" if failed else "unavailable",
                        reason="HTML model analysis failed"
                        if failed
                        else "HTML model unavailable",
                        details={"component_of": "HtmlScraper"},
                    )
                )

            # Compatibility for custom pipelines that still include a resolver as a scanner.
            resolved_url = stage_result.details.get("resolved_url")
            if resolved_url and resolved_url != current_url:
                current_url = resolved_url

        return self._build_response(
            current_url, original_input, stages, preprocessing_details
        )

    def _scan_threat_intelligence_targets(
        self, targets: list[str], blocked: bool
    ) -> list[StageResult]:
        if len(targets) == 1 or blocked:
            return self._scan_threat_intelligence(targets[-1], blocked)
        by_provider: dict[str, list[StageResult]] = {}
        for target in targets:
            for stage in self._scan_threat_intelligence(target, False):
                by_provider.setdefault(stage.scanner, []).append(stage)
        combined: list[StageResult] = []
        for name, results in by_provider.items():
            hits = [
                stage
                for stage in results
                if stage.status == "completed" and stage.verdict == "malicious"
            ]
            missing = [stage for stage in results if stage.status != "completed"]
            reviews = [stage for stage in results if stage.status == "completed" and stage.details.get("requires_review") is True]
            selected = (hits or reviews or missing or results)[0].model_copy(deep=True)
            selected.details["checked_targets"] = list(targets)
            combined.append(selected)
            if (hits or reviews) and missing:
                combined.append(
                    StageResult(
                        scanner=f"{name}Coverage",
                        verdict="unknown",
                        status="unavailable",
                        reason="Some redirect reputation checks were incomplete",
                    )
                )
        return combined

    @staticmethod
    def _should_skip_external_reputation(resolver_result: StageResult) -> bool:
        safety = resolver_result.details.get("safety") or {}
        reason = f"{resolver_result.reason or ''} {safety.get('reason') or ''}".lower()
        hostname = str(safety.get("hostname") or "").lower().strip(".")

        if safety.get("blocked_ips"):
            return True
        if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(
            ".localhost"
        ):
            return True
        if "embedded credentials" in reason:
            return True
        if "only http and https" in reason:
            return True
        if "does not include a hostname" in reason:
            return True
        return False

    def _build_response(
        self,
        current_url: str,
        original_input: str | None,
        stages: list[StageResult],
        preprocessing_details: dict[str, object],
        decided_by: str = "RiskAggregator",
        extra_signals: dict[str, object] | None = None,
    ) -> AnalyzeUrlResponse:
        decision = self.risk_aggregator.aggregate(stages)
        completed = [
            stage
            for stage in stages
            if stage.status == "completed" and stage.scanner != "UrlResolver"
        ]
        scan_status = (
            "complete"
            if stages and all(stage.status == "completed" for stage in stages)
            else ("partial" if completed else "failed")
        )
        signals = dict(decision.signals)
        if preprocessing_details:
            signals["preprocessing"] = preprocessing_details
        if extra_signals:
            signals.update(extra_signals)

        return AnalyzeUrlResponse(
            scan_status=scan_status,
            url=current_url,
            original_input=original_input,
            normalized_url=current_url,
            final_verdict=decision.final_verdict,
            confidence=decision.confidence,
            risk_score=decision.risk_score,
            malicious_probability=decision.malicious_probability,
            clean_probability=decision.clean_probability,
            decided_by=decided_by,
            summary=decision.summary,
            signals=signals,
            stages=stages,
        )

    def _scan_threat_intelligence(
        self, url: str, skip_due_to_safety: bool
    ) -> list[StageResult]:
        if not self.threat_intel_scanners:
            return []

        if skip_due_to_safety:
            return [
                StageResult(
                    scanner=scanner.name,
                    verdict="unknown",
                    status="skipped",
                    risk_score=0.0,
                    reason="Skipped external reputation lookup because URL is not public-fetch safe",
                    details={"skipped": True, "skip_reason": "unsafe_url"},
                )
                for scanner in self.threat_intel_scanners
            ]

        if len(self.threat_intel_scanners) == 1:
            return [self._scan_with_cache(self.threat_intel_scanners[0], url)]

        results_by_index: dict[int, StageResult] = {}
        with ThreadPoolExecutor(
            max_workers=len(self.threat_intel_scanners)
        ) as executor:
            future_to_scanner = {
                executor.submit(copy_context().run, self._scan_with_cache, scanner, url): (index, scanner)
                for index, scanner in enumerate(self.threat_intel_scanners)
            }
            for future in as_completed(future_to_scanner):
                index, scanner = future_to_scanner[future]
                try:
                    results_by_index[index] = future.result()
                except Exception:
                    results_by_index[index] = StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
                        status="failed",
                        risk_score=0.0,
                        reason="Threat intelligence scan failed",
                        details={"error": "scanner_failed"},
                    )

        return [
            results_by_index[index] for index in range(len(self.threat_intel_scanners))
        ]

    def _scan_with_cache(self, scanner: BaseScanner, url: str) -> StageResult:
        cacheable = scanner.name not in {
            "UrlResolver",
            "HtmlScraper",
            "LocalPhishingFeed",
        }
        if self.scan_cache is not None and cacheable:
            cached = self.scan_cache.get(scanner.name, url)
            if cached is not None:
                return cached

        try:
            result = scanner.scan(url)
        except Exception:
            result = StageResult(
                scanner=scanner.name,
                verdict="unknown",
                status="failed",
                reason="Scanner failed",
                details={"error": "scanner_failed"},
            )
        if result.status == "completed" and result.verdict == "unknown":
            reason = (result.reason or "").lower()
            if result.details.get("skipped"):
                result.status = "skipped"
            elif result.details.get("error") or result.details.get("safety"):
                result.status = "failed"
                if result.details.get("error"):
                    result.details["error"] = "scanner_failed"
            elif (
                isinstance(result.details.get("status_code"), int)
                and result.details["status_code"] >= 400
                and not (
                    result.scanner == "VirusTotalScanner"
                    and result.details["status_code"] == 404
                )
            ):
                result.status = "failed"
            elif any(
                word in reason
                for word in (
                    "unavailable",
                    "not configured",
                    "not available",
                    "missing",
                    "disabled",
                )
            ):
                result.status = "unavailable"
            elif "timed out" in reason or "unexpected response" in reason:
                result.status = "failed"
        if self.scan_cache is not None and cacheable:
            self.scan_cache.set(scanner.name, url, result)
        return result

    def _should_skip_html_scan(self, stages: list[StageResult]) -> bool:
        if not self.skip_html_on_confident_clean:
            return False

        if not stages:
            return False

        prior_decision = self.risk_aggregator.aggregate(stages)
        if (prior_decision.risk_score or 0.0) > self.html_skip_max_prior_risk:
            return False

        has_clean_url_heuristic = any(
            stage.scanner == "URLHeuristicScanner" and stage.verdict == "clean"
            for stage in stages
        )
        has_confident_clean_ml = any(
            stage.scanner == "MLModelScanner"
            and stage.verdict == "clean"
            and stage.details.get("decision") == "confident_clean"
            for stage in stages
        )
        has_blocking_or_suspicious_signal = any(
            stage.verdict == "malicious"
            or (
                stage.risk_score is not None
                and stage.risk_score > self.html_skip_max_prior_risk
            )
            or bool(stage.details.get("safety"))
            for stage in stages
        )

        return (
            has_clean_url_heuristic
            and has_confident_clean_ml
            and not has_blocking_or_suspicious_signal
        )

    def health_report(self) -> dict[str, object]:
        layers: list[dict[str, object]] = []

        if self.redirect_resolver is not None:
            layers.append(
                {
                    "layer": "redirect_resolver",
                    "status": "ok",
                    "scanner": self._scanner_health(self.redirect_resolver),
                    "purpose": "Resolve redirects before scoring; does not add phishing risk by itself.",
                }
            )

        threat_intel_scanners = [
            self._scanner_health(scanner) for scanner in self.threat_intel_scanners
        ]
        layers.append(
            {
                "layer": "threat_intelligence",
                "status": self._combine_health_status(threat_intel_scanners),
                "parallel": True,
                "short_circuit_on_malicious": True,
                "scanners": threat_intel_scanners,
            }
        )

        runtime_scanners = [self._scanner_health(scanner) for scanner in self.scanners]
        layers.append(
            {
                "layer": "local_analysis",
                "status": self._combine_health_status(runtime_scanners),
                "scanners": runtime_scanners,
            }
        )

        layers.append(
            {
                "layer": "risk_aggregator",
                "status": "ok",
                "malicious_threshold": self.risk_aggregator.MALICIOUS_THRESHOLD,
                "unknown_threshold": self.risk_aggregator.UNKNOWN_THRESHOLD,
            }
        )
        layers.append(
            {
                "layer": "scanner_cache",
                "status": "ok" if self.scan_cache is not None else "disabled",
                "enabled": self.scan_cache is not None,
                "ttl_seconds": self.scan_cache.ttl_seconds
                if self.scan_cache is not None
                else 0,
                "max_entries": self.scan_cache.max_entries
                if self.scan_cache is not None
                else 0,
            }
        )

        return {
            "status": self._combine_health_status(layers),
            "layers": layers,
        }

    @classmethod
    def _scanner_health(cls, scanner: BaseScanner) -> dict[str, object]:
        status = "ok"
        details: dict[str, object] = {
            "name": scanner.name,
            "implementation": type(scanner).__name__,
        }

        if scanner.name == "LocalPhishingFeed":
            details.update(scanner.health())
            status = "ok" if details.get("available") else "degraded"

        elif scanner.name == "WhoisScanner":
            whois_available = shutil.which("whois") is not None
            details["whois_command_available"] = whois_available
            status = "ok" if whois_available else "degraded"

        elif scanner.name == "URLhausScanner":
            details["auth_key_required"] = True
            details["auth_key_configured"] = bool(getattr(scanner, "auth_key", None))
            status = "ok" if details["auth_key_configured"] else "degraded"

        elif scanner.name == "GoogleSafeBrowsing":
            api_key_configured = bool(getattr(scanner, "api_key", None))
            details["api_key_configured"] = api_key_configured
            status = "ok" if api_key_configured else "degraded"

        elif scanner.name == "GoogleWebRisk":
            api_key_configured = bool(getattr(scanner, "api_key", None))
            details["api_key_configured"] = api_key_configured
            details["threat_types"] = list(getattr(scanner, "THREAT_TYPES", ()))
            details["url_sharing_enabled"] = bool(getattr(scanner, "allow_url_sharing", False))
            details["query_url_sharing_enabled"] = bool(getattr(scanner, "allow_query_urls", False))
            status = "ok" if api_key_configured and details["url_sharing_enabled"] else "degraded"

        elif scanner.name == "CloudflareDnsSecurity":
            details["scope"] = "hostname_only"
            details["account_required"] = False
            details["publishes_url_scans"] = False
            status = "ok"

        elif scanner.name == "VirusTotalScanner":
            settings = getattr(scanner, "settings", None)
            api_key_count = len(getattr(settings, "virustotal_api_keys", []) or [])
            api_key_configured = api_key_count > 0
            details["api_key_configured"] = api_key_configured
            details["api_key_count"] = api_key_count
            details["timeout_seconds"] = getattr(
                settings, "virustotal_timeout_seconds", None
            )
            status = "ok" if api_key_configured else "degraded"

        elif scanner.name == "MLModelScanner":
            settings = getattr(scanner, "settings", None)
            model_loaded = getattr(scanner, "model", None) is not None
            details["model_loaded"] = model_loaded
            details["probabilities_available"] = hasattr(
                getattr(scanner, "model", None), "predict_proba"
            )
            details["model_path"] = getattr(settings, "ml_model_path", None)
            details["scaler_loaded"] = getattr(scanner, "scaler", None) is not None
            details["malicious_threshold"] = getattr(
                settings, "ml_malicious_threshold", None
            )
            status = (
                "ok"
                if model_loaded and details["probabilities_available"]
                else "degraded"
            )

        elif scanner.name == "HtmlScraper":
            model_path = getattr(scanner, "model_path", None)
            model_loaded = getattr(scanner, "model", None) is not None
            browser_render_enabled = bool(
                getattr(scanner, "browser_render_enabled", False)
            )
            details["model_path"] = model_path
            details["model_loaded"] = model_loaded
            details["browser_render_enabled"] = browser_render_enabled
            details["browser_render_available"] = False
            details["browser_timeout_ms"] = getattr(scanner, "browser_timeout_ms", None)
            if browser_render_enabled:
                playwright_available = (
                    importlib.util.find_spec("playwright") is not None
                )
                details["playwright_available"] = playwright_available
                details["browser_isolation_required"] = True
                status = "degraded"
            if model_path and not model_loaded:
                status = "degraded"

        details["status"] = status
        return details

    @staticmethod
    def _combine_health_status(items: list[dict[str, object]]) -> str:
        if not items:
            return "disabled"
        statuses = {str(item.get("status", "ok")) for item in items}
        if "down" in statuses:
            return "down"
        if "degraded" in statuses:
            return "degraded"
        if statuses == {"disabled"}:
            return "disabled"
        return "ok"
