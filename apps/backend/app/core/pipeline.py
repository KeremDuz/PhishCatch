from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import shutil

from app.core.risk_aggregator import RiskAggregator
from app.core.scan_cache import ScannerResultCache
from app.models.schemas import AnalyzeUrlResponse, StageResult
from app.services.base_scanner import BaseScanner


EXTERNAL_REPUTATION_SCANNERS = {
    "URLhausScanner",
    "GoogleSafeBrowsing",
    "GoogleWebRisk",
    "VirusTotalScanner",
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

    def run(self, url: str, original_input: str | None = None) -> AnalyzeUrlResponse:
        stages: list[StageResult] = []
        current_url = url
        fetch_safety_blocked = False
        external_reputation_blocked = False
        preprocessing_details: dict[str, object] = {}

        if self.redirect_resolver is not None:
            resolver_result = self._scan_with_cache(self.redirect_resolver, current_url)
            preprocessing_details = {
                "redirect_resolver": {
                    "scanner": resolver_result.scanner,
                    "verdict": resolver_result.verdict,
                    "reason": resolver_result.reason,
                    "details": resolver_result.details,
                }
            }

            if resolver_result.details.get("safety"):
                fetch_safety_blocked = True
                external_reputation_blocked = self._should_skip_external_reputation(resolver_result)

            resolved_url = resolver_result.details.get("resolved_url")
            if resolved_url and resolved_url != current_url:
                current_url = resolved_url

        threat_intel_stages = self._scan_threat_intelligence(current_url, external_reputation_blocked)
        stages.extend(threat_intel_stages)
        if any(stage.verdict == "malicious" for stage in threat_intel_stages):
            return self._build_response(current_url, original_input, stages, preprocessing_details)

        for scanner in self.scanners:
            if external_reputation_blocked and scanner.name in EXTERNAL_REPUTATION_SCANNERS:
                stages.append(
                    StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
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
                        risk_score=0.0,
                        reason="Skipped HTML scan because earlier signals were confidently clean",
                        details={
                            "skipped": True,
                            "skip_reason": "confident_clean_prior_signals",
                            "prior_risk_score": self.risk_aggregator.aggregate(stages).risk_score,
                        },
                    )
                )
                continue

            stage_result = self._scan_with_cache(scanner, current_url)
            stages.append(stage_result)

            if stage_result.details.get("safety"):
                fetch_safety_blocked = True

            # Compatibility for custom pipelines that still include a resolver as a scanner.
            resolved_url = stage_result.details.get("resolved_url")
            if resolved_url and resolved_url != current_url:
                current_url = resolved_url

        return self._build_response(current_url, original_input, stages, preprocessing_details)

    @staticmethod
    def _should_skip_external_reputation(resolver_result: StageResult) -> bool:
        safety = resolver_result.details.get("safety") or {}
        reason = f"{resolver_result.reason or ''} {safety.get('reason') or ''}".lower()
        hostname = str(safety.get("hostname") or "").lower().strip(".")

        if safety.get("blocked_ips"):
            return True
        if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
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
    ) -> AnalyzeUrlResponse:
        decision = self.risk_aggregator.aggregate(stages)
        signals = dict(decision.signals)
        if preprocessing_details:
            signals["preprocessing"] = preprocessing_details

        return AnalyzeUrlResponse(
            url=current_url,
            original_input=original_input,
            normalized_url=current_url,
            final_verdict=decision.final_verdict,
            confidence=decision.confidence,
            risk_score=decision.risk_score,
            malicious_probability=decision.malicious_probability,
            clean_probability=decision.clean_probability,
            decided_by="RiskAggregator",
            summary=decision.summary,
            signals=signals,
            stages=stages,
        )

    def _scan_threat_intelligence(self, url: str, skip_due_to_safety: bool) -> list[StageResult]:
        if not self.threat_intel_scanners:
            return []

        if skip_due_to_safety:
            return [
                StageResult(
                    scanner=scanner.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="Skipped external reputation lookup because URL is not public-fetch safe",
                    details={"skipped": True, "skip_reason": "unsafe_url"},
                )
                for scanner in self.threat_intel_scanners
            ]

        if len(self.threat_intel_scanners) == 1:
            return [self._scan_with_cache(self.threat_intel_scanners[0], url)]

        results_by_index: dict[int, StageResult] = {}
        with ThreadPoolExecutor(max_workers=len(self.threat_intel_scanners)) as executor:
            future_to_scanner = {
                executor.submit(self._scan_with_cache, scanner, url): (index, scanner)
                for index, scanner in enumerate(self.threat_intel_scanners)
            }
            for future in as_completed(future_to_scanner):
                index, scanner = future_to_scanner[future]
                try:
                    results_by_index[index] = future.result()
                except Exception as exc:
                    results_by_index[index] = StageResult(
                        scanner=scanner.name,
                        verdict="unknown",
                        risk_score=0.0,
                        reason="Threat intelligence scan failed",
                        details={"error": str(exc)},
                    )

        return [
            results_by_index[index]
            for index in range(len(self.threat_intel_scanners))
        ]

    def _scan_with_cache(self, scanner: BaseScanner, url: str) -> StageResult:
        if self.scan_cache is not None:
            cached = self.scan_cache.get(scanner.name, url)
            if cached is not None:
                return cached

        result = scanner.scan(url)
        if self.scan_cache is not None:
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
            or (stage.risk_score is not None and stage.risk_score > self.html_skip_max_prior_risk)
            or bool(stage.details.get("safety"))
            for stage in stages
        )

        return has_clean_url_heuristic and has_confident_clean_ml and not has_blocking_or_suspicious_signal

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
            self._scanner_health(scanner)
            for scanner in self.threat_intel_scanners
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

        runtime_scanners = [
            self._scanner_health(scanner)
            for scanner in self.scanners
        ]
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
                "ttl_seconds": self.scan_cache.ttl_seconds if self.scan_cache is not None else 0,
                "max_entries": self.scan_cache.max_entries if self.scan_cache is not None else 0,
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

        if scanner.name == "WhoisScanner":
            whois_available = shutil.which("whois") is not None
            details["whois_command_available"] = whois_available
            status = "ok" if whois_available else "degraded"

        elif scanner.name == "URLhausScanner":
            details["auth_key_required"] = False
            details["auth_key_configured"] = bool(getattr(scanner, "auth_key", None))

        elif scanner.name == "GoogleSafeBrowsing":
            api_key_configured = bool(getattr(scanner, "api_key", None))
            details["api_key_configured"] = api_key_configured
            status = "ok" if api_key_configured else "degraded"

        elif scanner.name == "GoogleWebRisk":
            api_key_configured = bool(getattr(scanner, "api_key", None))
            details["api_key_configured"] = api_key_configured
            details["threat_types"] = list(getattr(scanner, "THREAT_TYPES", ()))
            status = "ok" if api_key_configured else "degraded"

        elif scanner.name == "VirusTotalScanner":
            settings = getattr(scanner, "settings", None)
            api_key_configured = bool(getattr(settings, "virustotal_api_key", None))
            details["api_key_configured"] = api_key_configured
            details["timeout_seconds"] = getattr(settings, "virustotal_timeout_seconds", None)
            status = "ok" if api_key_configured else "degraded"

        elif scanner.name == "MLModelScanner":
            settings = getattr(scanner, "settings", None)
            model_loaded = getattr(scanner, "model", None) is not None
            details["model_loaded"] = model_loaded
            details["model_path"] = getattr(settings, "ml_model_path", None)
            details["scaler_loaded"] = getattr(scanner, "scaler", None) is not None
            details["malicious_threshold"] = getattr(settings, "ml_malicious_threshold", None)
            status = "ok" if model_loaded else "degraded"

        elif scanner.name == "HtmlScraper":
            model_path = getattr(scanner, "model_path", None)
            model_loaded = getattr(scanner, "model", None) is not None
            browser_render_enabled = bool(getattr(scanner, "browser_render_enabled", False))
            details["model_path"] = model_path
            details["model_loaded"] = model_loaded
            details["browser_render_enabled"] = browser_render_enabled
            details["browser_timeout_ms"] = getattr(scanner, "browser_timeout_ms", None)
            if browser_render_enabled:
                playwright_available = importlib.util.find_spec("playwright") is not None
                details["playwright_available"] = playwright_available
                if not playwright_available:
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
