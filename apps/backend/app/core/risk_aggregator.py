from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from app.models.schemas import StageResult


FinalVerdict = Literal["malicious", "clean", "unknown"]


@dataclass(frozen=True)
class RiskEvidence:
    scanner: str
    score: float
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "score": round(self.score, 4),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RiskDecision:
    final_verdict: FinalVerdict
    risk_score: float
    confidence: float
    malicious_probability: float
    clean_probability: float
    summary: str
    signals: dict[str, object] = field(default_factory=dict)


class RiskAggregator:
    """Combines scanner evidence into the public phishing/clean/unknown verdict."""

    MALICIOUS_THRESHOLD = 0.6
    UNKNOWN_THRESHOLD = 0.35
    THREAT_INTEL_SCANNERS = {
        "URLhausScanner",
        "GoogleSafeBrowsing",
        "VirusTotalScanner",
    }

    def aggregate(self, stages: list[StageResult]) -> RiskDecision:
        positive: list[RiskEvidence] = []
        negative: list[RiskEvidence] = []

        for stage in stages:
            stage_positive, stage_negative = self._score_stage(stage)
            if stage_positive:
                positive.append(stage_positive)
            if stage_negative:
                negative.append(stage_negative)

        positive_risk = self._noisy_or(evidence.score for evidence in positive)
        negative_offset = self._negative_offset(positive, negative)
        risk_score = self._clamp(positive_risk - negative_offset)

        if risk_score >= self.MALICIOUS_THRESHOLD:
            final_verdict: FinalVerdict = "malicious"
        elif positive and risk_score >= self.UNKNOWN_THRESHOLD:
            final_verdict = "unknown"
        else:
            final_verdict = "clean"
        confidence = self._confidence(final_verdict, risk_score)

        strongest_positive = max(positive, key=lambda item: item.score, default=None)
        strongest_negative = max(negative, key=lambda item: item.score, default=None)
        summary = self._summary(final_verdict, risk_score, strongest_positive, strongest_negative)

        return RiskDecision(
            final_verdict=final_verdict,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            malicious_probability=round(risk_score, 4),
            clean_probability=round(1 - risk_score, 4),
            summary=summary,
            signals={
                "malicious_threshold": self.MALICIOUS_THRESHOLD,
                "unknown_threshold": self.UNKNOWN_THRESHOLD,
                "positive": [evidence.as_dict() for evidence in sorted(positive, key=lambda item: item.score, reverse=True)],
                "negative": [evidence.as_dict() for evidence in sorted(negative, key=lambda item: item.score, reverse=True)],
            },
        )

    def _score_stage(self, stage: StageResult) -> tuple[RiskEvidence | None, RiskEvidence | None]:
        reason = stage.reason or f"{stage.scanner} returned {stage.verdict}"

        if stage.scanner in self.THREAT_INTEL_SCANNERS and stage.verdict == "malicious":
            score = self._clamp(stage.risk_score or stage.confidence or 0.95, minimum=0.75)
            return RiskEvidence(stage.scanner, score, reason), None

        if stage.scanner == "UrlResolver":
            return self._score_url_resolver(stage, reason)

        if stage.scanner == "WhoisScanner":
            return self._score_whois(stage, reason)

        if stage.scanner == "MLModelScanner":
            return self._score_ml(stage, reason)

        if stage.scanner == "HtmlScraper":
            return self._score_html(stage, reason)

        if stage.verdict == "malicious":
            score = stage.risk_score or stage.confidence or 0.7
            return RiskEvidence(stage.scanner, self._clamp(score, minimum=0.6), reason), None

        if stage.risk_score is not None and stage.risk_score > 0:
            return RiskEvidence(stage.scanner, self._clamp(stage.risk_score), reason), None

        if stage.verdict == "clean":
            return None, RiskEvidence(stage.scanner, 0.03, reason)

        return None, None

    def _score_url_resolver(self, stage: StageResult, reason: str) -> tuple[RiskEvidence | None, RiskEvidence | None]:
        safety = stage.details.get("safety") or {}
        if safety:
            hostname = safety.get("hostname", "")
            blocked_ips = safety.get("blocked_ips", [])
            if blocked_ips or hostname in {"localhost", "localhost.localdomain"}:
                return RiskEvidence(stage.scanner, 0.9, reason), None
            return RiskEvidence(stage.scanner, 0.35, reason), None

        redirect_chain = stage.details.get("redirect_chain") or []
        if len(redirect_chain) >= 4:
            return RiskEvidence(stage.scanner, 0.2, "Long redirect chain"), None

        if stage.risk_score is not None and stage.risk_score > 0:
            return RiskEvidence(stage.scanner, self._clamp(stage.risk_score), reason), None

        return None, RiskEvidence(stage.scanner, 0.03, reason)

    def _score_whois(self, stage: StageResult, reason: str) -> tuple[RiskEvidence | None, RiskEvidence | None]:
        signal = stage.details.get("signal")
        if signal == "direct_ip":
            return RiskEvidence(stage.scanner, 0.55, reason), None
        if signal == "new_domain":
            return RiskEvidence(stage.scanner, self._clamp(stage.risk_score or 0.45), reason), None
        if signal == "established_domain" or stage.verdict == "clean":
            return None, RiskEvidence(stage.scanner, 0.05, reason)
        return None, None

    def _score_ml(self, stage: StageResult, reason: str) -> tuple[RiskEvidence | None, RiskEvidence | None]:
        probability = stage.malicious_probability
        if probability is None:
            return None, None

        if probability >= 0.5:
            if probability >= 0.95:
                score = min(0.92, 0.85 + ((probability - 0.95) * 1.4))
            elif probability >= 0.9:
                score = min(0.84, 0.78 + ((probability - 0.9) * 1.2))
            elif probability >= 0.85:
                score = min(0.78, 0.72 + ((probability - 0.85) * 1.2))
            elif probability >= 0.8:
                score = 0.62 + ((probability - 0.8) * 2.0)
            else:
                score = 0.25 + ((probability - 0.5) * 0.8)
            return RiskEvidence(stage.scanner, score, reason), None

        clean_strength = min(0.35, (0.5 - probability) * 0.8)
        if clean_strength <= 0:
            return None, None
        return None, RiskEvidence(stage.scanner, clean_strength, reason)

    def _score_html(self, stage: StageResult, reason: str) -> tuple[RiskEvidence | None, RiskEvidence | None]:
        threat_score = stage.risk_score
        if threat_score is None:
            threat_score = stage.details.get("threat_score")
        if threat_score is None:
            return None, None

        threat_score = float(threat_score)
        if threat_score >= 0.3:
            return RiskEvidence(stage.scanner, self._clamp(threat_score), reason), None

        return None, RiskEvidence(stage.scanner, 0.1, reason)

    def _negative_offset(self, positive: list[RiskEvidence], negative: list[RiskEvidence]) -> float:
        raw_offset = min(0.45, sum(evidence.score for evidence in negative))
        if raw_offset <= 0:
            return 0.0

        has_threat_intel_hit = any(
            evidence.scanner in self.THREAT_INTEL_SCANNERS and evidence.score >= 0.75
            for evidence in positive
        )
        if has_threat_intel_hit:
            return 0.0

        has_strong_local_hit = any(
            evidence.scanner in {"HtmlScraper", "MLModelScanner", "URLHeuristicScanner"} and evidence.score >= 0.6
            for evidence in positive
        )
        if has_strong_local_hit:
            return min(0.05, raw_offset)

        has_moderate_non_resolver_hit = any(
            evidence.scanner != "UrlResolver" and evidence.score >= 0.4
            for evidence in positive
        )
        if has_moderate_non_resolver_hit:
            return min(0.04, raw_offset)

        has_multiple_local_hits = (
            len([evidence for evidence in positive if evidence.scanner != "UrlResolver"]) >= 2
            and max((evidence.score for evidence in positive), default=0.0) >= 0.35
        )
        if has_multiple_local_hits:
            return min(0.04, raw_offset)

        return raw_offset

    @staticmethod
    def _noisy_or(scores) -> float:
        safe_product = 1.0
        for score in scores:
            safe_product *= 1 - RiskAggregator._clamp(float(score))
        return 1 - safe_product

    @staticmethod
    def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
        return max(minimum, min(maximum, value))

    @classmethod
    def _confidence(cls, final_verdict: FinalVerdict, risk_score: float) -> float:
        if final_verdict == "malicious":
            distance = (risk_score - cls.MALICIOUS_THRESHOLD) / (1 - cls.MALICIOUS_THRESHOLD)
        elif final_verdict == "unknown":
            band_width = cls.MALICIOUS_THRESHOLD - cls.UNKNOWN_THRESHOLD
            midpoint = cls.UNKNOWN_THRESHOLD + (band_width / 2)
            distance = 1 - (abs(risk_score - midpoint) / max(band_width / 2, 0.01))
            return cls._clamp(0.55 + (distance * 0.15))
        else:
            distance = (cls.UNKNOWN_THRESHOLD - risk_score) / cls.UNKNOWN_THRESHOLD

        return cls._clamp(0.5 + (distance * 0.5))

    @staticmethod
    def _summary(
        final_verdict: FinalVerdict,
        risk_score: float,
        strongest_positive: RiskEvidence | None,
        strongest_negative: RiskEvidence | None,
    ) -> str:
        if final_verdict == "malicious":
            if strongest_positive:
                return f"Phishing risk is high: {strongest_positive.reason}"
            return "Phishing risk is high based on combined scanner signals."

        if final_verdict == "unknown":
            if strongest_positive:
                return f"Suspicious phishing signals found: {strongest_positive.reason}"
            return "Suspicious phishing signals found; result needs review."

        if strongest_negative and risk_score < 0.25:
            return f"No strong phishing signal found: {strongest_negative.reason}"
        return "No strong phishing signal found; internal signals stayed below the phishing threshold."
