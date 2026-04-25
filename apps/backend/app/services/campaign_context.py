from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

from app.utils.url_utils import parse_url_parts
from app.services.url_heuristic_scanner import AUTH_TERMS, BRAND_TERMS, FREE_HOSTING_SUFFIXES


HIGH_RISK_CAMPAIGN_SUFFIXES = tuple(
    sorted(
        set(FREE_HOSTING_SUFFIXES)
        | {
            "5mp.eu",
            "contactsite.us",
            "edgeone.app",
            "in.net",
            "mytemp.website",
            "pancake.run",
            "run.place",
            "temporary.site",
            "weebly.com",
        }
    )
)

SUSPICIOUS_PATH_TERMS = {
    "account",
    "auth",
    "cart",
    "claim",
    "connect",
    "help",
    "info",
    "login",
    "mpps",
    "pairs",
    "secure",
    "signin",
    "support",
    "v3",
    "verify",
    "wallet",
    "websrc",
}


@dataclass(frozen=True)
class CampaignSignal:
    score: float
    reason: str
    details: dict[str, object]

    def as_positive_signal(self) -> dict[str, object]:
        return {
            "scanner": "CampaignContext",
            "score": round(self.score, 4),
            "reason": self.reason,
            "details": self.details,
        }


@dataclass(frozen=True)
class CampaignContext:
    host_counts: Counter[str]
    host_path_pattern_counts: Counter[tuple[str, str]]


def build_campaign_context(urls: list[str]) -> CampaignContext:
    host_counts: Counter[str] = Counter()
    host_path_pattern_counts: Counter[tuple[str, str]] = Counter()

    for url in urls:
        host, path = _parse_host_path(url)
        if not host:
            continue
        host_counts[host] += 1
        host_path_pattern_counts[(host, path_pattern(path))] += 1

    return CampaignContext(host_counts=host_counts, host_path_pattern_counts=host_path_pattern_counts)


def evaluate_campaign_url(url: str, context: CampaignContext) -> CampaignSignal | None:
    host, path = _parse_host_path(url)
    if not host:
        return None

    pattern = path_pattern(path)
    host_count = context.host_counts.get(host, 0)
    pattern_count = context.host_path_pattern_counts.get((host, pattern), 0)
    host_is_high_risk = _endswith_any(host, HIGH_RISK_CAMPAIGN_SUFFIXES)
    path_is_suspicious = _path_has_suspicious_terms(path) or _path_looks_like_campaign(path)
    host_has_brand_or_auth = any(term in host for term in BRAND_TERMS | AUTH_TERMS)

    signals: list[CampaignSignal] = []

    if host_count >= 5 and host_is_high_risk:
        signals.append(
            CampaignSignal(
                score=0.6,
                reason=f"Repeated high-risk campaign host in feed ({host_count} URLs on {host})",
                details={"host": host, "host_count": host_count, "path_pattern": pattern},
            )
        )
    elif host_count >= 3 and host_is_high_risk:
        signals.append(
            CampaignSignal(
                score=0.52,
                reason=f"Repeated high-risk host in feed ({host_count} URLs on {host})",
                details={"host": host, "host_count": host_count, "path_pattern": pattern},
            )
        )

    if pattern_count >= 2 and path_is_suspicious:
        signals.append(
            CampaignSignal(
                score=0.48 if pattern_count < 4 else 0.56,
                reason=f"Repeated suspicious path pattern in feed ({pattern_count} matches)",
                details={"host": host, "host_count": host_count, "path_pattern": pattern, "pattern_count": pattern_count},
            )
        )

    if host_count >= 2 and host_has_brand_or_auth and host_is_high_risk:
        signals.append(
            CampaignSignal(
                score=0.42,
                reason=f"Repeated hosted URL uses brand/auth terms ({host_count} URLs on {host})",
                details={"host": host, "host_count": host_count, "path_pattern": pattern},
            )
        )

    if not signals:
        return None

    score = _noisy_or(signal.score for signal in signals)
    details = {
        "host": host,
        "host_count": host_count,
        "path_pattern": pattern,
        "pattern_count": pattern_count,
        "matched_rules": [signal.details for signal in signals],
    }
    return CampaignSignal(
        score=score,
        reason=" | ".join(signal.reason for signal in sorted(signals, key=lambda item: item.score, reverse=True)[:3]),
        details=details,
    )


def path_pattern(path: str) -> str:
    decoded_path = unquote(path or "").lower()
    parts = [part for part in decoded_path.split("/") if part]
    normalized: list[str] = []
    for part in parts[:6]:
        cleaned = re.sub(r"[^a-z0-9_-]+", "", part)
        if re.fullmatch(r"[a-f0-9]{8,}", cleaned):
            normalized.append("{hex}")
        elif re.fullmatch(r"[a-z0-9_-]{12,}", cleaned):
            normalized.append("{token}")
        elif re.fullmatch(r"\d{4,}", cleaned):
            normalized.append("{num}")
        else:
            normalized.append(cleaned[:32])
    return "/" + "/".join(normalized)


def _parse_host_path(url: str) -> tuple[str, str]:
    try:
        parts = parse_url_parts(url)
        return parts.normalized_hostname, parts.path or ""
    except Exception:
        parsed = urlparse(url if str(url).startswith(("http://", "https://")) else f"https://{url}")
        return (parsed.hostname or "").lower().strip("."), parsed.path or ""


def _path_has_suspicious_terms(path: str) -> bool:
    tokens = set(re.split(r"[^a-z0-9]+", unquote(path or "").lower()))
    return bool(tokens & SUSPICIOUS_PATH_TERMS)


def _path_looks_like_campaign(path: str) -> bool:
    decoded_path = unquote(path or "").lower()
    return bool(
        re.search(r"/mpps/[a-f0-9]{6,}/(?:websrc)?", decoded_path)
        or re.search(r"/(?:login|auth|verify|wallet|mail)/[a-z0-9_-]{8,}", decoded_path)
    )


def _endswith_any(hostname: str, suffixes: tuple[str, ...]) -> bool:
    return any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes)


def _noisy_or(scores) -> float:
    safe_product = 1.0
    for score in scores:
        safe_product *= 1 - max(0.0, min(1.0, float(score)))
    return min(1.0, 1 - safe_product)
