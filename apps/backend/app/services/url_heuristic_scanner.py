from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.utils.url_utils import UrlParts, hostname_matches_allowed, parse_url_parts


BRAND_TERMS = {
    "adobe",
    "amazon",
    "apple",
    "att",
    "aws",
    "bellsouth",
    "binance",
    "coinbase",
    "docusign",
    "facebook",
    "instagram",
    "kucoin",
    "ledger",
    "mastercard",
    "mercadolibre",
    "mercadopago",
    "metamask",
    "microsoft",
    "netflix",
    "office",
    "onedrive",
    "outlook",
    "pancake",
    "pancakeswap",
    "paypal",
    "roblox",
    "sharepoint",
    "spotify",
    "steam",
    "tiktok",
    "tiktokshop",
    "trezor",
    "uniswap",
    "uphold",
    "usps",
    "visa",
    "whatsapp",
}

LEGITIMATE_BRAND_HOSTS = {
    "adobe": {"adobe.com", "acrobat.com"},
    "amazon": {"amazon.com", "amazonaws.com"},
    "apple": {"apple.com", "icloud.com"},
    "att": {"att.com"},
    "aws": {"aws.amazon.com", "amazonaws.com"},
    "bellsouth": {"bellsouth.net", "att.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "kucoin": {"kucoin.com"},
    "ledger": {"ledger.com"},
    "mastercard": {"mastercard.com"},
    "mercadolibre": {"mercadolibre.com", "mercadolibre.cl", "mercadolibre.com.ar", "mercadolibre.com.mx"},
    "mercadopago": {"mercadopago.com", "mercadopago.cl", "mercadopago.com.ar", "mercadopago.com.mx"},
    "metamask": {"metamask.io"},
    "microsoft": {"microsoft.com", "office.com", "live.com"},
    "netflix": {"netflix.com"},
    "office": {"office.com", "microsoft.com", "office365.com", "live.com"},
    "onedrive": {"onedrive.live.com", "live.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "microsoft.com"},
    "pancake": {"pancakeswap.finance"},
    "pancakeswap": {"pancakeswap.finance"},
    "paypal": {"paypal.com"},
    "roblox": {"roblox.com"},
    "sharepoint": {"sharepoint.com", "microsoft.com"},
    "spotify": {"spotify.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "tiktok": {"tiktok.com", "tiktokshop.com"},
    "tiktokshop": {"tiktokshop.com"},
    "trezor": {"trezor.io"},
    "uniswap": {"uniswap.org"},
    "uphold": {"uphold.com"},
    "usps": {"usps.com"},
    "visa": {"visa.com"},
    "whatsapp": {"whatsapp.com"},
}

LOOKALIKE_BRANDS = {
    "koquin": "kucoin",
    "trezzure": "trezor",
    "trezzuresuite": "trezor",
    "robiox": "roblox",
}

AUTH_TERMS = {
    "account",
    "auth",
    "authorize",
    "billing",
    "help",
    "login",
    "mail",
    "oauth",
    "password",
    "portal",
    "recovery",
    "secure",
    "security",
    "service",
    "signin",
    "sso",
    "support",
    "update",
    "verify",
    "wallet",
    "wholesale",
}

FREE_HOSTING_SUFFIXES = (
    "blogspot.com",
    "framer.app",
    "github.io",
    "godaddysites.com",
    "edgeone.app",
    "5mp.eu",
    "contactsite.us",
    "netlify.app",
    "mytemp.website",
    "pages.dev",
    "run.place",
    "temporary.site",
    "typedream.app",
    "vercel.app",
    "webflow.io",
    "weebly.com",
    "workers.dev",
    "zapier.app",
)

HIGH_RISK_CAMPAIGN_SUFFIXES = FREE_HOSTING_SUFFIXES + (
    "pancake.run",
    "in.net",
)

OBJECT_STORAGE_SUFFIXES = (
    "backblazeb2.com",
    "oortstorages.com",
    "s3.amazonaws.com",
)

SHORTENER_HOSTS = {
    "bit.ly",
    "cutt.ly",
    "did.li",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "reurl.cc",
    "surl.li",
    "t.co",
    "tinyurl.com",
    "urlz.fr",
}


class URLHeuristicScanner(BaseScanner):
    """Local, explainable URL heuristics for current phishing campaign patterns."""

    def __init__(self) -> None:
        super().__init__(name="URLHeuristicScanner")

    def scan(self, url: str) -> StageResult:
        url_parts = parse_url_parts(url)
        hostname = url_parts.normalized_hostname
        path = unquote(url_parts.path or "").lower()
        query = unquote(url_parts.query or "").lower()
        fragment = unquote(url_parts.fragment or "").lower()
        full_url = f"{hostname}{path}?{query}#{fragment}".lower()

        signals = self._signals(hostname, path, query, full_url, url_parts)
        if not signals:
            return StageResult(
                scanner=self.name,
                verdict="clean",
                risk_score=0.0,
                reason="No high-risk URL pattern found",
                details={
                    "matched_rules": [],
                    "registrable_domain": url_parts.registrable_domain,
                    "suffix": url_parts.suffix,
                },
            )

        risk_score = self._noisy_or(signal["score"] for signal in signals)
        verdict = "malicious" if risk_score >= 0.65 else "unknown"
        reason = " | ".join(str(signal["reason"]) for signal in signals[:4])
        return StageResult(
            scanner=self.name,
            verdict=verdict,
            confidence=round(risk_score, 4),
            risk_score=round(risk_score, 4),
            reason=reason,
            details={
                "matched_rules": signals,
                "registrable_domain": url_parts.registrable_domain,
                "suffix": url_parts.suffix,
                "idn": url_parts.is_idn,
                "punycode": url_parts.has_punycode_label,
                "mixed_script": url_parts.has_mixed_script,
                "skeleton_hostname": url_parts.skeleton_hostname,
            },
        )

    def _signals(self, hostname: str, path: str, query: str, full_url: str, url_parts: UrlParts) -> list[dict[str, object]]:
        signals: list[dict[str, object]] = []
        brand_hits = sorted(term for term in BRAND_TERMS if term in full_url)
        auth_hits = sorted(term for term in AUTH_TERMS if term in full_url)
        hostname_brand_hits = sorted(term for term in BRAND_TERMS if term in hostname)
        skeleton_brand_hits = sorted(term for term in BRAND_TERMS if term in url_parts.skeleton_hostname)
        is_free_host = self._endswith_any(hostname, FREE_HOSTING_SUFFIXES)
        is_high_risk_campaign_host = self._endswith_any(hostname, HIGH_RISK_CAMPAIGN_SUFFIXES)
        is_object_storage = self._endswith_any(hostname, OBJECT_STORAGE_SUFFIXES)
        is_shortener = hostname in SHORTENER_HOSTS or any(hostname.endswith(f".{host}") for host in SHORTENER_HOSTS)

        suspicious_host_brands = [
            brand for brand in hostname_brand_hits if not self._is_legitimate_brand_host(hostname, brand)
        ]
        if suspicious_host_brands:
            has_auth_context = bool(
                auth_hits
                or re.search(r"(?:login|signin|auth|secure|service|support|shop|cart|wallet|verify|wholesale)", path)
            )
            signals.append(
                {
                    "rule": "brand_impersonation_hostname",
                    "score": 0.68 if has_auth_context else 0.52,
                    "reason": f"Hostname imitates known brand(s): {', '.join(suspicious_host_brands[:3])}",
                }
            )

        homoglyph_hits = [
            brand
            for brand in skeleton_brand_hits
            if brand not in hostname and not self._is_legitimate_brand_host(hostname, brand)
        ]
        if homoglyph_hits and (url_parts.is_idn or url_parts.has_punycode_label or url_parts.has_mixed_script):
            has_auth_context = bool(
                auth_hits
                or re.search(r"(?:login|signin|auth|secure|service|support|wallet|verify|account)", path)
            )
            signals.append(
                {
                    "rule": "idn_homoglyph_brand",
                    "score": 0.78 if has_auth_context else 0.68,
                    "reason": f"Hostname uses IDN/homoglyph characters for known brand(s): {', '.join(homoglyph_hits[:3])}",
                }
            )

        if suspicious_host_brands and is_high_risk_campaign_host:
            signals.append(
                {
                    "rule": "brand_on_high_risk_host",
                    "score": 0.46,
                    "reason": "Known brand appears on a high-risk hosted/campaign domain",
                }
            )

        lookalike_hits = self._lookalike_brand_hits(hostname)
        if lookalike_hits:
            brands = ", ".join(lookalike_hits[:3])
            signals.append(
                {
                    "rule": "brand_lookalike_hostname",
                    "score": 0.68,
                    "reason": f"Hostname uses lookalike spelling for known brand(s): {brands}",
                }
            )

        if is_free_host and (brand_hits or auth_hits):
            signals.append(
                {
                    "rule": "free_hosting_auth_or_brand",
                    "score": 0.55,
                    "reason": "Free hosting URL contains brand/authentication terms",
                }
            )

        if is_object_storage and (auth_hits or {"html", "mail", "security"} & set(re.split(r"[^a-z0-9]+", full_url))):
            signals.append(
                {
                    "rule": "object_storage_landing",
                    "score": 0.35,
                    "reason": "Object-storage landing page contains login/security terms",
                }
            )

        if is_shortener:
            signals.append(
                {
                    "rule": "shortened_url",
                    "score": 0.26,
                    "reason": "Shortened URL hides the final destination",
                }
            )

        if self._has_encoded_brand_redirect(query):
            signals.append(
                {
                    "rule": "encoded_brand_redirect",
                    "score": 0.35,
                    "reason": "URL query contains encoded redirect to a known brand",
                }
            )

        if self._looks_like_random_campaign(hostname, path) and (auth_hits or is_free_host):
            signals.append(
                {
                    "rule": "randomized_campaign_host",
                    "score": 0.4 if is_high_risk_campaign_host else 0.32,
                    "reason": "Randomized campaign-style host/path with auth or free-hosting context",
                }
            )

        if self._matches_known_campaign_path(path, hostname):
            signals.append(
                {
                    "rule": "known_campaign_path_pattern",
                    "score": 0.42,
                    "reason": "URL path matches a repeated phishing campaign pattern",
                }
            )

        if hostname == "awscfdns.com" or hostname.endswith(".awscfdns.com"):
            signals.append(
                {
                    "rule": "aws_cloudfront_lookalike",
                    "score": 0.52,
                    "reason": "Hostname imitates AWS/CloudFront infrastructure naming",
                }
            )

        if len(hostname) >= 45 and hostname.count("-") >= 3 and (brand_hits or auth_hits):
            signals.append(
                {
                    "rule": "long_hyphenated_auth_host",
                    "score": 0.25,
                    "reason": "Long hyphenated hostname contains brand/authentication terms",
                }
            )

        return sorted(signals, key=lambda item: float(item["score"]), reverse=True)

    @staticmethod
    def _endswith_any(hostname: str, suffixes: tuple[str, ...]) -> bool:
        return any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes)

    @staticmethod
    def _is_legitimate_brand_host(hostname: str, brand: str) -> bool:
        allowed_hosts = LEGITIMATE_BRAND_HOSTS.get(brand, set())
        return hostname_matches_allowed(hostname, allowed_hosts)

    @classmethod
    def _lookalike_brand_hits(cls, hostname: str) -> list[str]:
        hits = {LOOKALIKE_BRANDS[alias] for alias in LOOKALIKE_BRANDS if alias in hostname}
        labels = re.split(r"[^a-z0-9]+", hostname.lower())
        normalized_labels = [cls._normalize_lookalike_text(label) for label in labels if len(label) >= 4]

        for label in normalized_labels:
            stripped_label = cls._strip_auth_terms(label)
            candidates = {label, stripped_label}
            for brand in BRAND_TERMS:
                if not cls._is_legitimate_brand_host(hostname, brand) and cls._is_near_brand_token(candidates, brand):
                    hits.add(brand)

        return sorted(hits)

    @staticmethod
    def _normalize_lookalike_text(value: str) -> str:
        return value.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"}))

    @staticmethod
    def _strip_auth_terms(value: str) -> str:
        stripped = value
        for term in sorted(AUTH_TERMS, key=len, reverse=True):
            stripped = stripped.replace(term, "")
        return stripped

    @classmethod
    def _is_near_brand_token(cls, candidates: set[str], brand: str) -> bool:
        if len(brand) < 5:
            return False

        for candidate in candidates:
            if not candidate:
                continue
            if brand in candidate:
                return True
            if abs(len(candidate) - len(brand)) > 2:
                continue
            limit = 2 if len(brand) >= 6 else 1
            if cls._edit_distance(candidate, brand, limit) <= limit:
                return True
        return False

    @staticmethod
    def _edit_distance(left: str, right: str, limit: int) -> int:
        if abs(len(left) - len(right)) > limit:
            return limit + 1

        previous = list(range(len(right) + 1))
        for index, left_char in enumerate(left, start=1):
            current = [index]
            row_min = index
            for right_index, right_char in enumerate(right, start=1):
                cost = 0 if left_char == right_char else 1
                current_value = min(
                    current[right_index - 1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + cost,
                )
                current.append(current_value)
                row_min = min(row_min, current_value)
            if row_min > limit:
                return limit + 1
            previous = current

        return previous[-1]

    @staticmethod
    def _has_encoded_brand_redirect(query: str) -> bool:
        if not query:
            return False

        values = [value for _key, value in parse_qsl(query, keep_blank_values=True)]
        decoded_query = unquote(query)
        haystacks = values + [decoded_query]
        redirect_keys = ("redirect", "redirect_uri", "return", "target", "url", "q")
        has_redirect_key = any(key in query for key in redirect_keys)
        return has_redirect_key and any(brand in haystack for haystack in haystacks for brand in BRAND_TERMS)

    @staticmethod
    def _looks_like_random_campaign(hostname: str, path: str) -> bool:
        tokens = re.findall(r"[a-z0-9]{10,}", f"{hostname}/{path}")
        dashed_random = bool(re.search(r"[a-z0-9]{4,}-[a-z0-9]{4,}-[a-z0-9]{3,}", hostname))
        lp_token = bool(re.search(r"/(?:lp|login|auth|mail)/[a-z0-9_-]{8,}", path))
        return dashed_random or lp_token or bool(tokens)

    @staticmethod
    def _matches_known_campaign_path(path: str, hostname: str) -> bool:
        return bool(
            re.search(r"/mpps/[a-f0-9]{6,}/(?:websrc)?", path)
            or (hostname.endswith(".pancake.run") and re.search(r"/info/(?:v3|pairs)", path))
            or (hostname.endswith(".edgeone.app") and re.search(r"/[a-z0-9_-]{4,}\.html/?$", path))
        )

    @staticmethod
    def _noisy_or(scores) -> float:
        safe_product = 1.0
        for score in scores:
            safe_product *= 1 - max(0.0, min(1.0, float(score)))
        return min(1.0, 1 - safe_product)
