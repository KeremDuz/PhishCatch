"""Versioned DOM policy; observations about normal inputs are not threat evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import tldextract
from bs4 import BeautifulSoup

_PSL = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def resolve_target(soup: BeautifulSoup, page_url: str, value: str) -> str | None:
    """Resolve HTML targets without visiting them or submitting any form."""
    base = soup.find("base", href=True)
    base_url = urljoin(page_url, str(base.get("href"))) if base else page_url
    target = urljoin(base_url, value.strip()) if value.strip() else page_url
    try:
        parsed = urlsplit(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.port == 0:
            return None
    except ValueError:
        return None
    return target


def site_key(url: str) -> str:
    try:
        hostname = (
            (urlsplit(url).hostname or "")
            .rstrip(".")
            .encode("idna")
            .decode("ascii")
            .lower()
        )
        extracted = _PSL(hostname)
        return extracted.top_domain_under_public_suffix or hostname
    except (ValueError, UnicodeError):
        return ""


def external_form_targets(soup: BeautifulSoup, page_url: str) -> tuple[int, int]:
    external: set[str] = set()
    unsupported = 0
    elements = list(soup.find_all("form")) + list(
        soup.find_all(["button", "input"], formaction=True)
    )
    for element in elements:
        raw = str(
            element.get("action" if element.name == "form" else "formaction") or ""
        )
        target = resolve_target(soup, page_url, raw)
        if target is None:
            unsupported += 1
        elif site_key(target) != site_key(page_url):
            # Only the target identity affects the rule; query values are not copied.
            parsed = urlsplit(target)
            external.add(f"{parsed.scheme}://{parsed.netloc}")
    return len(external), unsupported


@dataclass(frozen=True)
class DomAssessment:
    score: float
    reasons: list[str]
    requires_review: bool
    context: dict[str, Any]


def dynamic_coverage_reasons(
    soup: BeautifulSoup, findings: dict[str, Any]
) -> list[str]:
    """Identify content/data flows the static scanner did not inspect.

    This is a coverage check, not JavaScript or iframe reputation. Rendering a
    DOM alone would not establish where handlers send a user's sensitive data.
    """
    sensitive = any(
        findings.get(key)
        for key in (
            "credentials", "credit_card", "cvv", "expiry", "banking",
            "identity", "crypto", "pin_otp",
        )
    )
    reasons: list[str] = []
    executable_scripts = any(
        (
            not str(script.get("type") or "").strip()
            or str(script.get("type")).strip().lower() == "module"
            or "javascript" in str(script.get("type")).lower()
            or "ecmascript" in str(script.get("type")).lower()
        )
        and (script.get("src") or script.get_text(strip=True))
        for script in soup.find_all("script")
    )
    event_handlers = any(
        str(attribute).lower().startswith("on") and bool(value)
        for element in soup.find_all(True)
        for attribute, value in element.attrs.items()
    )
    javascript_links = any(
        str(element.get(attribute) or "").strip().lower().startswith("javascript:")
        for element in soup.find_all(True)
        for attribute in ("href", "src", "action", "formaction")
    )
    if sensitive and (executable_scripts or event_handlers or javascript_links):
        reasons.append("sensitive_javascript_flow_uninspected")
    # Both same-origin and unrelated frames can contain a login form. Never
    # visit their URLs here: the bounded fetcher analyzed only the outer page.
    if any(
        frame.get("srcdoc")
        or str(frame.get("src") or "").strip().lower()
        not in {"", "about:blank"}
        for frame in soup.find_all("iframe")
    ):
        reasons.append("embedded_frame_content_uninspected")
    return reasons


def assess_dom(
    soup: BeautifulSoup,
    page_url: str,
    findings: dict[str, Any],
    js: dict[str, Any],
    brand_signals: list[dict[str, Any]],
) -> DomAssessment:
    families = {
        "credentials": bool(findings.get("credentials")),
        "payment": any(findings.get(key) for key in ("credit_card", "cvv", "expiry")),
        "banking": bool(findings.get("banking")),
        "identity": bool(findings.get("identity")),
        "crypto": bool(findings.get("crypto")),
        "otp": bool(findings.get("pin_otp")),
    }
    sensitive = any(families.values())
    external, unsupported = external_form_targets(soup, page_url)
    # A logo and the same brand in the title describe one claim, not two witnesses.
    brand_score = (
        max((float(item["score"]) for item in brand_signals), default=0.0)
        if sensitive
        else 0.0
    )
    reasons: list[str] = []
    score = 0.0
    review = False
    if sensitive and external:
        score += 0.35
        review = True
        reasons.append("Sensitive form has an unrelated submission destination")
        if families["crypto"]:
            score += 0.25
            reasons.append("Recovery secret is submitted to an unrelated site")
    if brand_score:
        score += brand_score
        review = True
        reasons.append("Credential-taking page claims a brand on an unrelated host")
    if sensitive and urlsplit(page_url).scheme.lower() == "http":
        score += 0.25
        review = True
        reasons.append("Sensitive information is collected over unencrypted HTTP")
    if sensitive and unsupported:
        review = True
        reasons.append("Form submission destination could not be assessed statically")
    dynamic_reasons = dynamic_coverage_reasons(soup, findings)
    if dynamic_reasons:
        review = True
        reasons.append("Sensitive script behavior or embedded content was not inspected")
    # Keyboard, clipboard, autocomplete, CSRF, normal iframes and sensitive inputs
    # are observations only. A regex is not proof of keylogging/exfiltration.
    return DomAssessment(
        min(score, 1.0),
        reasons,
        review,
        {
            "policy_version": "dom-v3",
            "sensitive_families": [key for key, present in families.items() if present],
            "external_form_actions": external,
            "unsupported_form_actions": unsupported,
            "dynamic_review_reasons": dynamic_reasons,
            "sensitive_script_transfer_observed": sensitive and bool(js.get("exfiltration")),
            "strong_signal": sensitive and external > 0 and brand_score >= 0.45,
        },
    )
