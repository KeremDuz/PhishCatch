from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import pandas as pd
from bs4 import BeautifulSoup

from app.ml.feature_extractor import (
    BRAND_WORDS,
    MENDELEY_48_FEATURE_COLUMNS,
    extract_48_features,
)


HTML_EXTRA_FEATURE_COLUMNS = [
    "HtmlLength",
    "TextLength",
    "TitleLength",
    "FormCount",
    "InputCount",
    "PasswordInputCount",
    "SensitiveInputCount",
    "HiddenInputCount",
    "FileInputCount",
    "ButtonCount",
    "ExternalFormActionCount",
    "AbnormalFormActionCount",
    "ScriptCount",
    "InlineScriptCount",
    "ExternalScriptCount",
    "IframeCount",
    "HiddenIframeCount",
    "MetaRefreshCount",
    "LinkCount",
    "ExternalLinkCount",
    "NullSelfRedirectLinkCount",
    "ResourceCount",
    "ExternalResourceCount",
    "ImageCount",
    "LoginKeywordCount",
    "BrandKeywordCount",
    "KeyEventHandlerCount",
    "FetchOrXhrCount",
    "EvalLikeCount",
    "ClipboardAccess",
]

HTML_MODEL_FEATURE_COLUMNS = MENDELEY_48_FEATURE_COLUMNS + HTML_EXTRA_FEATURE_COLUMNS

SENSITIVE_INPUT_WORDS = [
    "password",
    "passwd",
    "pass",
    "pwd",
    "login",
    "signin",
    "account",
    "verify",
    "otp",
    "pin",
    "card",
    "credit",
    "cvv",
    "cvc",
    "iban",
    "wallet",
    "seed",
    "ssn",
]

LOGIN_WORDS = [
    "login",
    "signin",
    "password",
    "account",
    "verify",
    "verification",
    "secure",
    "wallet",
    "bank",
]

RESOURCE_TAGS = {
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
    "frame": "src",
    "source": "src",
    "embed": "src",
}


def extract_html_features_dataframe(url: str, raw_html: str, final_url: str | None = None) -> pd.DataFrame:
    return pd.DataFrame(
        [extract_html_features(url=url, raw_html=raw_html, final_url=final_url).to_dict()],
        columns=HTML_MODEL_FEATURE_COLUMNS,
    )


def extract_html_features(url: str, raw_html: str, final_url: str | None = None) -> pd.Series:
    page_url = final_url or url
    raw_html = raw_html or ""
    soup = BeautifulSoup(raw_html, "lxml")
    parsed = _safe_urlparse(page_url)
    base_host = parsed.netloc.lower()

    base_features = extract_48_features(page_url).to_dict()
    html_features = _extract_dom_features(page_url, raw_html, soup, base_host)
    base_features.update(html_features)

    return pd.Series(base_features, index=HTML_MODEL_FEATURE_COLUMNS).fillna(0.0).astype(float)


def _extract_dom_features(page_url: str, raw_html: str, soup: BeautifulSoup, base_host: str) -> dict[str, float]:
    html_lower = raw_html.lower()
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    text = soup.get_text(" ", strip=True)

    links = [tag.get("href", "") or "" for tag in soup.find_all("a")]
    external_links = [href for href in links if _is_external_url(page_url, href, base_host)]
    null_self_links = [href for href in links if _is_null_or_self_redirect(href)]

    resource_urls = _resource_urls(soup)
    external_resources = [src for src in resource_urls if _is_external_url(page_url, src, base_host)]

    forms = soup.find_all("form")
    form_stats = _form_stats(page_url, forms, base_host)
    input_stats = _input_stats(soup)
    iframe_stats = _iframe_stats(page_url, soup, base_host)
    script_stats = _script_stats(soup, html_lower)

    link_count = len([href for href in links if href])
    resource_count = len([src for src in resource_urls if src])

    pct_external_links = _ratio_percent(len(external_links), link_count)
    pct_external_resources = _ratio_percent(len(external_resources), resource_count)
    pct_null_self_redirects = _ratio_percent(len(null_self_links), link_count)

    ext_meta_script_link = _ratio_triplet(
        len(external_resources) + len(soup.find_all("meta")),
        max(1, resource_count + len(soup.find_all("meta"))),
        warn=0.25,
        bad=0.6,
    )

    features = {
        "PctExtHyperlinks": pct_external_links,
        "PctExtResourceUrls": pct_external_resources,
        "ExtFavicon": float(_has_external_favicon(page_url, soup, base_host)),
        "InsecureForms": float(form_stats["insecure_forms"] > 0),
        "RelativeFormAction": float(form_stats["relative_actions"] > 0),
        "ExtFormAction": float(form_stats["external_actions"] > 0),
        "AbnormalFormAction": float(form_stats["abnormal_actions"] > 0),
        "PctNullSelfRedirectHyperlinks": pct_null_self_redirects,
        "FrequentDomainNameMismatch": float(pct_external_links >= 50.0 or pct_external_resources >= 50.0),
        "FakeLinkInStatusBar": float("window.status" in html_lower or "statusbar" in html_lower),
        "RightClickDisabled": float(_right_click_disabled(html_lower)),
        "PopUpWindow": float("window.open" in html_lower or "popup" in html_lower),
        "SubmitInfoToEmail": float("mailto:" in html_lower),
        "IframeOrFrame": float(iframe_stats["iframe_count"] > 0),
        "MissingTitle": float(not title),
        "ImagesOnlyInForm": float(form_stats["images_only_forms"] > 0),
        "SubdomainLevelRT": _threshold_triplet(base_features_value(page_url, "SubdomainLevel"), warn=1, bad=3),
        "UrlLengthRT": _threshold_triplet(len(page_url), warn=75, bad=120),
        "PctExtResourceUrlsRT": _ratio_triplet(len(external_resources), resource_count, warn=0.25, bad=0.6),
        "AbnormalExtFormActionR": float(form_stats["external_actions"] > 0 or form_stats["abnormal_actions"] > 0),
        "ExtMetaScriptLinkRT": ext_meta_script_link,
        "PctExtNullSelfRedirectHyperlinksRT": _ratio_triplet(len(null_self_links), link_count, warn=0.25, bad=0.6),
        "HtmlLength": float(len(raw_html)),
        "TextLength": float(len(text)),
        "TitleLength": float(len(title)),
        "FormCount": float(len(forms)),
        "InputCount": float(input_stats["input_count"]),
        "PasswordInputCount": float(input_stats["password_inputs"]),
        "SensitiveInputCount": float(input_stats["sensitive_inputs"]),
        "HiddenInputCount": float(input_stats["hidden_inputs"]),
        "FileInputCount": float(input_stats["file_inputs"]),
        "ButtonCount": float(len(soup.find_all(["button", "input"], attrs={"type": re.compile("button|submit|image", re.I)}))),
        "ExternalFormActionCount": float(form_stats["external_actions"]),
        "AbnormalFormActionCount": float(form_stats["abnormal_actions"]),
        "ScriptCount": float(script_stats["script_count"]),
        "InlineScriptCount": float(script_stats["inline_scripts"]),
        "ExternalScriptCount": float(script_stats["external_scripts"]),
        "IframeCount": float(iframe_stats["iframe_count"]),
        "HiddenIframeCount": float(iframe_stats["hidden_iframes"]),
        "MetaRefreshCount": float(len(soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}))),
        "LinkCount": float(link_count),
        "ExternalLinkCount": float(len(external_links)),
        "NullSelfRedirectLinkCount": float(len(null_self_links)),
        "ResourceCount": float(resource_count),
        "ExternalResourceCount": float(len(external_resources)),
        "ImageCount": float(len(soup.find_all("img"))),
        "LoginKeywordCount": float(sum(html_lower.count(word) for word in LOGIN_WORDS)),
        "BrandKeywordCount": float(sum(html_lower.count(word) for word in BRAND_WORDS)),
        "KeyEventHandlerCount": float(script_stats["key_event_handlers"]),
        "FetchOrXhrCount": float(script_stats["fetch_or_xhr"]),
        "EvalLikeCount": float(script_stats["eval_like"]),
        "ClipboardAccess": float("clipboard" in html_lower or "execcommand('copy" in html_lower),
    }

    return features


def base_features_value(url: str, feature_name: str) -> float:
    return float(extract_48_features(url).get(feature_name, 0.0))


def _input_stats(soup: BeautifulSoup) -> dict[str, int]:
    stats = {
        "input_count": 0,
        "password_inputs": 0,
        "sensitive_inputs": 0,
        "hidden_inputs": 0,
        "file_inputs": 0,
    }

    labels_by_for = {
        label.get("for", ""): label.get_text(" ", strip=True).lower()
        for label in soup.find_all("label")
        if label.get("for")
    }

    for element in soup.find_all(["input", "textarea", "select"]):
        stats["input_count"] += 1
        input_type = (element.get("type") or element.name or "text").lower()
        if input_type == "password":
            stats["password_inputs"] += 1
        if input_type == "hidden":
            stats["hidden_inputs"] += 1
        if input_type == "file":
            stats["file_inputs"] += 1

        attrs = _element_text_signal(element, labels_by_for)
        if input_type == "password" or any(word in attrs for word in SENSITIVE_INPUT_WORDS):
            stats["sensitive_inputs"] += 1

    return stats


def _form_stats(page_url: str, forms: list, base_host: str) -> dict[str, int]:
    stats = {
        "external_actions": 0,
        "relative_actions": 0,
        "abnormal_actions": 0,
        "insecure_forms": 0,
        "images_only_forms": 0,
    }

    page_scheme = _safe_urlparse(page_url).scheme
    for form in forms:
        action = (form.get("action") or "").strip()
        if not action or action.startswith("#") or action.lower().startswith(("javascript:", "data:")):
            stats["abnormal_actions"] += 1
        elif action.lower().startswith("mailto:"):
            stats["abnormal_actions"] += 1
        elif action.startswith(("http://", "https://")):
            action_host = _safe_urlparse(action).netloc.lower()
            if action_host and action_host != base_host:
                stats["external_actions"] += 1
            if action.startswith("http://") and page_scheme == "https":
                stats["insecure_forms"] += 1
        else:
            stats["relative_actions"] += 1

        input_types = [(field.get("type") or field.name or "text").lower() for field in form.find_all(["input", "textarea", "select"])]
        if input_types and all(input_type in {"image", "hidden"} for input_type in input_types):
            stats["images_only_forms"] += 1

    return stats


def _iframe_stats(page_url: str, soup: BeautifulSoup, base_host: str) -> dict[str, int]:
    iframe_count = 0
    hidden_iframes = 0
    for iframe in soup.find_all(["iframe", "frame"]):
        iframe_count += 1
        style = (iframe.get("style") or "").replace(" ", "").lower()
        width = str(iframe.get("width") or "")
        height = str(iframe.get("height") or "")
        src = iframe.get("src", "") or ""
        if "display:none" in style or width == "0" or height == "0":
            hidden_iframes += 1
        elif _is_external_url(page_url, src, base_host) and ("visibility:hidden" in style or "opacity:0" in style):
            hidden_iframes += 1

    return {"iframe_count": iframe_count, "hidden_iframes": hidden_iframes}


def _script_stats(soup: BeautifulSoup, html_lower: str) -> dict[str, int]:
    scripts = soup.find_all("script")
    external_scripts = [script for script in scripts if script.get("src")]
    inline_scripts = len(scripts) - len(external_scripts)

    return {
        "script_count": len(scripts),
        "external_scripts": len(external_scripts),
        "inline_scripts": inline_scripts,
        "key_event_handlers": len(re.findall(r"key(?:down|press|up)|onkey", html_lower)),
        "fetch_or_xhr": len(re.findall(r"\bfetch\s*\(|xmlhttprequest|\.ajax\s*\(", html_lower)),
        "eval_like": len(re.findall(r"\beval\s*\(|atob\s*\(|fromcharcode|unescape\s*\(", html_lower)),
    }


def _resource_urls(soup: BeautifulSoup) -> list[str]:
    urls: list[str] = []
    for tag_name, attribute in RESOURCE_TAGS.items():
        for tag in soup.find_all(tag_name):
            value = tag.get(attribute)
            if value:
                urls.append(str(value))
    return urls


def _has_external_favicon(page_url: str, soup: BeautifulSoup, base_host: str) -> bool:
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel", [])).lower()
        href = link.get("href", "") or ""
        if "icon" in rel and _is_external_url(page_url, href, base_host):
            return True
    return False


def _element_text_signal(element, labels_by_for: dict[str, str]) -> str:
    values = [
        element.get("name", ""),
        element.get("id", ""),
        element.get("placeholder", ""),
        element.get("autocomplete", ""),
        element.get("aria-label", ""),
        element.get("title", ""),
        labels_by_for.get(element.get("id", ""), ""),
        " ".join(element.get("class", [])),
    ]
    return " ".join(str(value).lower().replace("-", "_") for value in values if value)


def _is_external_url(page_url: str, candidate_url: str, base_host: str) -> bool:
    if not candidate_url or _is_null_or_self_redirect(candidate_url):
        return False
    lowered = candidate_url.strip().lower()
    if lowered.startswith(("mailto:", "tel:", "javascript:", "data:")):
        return False

    try:
        absolute_url = urljoin(page_url, candidate_url)
    except ValueError:
        return False

    parsed = _safe_urlparse(absolute_url)
    return bool(parsed.netloc and parsed.netloc.lower() != base_host)


def _is_null_or_self_redirect(href: str) -> bool:
    lowered = (href or "").strip().lower()
    return lowered in {"", "#", "#content", "#top", "javascript:void(0)", "javascript:;"} or lowered.startswith("javascript:void")


def _right_click_disabled(html_lower: str) -> bool:
    return (
        "oncontextmenu" in html_lower
        or ("contextmenu" in html_lower and ("preventdefault" in html_lower or "return false" in html_lower))
    )


def _ratio_percent(count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((count / total) * 100.0, 4)


def _ratio_triplet(count: int, total: int, warn: float, bad: float) -> float:
    if total <= 0:
        return 1.0
    ratio = count / total
    if ratio >= bad:
        return -1.0
    if ratio >= warn:
        return 0.0
    return 1.0


def _threshold_triplet(value: float, warn: float, bad: float) -> float:
    if value >= bad:
        return -1.0
    if value >= warn:
        return 0.0
    return 1.0


def _safe_urlparse(url: str):
    try:
        return urlparse(url if str(url).startswith(("http://", "https://")) else f"http://{url}")
    except ValueError:
        return urlparse("http://")
