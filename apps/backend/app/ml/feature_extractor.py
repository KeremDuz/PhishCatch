import math
import re
from urllib.parse import urlparse

import pandas as pd


URL_FEATURE_COLUMNS = [
    "UrlLength",
    "HostnameLength",
    "PathLength",
    "QueryLength",
    "FirstDirLength",
    "NumDots",
    "SubdomainLevel",
    "PathLevel",
    "NumDash",
    "NumDashInHostname",
    "AtSymbol",
    "TildeSymbol",
    "NumUnderscore",
    "NumPercent",
    "NumQueryComponents",
    "NumAmpersand",
    "NumHash",
    "NumNumericChars",
    "NumLetterChars",
    "NoHttps",
    "IpAddress",
    "IsShortened",
    "RandomString",
    "UrlEntropy",
    "NumSensitiveWords",
    "EmbeddedBrandName",
    "DomainInSubdomains",
    "DomainInPaths",
    "HttpsInHostname",
    "DoubleSlashInPath",
]

MENDELEY_48_FEATURE_COLUMNS = [
    "NumDots",
    "SubdomainLevel",
    "PathLevel",
    "UrlLength",
    "NumDash",
    "NumDashInHostname",
    "AtSymbol",
    "TildeSymbol",
    "NumUnderscore",
    "NumPercent",
    "NumQueryComponents",
    "NumAmpersand",
    "NumHash",
    "NumNumericChars",
    "NoHttps",
    "RandomString",
    "IpAddress",
    "DomainInSubdomains",
    "DomainInPaths",
    "HttpsInHostname",
    "HostnameLength",
    "PathLength",
    "QueryLength",
    "DoubleSlashInPath",
    "NumSensitiveWords",
    "EmbeddedBrandName",
    "PctExtHyperlinks",
    "PctExtResourceUrls",
    "ExtFavicon",
    "InsecureForms",
    "RelativeFormAction",
    "ExtFormAction",
    "AbnormalFormAction",
    "PctNullSelfRedirectHyperlinks",
    "FrequentDomainNameMismatch",
    "FakeLinkInStatusBar",
    "RightClickDisabled",
    "PopUpWindow",
    "SubmitInfoToEmail",
    "IframeOrFrame",
    "MissingTitle",
    "ImagesOnlyInForm",
    "SubdomainLevelRT",
    "UrlLengthRT",
    "PctExtResourceUrlsRT",
    "AbnormalExtFormActionR",
    "ExtMetaScriptLinkRT",
    "PctExtNullSelfRedirectHyperlinksRT",
]

# Default training/runtime schema for new models. It only uses URL-visible
# signals; DOM/form/page-content signals belong to HtmlScraperScanner.
FEATURE_COLUMNS = URL_FEATURE_COLUMNS

LEGACY_FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "first_dir_length",
    "dot_count",
    "hyphen_count",
    "at_symbol_count",
    "slash_count",
    "question_mark_count",
    "equal_count",
    "digit_count",
    "letter_count",
    "entropy",
    "has_ip_in_domain",
    "has_suspicious_word",
    "is_shortened",
]

SENSITIVE_WORDS = [
    "login",
    "secure",
    "update",
    "account",
    "verify",
    "bank",
    "free",
    "admin",
    "webscr",
    "password",
    "signin",
    "wallet",
    "token",
]

BRAND_WORDS = [
    "paypal",
    "apple",
    "microsoft",
    "google",
    "facebook",
    "instagram",
    "netflix",
    "amazon",
    "whatsapp",
    "telegram",
    "bank",
]

SHORTENERS = ["bit.ly", "goo.gl", "tinyurl", "t.co", "is.gd", "ow.ly", "cutt.ly"]


def _safe_urlparse(url: str):
    return urlparse(url if str(url).startswith(("http://", "https://")) else f"http://{url}")


def _is_ip(hostname: str) -> int:
    return 1 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", hostname or "") else 0


def _random_string_score(url: str) -> int:
    tokens = re.findall(r"[a-z0-9]{12,}", url.lower())
    return 1 if tokens else 0


def _count_path_level(path: str) -> int:
    return len([segment for segment in (path or "").split("/") if segment])


def _subdomain_level(hostname: str) -> int:
    parts = [part for part in (hostname or "").split(".") if part]
    if len(parts) <= 2:
        return 0
    if parts and parts[0] == "www":
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def calculate_entropy(url: str) -> float:
    if not url:
        return 0.0

    entropy = 0.0
    for character in set(url):
        probability = float(url.count(character)) / len(url)
        entropy += -probability * math.log(probability, 2)
    return round(float(entropy), 4)


def extract_url_features(url: str) -> pd.Series:
    if not isinstance(url, str):
        return pd.Series({column: 0.0 for column in URL_FEATURE_COLUMNS})

    url_lower = url.lower()
    parsed = _safe_urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    path_parts = [part for part in path.split("/") if part]
    subdomain = hostname.split(".")[0] if hostname else ""

    sensitive_count = sum(1 for word in SENSITIVE_WORDS if word in url_lower)
    embedded_brand = 1 if any(word in url_lower for word in BRAND_WORDS) else 0

    features = {
        "UrlLength": float(len(url)),
        "HostnameLength": float(len(hostname)),
        "PathLength": float(len(path)),
        "QueryLength": float(len(query)),
        "FirstDirLength": float(len(path_parts[0])) if path_parts else 0.0,
        "NumDots": float(url.count(".")),
        "SubdomainLevel": float(_subdomain_level(hostname)),
        "PathLevel": float(_count_path_level(path)),
        "NumDash": float(url.count("-")),
        "NumDashInHostname": float(hostname.count("-")),
        "AtSymbol": float(url.count("@")),
        "TildeSymbol": float(url.count("~")),
        "NumUnderscore": float(url.count("_")),
        "NumPercent": float(url.count("%")),
        "NumQueryComponents": float(len([part for part in query.split("&") if part]) if query else 0),
        "NumAmpersand": float(url.count("&")),
        "NumHash": float(url.count("#")),
        "NumNumericChars": float(sum(character.isdigit() for character in url)),
        "NumLetterChars": float(sum(character.isalpha() for character in url)),
        "NoHttps": float(0 if parsed.scheme == "https" else 1),
        "IpAddress": float(_is_ip(hostname)),
        "IsShortened": float(1 if any(short in hostname for short in SHORTENERS) else 0),
        "RandomString": float(_random_string_score(url)),
        "UrlEntropy": float(calculate_entropy(url)),
        "NumSensitiveWords": float(sensitive_count),
        "EmbeddedBrandName": float(embedded_brand),
        "DomainInSubdomains": float(1 if any(word in subdomain for word in BRAND_WORDS) else 0),
        "DomainInPaths": float(1 if any(word in path.lower() for word in BRAND_WORDS) else 0),
        "HttpsInHostname": float(1 if "https" in hostname else 0),
        "DoubleSlashInPath": float(1 if "//" in path else 0),
    }

    return pd.Series(features, index=URL_FEATURE_COLUMNS)


def extract_48_features(url: str) -> pd.Series:
    if not isinstance(url, str):
        return pd.Series({column: 0.0 for column in MENDELEY_48_FEATURE_COLUMNS})

    url_lower = url.lower()
    parsed = _safe_urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    subdomain = hostname.split(".")[0] if hostname else ""

    sensitive_count = sum(1 for word in SENSITIVE_WORDS if word in url_lower)
    embedded_brand = 1 if any(word in url_lower for word in BRAND_WORDS) else 0
    http_links_like = len(re.findall(r"https?%3a|https?://", url_lower))
    resource_hits = len(re.findall(r"\.js|\.css|\.png|\.jpg|\.svg|\.ico", url_lower))

    features = {
        "NumDots": float(url.count(".")),
        "SubdomainLevel": float(_subdomain_level(hostname)),
        "PathLevel": float(_count_path_level(path)),
        "UrlLength": float(len(url)),
        "NumDash": float(url.count("-")),
        "NumDashInHostname": float(hostname.count("-")),
        "AtSymbol": float(url.count("@")),
        "TildeSymbol": float(url.count("~")),
        "NumUnderscore": float(url.count("_")),
        "NumPercent": float(url.count("%")),
        "NumQueryComponents": float(len([part for part in query.split("&") if part]) if query else 0),
        "NumAmpersand": float(url.count("&")),
        "NumHash": float(url.count("#")),
        "NumNumericChars": float(sum(character.isdigit() for character in url)),
        "NoHttps": float(0 if parsed.scheme == "https" else 1),
        "RandomString": float(_random_string_score(url)),
        "IpAddress": float(_is_ip(hostname)),
        "DomainInSubdomains": float(1 if any(word in subdomain for word in BRAND_WORDS) else 0),
        "DomainInPaths": float(1 if any(word in path.lower() for word in BRAND_WORDS) else 0),
        "HttpsInHostname": float(1 if "https" in hostname else 0),
        "HostnameLength": float(len(hostname)),
        "PathLength": float(len(path)),
        "QueryLength": float(len(query)),
        "DoubleSlashInPath": float(1 if "//" in path else 0),
        "NumSensitiveWords": float(sensitive_count),
        "EmbeddedBrandName": float(embedded_brand),
        "PctExtHyperlinks": float(min(100.0, http_links_like * 20.0)),
        "PctExtResourceUrls": float(min(100.0, resource_hits * 20.0)),
        "ExtFavicon": float(1 if "favicon" in url_lower and "http" in url_lower else 0),
        "InsecureForms": float(1 if parsed.scheme == "http" and "login" in url_lower else 0),
        "RelativeFormAction": float(1 if "?" in url and not query.startswith("http") else 0),
        "ExtFormAction": float(1 if "redirect=" in url_lower or "url=" in url_lower else 0),
        "AbnormalFormAction": float(1 if "javascript:" in url_lower else 0),
        "PctNullSelfRedirectHyperlinks": float(100.0 if "#" in url else 0.0),
        "FrequentDomainNameMismatch": float(
            1 if embedded_brand and any(tld in hostname for tld in ["xyz", "top", "rest", "click"]) else 0
        ),
        "FakeLinkInStatusBar": float(1 if "status" in url_lower and "bar" in url_lower else 0),
        "RightClickDisabled": float(1 if "rightclick" in url_lower else 0),
        "PopUpWindow": float(1 if "popup" in url_lower or "pop" in query.lower() else 0),
        "SubmitInfoToEmail": float(1 if "mailto" in url_lower else 0),
        "IframeOrFrame": float(1 if "iframe" in url_lower or "frame" in url_lower else 0),
        "MissingTitle": 0.0,
        "ImagesOnlyInForm": 0.0,
        "SubdomainLevelRT": float(min(1.0, _subdomain_level(hostname) / 3.0)),
        "UrlLengthRT": float(min(1.0, len(url) / 120.0)),
        "PctExtResourceUrlsRT": float(min(1.0, (resource_hits * 20.0) / 100.0)),
        "AbnormalExtFormActionR": float(1 if "redirect" in url_lower and "http" in url_lower else 0),
        "ExtMetaScriptLinkRT": float(min(1.0, (resource_hits + url_lower.count("script")) / 5.0)),
        "PctExtNullSelfRedirectHyperlinksRT": float(1.0 if "#" in url else 0.0),
    }

    return pd.Series(features, index=MENDELEY_48_FEATURE_COLUMNS)


def extract_legacy_features_dict(url: str) -> dict[str, float]:
    if not isinstance(url, str):
        url = ""

    url_lower = url.lower()
    parsed_url = _safe_urlparse(url)
    path_parts = [part for part in parsed_url.path.split("/") if part]

    return {
        "url_length": float(len(url)),
        "hostname_length": float(len(parsed_url.netloc)),
        "path_length": float(len(parsed_url.path)),
        "first_dir_length": float(len(path_parts[0])) if path_parts else 0.0,
        "dot_count": float(url.count(".")),
        "hyphen_count": float(url.count("-")),
        "at_symbol_count": float(url.count("@")),
        "slash_count": float(url.count("/")),
        "question_mark_count": float(url.count("?")),
        "equal_count": float(url.count("=")),
        "digit_count": float(sum(character.isdigit() for character in url)),
        "letter_count": float(sum(character.isalpha() for character in url)),
        "entropy": float(calculate_entropy(url)),
        "has_ip_in_domain": float(_is_ip(parsed_url.netloc)),
        "has_suspicious_word": float(1 if any(word in url_lower for word in SENSITIVE_WORDS) else 0),
        "is_shortened": float(1 if any(short in parsed_url.netloc for short in SHORTENERS) else 0),
    }


def extract_legacy_features_dataframe(url: str) -> pd.DataFrame:
    return pd.DataFrame([extract_legacy_features_dict(url)], columns=LEGACY_FEATURE_COLUMNS)


def extract_48_features_dataframe(url: str) -> pd.DataFrame:
    return pd.DataFrame([extract_48_features(url).to_dict()], columns=MENDELEY_48_FEATURE_COLUMNS)


def extract_url_features_dataframe(url: str) -> pd.DataFrame:
    return pd.DataFrame([extract_url_features(url).to_dict()], columns=URL_FEATURE_COLUMNS)


def extract_features_dict(url: str) -> dict[str, float]:
    return extract_url_features(url).to_dict()


def extract_features_dataframe(url: str) -> pd.DataFrame:
    return extract_url_features_dataframe(url)
