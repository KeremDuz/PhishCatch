from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlparse

import pandas as pd


FEATURE_COLUMNS = [
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

BALANCED_URLS_PATH = Path("balanced_urls.csv")
MENDELEY_INDEX_PATH = Path("Mendeley_dataset/index.sql")


def _safe_urlparse(url: str):
    return urlparse(url if str(url).startswith(("http://", "https://")) else f"http://{url}")


def _is_ip(hostname: str) -> int:
    return 1 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", hostname or "") else 0


def _random_string_score(url: str) -> int:
    token_pattern = re.compile(r"[a-z0-9]{12,}")
    tokens = token_pattern.findall(url.lower())
    return 1 if tokens else 0


def _count_path_level(path: str) -> int:
    return len([segment for segment in (path or "").split("/") if segment])


def _subdomain_level(hostname: str) -> int:
    parts = [p for p in (hostname or "").split(".") if p]
    if len(parts) <= 2:
        return 0
    if parts and parts[0] == "www":
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def extract_48_features(url: str) -> pd.Series:
    if not isinstance(url, str):
        return pd.Series({column: 0.0 for column in FEATURE_COLUMNS})

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
        "NumQueryComponents": float(len([p for p in query.split("&") if p]) if query else 0),
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
        "FrequentDomainNameMismatch": float(1 if embedded_brand and any(tld in hostname for tld in ["xyz", "top", "rest", "click"]) else 0),
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

    return pd.Series(features, index=FEATURE_COLUMNS)


def _load_mendeley_urls(index_sql_path: Path) -> pd.DataFrame:
    if not index_sql_path.exists():
        return pd.DataFrame(columns=["url", "result"])

    sql_text = index_sql_path.read_text(encoding="utf-8", errors="ignore")
    tuple_pattern = re.compile(
        r"\(\s*\d+\s*,\s*'((?:\\'|[^'])*)'\s*,\s*'((?:\\'|[^'])*)'\s*,\s*(\d+)\s*,\s*'((?:\\'|[^'])*)'\s*\)",
        re.DOTALL,
    )

    rows: list[dict[str, object]] = []
    for url_value, _website_value, result_value, _created_date in tuple_pattern.findall(sql_text):
        cleaned_url = url_value.replace("\\'", "'").strip()
        if cleaned_url:
            rows.append({"url": cleaned_url, "result": int(result_value)})

    if not rows:
        return pd.DataFrame(columns=["url", "result"])

    return pd.DataFrame(rows)


def _merge_and_deduplicate_url_sets(base_dataframe: pd.DataFrame, extra_dataframe: pd.DataFrame) -> pd.DataFrame:
    combined = pd.concat([base_dataframe[["url", "result"]], extra_dataframe[["url", "result"]]], ignore_index=True)
    combined = combined.dropna(subset=["url", "result"]).copy()
    combined["url"] = combined["url"].astype(str).str.strip()
    combined = combined[combined["url"] != ""]
    combined["result"] = combined["result"].astype(int)

    grouped = (
        combined.groupby("url", as_index=False)
        .agg(result_mean=("result", "mean"), vote_count=("result", "size"))
    )
    grouped["result"] = (grouped["result_mean"] >= 0.5).astype(int)

    return grouped[["url", "result"]]


def main() -> None:
    print("1. balanced_urls.csv yükleniyor...")
    dataframe = pd.read_csv(BALANCED_URLS_PATH)

    if "url" not in dataframe.columns or "result" not in dataframe.columns:
        raise ValueError("balanced_urls.csv must contain 'url' and 'result' columns")

    print("2. Mendeley_dataset/index.sql kontrol ediliyor...")
    mendeley_dataframe = _load_mendeley_urls(MENDELEY_INDEX_PATH)
    if len(mendeley_dataframe) > 0:
        print(f"Mendeley etiketli URL bulundu: {len(mendeley_dataframe)}")
        dataframe = _merge_and_deduplicate_url_sets(dataframe, mendeley_dataframe)
        print(f"Birleşik ve tekilleştirilmiş URL sayısı: {len(dataframe)}")
    else:
        dataframe = dataframe[["url", "result"]].dropna().copy()
        dataframe["result"] = dataframe["result"].astype(int)
        print("Mendeley verisi bulunamadı, yalnızca balanced_urls.csv kullanılacak.")

    print("3. 48 feature çıkarılıyor... (birkaç dakika sürebilir)")
    extracted = dataframe["url"].apply(extract_48_features)

    final_dataframe = pd.concat([dataframe["result"].astype(int), extracted], axis=1)
    output_path = "phishcatch_training_data_48.csv"
    final_dataframe.to_csv(output_path, index=False)

    print(f"4. Tamamlandı: '{output_path}' oluşturuldu.")
    print(f"Satır sayısı: {len(final_dataframe)}")
    print(f"Kolon sayısı: {len(final_dataframe.columns)} (1 label + 48 feature)")


if __name__ == "__main__":
    main()