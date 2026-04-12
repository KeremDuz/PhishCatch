import math
import re
from urllib.parse import urlparse

import pandas as pd


SUSPICIOUS_WORDS = [
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
]

SHORTENERS = ["bit.ly", "goo.gl", "tinyurl", "t.co", "is.gd", "ow.ly", "cutt.ly"]


# This extractor intentionally mirrors training-time features for consistency.
def calculate_entropy(url: str) -> float:
    if not url:
        return 0.0

    entropy = 0.0
    for character in set(url):
        probability = float(url.count(character)) / len(url)
        entropy += -probability * math.log(probability, 2)
    return round(float(entropy), 4)


def extract_features_dict(url: str) -> dict[str, float]:
    if not isinstance(url, str):
        url = ""

    url_lower = url.lower()
    parsed_url = urlparse(url) if url.startswith("http") else urlparse("http://" + url)

    path_parts = [part for part in parsed_url.path.split("/") if part]

    features = {
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
        "has_ip_in_domain": float(1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed_url.netloc) else 0),
        "has_suspicious_word": float(1 if any(word in url_lower for word in SUSPICIOUS_WORDS) else 0),
        "is_shortened": float(1 if any(short in parsed_url.netloc for short in SHORTENERS) else 0),
    }
    return features


def extract_features_dataframe(url: str) -> pd.DataFrame:
    return pd.DataFrame([extract_features_dict(url)])
