from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
import numpy as np
from bs4 import BeautifulSoup


@dataclass
class ExtractedFeaturePayload:
    vector: np.ndarray
    feature_map: dict[str, float]
    html_fetched: bool
    fetch_error: str | None = None


class FeatureExtractor:
    FEATURE_VECTOR_SIZE = 48
    CORE_FEATURES = [
        "PctExtNullSelfRedirectHyperlinksRT",
        "PctExtHyperlinks",
        "FrequentDomainNameMismatch",
        "InsecureForms",
        "PctNullHyperlinks",
        "NumHyperlinks",
        "NumForms",
        "NumExternalResources",
        "NumScripts",
        "NumIframes",
    ]

    def __init__(self, timeout_seconds: float = 4.0, verify_ssl: bool | str = True) -> None:
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl

    async def extract(self, url: str) -> ExtractedFeaturePayload:
        normalized_url = self._normalize_url(url)
        html, error = await self._fetch_html(normalized_url)

        if not html:
            vector = np.zeros((1, self.FEATURE_VECTOR_SIZE), dtype=np.float32)
            return ExtractedFeaturePayload(
                vector=vector,
                feature_map={name: 0.0 for name in self.CORE_FEATURES},
                html_fetched=False,
                fetch_error=error,
            )

        soup = BeautifulSoup(html, "html.parser")
        core_features = self._build_core_features(normalized_url, soup)
        vector = self._build_padded_vector(core_features)
        return ExtractedFeaturePayload(vector=vector, feature_map=core_features, html_fetched=True)

    def _build_padded_vector(self, core_features: dict[str, float]) -> np.ndarray:
        values = [float(core_features.get(name, 0.0)) for name in self.CORE_FEATURES]
        if len(values) < self.FEATURE_VECTOR_SIZE:
            values.extend([0.0] * (self.FEATURE_VECTOR_SIZE - len(values)))
        return np.array([values[: self.FEATURE_VECTOR_SIZE]], dtype=np.float32)

    def _build_core_features(self, url: str, soup: BeautifulSoup) -> dict[str, float]:
        parsed_url = urlparse(url)
        page_domain = parsed_url.netloc.lower()

        anchors = soup.find_all("a", href=True)
        forms = soup.find_all("form")
        scripts = soup.find_all("script")
        iframes = soup.find_all("iframe")

        external_links = 0
        null_or_self_redirect_links = 0
        null_links = 0
        mismatched_domains = 0

        for anchor in anchors:
            href = (anchor.get("href") or "").strip()
            if not href:
                null_links += 1
                null_or_self_redirect_links += 1
                continue

            href_lower = href.lower()
            if href_lower in {"#", "javascript:void(0)", "javascript:void(0);"}:
                null_links += 1
                null_or_self_redirect_links += 1
                continue

            full_href = urljoin(url, href)
            link_domain = urlparse(full_href).netloc.lower()

            if link_domain and link_domain != page_domain:
                external_links += 1
                mismatched_domains += 1

            if full_href == url:
                null_or_self_redirect_links += 1

        img_count = len(soup.find_all("img", src=True))
        link_tag_count = len(soup.find_all("link", href=True))
        media_count = len(soup.find_all(["audio", "video", "source"]))
        external_resources = img_count + link_tag_count + media_count

        insecure_forms = 0
        for form in forms:
            action = (form.get("action") or "").strip().lower()
            if parsed_url.scheme == "https" and action.startswith("http://"):
                insecure_forms += 1

        total_links = len(anchors) if anchors else 1
        total_forms = len(forms) if forms else 1

        return {
            "PctExtNullSelfRedirectHyperlinksRT": (null_or_self_redirect_links / total_links) * 100,
            "PctExtHyperlinks": (external_links / total_links) * 100,
            "FrequentDomainNameMismatch": 1.0 if mismatched_domains > (len(anchors) * 0.5) else 0.0,
            "InsecureForms": (insecure_forms / total_forms) * 100,
            "PctNullHyperlinks": (null_links / total_links) * 100,
            "NumHyperlinks": float(len(anchors)),
            "NumForms": float(len(forms)),
            "NumExternalResources": float(external_resources),
            "NumScripts": float(len(scripts)),
            "NumIframes": float(len(iframes)),
        }

    async def _fetch_html(self, url: str) -> tuple[str | None, str | None]:
        timeout = httpx.Timeout(self.timeout_seconds)
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                verify=self.verify_ssl,
            ) as client:
                response = await client.get(url)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    return None, f"Unsupported content type: {content_type}"
                return response.text, None
        except Exception as exc:
            return None, str(exc)

    @staticmethod
    def _normalize_url(url: str) -> str:
        value = (url or "").strip()
        if not value:
            return ""
        if not value.startswith(("http://", "https://")):
            return f"https://{value}"
        return value
