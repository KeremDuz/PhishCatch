import re
import unicodedata
from pathlib import Path

import joblib
import requests
from bs4 import BeautifulSoup, UnicodeDammit
from urllib.parse import urlparse

from app.ml.html_feature_extractor import extract_html_features_dataframe
from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.browser_renderer import BrowserRenderResult, render_page
from app.services.page_fetch import BufferedPageResponse, fetch_page
from app.services.html_policy import assess_dom, external_form_targets, resolve_target, site_key
from app.services.url_heuristic_scanner import BRAND_TERMS, FREE_HOSTING_SUFFIXES, LEGITIMATE_BRAND_HOSTS
from app.utils.url_utils import hostname_matches_allowed


# ─── Hacker'ın çalmak istediği veri türleri ve bunları yakalayan kalıplar ───

# 1. Credential theft (en yaygın)
CREDENTIAL_PATTERNS = [
    "password", "passwd", "pass", "pwd", "sifre", "parola",
    "login", "signin", "sign_in", "giris", "oturum",
]

# 2. Kredi kartı bilgisi
CREDIT_CARD_PATTERNS = [
    "card", "credit", "cc_number", "cardnum", "kartno", "kart_no",
    "card_number", "creditcard", "debit",
]

CVV_PATTERNS = [
    "cvv", "cvc", "cvc2", "cvv2", "security_code", "guvenlik_kodu",
    "card_code", "sec_code",
]

EXPIRY_PATTERNS = [
    "expiry", "exp_month", "exp_year", "expiration", "son_kullanma",
    "mm_yy", "valid_thru", "card_exp",
]

# 3. Banka bilgisi
BANKING_PATTERNS = [
    "iban", "account_number", "routing", "sort_code", "swift",
    "bic", "bank_account", "hesap_no", "hesap_numarasi",
]

PIN_OTP_PATTERNS = [
    "pin", "otp", "verification", "dogrulama", "sms_code",
    "auth_code", "onay_kodu", "verify_code", "2fa", "mfa",
    "one_time", "tek_kullanimlik",
]

# 4. Kimlik / kişisel bilgi
IDENTITY_PATTERNS = [
    "ssn", "social_security", "tc", "tckimlik", "tc_kimlik",
    "kimlik_no", "identity", "national_id", "citizen",
    "date_of_birth", "dob", "dogum_tarihi",
]

# 5. Crypto wallet
CRYPTO_PATTERNS = [
    "seed", "mnemonic", "private_key", "wallet", "recovery_phrase",
    "secret_key", "passphrase", "seed_phrase",
]

# Standard browser autofill hints identify field purpose, not malicious behavior.
SENSITIVE_AUTOCOMPLETE = [
    "cc-number", "cc-exp", "cc-csc", "cc-name", "cc-type",
    "new-password", "current-password",
]

# 7. JS keylogger kalıpları
KEYLOGGER_PATTERNS = [
    r"addEventListener\s*\(\s*['\"]key(?:down|press|up)['\"]",
    r"onkeydown\s*=", r"onkeypress\s*=", r"onkeyup\s*=",
    r"document\.onkey",
]

# 8. Exfiltration (veriyi dışarı gönderme) kalıpları — hassas veri referansı gerekli
EXFIL_PATTERNS = [
    r"new\s+WebSocket\s*\(",
    r"navigator\.sendBeacon\s*\(",
    r"\.send\s*\(.*(?:password|card|cvv|pin|otp|ssn|iban)",
    r"fetch\s*\(.*(?:password|card|cvv|pin|otp|ssn|iban)",
]


def _attr_matches(value: str, patterns: list[str]) -> bool:
    """Match identifier tokens, including camelCase and Turkish labels."""
    if not value:
        return False

    def normalized(text: str) -> str:
        text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
        text = unicodedata.normalize("NFKD", text.casefold().replace("ı", "i"))
        text = "".join(char for char in text if not unicodedata.combining(char))
        return " ".join(re.findall(r"[a-z0-9]+", text))

    tokens = f" {normalized(value)} "
    return any(f" {normalized(pattern)} " in tokens for pattern in patterns)


def _scan_inputs(soup: BeautifulSoup) -> dict:
    """Sayfadaki TÜM input mekanizmalarını tara ve sınıflandır.

    Bir hacker veri toplamak için şunları kullanabilir:
    - <input> (text, password, tel, number, email, hidden, file)
    - <textarea> (seed phrase, notlar)
    - <select> (ay/yıl dropdown)
    - contenteditable="true" div'ler
    - <label> text'inden ipucu (input'un kendisinde attribute yoksa)
    - class, data-*, inputmode attribute'ları
    - <button formaction="evil.com"> ile form action override
    - type="hidden" ile sessiz veri sızdırma
    """
    findings = {
        "credentials": [],
        "credit_card": [],
        "cvv": [],
        "expiry": [],
        "banking": [],
        "pin_otp": [],
        "identity": [],
        "crypto": [],
        "file_upload": [],
        "hidden_exfil": [],
        "sensitive_autocomplete": [],
        "hidden_fields": [],
    }

    # ── 1. Label → input eşleştirme haritası ──
    # <label for="myInput">Şifreniz:</label> <input id="myInput" type="text">
    # Input'un attribute'unda ipucu yok ama label'da var
    label_map: dict[str, str] = {}
    for label in soup.find_all("label"):
        for_attr = label.get("for", "")
        label_text = label.get_text(strip=True).lower()
        if for_attr and label_text:
            label_map[for_attr] = label_text

    # ── 2. Tüm form elementlerini tara ──
    all_inputs = soup.find_all(["input", "textarea", "select"])

    for element in all_inputs:
        tag_name = element.name
        input_type = (element.get("type") or "text").lower()
        name = element.get("name", "") or ""
        id_attr = element.get("id", "") or ""
        placeholder = element.get("placeholder", "") or ""
        autocomplete = element.get("autocomplete", "") or ""
        aria_label = element.get("aria-label", "") or ""
        class_attr = " ".join(element.get("class", []))
        title_attr = element.get("title", "") or ""

        # data-* attribute'ları topla
        data_attrs = " ".join(
            str(v) for k, v in element.attrs.items()
            if isinstance(k, str) and k.startswith("data-")
        )

        # Label text'ini de kontrol et
        label_text = label_map.get(id_attr, "")

        # Tüm ipuçlarını birleştir
        all_attrs = (
            f"{name} {id_attr} {placeholder} {autocomplete} {aria_label} "
            f"{class_attr} {data_attrs} {label_text} {title_attr}"
        )

        # ── type="password" → her zaman credential ──
        if input_type == "password":
            findings["credentials"].append({
                "tag": tag_name, "type": input_type,
                "name": name, "id": id_attr,
            })
            continue

        # ── type="hidden" → sessiz veri sızdırma ──
        # Hacker bazen kullanıcı bilgisini hidden input'a koyar
        if input_type == "hidden":
            # Do not retain hidden values (CSRF/session tokens) in scan metadata.
            findings["hidden_fields"].append({"tag": tag_name, "name": name})
            continue

        # ── type="file" → kimlik belgesi yükleme ──
        if input_type == "file":
            accept = element.get("accept", "") or ""
            findings["file_upload"].append({
                "tag": tag_name, "name": name, "id": id_attr,
                "accept": accept,
            })
            continue

        # ── Autocomplete abuse ──
        if autocomplete and autocomplete.lower() in SENSITIVE_AUTOCOMPLETE:
            findings["sensitive_autocomplete"].append({
                "tag": tag_name, "autocomplete": autocomplete,
                "name": name, "id": id_attr,
            })

        # ── Credential kalıpları ──
        if _attr_matches(all_attrs, CREDENTIAL_PATTERNS):
            findings["credentials"].append({
                "tag": tag_name, "type": input_type,
                "name": name, "id": id_attr,
                "matched_via": "attribute/label",
            })

        # ── Kredi kartı ──
        if _attr_matches(all_attrs, CREDIT_CARD_PATTERNS):
            findings["credit_card"].append({
                "tag": tag_name, "type": input_type,
                "name": name, "id": id_attr, "placeholder": placeholder,
            })

        # ── CVV ──
        if _attr_matches(all_attrs, CVV_PATTERNS):
            findings["cvv"].append({
                "tag": tag_name, "name": name,
            })

        # ── Expiry ──
        if _attr_matches(all_attrs, EXPIRY_PATTERNS):
            findings["expiry"].append({
                "tag": tag_name, "name": name,
            })
        if tag_name == "select" and _attr_matches(
            all_attrs, EXPIRY_PATTERNS + ["month", "year", "ay", "yil"]
        ):
            findings["expiry"].append({
                "tag": "select", "name": name,
            })

        # ── Banka ──
        if _attr_matches(all_attrs, BANKING_PATTERNS):
            findings["banking"].append({
                "tag": tag_name, "name": name,
            })

        # ── PIN / OTP (attribute bazlı) ──
        if _attr_matches(all_attrs, PIN_OTP_PATTERNS) or autocomplete.lower() == "one-time-code":
            findings["pin_otp"].append({
                "tag": tag_name, "type": input_type, "name": name,
            })

        # ── Kimlik ──
        if _attr_matches(all_attrs, IDENTITY_PATTERNS):
            findings["identity"].append({
                "tag": tag_name, "name": name,
            })

        # ── Crypto ──
        if _attr_matches(all_attrs, CRYPTO_PATTERNS):
            findings["crypto"].append({
                "tag": tag_name, "name": name, "placeholder": placeholder,
            })

    # ── 3. contenteditable div'ler (modern JS-based input) ──
    editable_divs = soup.find_all(attrs={"contenteditable": "true"})
    if editable_divs:
        findings.setdefault("contenteditable", [])
        for div in editable_divs:
            findings["contenteditable"].append({
                "tag": div.name,
                "id": div.get("id", ""),
                "class": " ".join(div.get("class", [])),
            })

    # ── 4. <button formaction="evil.com"> override ──
    # Bir button, form'un action'ını override edebilir
    formaction_buttons = soup.find_all(["button", "input"], attrs={"formaction": True})
    if formaction_buttons:
        findings.setdefault("formaction_override", [])
        for btn in formaction_buttons:
            findings["formaction_override"].append({
                "tag": btn.name,
                "formaction": btn.get("formaction", "")[:200],
            })

    return findings


def _scan_js_threats(soup: BeautifulSoup, raw_html: str) -> dict:
    """JavaScript tabanlı tehditleri tara."""
    threats = {
        "keyloggers": [],
        "exfiltration": [],
        "popups": False,
        "right_click_disabled": False,
        "clipboard_hijack": False,
    }

    html_lower = raw_html.lower()

    # Script tag'larının içeriğini topla
    scripts_text = " ".join(
        script.string or "" for script in soup.find_all("script")
    )

    combined = f"{scripts_text} {html_lower}"

    # Keylogger detection
    for pattern in KEYLOGGER_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            threats["keyloggers"].extend(matches[:3])  # Max 3 örnek

    # Exfiltration detection
    for pattern in EXFIL_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            threats["exfiltration"].extend(matches[:3])

    # Popup / yeni pencere açma
    if "window.open(" in combined or "popup" in combined:
        threats["popups"] = True

    # Sağ tık engelleme (kullanıcıyı hapsetme)
    if "contextmenu" in combined and ("preventdefault" in combined or "return false" in combined):
        threats["right_click_disabled"] = True

    # Clipboard hijack (kripto adres değiştirme)
    if "clipboard" in combined or "execcommand" in combined and "copy" in combined:
        threats["clipboard_hijack"] = True

    return threats


def _scan_iframes(soup: BeautifulSoup, page_url: str) -> list:
    """Dış kaynaklı iframe'leri bul — form gizleme, overlay saldırısı."""
    suspicious = []
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "") or ""
        resolved = resolve_target(soup, page_url, src)
        if resolved:
            iframe_domain = urlparse(resolved).hostname
            if iframe_domain and site_key(resolved) != site_key(page_url):
                suspicious.append({
                    "domain": iframe_domain,
                    "hidden": iframe.get("style", "").find("display:none") >= 0
                              or iframe.get("width") == "0"
                              or iframe.get("height") == "0",
                })
    return suspicious


class HtmlScraperScanner(BaseScanner):
    def __init__(
        self,
        model_path: str | None = None,
        browser_render_enabled: bool = False,
        browser_timeout_ms: int = 7000,
        browser_screenshot_enabled: bool = False,
        isolated: bool = False,
    ) -> None:
        super().__init__(name="HtmlScraper")
        self.max_redirects = 5
        self.model_path = model_path
        self.model = self._load_model(model_path)
        self.browser_render_enabled = browser_render_enabled
        self.browser_timeout_ms = browser_timeout_ms
        self.browser_screenshot_enabled = browser_screenshot_enabled
        self.isolated = isolated

    def scan(self, url: str) -> StageResult:
        try:
            if self.isolated:
                from app.services.worker_process import run_worker
                page = fetch_page(url)
                result = run_worker("html", {"page": page.to_wire(), "model_path": self.model_path}, timeout=20)
                if "error" in result:
                    raise ValueError("Isolated HTML analysis failed")
                return StageResult.model_validate({**result["stage"], "training_features": result["training_features"]})
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response, final_url, redirect_chain = self._safe_get(url, headers=headers)
            try:
                response.raise_for_status()
            except requests.RequestException:
                response.close()
                raise
            parsed_url = urlparse(final_url)

            content_type = response.headers.get("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() not in {"text/html", "application/xhtml+xml"}:
                response.close()
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    status="unavailable",
                    risk_score=0.0,
                    reason="Target is not a valid HTML page",
                )

            # Maksimum 1MB indir
            html_bytes = b""
            try:
                for chunk in response.iter_content(chunk_size=1024 * 100):
                    html_bytes += chunk
                    if len(html_bytes) > 1024 * 1024:
                        return StageResult(
                            scanner=self.name, verdict="unknown", status="failed",
                            reason="HTML content exceeds the analysis size limit",
                            details={"error": "html_too_large"},
                        )
            finally:
                response.close()

            decoded = UnicodeDammit(html_bytes, is_html=True)
            raw_html = decoded.unicode_markup
            if raw_html is None:
                raise ValueError("HTML encoding could not be decoded")
            soup = BeautifulSoup(raw_html, "lxml")
            browser_render = self._maybe_render_html(final_url, raw_html, soup)
            needs_dynamic_analysis = self._should_try_browser_render(raw_html, soup) and not browser_render.available
            if browser_render.available and browser_render.html:
                raw_html = browser_render.html
                final_url = browser_render.final_url or final_url
                parsed_url = urlparse(final_url)
                soup = BeautifulSoup(raw_html, "lxml")

            # ── Analiz ──
            input_findings = _scan_inputs(soup)
            js_threats = _scan_js_threats(soup, raw_html)
            external_iframes = _scan_iframes(soup, final_url)
            html_model_result = self._predict_html_model(final_url, raw_html)
            html_training_features = html_model_result.pop("features", None)

            forms = soup.find_all("form")
            external_actions, abnormal_actions = external_form_targets(soup, final_url)

            title = soup.title.string.strip()[:256] if soup.title and soup.title.string else None
            visual_brand_signals = self._scan_visual_brand_signals(soup, final_url, input_findings)

            # Normal form controls are observations. Risk needs contextual evidence.
            assessment = assess_dom(soup, final_url, input_findings, js_threats, visual_brand_signals)
            threat_score = assessment.score
            reasons = list(assessment.reasons)

            # ── Karar ──
            rule_threat_score = min(threat_score, 1.0)
            threat_score = self._combine_rule_and_model_scores(rule_threat_score, html_model_result)
            if html_model_result.get("available") and html_model_result.get("model_risk_score", 0.0) >= 0.3:
                reasons.append(
                    f"HTML model phishing probability {html_model_result['malicious_probability']}"
                )

            # Aktif input sayısı (non-empty categories)
            active_categories = sum(
                1 for k, v in input_findings.items()
                if isinstance(v, list) and len(v) > 0
            )

            details = {
                "requires_review": assessment.requires_review or needs_dynamic_analysis,
                "rule_context": assessment.context,
                "dynamic_analysis": {"required": needs_dynamic_analysis, "available": browser_render.available},
                "title": title,
                "total_forms": len(forms),
                "external_form_actions": external_actions,
                "abnormal_form_actions": abnormal_actions,
                "rule_threat_score": round(rule_threat_score, 3),
                "threat_score": round(threat_score, 3),
                "html_model": html_model_result,
                "browser_render": browser_render.as_dict(),
                "visual_brand_signals": visual_brand_signals,
                "active_threat_categories": active_categories,
                "input_summary": {
                    k: len(v) for k, v in input_findings.items()
                    if isinstance(v, list) and len(v) > 0
                },
                "js_threats": {
                    k: (len(v) if isinstance(v, list) else v)
                    for k, v in js_threats.items()
                    if v
                },
                "external_iframes": len(external_iframes),
                "final_url": final_url,
                "redirect_chain": redirect_chain,
                "reasons": reasons,
            }

            if threat_score >= 0.6:
                return StageResult(
                    scanner=self.name,
                    verdict="malicious",
                    risk_score=round(threat_score, 4),
                    malicious_probability=html_model_result.get("malicious_probability"),
                    clean_probability=html_model_result.get("clean_probability"),
                    reason=" | ".join(reasons[:5]),
                    details=details,
                    training_features={"html_features": html_training_features} if html_training_features else {},
                )
            elif threat_score >= 0.3 or assessment.requires_review or needs_dynamic_analysis:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=round(threat_score, 4),
                    malicious_probability=html_model_result.get("malicious_probability"),
                    clean_probability=html_model_result.get("clean_probability"),
                    reason=" | ".join(reasons[:5]),
                    details=details,
                    training_features={"html_features": html_training_features} if html_training_features else {},
                )
            else:
                return StageResult(
                    scanner=self.name,
                    verdict="clean",
                    risk_score=round(threat_score, 4),
                    malicious_probability=html_model_result.get("malicious_probability"),
                    clean_probability=html_model_result.get("clean_probability"),
                    reason="DOM structure appears normal",
                    details=details,
                    training_features={"html_features": html_training_features} if html_training_features else {},
                )

        except Exception:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                status="failed",
                risk_score=None,
                reason="Failed to scrape HTML content",
                details={"error": "html_scan_failed"},
            )

    def _maybe_render_html(self, final_url: str, raw_html: str, soup: BeautifulSoup) -> BrowserRenderResult:
        if not self.browser_render_enabled:
            return BrowserRenderResult(available=False, final_url=final_url, reason="Browser render disabled")

        if not self._should_try_browser_render(raw_html, soup):
            return BrowserRenderResult(available=False, final_url=final_url, reason="Static HTML was sufficient")

        rendered = render_page(
            final_url,
            timeout_ms=self.browser_timeout_ms,
            screenshot=self.browser_screenshot_enabled,
        )
        if rendered.available and len(rendered.html) <= len(raw_html) and not rendered.visible_text:
            return BrowserRenderResult(
                available=False,
                final_url=rendered.final_url or final_url,
                reason="Browser render did not reveal additional content",
                error=rendered.error,
            )
        return rendered

    @staticmethod
    def _should_try_browser_render(raw_html: str, soup: BeautifulSoup) -> bool:
        text = soup.get_text(" ", strip=True)
        scripts = soup.find_all("script")
        inputs = soup.find_all("input")
        forms = soup.find_all("form")
        html_lower = raw_html.lower()
        has_app_shell = bool(soup.select("#root, #app, app-root, main-app, [data-reactroot]"))
        asks_for_javascript = "enable javascript" in html_lower or "requires javascript" in html_lower
        empty_app_shell = has_app_shell and any(
            not node.get_text(" ", strip=True) and not node.find(["form", "input", "article", "p"])
            for node in soup.select("#root, #app, app-root, main-app, [data-reactroot]")
        )
        # Raw byte length is not evidence that external scripts have been analyzed.
        sparse_shell = bool(scripts) and not inputs and not forms and len(text) < 200
        script_heavy_without_forms = len(scripts) >= 5 and not inputs and not forms and len(text) < 1200
        return asks_for_javascript or (empty_app_shell and bool(scripts)) or sparse_shell or script_heavy_without_forms

    def _scan_visual_brand_signals(
        self,
        soup: BeautifulSoup,
        final_url: str,
        input_findings: dict,
    ) -> list[dict[str, object]]:
        parsed = urlparse(final_url)
        hostname = (parsed.hostname or "").lower().strip(".")
        # Brand references in articles, social-login buttons and footer links are
        # not an identity claim. Prefer the page title and primary heading.
        visual_text = " ".join(tag.get_text(" ", strip=True) for tag in soup.find_all(["title", "h1"], limit=5))
        visual_haystack = visual_text.lower()
        brand_hits = sorted(brand for brand in BRAND_TERMS if brand in visual_haystack)
        logo_hits = self._brand_asset_hits(soup)
        if not brand_hits and not logo_hits:
            return []

        credential_count = len(input_findings.get("credentials", []))
        sensitive_count = sum(
            len(input_findings.get(category, []))
            for category in ("credit_card", "cvv", "banking", "pin_otp", "identity", "crypto")
        )
        auth_context = credential_count > 0 or sensitive_count > 0 or bool(
            re.search(r"\b(sign in|signin|login|verify|password|wallet|account|security|support)\b", visual_haystack)
        )
        is_hosted = self._endswith_any(hostname, FREE_HOSTING_SUFFIXES)

        signals: list[dict[str, object]] = []
        suspicious_brands = [
            brand for brand in brand_hits if not self._is_legitimate_brand_host(hostname, brand)
        ]
        if suspicious_brands and auth_context:
            score = 0.45 if credential_count or sensitive_count else 0.32
            if is_hosted:
                score += 0.08
            signals.append(
                {
                    "rule": "visual_brand_mismatch",
                    "score": min(score, 0.6),
                    "brands": suspicious_brands[:5],
                    "reason": f"Page visually references brand(s) on unrelated host: {', '.join(suspicious_brands[:3])}",
                }
            )

        suspicious_logo_hits = [
            brand for brand in logo_hits if not self._is_legitimate_brand_host(hostname, brand)
        ]
        if suspicious_logo_hits and not signals and (credential_count or sensitive_count):
            signals.append(
                {
                    "rule": "brand_logo_asset_mismatch",
                    "score": 0.28 if auth_context else 0.18,
                    "brands": suspicious_logo_hits[:5],
                    "reason": f"Logo/favicon asset references brand(s) on unrelated host: {', '.join(suspicious_logo_hits[:3])}",
                }
            )

        return sorted(signals, key=lambda item: float(item["score"]), reverse=True)

    @staticmethod
    def _extract_visual_text(soup: BeautifulSoup) -> str:
        chunks: list[str] = []
        if soup.title and soup.title.string:
            chunks.append(soup.title.string)
        for tag_name in ("h1", "h2", "h3", "button", "label", "a", "span", "p"):
            for tag in soup.find_all(tag_name, limit=40):
                text = tag.get_text(" ", strip=True)
                if text:
                    chunks.append(text)
        for tag in soup.find_all(["img", "input"], limit=80):
            for attribute in ("alt", "aria-label", "placeholder", "value", "name", "id", "class", "src"):
                value = tag.get(attribute)
                if isinstance(value, list):
                    value = " ".join(str(item) for item in value)
                if value:
                    chunks.append(str(value))
        return " ".join(chunks)[:20000]

    @staticmethod
    def _brand_asset_hits(soup: BeautifulSoup) -> list[str]:
        values: list[str] = []
        for tag in soup.find_all(["img", "link"], limit=80):
            rel = " ".join(tag.get("rel", []) if isinstance(tag.get("rel"), list) else [str(tag.get("rel") or "")])
            if tag.name == "link" and "icon" not in rel.lower():
                continue
            for attribute in ("src", "href", "alt"):
                value = tag.get(attribute)
                if value:
                    values.append(str(value).lower())
        haystack = " ".join(values)
        return sorted(brand for brand in BRAND_TERMS if brand in haystack)

    @staticmethod
    def _is_legitimate_brand_host(hostname: str, brand: str) -> bool:
        allowed_hosts = LEGITIMATE_BRAND_HOSTS.get(brand, set())
        return hostname_matches_allowed(hostname, allowed_hosts)

    @staticmethod
    def _endswith_any(hostname: str, suffixes: tuple[str, ...]) -> bool:
        return any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes)

    def _safe_get(self, url: str, headers: dict[str, str]):
        page = fetch_page(url, headers=headers)
        return BufferedPageResponse(page), page.final_url, list(page.redirect_chain)

    @staticmethod
    def _load_model(model_path: str | None):
        if not model_path:
            return None

        path = Path(model_path)
        if not path.exists():
            return None

        try:
            return joblib.load(path)
        except Exception:
            return None

    def _predict_html_model(self, final_url: str, raw_html: str) -> dict[str, object]:
        try:
            features = extract_html_features_dataframe(url=final_url, raw_html=raw_html, final_url=final_url)
            feature_values = {
                str(column): float(features.iloc[0][column])
                for column in features.columns
            }
        except Exception as exc:
            return {
                "available": False,
                "model_path": self.model_path,
                "reason": "HTML feature extraction failed",
                "error": str(exc),
            }

        if self.model is None:
            return {
                "available": False,
                "model_path": self.model_path,
                "reason": "HTML model unavailable",
                "features": feature_values,
            }

        try:
            classes = list(getattr(self.model, "classes_", []))
            if len(classes) != 2 or set(classes) != {0, 1}:
                raise ValueError("HTML model requires clean=0 and malicious=1 classes")
            probability = float(self.model.predict_proba(features)[0][classes.index(1)])
            if not 0.0 <= probability <= 1.0:
                raise ValueError("HTML model probability is invalid")
            model_risk_score = self._model_probability_to_risk(probability)
            return {
                "available": True,
                "model_path": self.model_path,
                "malicious_probability": round(probability, 4),
                "clean_probability": round(1 - probability, 4),
                "model_risk_score": round(model_risk_score, 4),
                "feature_count": int(features.shape[1]),
                "features": feature_values,
            }
        except Exception as exc:
            return {
                "available": False,
                "model_path": self.model_path,
                "reason": "HTML model prediction failed",
                "error": str(exc),
                "features": feature_values,
            }

    @staticmethod
    def _model_probability_to_risk(probability: float) -> float:
        if probability < 0.5:
            return 0.0
        if probability >= 0.8:
            return min(0.88, 0.75 + ((probability - 0.8) * 0.5))
        return 0.25 + ((probability - 0.5) * (0.5 / 0.3))

    @staticmethod
    def _combine_rule_and_model_scores(rule_score: float, html_model_result: dict[str, object]) -> float:
        model_risk_score = float(html_model_result.get("model_risk_score") or 0.0)
        if model_risk_score <= 0:
            return min(rule_score, 1.0)
        return min(1.0, 1 - ((1 - rule_score) * (1 - model_risk_score)))
