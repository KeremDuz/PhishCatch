import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from app.models.schemas import StageResult
from app.services.base_scanner import BaseScanner
from app.services.url_safety import validate_public_http_url


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
    "iban", "account", "hesap", "routing", "sort_code", "swift",
    "bic", "bank_account", "hesap_no",
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

# 6. Autocomplete attribute'ları — tarayıcıyı kandırma girişimi
SUSPICIOUS_AUTOCOMPLETE = [
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
    """input'un name/id/placeholder/autocomplete attribute'unu kontrol et."""
    if not value:
        return False
    normalized = value.lower().replace("-", "_").replace(" ", "_")
    return any(p in normalized for p in patterns)


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
        "suspicious_autocomplete": [],
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
        inputmode = element.get("inputmode", "") or ""
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
            value = element.get("value", "") or ""
            # Eğer name veya value'da hassas kelimeler varsa
            hidden_check = f"{name} {id_attr} {value}"
            suspicious_hidden_words = [
                "token", "session", "csrf", "user_id", "email",
                "device", "fingerprint", "browser",
            ]
            if any(w in hidden_check.lower() for w in suspicious_hidden_words):
                findings["hidden_exfil"].append({
                    "tag": tag_name, "name": name, "value_preview": value[:50],
                })
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
        if autocomplete and autocomplete.lower() in SUSPICIOUS_AUTOCOMPLETE:
            findings["suspicious_autocomplete"].append({
                "tag": tag_name, "autocomplete": autocomplete,
                "name": name, "id": id_attr,
            })

        # ── inputmode="numeric" + kısa maxlength → PIN/OTP ipucu ──
        if inputmode == "numeric":
            maxlength = element.get("maxlength", "")
            try:
                ml = int(maxlength)
            except (ValueError, TypeError):
                ml = 999
            if ml <= 8:  # PIN: 4-6, OTP: 6, CVV: 3
                findings["pin_otp"].append({
                    "tag": tag_name, "type": input_type, "name": name,
                    "inputmode": inputmode, "maxlength": maxlength,
                    "hint": "numeric inputmode with short maxlength",
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
        if _attr_matches(all_attrs, PIN_OTP_PATTERNS):
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


def _scan_iframes(soup: BeautifulSoup, base_domain: str) -> list:
    """Dış kaynaklı iframe'leri bul — form gizleme, overlay saldırısı."""
    suspicious = []
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "") or ""
        if src.startswith("http"):
            iframe_domain = urlparse(src).netloc
            if iframe_domain and iframe_domain != base_domain:
                suspicious.append({
                    "src": src[:200],
                    "domain": iframe_domain,
                    "hidden": iframe.get("style", "").find("display:none") >= 0
                              or iframe.get("width") == "0"
                              or iframe.get("height") == "0",
                })
    return suspicious


class HtmlScraperScanner(BaseScanner):
    def __init__(self) -> None:
        super().__init__(name="HtmlScraper")
        self.max_redirects = 5

    def scan(self, url: str) -> StageResult:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response, final_url, redirect_chain = self._safe_get(url, headers=headers)
            parsed_url = urlparse(final_url)
            base_domain = parsed_url.netloc

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    risk_score=0.0,
                    reason="Target is not a valid HTML page",
                )

            # Maksimum 1MB indir
            html_bytes = b""
            for chunk in response.iter_content(chunk_size=1024 * 100):
                html_bytes += chunk
                if len(html_bytes) > 1024 * 1024:
                    break

            raw_html = html_bytes.decode("utf-8", errors="ignore")
            soup = BeautifulSoup(raw_html, "lxml")

            # ── Analiz ──
            input_findings = _scan_inputs(soup)
            js_threats = _scan_js_threats(soup, raw_html)
            external_iframes = _scan_iframes(soup, base_domain)

            # Form action analizi
            forms = soup.find_all("form")
            external_actions = 0
            abnormal_actions = 0
            for form in forms:
                action = (form.get("action") or "").strip()
                if not action or action.startswith("#") or action.startswith("javascript:"):
                    abnormal_actions += 1
                elif action.startswith("http"):
                    action_domain = urlparse(action).netloc
                    if action_domain and action_domain != base_domain:
                        external_actions += 1

            title = soup.title.string.strip() if soup.title and soup.title.string else None

            # ── Tehdit puanı hesapla ──
            threat_score = 0.0
            reasons = []

            # Credential theft — tek başına düşük puan (her login sayfasında var)
            # Diğer sinyallerle birleşince tehlikeli olur
            cred_count = len(input_findings["credentials"])
            if cred_count > 0:
                threat_score += 0.15
                reasons.append(f"{cred_count} credential input(s) found")

            # Kredi kartı bilgisi toplama
            cc_count = len(input_findings["credit_card"])
            cvv_count = len(input_findings["cvv"])
            if cc_count > 0:
                threat_score += 0.35
                reasons.append(f"Credit card input detected ({cc_count} field(s))")
            if cvv_count > 0:
                threat_score += 0.15
                reasons.append(f"CVV/security code field detected")

            # Banka bilgisi
            bank_count = len(input_findings["banking"])
            if bank_count > 0:
                threat_score += 0.3
                reasons.append(f"Banking/IBAN input detected ({bank_count} field(s))")

            # PIN / OTP
            pin_count = len(input_findings["pin_otp"])
            if pin_count > 0:
                threat_score += 0.25
                reasons.append(f"PIN/OTP verification input detected")

            # Kimlik bilgisi
            id_count = len(input_findings["identity"])
            if id_count > 0:
                threat_score += 0.25
                reasons.append(f"Identity/SSN input detected ({id_count} field(s))")

            # Crypto seed
            crypto_count = len(input_findings["crypto"])
            if crypto_count > 0:
                threat_score += 0.4
                reasons.append(f"Crypto wallet/seed phrase input detected")

            # Dosya yükleme — kimlik belgesi
            file_count = len(input_findings["file_upload"])
            if file_count > 0 and cred_count > 0:
                threat_score += 0.2
                reasons.append(f"File upload with credential fields (ID theft risk)")

            # Autocomplete kötüye kullanım
            ac_count = len(input_findings["suspicious_autocomplete"])
            if ac_count > 0:
                threat_score += 0.15
                reasons.append(f"Suspicious autocomplete attributes (browser autofill abuse)")

            # Form action dışarı gidiyor
            if external_actions > 0 and (cred_count > 0 or cc_count > 0):
                threat_score += 0.25
                reasons.append(f"Form submits sensitive data to external domain")

            # Abnormal form action
            if abnormal_actions > 0 and (cred_count > 0 or cc_count > 0):
                threat_score += 0.1
                reasons.append(f"Form has empty/javascript action (data exfil via JS)")

            # JS keylogger
            if js_threats["keyloggers"]:
                threat_score += 0.3
                reasons.append(f"JavaScript keylogger detected")

            # JS exfiltration
            if js_threats["exfiltration"]:
                threat_score += 0.2
                reasons.append(f"JavaScript data exfiltration pattern found")

            # Right-click disabled — many legit sites also do this
            if js_threats["right_click_disabled"]:
                threat_score += 0.05
                reasons.append(f"Right-click disabled (anti-inspection)")

            # Clipboard hijack
            if js_threats["clipboard_hijack"]:
                threat_score += 0.15
                reasons.append(f"Clipboard manipulation detected")

            # External iframe
            if external_iframes:
                threat_score += 0.2
                reasons.append(f"{len(external_iframes)} external iframe(s) found (overlay/clickjacking risk)")

            # HTTP + sensitive input
            if parsed_url.scheme != "https" and (cred_count > 0 or cc_count > 0 or bank_count > 0):
                threat_score += 0.2
                reasons.append(f"Sensitive data collected over insecure HTTP")

            # Title yok ama input var
            if not title and (cred_count > 0 or cc_count > 0):
                threat_score += 0.1
                reasons.append(f"Missing page title (cheap phishing clone)")

            # Hidden input ile veri sızdırma
            hidden_count = len(input_findings.get("hidden_exfil", []))
            if hidden_count > 0 and (cred_count > 0 or cc_count > 0):
                threat_score += 0.1
                reasons.append(f"Hidden inputs collecting session/device data ({hidden_count})")

            # formaction override — form action'ı button ile değiştirme
            formaction_count = len(input_findings.get("formaction_override", []))
            if formaction_count > 0:
                threat_score += 0.2
                reasons.append(f"Button formaction override detected (bypasses form action)")

            # contenteditable — modern JS input
            ce_count = len(input_findings.get("contenteditable", []))
            if ce_count > 0 and (cred_count > 0 or cc_count > 0):
                threat_score += 0.1
                reasons.append(f"contenteditable elements with sensitive inputs")

            # ── Karar ──
            threat_score = min(threat_score, 1.0)

            # Aktif input sayısı (non-empty categories)
            active_categories = sum(
                1 for k, v in input_findings.items()
                if isinstance(v, list) and len(v) > 0
            )

            details = {
                "title": title,
                "total_forms": len(forms),
                "external_form_actions": external_actions,
                "abnormal_form_actions": abnormal_actions,
                "threat_score": round(threat_score, 3),
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
                    confidence=round(threat_score, 4),
                    risk_score=round(threat_score, 4),
                    reason=" | ".join(reasons[:5]),
                    details=details,
                )
            elif threat_score >= 0.3:
                return StageResult(
                    scanner=self.name,
                    verdict="unknown",
                    confidence=round(threat_score, 4),
                    risk_score=round(threat_score, 4),
                    reason=" | ".join(reasons[:5]),
                    details=details,
                )
            else:
                return StageResult(
                    scanner=self.name,
                    verdict="clean",
                    risk_score=round(threat_score, 4),
                    reason="DOM structure appears normal",
                    details=details,
                )

        except Exception as e:
            return StageResult(
                scanner=self.name,
                verdict="unknown",
                risk_score=None,
                reason="Failed to scrape HTML content",
                details={"error": str(e)},
            )

    def _safe_get(self, url: str, headers: dict[str, str]) -> tuple[requests.Response, str, list[dict]]:
        current_url = url
        redirect_chain = []

        for _ in range(self.max_redirects + 1):
            safety = validate_public_http_url(current_url)
            if not safety.is_safe:
                raise ValueError(f"URL fetch blocked: {safety.reason}")

            response = requests.get(
                current_url,
                headers=headers,
                timeout=5,
                stream=True,
                allow_redirects=False,
            )

            if not response.is_redirect:
                return response, current_url, redirect_chain

            location = response.headers.get("Location")
            if not location:
                return response, current_url, redirect_chain

            next_url = urljoin(current_url, location)
            redirect_chain.append(
                {
                    "from": current_url,
                    "to": next_url,
                    "status_code": response.status_code,
                }
            )
            current_url = next_url

        raise ValueError("Maximum redirect depth exceeded")
