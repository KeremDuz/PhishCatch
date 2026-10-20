from functools import lru_cache

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.core.scan_cache import ScannerResultCache
from app.services.ml_model_scanner import MLModelScanner
from app.services.virustotal_scanner import VirusTotalScanner
from app.services.url_resolver_scanner import UrlResolverScanner
from app.services.rdap_scanner import RdapScanner
from app.services.local_phishing_feed import LocalPhishingFeed
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.threat_intel_scanners import (
    GoogleSafeBrowsingScanner,
    GoogleWebRiskScanner,
    UrlhausScanner,
)
from app.storage import TrainingStore


@lru_cache(maxsize=1)
def get_scanning_pipeline() -> ScanningPipeline:
    """
    Backend karar akışı:

    1. UrlResolver     → Gizli preprocessing; kısa link/redirect çöz, ekranda katman olarak gösterilmez.
    2. Reputation     → Güncel yerel phishing listesi ve yapılandırılmış itibar kaynakları.
                         Bu katmanda en az bir kaynak malicious dönerse pipeline burada durur.
    3. RDAP            → İsteğe bağlı kayıt yaşı bağlamı; güvenli olduğuna kanıt değildir.
    4. MLModel         → URL-only lexical skor üretir.
    5. HtmlScraper     → Aynı GET üzerinde statik DOM/form/HTML modeli; eksik JS açıkça belirtilir.
    6. RiskAggregator  → Çalışan katmanların sinyalini final karara çevirir.

    URLHeuristicScanner bilinçli olarak pipeline dışında tutulur.
    """
    threat_intel_scanners = [
        LocalPhishingFeed(
            settings.phishing_feed_path, settings.phishing_feed_max_age_hours
        ),
    ]
    if settings.urlhaus_auth_key:
        threat_intel_scanners.append(UrlhausScanner(auth_key=settings.urlhaus_auth_key))

    # Google Safe Browsing — key varsa ekle (10K/gün)
    if settings.google_safe_browsing_api_key:
        threat_intel_scanners.append(
            GoogleSafeBrowsingScanner(api_key=settings.google_safe_browsing_api_key)
        )

    # Google Web Risk — key varsa ekle (production reputation sinyali)
    if settings.google_web_risk_api_key:
        threat_intel_scanners.append(
            GoogleWebRiskScanner(api_key=settings.google_web_risk_api_key)
        )

    # VirusTotal — key varsa ekle (opsiyonel, düşük limit; çoklu key ile 429 rotasyonu desteklenir)
    if settings.virustotal_api_keys:
        threat_intel_scanners.append(VirusTotalScanner(settings=settings))

    scanners = [
        RdapScanner(),
    ]

    # ML Model — hızlı URL lexical sinyal üretir
    scanners.append(MLModelScanner(settings=settings))

    # HtmlScraper — yavaş ama derin DOM/form sinyali üretir
    scanners.append(
        HtmlScraperScanner(
            model_path=settings.html_model_path,
            browser_render_enabled=settings.html_browser_render_enabled,
            browser_timeout_ms=settings.html_browser_render_timeout_ms,
            browser_screenshot_enabled=settings.html_browser_screenshot_enabled,
            isolated=True,
        )
    )

    scan_cache = (
        ScannerResultCache(
            ttl_seconds=settings.scanner_cache_ttl_seconds,
            max_entries=settings.scanner_cache_max_entries,
        )
        if settings.scanner_cache_enabled
        else None
    )

    return ScanningPipeline(
        scanners=scanners,
        redirect_resolver=UrlResolverScanner(),
        threat_intel_scanners=threat_intel_scanners,
        scan_cache=scan_cache,
        skip_html_on_confident_clean=settings.html_skip_on_confident_clean,
        html_skip_max_prior_risk=settings.html_skip_max_prior_risk,
        fetch_worker=True,
    )


@lru_cache(maxsize=1)
def get_training_store() -> TrainingStore:
    store = TrainingStore(settings.training_db_path)
    store.init_db()
    return store
