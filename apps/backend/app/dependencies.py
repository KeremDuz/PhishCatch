from functools import lru_cache

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.core.scan_cache import ScannerResultCache
from app.services.ml_model_scanner import MLModelScanner
from app.services.virustotal_scanner import VirusTotalScanner
from app.services.url_resolver_scanner import UrlResolverScanner
from app.services.whois_scanner import WhoisScanner
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.threat_intel_scanners import UrlhausScanner, GoogleSafeBrowsingScanner
from app.services.url_heuristic_scanner import URLHeuristicScanner


@lru_cache(maxsize=1)
def get_scanning_pipeline() -> ScanningPipeline:
    """
    Backend karar akışı:
    
    1. URLHeuristic    → Brand/campaign/free-hosting URL sinyalleri
    2. UrlResolver     → Kısa link çöz, güvenli fetch sınırlarını uygula
    3. WhoisScanner    → Domain yaşı / direkt IP sinyali üret
    4. URLhaus         → Bilinen kötü URL veritabanı
    5. SafeBrowsing    → Google kara listesi (opsiyonel)
    6. VirusTotal      → Opsiyonel reputation sinyali
    7. MLModel         → URL-only model ile hızlı lexical skor
    8. HtmlScraper     → DOM/form/JS/render/visual analiz
    9. RiskAggregator  → Tüm sinyalleri birleştirip malicious/unknown/clean döndürür
    
    Scanner'lar tek başına final karar vermez; final karar risk aggregator'dadır.
    """
    scanners = [
        URLHeuristicScanner(),
        UrlResolverScanner(),
        WhoisScanner(),
    ]

    # URLhaus — query endpoint can run without a key; key is optional.
    scanners.append(
        UrlhausScanner(auth_key=settings.urlhaus_auth_key)
    )

    # Google Safe Browsing — key varsa ekle (10K/gün)
    if settings.google_safe_browsing_api_key:
        scanners.append(
            GoogleSafeBrowsingScanner(api_key=settings.google_safe_browsing_api_key)
        )

    # VirusTotal — key varsa ekle (opsiyonel, düşük limit)
    if settings.virustotal_api_key:
        scanners.append(VirusTotalScanner(settings=settings))

    # ML Model — hızlı URL lexical sinyal üretir
    scanners.append(MLModelScanner(settings=settings))

    # HtmlScraper — yavaş ama derin DOM/form sinyali üretir
    scanners.append(
        HtmlScraperScanner(
            model_path=settings.html_model_path,
            browser_render_enabled=settings.html_browser_render_enabled,
            browser_timeout_ms=settings.html_browser_render_timeout_ms,
            browser_screenshot_enabled=settings.html_browser_screenshot_enabled,
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
        scan_cache=scan_cache,
        skip_html_on_confident_clean=settings.html_skip_on_confident_clean,
        html_skip_max_prior_risk=settings.html_skip_max_prior_risk,
    )
