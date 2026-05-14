from functools import lru_cache

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.core.scan_cache import ScannerResultCache
from app.services.ml_model_scanner import MLModelScanner
from app.services.virustotal_scanner import VirusTotalScanner
from app.services.url_resolver_scanner import UrlResolverScanner
from app.services.whois_scanner import WhoisScanner
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.threat_intel_scanners import GoogleSafeBrowsingScanner, GoogleWebRiskScanner, UrlhausScanner


@lru_cache(maxsize=1)
def get_scanning_pipeline() -> ScanningPipeline:
    """
    Backend karar akışı:
    
    0. Redirect resolve → Kısa/yönlenen linkleri final hedefe çözer; risk sinyali üretmez
    1. ThreatIntel     → URLhaus / SafeBrowsing / WebRisk / VirusTotal eş zamanlı sorgulanır
    2. WhoisScanner    → Domain yaşı / direkt IP sinyali üret
    3. MLModel         → URL-only model ile hızlı lexical skor
    4. HtmlScraper     → DOM/form/JS/render/visual analiz
    5. RiskAggregator  → Tüm sinyalleri birleştirip malicious/unknown/clean döndürür
    
    URL heuristic scanner final pipeline'dan çıkarıldı. Kısa linkler sırf kısa
    oldukları için risk puanı almaz; resolver sadece gerçek hedef URL'yi bulur.
    Threat-intel kaynaklarından biri malicious derse pipeline sonraki katmanlara
    geçmeden RiskAggregator sonucu döndürür.
    Scanner'lar tek başına final karar vermez; final karar risk aggregator'dadır.
    """
    scanners = [
        WhoisScanner(),
    ]

    threat_intel_scanners = [
        UrlhausScanner(auth_key=settings.urlhaus_auth_key)
    ]

    # Google Safe Browsing — key varsa ekle (10K/gün)
    if settings.google_safe_browsing_api_key:
        threat_intel_scanners.append(
            GoogleSafeBrowsingScanner(api_key=settings.google_safe_browsing_api_key)
        )

    # Google Web Risk — production reputation lookup; key varsa ekle
    if settings.google_web_risk_api_key:
        threat_intel_scanners.append(
            GoogleWebRiskScanner(api_key=settings.google_web_risk_api_key)
        )

    # VirusTotal — key varsa ekle (opsiyonel, düşük limit)
    if settings.virustotal_api_key:
        threat_intel_scanners.append(VirusTotalScanner(settings=settings))

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
        redirect_resolver=UrlResolverScanner(),
        threat_intel_scanners=threat_intel_scanners,
        scan_cache=scan_cache,
        skip_html_on_confident_clean=settings.html_skip_on_confident_clean,
        html_skip_max_prior_risk=settings.html_skip_max_prior_risk,
    )
