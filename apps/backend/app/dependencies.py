from functools import lru_cache

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.services.ml_model_scanner import MLModelScanner
from app.services.virustotal_scanner import VirusTotalScanner
from app.services.url_resolver_scanner import UrlResolverScanner
from app.services.whois_scanner import WhoisScanner
from app.services.html_scraper_scanner import HtmlScraperScanner
from app.services.threat_intel_scanners import UrlhausScanner, GoogleSafeBrowsingScanner


@lru_cache(maxsize=1)
def get_scanning_pipeline() -> ScanningPipeline:
    """
    Backend karar akışı:
    
    1. UrlResolver     → Kısa link çöz, güvenli fetch sınırlarını uygula
    2. WhoisScanner    → Domain yaşı / direkt IP sinyali üret
    3. URLhaus         → Bilinen kötü URL veritabanı
    4. SafeBrowsing    → Google kara listesi (opsiyonel)
    5. VirusTotal      → Opsiyonel reputation sinyali
    6. MLModel         → URL-only model ile hızlı lexical skor
    7. HtmlScraper     → DOM/form/JS davranış analizi
    8. RiskAggregator  → Tüm sinyalleri birleştirip phishing/clean döndürür
    
    Scanner'lar tek başına final karar vermez; final karar risk aggregator'dadır.
    """
    scanners = [
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
    scanners.append(HtmlScraperScanner())

    return ScanningPipeline(scanners=scanners)
