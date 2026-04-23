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
    YENİ AKIŞ:
    
    1. UrlResolver     → Kısa link çöz (bit.ly → gerçek URL)
    2. WhoisScanner    → Domain yaşı kontrol (<30 gün = şüpheli)
    3. URLhaus         → Ücretsiz, sınırsız. Bilinen malware URL veritabanı
    4. SafeBrowsing    → Google kara listesi (10K/gün, opsiyonel)
    5. MLModel         → 48 feature ile sınıflandır
                         - Kesin malicious (>=0.85) → DUR
                         - Kesin clean (<=0.15) → DUR
                         - Kararsız (0.15-0.85) → devam et ↓
    6. HtmlScraper     → DOM analizi (sadece ML kararsızsa çalışır)
                         Credential, kredi kartı, OTP, keylogger vb. tarar
    
    VirusTotal opsiyonel — API key varsa eklenir, yoksa atlanır.
    """
    scanners = [
        UrlResolverScanner(),
        WhoisScanner(),
    ]

    # URLhaus — key varsa ekle (ücretsiz, sınırsız)
    if settings.urlhaus_auth_key:
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

    # ML Model — hızlı karar. Kesinse durur, kararsızsa devam eder
    scanners.append(MLModelScanner(settings=settings))

    # HtmlScraper — yavaş ama derin. Sadece ML kararsız kaldığında çalışır
    scanners.append(HtmlScraperScanner())

    return ScanningPipeline(scanners=scanners)
