from functools import lru_cache

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.services.ml_model_scanner import MLModelScanner
from app.services.virustotal_scanner import VirusTotalScanner


@lru_cache(maxsize=1)
def get_scanning_pipeline() -> ScanningPipeline:
    scanners = [
        VirusTotalScanner(settings=settings),
        MLModelScanner(settings=settings),
    ]
    return ScanningPipeline(scanners=scanners)
