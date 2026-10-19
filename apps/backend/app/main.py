from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.pipeline import ScanningPipeline
from app.dependencies import get_scanning_pipeline
from app.routers.admin_training import router as admin_training_router
from app.routers.analyze import router as analyze_router

LOCALHOST_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"

app = FastAPI(title=settings.app_name, version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_origin_regex=LOCALHOST_ORIGIN_REGEX,
    allow_credentials="*" not in settings.cors_allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(admin_training_router)


@app.get("/health", tags=["System"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/layers", tags=["System"])
@app.get("/api/v1/health/layers", tags=["System"])
def health_layers(
    pipeline: ScanningPipeline = Depends(get_scanning_pipeline),
) -> dict[str, object]:
    return pipeline.health_report()
