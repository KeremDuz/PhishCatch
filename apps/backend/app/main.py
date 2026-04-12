from fastapi import FastAPI

from app.core.config import settings
from app.routers.analyze import router as analyze_router

app = FastAPI(title=settings.app_name, version=settings.app_version)

app.include_router(analyze_router)


@app.get("/health", tags=["System"])
def health() -> dict[str, str]:
    return {"status": "ok"}
